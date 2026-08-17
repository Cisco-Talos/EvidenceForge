# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical phase planning for explicit forward-proxy transactions."""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from evidenceforge.events.proxy import ProxyTerminalOutcome, ProxyTransactionPlan
from evidenceforge.generation.activity.proxy_phase_profiles import (
    MillisecondRange,
    ProxyResolverProfile,
    proxy_phase_timing,
    proxy_resolver_profiles,
)
from evidenceforge.generation.source_timing import SourceTimingPlanningRuntime
from evidenceforge.generation.timing import (
    ConstantDistribution,
    TimingRuntime,
    TimingScope,
    TriangularDistribution,
)
from evidenceforge.utils.rng import _stable_seed

if TYPE_CHECKING:
    from evidenceforge.events.contexts import ProxyContext
    from evidenceforge.generation.actions.proxy_transaction import ProxyTransactionRequest


class ProxyPhasePlanner:
    """Finalize conditional proxy phases before any child event is constructed."""

    def __init__(
        self,
        timing_runtime: TimingRuntime | SourceTimingPlanningRuntime | None = None,
    ) -> None:
        """Initialize the planner with the engine-owned timing runtime."""

        self._timing_runtime = (
            timing_runtime
            if isinstance(timing_runtime, (TimingRuntime, SourceTimingPlanningRuntime))
            else TimingRuntime.compatibility_default()
        )

    def plan(
        self,
        request: ProxyTransactionRequest,
        proxy: ProxyContext,
        client_connect_at: datetime,
    ) -> ProxyTransactionPlan:
        """Return immutable phase truth for one explicit-proxy request."""

        rng = random.Random(_stable_seed(f"proxy_phase_plan:{request.stable_id}"))
        timing = proxy_phase_timing()
        timing_scope = self._timing_scope(request)
        tunnel_request_at: datetime | None = None
        first_request_at = client_connect_at + self._sample(
            timing.request_after_connect_ms,
            relationship_key="proxy.request_after_connect",
            scope=timing_scope,
            sample_key="first_request",
        )
        if request.dst_port == 443 and proxy.method != "CONNECT":
            tunnel_request_at = first_request_at
            request_at = tunnel_request_at + self._sample(
                timing.inspected_request_after_connect_setup_ms,
                relationship_key="proxy.inspected_request_after_connect_setup",
                scope=timing_scope,
                sample_key="inspected_request",
            )
        else:
            request_at = first_request_at
            if proxy.method == "CONNECT":
                tunnel_request_at = request_at
        decision_at = request_at + self._sample(
            timing.policy_decision_after_request_ms,
            relationship_key="proxy.policy_decision_after_request",
            scope=timing_scope,
            sample_key="decision",
        )
        terminal_outcome = self.terminal_outcome(proxy)

        resolver_profile: ProxyResolverProfile | None = None
        dns_query_at: datetime | None = None
        dns_response_at: datetime | None = None
        origin_connect_at: datetime | None = None
        tls_complete_at: datetime | None = None
        origin_request_at: datetime | None = None
        origin_response_at: datetime | None = None
        origin_close_at: datetime | None = None
        origin_conn_state: str | None = None

        if terminal_outcome in {"success", "gateway_failure"}:
            resolver_profile = self._pick_resolver_profile(rng)
            if resolver_profile.name == "resolver_cache_hit":
                if resolver_profile.origin_after_request_ms is None:
                    raise ValueError("Resolver cache profile requires an origin request gap")
                origin_connect_at = request_at + self._sample(
                    resolver_profile.origin_after_request_ms,
                    relationship_key="proxy.origin.connect_after_cached_resolution",
                    scope=timing_scope,
                    sample_key=resolver_profile.name,
                )
                origin_connect_at = max(origin_connect_at, decision_at + timedelta(milliseconds=1))
            else:
                if (
                    resolver_profile.dns_completion_after_request_ms is None
                    or resolver_profile.origin_after_dns_ms is None
                ):
                    raise ValueError("Resolver lookup profiles require DNS timing ranges")
                dns_query_at = decision_at + self._sample_microsecond_gap(
                    timing.dns_query_after_decision_ms,
                    relationship_key="proxy.dns.query_after_decision",
                    scope=timing_scope,
                    sample_key=resolver_profile.name,
                )
                dns_response_at = request_at + self._sample_microsecond_gap(
                    resolver_profile.dns_completion_after_request_ms,
                    relationship_key="proxy.dns.response_after_request",
                    scope=timing_scope,
                    sample_key=resolver_profile.name,
                )
                if dns_response_at <= dns_query_at:
                    repair_slack = self._sample_microsecond_gap(
                        timing.dns_query_after_decision_ms,
                        relationship_key="proxy.dns.response_repair_slack",
                        scope=timing_scope,
                        sample_key=resolver_profile.name,
                    )
                    dns_response_at = dns_query_at + repair_slack
                    self._timing_runtime.audit.record_repair("proxy.dns.response_after_request")
                origin_connect_at = dns_response_at + self._sample_microsecond_gap(
                    resolver_profile.origin_after_dns_ms,
                    relationship_key="proxy.origin.connect_after_dns",
                    scope=timing_scope,
                    sample_key=resolver_profile.name,
                )

            if terminal_outcome == "gateway_failure":
                origin_conn_state = self._gateway_conn_state(proxy.status_code, rng)
                attempt_duration = self._sample(
                    timing.gateway_attempt_ms,
                    relationship_key="proxy.gateway.attempt_duration",
                    scope=timing_scope,
                    sample_key="gateway_attempt",
                )
                origin_close_at = origin_connect_at + attempt_duration
                client_flush_at = origin_close_at + self._sample(
                    timing.client_flush_after_response_ms,
                    relationship_key="proxy.client_flush_after_gateway_response",
                    scope=timing_scope,
                    sample_key="gateway_flush",
                )
            else:
                origin_conn_state = "SF"
                origin_duration = self._origin_duration(
                    request,
                    proxy,
                    timing.origin_service_ms,
                    scope=timing_scope,
                )
                origin_close_at = origin_connect_at + origin_duration
                response_anchor = origin_connect_at
                if request.dst_port == 443:
                    tls_complete_at = origin_connect_at + self._sample(
                        timing.tls_after_origin_connect_ms,
                        relationship_key="proxy.tls_after_origin_connect",
                        scope=timing_scope,
                        sample_key="tls_complete",
                    )
                    response_anchor = tls_complete_at
                if proxy.method != "CONNECT":
                    origin_request_at = response_anchor + timedelta(milliseconds=1)
                    response_anchor = origin_request_at
                response_budget = origin_close_at - response_anchor
                response_fraction = self._timing_runtime.sampler.sample_value(
                    TriangularDistribution(minimum=0.55, mode=0.68, maximum=0.85),
                    relationship_key="proxy.origin.response_phase_fraction",
                    scope=timing_scope,
                    sample_key="response_fraction",
                )
                origin_response_at = response_anchor + max(
                    timedelta(milliseconds=1),
                    response_budget * response_fraction,
                )
                origin_response_at = min(
                    origin_response_at,
                    origin_close_at - timedelta(microseconds=1),
                )
                client_flush_at = origin_response_at + self._sample(
                    timing.client_flush_after_response_ms,
                    relationship_key="proxy.client_flush_after_origin_response",
                    scope=timing_scope,
                    sample_key="origin_flush",
                )
        else:
            client_flush_at = decision_at + self._sample(
                timing.terminal_response_after_decision_ms,
                relationship_key="proxy.terminal_response_after_decision",
                scope=timing_scope,
                sample_key=terminal_outcome,
            )

        close_at = max(
            client_flush_at
            + self._sample(
                timing.close_after_flush_ms,
                relationship_key="proxy.close_after_flush",
                scope=timing_scope,
                sample_key="close",
            ),
            origin_close_at or client_flush_at,
        )
        setup_cs_bytes, setup_sc_bytes, setup_time_taken_ms = self._tunnel_setup(
            request,
            proxy,
            tunnel_request_at,
            request_at,
            rng,
        )
        return ProxyTransactionPlan(
            stable_id=request.stable_id,
            terminal_outcome=terminal_outcome,
            resolver_mode=resolver_profile.name if resolver_profile is not None else None,
            client_connect_at=client_connect_at,
            tunnel_request_at=tunnel_request_at,
            request_at=request_at,
            decision_at=decision_at,
            dns_query_at=dns_query_at,
            dns_response_at=dns_response_at,
            origin_connect_at=origin_connect_at,
            tls_complete_at=tls_complete_at,
            origin_request_at=origin_request_at,
            origin_response_at=origin_response_at,
            origin_close_at=origin_close_at,
            client_flush_at=client_flush_at,
            close_at=close_at,
            origin_conn_state=origin_conn_state,
            tunnel_setup_cs_bytes=setup_cs_bytes,
            tunnel_setup_sc_bytes=setup_sc_bytes,
            tunnel_setup_time_taken_ms=setup_time_taken_ms,
        )

    def plan_reused(
        self,
        request: ProxyTransactionRequest,
        proxy: ProxyContext,
        request_at: datetime,
    ) -> ProxyTransactionPlan:
        """Plan an application transaction over an already-open proxy tunnel."""

        timing = proxy_phase_timing()
        timing_scope = self._timing_scope(request)
        terminal_outcome = self.terminal_outcome(proxy)
        if terminal_outcome not in {"success", "cache_hit"}:
            raise ValueError(
                "Only successful or cache-hit proxy requests can reuse an open transport"
            )
        decision_at = request_at + self._sample(
            timing.policy_decision_after_request_ms,
            relationship_key="proxy.reused.policy_decision_after_request",
            scope=timing_scope,
            sample_key="decision",
        )
        service_delay = self._sample(
            timing.origin_service_ms,
            relationship_key="proxy.reused.origin_service_duration",
            scope=timing_scope,
            sample_key="service",
        )
        client_flush_at = (
            decision_at
            + service_delay
            + self._sample(
                timing.client_flush_after_response_ms,
                relationship_key="proxy.reused.client_flush_after_response",
                scope=timing_scope,
                sample_key="flush",
            )
        )
        close_at = client_flush_at + self._sample(
            timing.close_after_flush_ms,
            relationship_key="proxy.reused.close_after_flush",
            scope=timing_scope,
            sample_key="close",
        )
        return ProxyTransactionPlan(
            stable_id=request.stable_id,
            terminal_outcome=terminal_outcome,
            resolver_mode=None,
            client_connect_at=request_at,
            tunnel_request_at=None,
            request_at=request_at,
            decision_at=decision_at,
            dns_query_at=None,
            dns_response_at=None,
            origin_connect_at=None,
            tls_complete_at=None,
            origin_request_at=None,
            origin_response_at=None,
            origin_close_at=None,
            client_flush_at=client_flush_at,
            close_at=close_at,
            origin_conn_state=None,
            reused_transport=True,
        )

    def _sample(
        self,
        bounds: MillisecondRange,
        *,
        relationship_key: str,
        scope: TimingScope,
        sample_key: str,
    ) -> timedelta:
        """Sample one data-driven millisecond range at microsecond precision."""

        return self._sample_microsecond_gap(
            bounds,
            relationship_key=relationship_key,
            scope=scope,
            sample_key=sample_key,
        )

    def _sample_microsecond_gap(
        self,
        bounds: MillisecondRange,
        *,
        relationship_key: str,
        scope: TimingScope,
        sample_key: str,
    ) -> timedelta:
        """Sample one data-driven range at native microsecond precision."""

        minimum_us = bounds.minimum * 1_000
        maximum_us = bounds.maximum * 1_000
        if minimum_us == maximum_us:
            distribution = ConstantDistribution(float(minimum_us))
        else:
            mode_us = minimum_us + ((maximum_us - minimum_us) * 0.35)
            distribution = TriangularDistribution(
                minimum=float(minimum_us),
                mode=float(mode_us),
                maximum=float(maximum_us),
            )
        return self._timing_runtime.sampler.sample_timedelta(
            distribution,
            relationship_key=relationship_key,
            scope=scope,
            sample_key=sample_key,
        )

    @staticmethod
    def _timing_scope(request: ProxyTransactionRequest) -> TimingScope:
        """Return the stable semantic scope for one proxy transaction."""

        proxy_hostname = request.proxy_chain[0].hostname if request.proxy_chain else ""
        return TimingScope(
            stable_id=request.stable_id,
            host=proxy_hostname,
            source="explicit_proxy",
            lifecycle_id=request.parent_action_group_id or request.stable_id,
        )

    @staticmethod
    def terminal_outcome(proxy: ProxyContext) -> ProxyTerminalOutcome:
        """Map proxy policy/cache truth to a typed terminal outcome."""

        cache_result = proxy.cache_result.upper()
        if cache_result == "HIT":
            return "cache_hit"
        if cache_result == "DENIED":
            return "denied"
        if cache_result == "AUTH_REQUIRED":
            return "authentication_required"
        if cache_result == "GATEWAY_ERROR" or proxy.status_code in {502, 503, 504}:
            return "gateway_failure"
        return "success"

    @staticmethod
    def _pick_resolver_profile(rng: random.Random) -> ProxyResolverProfile:
        """Select one configured resolver path by weight."""

        profiles = proxy_resolver_profiles()
        return rng.choices(profiles, weights=[profile.weight for profile in profiles], k=1)[0]

    def _origin_duration(
        self,
        request: ProxyTransactionRequest,
        proxy: ProxyContext,
        fallback: MillisecondRange,
        *,
        scope: TimingScope,
    ) -> timedelta:
        """Return a source-compatible origin lifetime owned by the phase graph."""

        if request.duration is not None:
            duration_seconds = max(0.04, request.duration)
        else:
            duration_seconds = self._sample_microsecond_gap(
                fallback,
                relationship_key="proxy.origin.service_duration",
                scope=scope,
                sample_key="origin_duration",
            ).total_seconds()
        from evidenceforge.generation.actions.file_transfer import (
            http_response_parent_duration_floor,
        )

        duration_seconds = max(
            duration_seconds,
            http_response_parent_duration_floor(proxy.response_body_bytes),
        )
        if request.dst_port == 443:
            duration_seconds = max(0.85, duration_seconds)
        return timedelta(seconds=duration_seconds)

    @staticmethod
    def _gateway_conn_state(status_code: int, rng: random.Random) -> str:
        """Return the failed transport state implied by a gateway error."""

        if status_code == 504:
            return "S0"
        if status_code == 503:
            return rng.choice(("REJ", "RSTO"))
        return rng.choice(("RSTO", "RSTR", "REJ"))

    @staticmethod
    def _tunnel_setup(
        request: ProxyTransactionRequest,
        proxy: ProxyContext,
        tunnel_request_at: datetime | None,
        request_at: datetime,
        rng: random.Random,
    ) -> tuple[int, int, int]:
        """Plan source-visible CONNECT setup accounting for inspected HTTPS."""

        if request.dst_port != 443 or proxy.method == "CONNECT" or tunnel_request_at is None:
            return 0, 0, 0
        host_len = len(proxy.host)
        return (
            rng.randint(180 + host_len, 520 + host_len),
            rng.randint(90, 260),
            max(1, round((request_at - tunnel_request_at).total_seconds() * 1000)),
        )
