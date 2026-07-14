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
from evidenceforge.utils.rng import _stable_seed

if TYPE_CHECKING:
    from evidenceforge.events.contexts import ProxyContext
    from evidenceforge.generation.actions.proxy_transaction import ProxyTransactionRequest


class ProxyPhasePlanner:
    """Finalize conditional proxy phases before any child event is constructed."""

    def plan(
        self,
        request: ProxyTransactionRequest,
        proxy: ProxyContext,
        client_connect_at: datetime,
    ) -> ProxyTransactionPlan:
        """Return immutable phase truth for one explicit-proxy request."""

        rng = random.Random(_stable_seed(f"proxy_phase_plan:{request.stable_id}"))
        timing = proxy_phase_timing()
        tunnel_request_at: datetime | None = None
        first_request_at = client_connect_at + self._sample(timing.request_after_connect_ms, rng)
        if request.dst_port == 443 and proxy.method != "CONNECT":
            tunnel_request_at = first_request_at
            request_at = tunnel_request_at + self._sample(
                timing.inspected_request_after_connect_setup_ms,
                rng,
            )
        else:
            request_at = first_request_at
            if proxy.method == "CONNECT":
                tunnel_request_at = request_at
        decision_at = request_at + self._sample(timing.policy_decision_after_request_ms, rng)
        terminal_outcome = self._terminal_outcome(proxy)

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
                    rng,
                )
                origin_connect_at = max(origin_connect_at, decision_at + timedelta(milliseconds=1))
            else:
                if (
                    resolver_profile.dns_completion_after_request_ms is None
                    or resolver_profile.origin_after_dns_ms is None
                ):
                    raise ValueError("Resolver lookup profiles require DNS timing ranges")
                dns_query_at = decision_at + timedelta(milliseconds=1)
                dns_response_at = request_at + self._sample(
                    resolver_profile.dns_completion_after_request_ms,
                    rng,
                )
                dns_response_at = max(
                    dns_response_at,
                    dns_query_at + timedelta(milliseconds=1),
                )
                origin_connect_at = dns_response_at + self._sample(
                    resolver_profile.origin_after_dns_ms,
                    rng,
                )

            if terminal_outcome == "gateway_failure":
                origin_conn_state = self._gateway_conn_state(proxy.status_code, rng)
                attempt_duration = self._sample(timing.gateway_attempt_ms, rng)
                origin_close_at = origin_connect_at + attempt_duration
                client_flush_at = origin_close_at + self._sample(
                    timing.client_flush_after_response_ms,
                    rng,
                )
            else:
                origin_conn_state = "SF"
                origin_duration = self._origin_duration(
                    request,
                    proxy,
                    timing.origin_service_ms,
                    rng,
                )
                origin_close_at = origin_connect_at + origin_duration
                response_anchor = origin_connect_at
                if request.dst_port == 443:
                    tls_complete_at = origin_connect_at + self._sample(
                        timing.tls_after_origin_connect_ms,
                        rng,
                    )
                    response_anchor = tls_complete_at
                if proxy.method != "CONNECT":
                    origin_request_at = response_anchor + timedelta(milliseconds=1)
                    response_anchor = origin_request_at
                response_budget = origin_close_at - response_anchor
                response_fraction = 0.55 + rng.random() * 0.30
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
                    rng,
                )
        else:
            client_flush_at = decision_at + self._sample(
                timing.terminal_response_after_decision_ms,
                rng,
            )

        close_at = max(
            client_flush_at + self._sample(timing.close_after_flush_ms, rng),
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

        rng = random.Random(_stable_seed(f"proxy_reused_phase_plan:{request.stable_id}"))
        timing = proxy_phase_timing()
        decision_at = request_at + self._sample(timing.policy_decision_after_request_ms, rng)
        service_delay = self._sample(timing.origin_service_ms, rng)
        client_flush_at = (
            decision_at
            + service_delay
            + self._sample(
                timing.client_flush_after_response_ms,
                rng,
            )
        )
        close_at = client_flush_at + self._sample(timing.close_after_flush_ms, rng)
        return ProxyTransactionPlan(
            stable_id=request.stable_id,
            terminal_outcome="success",
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

    @staticmethod
    def _sample(bounds: MillisecondRange, rng: random.Random) -> timedelta:
        """Sample one inclusive data-driven millisecond range."""

        return timedelta(milliseconds=rng.randint(bounds.minimum, bounds.maximum))

    @staticmethod
    def _terminal_outcome(proxy: ProxyContext) -> ProxyTerminalOutcome:
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

    @staticmethod
    def _origin_duration(
        request: ProxyTransactionRequest,
        proxy: ProxyContext,
        fallback: MillisecondRange,
        rng: random.Random,
    ) -> timedelta:
        """Return a source-compatible origin lifetime owned by the phase graph."""

        if request.duration is not None:
            duration_seconds = max(0.04, request.duration)
        else:
            duration_seconds = rng.randint(fallback.minimum, fallback.maximum) / 1000
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
