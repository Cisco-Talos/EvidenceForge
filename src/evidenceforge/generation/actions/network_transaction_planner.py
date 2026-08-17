# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Canonical network-connection action planner."""

from __future__ import annotations

import copy
from contextvars import ContextVar, Token
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from types import ModuleType
from typing import TYPE_CHECKING, Any

from evidenceforge.generation.http_channels import HttpChannelAffinity
from evidenceforge.generation.network_runtime import (
    NetworkConnectionCommitResult,
    NetworkRuntimePointFamily,
)
from evidenceforge.generation.state_manager import ConnectionMaterializationMode
from evidenceforge.generation.timing import (
    ClockWanderSpec,
    ConstantDistribution,
    MixtureDistribution,
    SourceClockKey,
    SourceClockSpec,
    TimingDistributionError,
    TimingScope,
    TriangularDistribution,
    TruncatedLognormalDistribution,
    WeightedDistribution,
)
from evidenceforge.models.exceptions import EventContractError, StateError
from evidenceforge.utils.rng import _stable_seed, stable_uuid
from evidenceforge.utils.time import ensure_utc

if TYPE_CHECKING:
    from evidenceforge.events.base import OccurrenceBuilder
    from evidenceforge.generation.actions.network_connection import NetworkConnectionRequest
    from evidenceforge.generation.activity.generator import ActivityGenerator


_ACTIVE_NETWORK_TIMING_RUNTIME: ContextVar[Any | None] = ContextVar(
    "evidenceforge_active_network_timing_runtime",
    default=None,
)


@dataclass(slots=True)
class _PreparedNetworkBoundary:
    """Own every revocable capability until the outer authority accepts transfer."""

    timing_context: Any = None
    timing_preparation: Any = None
    timing_runtime_token: Token[Any | None] | None = None
    network_runtime: Any = None
    network_preparation: Any = None
    root: Any = None
    application_manager: Any = None
    application_token: Any = None
    prerequisite_receipts: tuple[Any, ...] = ()
    lifecycle_adapter: Any = None
    lifecycle_token: Any = None
    identity_capture: Any = None
    identity_capture_claim: Any = None
    network_dependent_dispatcher: Any = None
    network_dependent_batch: Any = None
    transferred: bool = False

    def claim_identity_capture(self, capture: Any) -> None:
        """Claim one exact empty handoff before any prerequisite can mutate truth."""

        if capture is None:
            return
        from evidenceforge.generation.actions.network_connection import (
            NetworkConnectionIdentityCapture,
        )

        if type(capture) is not NetworkConnectionIdentityCapture:
            raise TypeError("Network request identity capture must be the exact carrier type")
        self.identity_capture = capture
        self.identity_capture_claim = capture._claim_empty()

    def validate_identity_capture_claim(self) -> None:
        """Authenticate the exact private handoff at the final precommit barrier."""

        if self.identity_capture is None:
            return
        if not self.identity_capture._authenticates_claim(self.identity_capture_claim):
            raise StateError("Network identity capture claim changed before publication")

    def publish_committed_capture_no_fail(
        self,
        *,
        root: Any,
        receipt: Any,
        application_receipt: Any,
        outcome: Any,
    ) -> None:
        """Populate the prevalidated occurrence-local capture after authority success."""

        if self.identity_capture is None:
            return
        capture = self.identity_capture
        claim = self.identity_capture_claim
        capture._publish_committed_claimed(
            claim,
            root=root,
            receipt=receipt,
            application_receipt=application_receipt,
            outcome=outcome,
        )
        self.identity_capture = None
        self.identity_capture_claim = None

    def track_network_dependent_batch(self, dispatcher: Any, batch: Any) -> None:
        """Own one claimed projection-only dependent batch until root acceptance."""

        if self.network_dependent_batch is not None:
            raise StateError("Network root cannot own multiple dependent dispatch batches")
        self.network_dependent_dispatcher = dispatcher
        self.network_dependent_batch = batch

    def validate_network_dependent_batch(self) -> None:
        """Authenticate the exact claimed dependent batch at the final precommit barrier."""

        if self.network_dependent_batch is None:
            return
        if not self.network_dependent_dispatcher.authenticates_prepared_network_dependent_batch(
            self.network_dependent_batch
        ):
            raise StateError("Network-dependent dispatch batch changed before publication")

    def track_application(
        self,
        manager: Any,
        token: Any,
        *,
        prerequisite_receipts: tuple[Any, ...] = (),
    ) -> None:
        """Retain at most one application admission for cancellation or transfer."""

        if token is None:
            return
        if self.application_token is not None:
            raise StateError("Network root cannot own multiple application admissions")
        self.application_manager = manager
        self.application_token = token
        self.prerequisite_receipts = prerequisite_receipts

    def begin(
        self,
        *,
        executor: ActivityGenerator,
        owner_rng: Any,
        stable_id: str,
        linearization_time: datetime,
        action_group_id: str,
    ) -> Any:
        """Open the shared timing overlay followed by the network runtime cursor."""

        self.timing_context = executor._source_timing_planner.prepared_planning()
        self.timing_preparation = self.timing_context.__enter__()
        staged_timing_runtime = self.timing_preparation.planning_runtime
        self.timing_runtime_token = _ACTIVE_NETWORK_TIMING_RUNTIME.set(staged_timing_runtime)
        self.network_runtime = executor._network_transaction_runtime
        try:
            self.network_preparation = self.network_runtime.begin(
                owner_rng=owner_rng,
                stable_id=stable_id,
                linearization_time=linearization_time,
                action_group_id=action_group_id,
            )
        except BaseException as error:
            self._close_timing(error)
            raise
        return self.network_preparation

    def seal_timing(self) -> None:
        """Seal the shared timing preparation after every related dispatch is prepared."""

        if self.timing_context is None:
            raise StateError("Network timing preparation was not opened")
        context = self.timing_context
        self.timing_context = None
        self._reset_timing_runtime()
        context.__exit__(None, None, None)

    def transfer(self) -> None:
        """Mark every capability as transferred to the outer no-fail coordinator."""

        self.transferred = True

    def cancel(self, error: BaseException) -> None:
        """Best-effort exact cancellation without masking the planner failure."""

        if self.identity_capture is not None and self.identity_capture_claim is not None:
            self.identity_capture._release_claim(self.identity_capture_claim)
            self.identity_capture = None
            self.identity_capture_claim = None
        if self.network_dependent_batch is not None:
            try:
                self.network_dependent_dispatcher.cancel_prepared_network_dependent_batch(
                    self.network_dependent_batch
                )
            except (AttributeError, EventContractError, StateError, TypeError, ValueError):
                pass
            self.network_dependent_dispatcher = None
            self.network_dependent_batch = None
        if self.transferred:
            return
        if self.lifecycle_token is not None and self.lifecycle_adapter is not None:
            try:
                self.lifecycle_adapter.cancel_closed_transport_publication(self.lifecycle_token)
            except (AttributeError, StateError, TypeError, ValueError):
                pass
        if self.application_token is not None and self.application_manager is not None:
            try:
                self.application_manager.cancel_prepared_admission(self.application_token)
            except (AttributeError, StateError, TypeError, ValueError):
                pass
        if self.root is not None and self.network_runtime is not None:
            try:
                self.network_runtime.cancel_preparation(self.root.runtime_token)
            except (AttributeError, StateError, TypeError, ValueError):
                pass
        elif self.network_preparation is not None:
            try:
                self.network_preparation.cancel()
            except (AttributeError, StateError, TypeError, ValueError):
                pass
        if self.timing_context is not None:
            self._close_timing(error)
        elif self.timing_preparation is not None and not self.timing_preparation.committed:
            try:
                self.timing_preparation.cancel()
            except StateError:
                pass

    def _close_timing(self, error: BaseException) -> None:
        context = self.timing_context
        self.timing_context = None
        self._reset_timing_runtime()
        if context is not None:
            context.__exit__(type(error), error, error.__traceback__)

    def _reset_timing_runtime(self) -> None:
        token = self.timing_runtime_token
        self.timing_runtime_token = None
        if token is not None:
            _ACTIVE_NETWORK_TIMING_RUNTIME.reset(token)


@dataclass(slots=True)
class _NetworkOccurrenceDraft:
    """Mutable planning surface used before the canonical event is constructed.

    Protocol and source metadata sometimes need to repair the initial transport
    estimates. Keeping those mutations on an action-owned draft prevents an
    incompletely planned ``OccurrenceBuilder`` from escaping into state or renderers.
    """

    timestamp: datetime
    src_host: Any = None
    dst_host: Any = None
    local_only: bool = False
    process: Any = None
    network: Any = None
    dns: Any = None
    email: Any = None
    smtp: Any = None
    ids_alerts: list[Any] = field(default_factory=list)
    ssl: Any = None
    http: Any = None
    file_transfer: Any = None
    file_transfers: list[Any] = field(default_factory=list)
    x509: Any = None
    x509_chain: list[Any] = field(default_factory=list)
    tls_presentation: Any = None
    ntp: Any = None
    ocsp: Any = None
    ocsp_transaction: Any = None
    pe: Any = None
    pe_analyses: list[Any] = field(default_factory=list)
    proxy: Any = None
    firewall: Any = None
    parent_action_group_id: str | None = None

    def build_event(self, generator_module: ModuleType) -> OccurrenceBuilder:
        """Construct the canonical event only after the transaction is frozen."""

        if self.network is None or self.network.transaction is None:
            raise ValueError("Cannot construct a network event before transaction finalization")
        from evidenceforge.events.lifecycle import ActionLifecycleContext

        transaction = self.network.transaction
        return generator_module.OccurrenceBuilder(
            timestamp=self.timestamp,
            event_type="connection",
            src_host=self.src_host,
            dst_host=self.dst_host,
            local_only=self.local_only,
            process=self.process,
            network=transaction,
            dns=self.dns,
            email=self.email,
            smtp=self.smtp,
            ids_alerts=tuple(self.ids_alerts),
            ssl=self.ssl,
            http=self.http,
            file_transfer=self.file_transfer,
            file_transfers=self.file_transfers,
            x509=self.x509,
            x509_chain=self.x509_chain,
            tls_presentation=self.tls_presentation,
            ntp=self.ntp,
            ocsp=self.ocsp,
            ocsp_transaction=self.ocsp_transaction,
            pe=self.pe,
            pe_analyses=self.pe_analyses,
            proxy=self.proxy,
            firewall=self.firewall,
            lifecycle=ActionLifecycleContext(
                group_id=transaction.stable_id,
                canonical_start=transaction.started_at,
                phase="start",
                parent_group_id=(
                    self.parent_action_group_id
                    or (transaction.conn_id if self.network.application_layer_only else None)
                ),
            ),
        )


@dataclass(frozen=True, slots=True)
class _HttpMultipartEndpointReadPlan:
    """One exact ordered owned-effect plan and its prebuilt projection members."""

    plan: Any
    builders: tuple[Any, ...]
    process_activity: tuple[Any, ...]


class NetworkTransactionPlanner:
    """Expand one network intent into a finalized canonical transaction."""

    def __init__(self, executor: ActivityGenerator) -> None:
        self._executor = executor

    @property
    def _timing_runtime(self) -> Any:
        """Return the active prepared timing overlay or the prerequisite runtime."""

        return _ACTIVE_NETWORK_TIMING_RUNTIME.get() or self._executor.timing_runtime

    def _stage_dns_observation(
        self,
        preparation: Any,
        *,
        src_ip: str,
        resolver_ip: str,
        dns: Any,
        time: datetime,
    ) -> bool:
        """Stage one resolver observation and report an overlapping visible TTL window."""

        from evidenceforge.generation.activity import generator as generator_module

        cache_key = generator_module._dns_observation_cache_key(src_ip, resolver_ip, dns)
        if cache_key is None or not self._executor._dns_observation_time_is_visible(time):
            return False
        start = time.timestamp()
        ttl = max(1.0, min(float(value) for value in dns.TTLs))
        end = start + ttl
        retained = preparation.read_point(
            NetworkRuntimePointFamily.DNS_OBSERVATION,
            cache_key,
            (),
            at=ensure_utc(time),
        )
        windows = [
            (float(old_start), float(old_end))
            for old_start, old_end in tuple(retained)
            if float(old_end) >= start - 86_400
        ][-32:]
        duplicate = any(start < old_end and end > old_start for old_start, old_end in windows)
        if not duplicate:
            windows.append((start, end))
            windows.sort()
            windows = windows[-32:]
            latest_end = max(old_end for _old_start, old_end in windows)
            retained_until = min(
                datetime.fromtimestamp(latest_end, tz=UTC),
                self._executor._network_transaction_runtime.window_end,
            )
            preparation.stage_point(
                NetworkRuntimePointFamily.DNS_OBSERVATION,
                cache_key,
                tuple(windows),
                expires_at=retained_until,
            )
        return duplicate

    @staticmethod
    def _timing_scope(request: NetworkConnectionRequest) -> TimingScope:
        """Return the durable scope shared by one canonical network transaction."""

        hostname = request.source_system.hostname if request.source_system is not None else ""
        return TimingScope(
            stable_id=request.stable_id,
            host=hostname,
            source="network",
            lifecycle_id=request.parent_action_group_id or request.stable_id,
        )

    def _tls_floor_slack_seconds(
        self,
        request: NetworkConnectionRequest,
        maximum_seconds: float,
    ) -> float:
        """Sample right-skew TLS completion slack above the protocol floor."""

        maximum_us = max(16_000, round(maximum_seconds * 1_000_000))
        median_us = min(maximum_us - 1.0, max(15_001.0, maximum_us * 0.24))
        return self._timing_runtime.sampler.sample_timedelta(
            TruncatedLognormalDistribution(
                median=median_us,
                sigma=0.72,
                minimum=15_000.0,
                maximum=float(maximum_us),
            ),
            relationship_key="network.tls.completed_floor_slack",
            scope=self._timing_scope(request),
            sample_key="tls_floor",
        ).total_seconds()

    def _tls_completed_extension_seconds(self, request: NetworkConnectionRequest) -> float:
        """Sample ordinary and long-tail TLS session extension time."""

        distribution = MixtureDistribution(
            components=(
                WeightedDistribution(
                    weight=0.92,
                    distribution=TruncatedLognormalDistribution(
                        median=240_000.0,
                        sigma=0.82,
                        minimum=15_000.0,
                        maximum=1_500_000.0,
                    ),
                ),
                WeightedDistribution(
                    weight=0.08,
                    distribution=TruncatedLognormalDistribution(
                        median=2_700_000.0,
                        sigma=0.55,
                        minimum=1_500_000.0,
                        maximum=8_000_000.0,
                    ),
                ),
            )
        )
        return self._timing_runtime.sampler.sample_timedelta(
            distribution,
            relationship_key="network.tls.completed_extension",
            scope=self._timing_scope(request),
            sample_key="tls_extension",
        ).total_seconds()

    def _http_floor_slack_seconds(self, request: NetworkConnectionRequest) -> float:
        """Sample positive source-admission slack above an HTTP duration floor."""

        return self._timing_runtime.sampler.sample_timedelta(
            TruncatedLognormalDistribution(
                median=3_600.0,
                sigma=0.88,
                minimum=0.0,
                maximum=25_001.0,
            ),
            relationship_key="network.http.duration_floor_slack",
            scope=self._timing_scope(request),
            sample_key="http_floor",
        ).total_seconds()

    def _http_default_duration_seconds(self, request: NetworkConnectionRequest) -> float:
        """Sample a right-skew completed HTTP transport duration."""

        return self._timing_runtime.sampler.sample_timedelta(
            TruncatedLognormalDistribution(
                median=180_000.0,
                sigma=0.92,
                minimum=10_000.0,
                maximum=2_000_001.0,
            ),
            relationship_key="network.http.default_duration",
            scope=self._timing_scope(request),
            sample_key="http_default",
        ).total_seconds()

    def _sample_duration_seconds(
        self,
        request: NetworkConnectionRequest,
        *,
        relationship_key: str,
        sample_key: str,
        minimum_us: int,
        median_us: int,
        maximum_us: int,
        sigma: float = 0.82,
    ) -> float:
        """Sample one open-support right-skew duration in whole microseconds."""

        if maximum_us <= minimum_us + 2:
            raise TimingDistributionError(
                f"{relationship_key} requires at least one interior microsecond: "
                f"minimum_us={minimum_us} maximum_us={maximum_us}"
            )
        bounded_median = min(maximum_us - 1, max(minimum_us + 1, median_us))
        return self._timing_runtime.sampler.sample_timedelta(
            TruncatedLognormalDistribution(
                median=float(bounded_median),
                sigma=sigma,
                minimum=float(minimum_us),
                maximum=float(maximum_us),
            ),
            relationship_key=relationship_key,
            scope=self._timing_scope(request),
            sample_key=sample_key,
        ).total_seconds()

    def _dns_rtt_seconds(
        self,
        request: NetworkConnectionRequest,
        *,
        is_public_resolver: bool,
    ) -> float:
        """Sample a canonical DNS response RTT without uniform-bin fingerprints."""

        if is_public_resolver:
            components = (
                (0.15, 2_001, 5_000, 8_001, 0.46),
                (0.55, 8_001, 17_000, 35_001, 0.68),
                (0.25, 35_001, 62_000, 120_001, 0.72),
                (0.05, 120_001, 178_000, 350_001, 0.68),
            )
        else:
            components = (
                (0.60, 99, 420, 1_001, 0.72),
                (0.25, 1_001, 3_200, 10_001, 0.76),
                (0.12, 10_001, 29_000, 80_001, 0.78),
                (0.03, 80_001, 128_000, 250_001, 0.72),
            )
        distribution = MixtureDistribution(
            components=tuple(
                WeightedDistribution(
                    weight=weight,
                    distribution=TruncatedLognormalDistribution(
                        median=float(median_us),
                        sigma=sigma,
                        minimum=float(minimum_us),
                        maximum=float(maximum_us),
                    ),
                )
                for weight, minimum_us, median_us, maximum_us, sigma in components
            )
        )
        return self._timing_runtime.sampler.sample_timedelta(
            distribution,
            relationship_key="network.dns.response_rtt",
            scope=self._timing_scope(request),
            sample_key="public" if is_public_resolver else "internal",
        ).total_seconds()

    def _dns_transport_duration_seconds(
        self,
        request: NetworkConnectionRequest,
        rtt_seconds: float,
    ) -> float:
        """Return DNS RTT plus typed transport teardown slack."""

        return rtt_seconds + self._sample_duration_seconds(
            request,
            relationship_key="network.dns.transport_close_slack",
            sample_key="dns_close",
            minimum_us=1_037,
            median_us=2_100,
            maximum_us=12_001,
            sigma=0.86,
        )

    def _kerberos_udp_duration_seconds(self, request: NetworkConnectionRequest) -> float:
        """Sample one response-bearing UDP Kerberos exchange lifetime."""

        return self._sample_duration_seconds(
            request,
            relationship_key="network.kerberos.udp_duration",
            sample_key="udp_exchange",
            minimum_us=3_000,
            median_us=14_000,
            maximum_us=160_001,
            sigma=0.78,
        )

    def _kerberos_tcp_duration_seconds(self, request: NetworkConnectionRequest) -> float:
        """Sample a response-bearing TCP Kerberos exchange with a small long tail."""

        distribution = MixtureDistribution(
            components=(
                WeightedDistribution(
                    weight=0.92,
                    distribution=TruncatedLognormalDistribution(
                        median=24_000.0,
                        sigma=0.82,
                        minimum=3_000.0,
                        maximum=180_001.0,
                    ),
                ),
                WeightedDistribution(
                    weight=0.08,
                    distribution=TruncatedLognormalDistribution(
                        median=1_350_000.0,
                        sigma=0.48,
                        minimum=500_000.0,
                        maximum=2_500_001.0,
                    ),
                ),
            )
        )
        return self._timing_runtime.sampler.sample_timedelta(
            distribution,
            relationship_key="network.kerberos.tcp_duration",
            scope=self._timing_scope(request),
            sample_key="tcp_exchange",
        ).total_seconds()

    def _kerberos_audit_floor_seconds(
        self,
        request: NetworkConnectionRequest,
        count: int,
    ) -> float:
        """Sample a lifecycle-coherent floor for DC audit companions."""

        per_exchange = self._sample_duration_seconds(
            request,
            relationship_key="network.kerberos.audit_exchange_duration",
            sample_key=f"audit:{count}",
            minimum_us=6_000,
            median_us=10_500,
            maximum_us=22_001,
            sigma=0.58,
        )
        return count * per_exchange

    def _generator_owned_duration_seconds(
        self,
        request: NetworkConnectionRequest,
        duration: float | None,
    ) -> float | None:
        """Diversify engine-owned placeholder durations through the shared runtime."""

        if duration is None:
            return None
        anchors = (0.8, 2.0, 0.2, 0.1, 0.02, 0.01)
        if not any(abs(duration - anchor) <= 1e-9 for anchor in anchors):
            return duration
        duration_us = max(1_000, round(duration * 1_000_000))
        if duration <= 0.02:
            minimum_us = max(100, round(duration_us * 0.55))
            maximum_us = round(duration_us * 1.85) + 4_001
            median_us = round(duration_us * 0.94) + 700
        else:
            minimum_us = max(1_000, round(duration_us * 0.82) - 14_999)
            maximum_us = round(duration_us * 1.24) + 35_001
            median_us = max(minimum_us + 1, round(duration_us * 0.98))
        return self._sample_duration_seconds(
            request,
            relationship_key="network.default_transport_duration",
            sample_key=f"anchor:{duration_us}",
            minimum_us=minimum_us,
            median_us=median_us,
            maximum_us=maximum_us,
            sigma=0.64,
        )

    def _failed_transport_duration_seconds(
        self,
        request: NetworkConnectionRequest,
        *,
        state: str,
        duration: float,
        sample_key: str,
    ) -> float:
        """Sample a state-specific partial transport lifetime within its base budget."""

        base_us = max(10, round(duration * 1_000_000))
        if state in {"S1", "SH", "SHR"}:
            minimum_us, median_us, maximum_us = 37, 28_000, 500_001
        elif state in {"S2", "S3"}:
            minimum_us = max(3, round(base_us * 0.30))
            median_us = max(minimum_us + 1, round(base_us * 0.43))
            maximum_us = max(minimum_us + 3, round(base_us * 0.80) + 1)
        elif state in {"RSTO", "RSTR"}:
            minimum_us = max(3, round(base_us * 0.10))
            median_us = max(minimum_us + 1, round(base_us * 0.19))
            maximum_us = max(minimum_us + 3, round(base_us * 0.50) + 1)
        else:
            minimum_us, median_us, maximum_us = 1_000, 44_000, 500_001
        return self._sample_duration_seconds(
            request,
            relationship_key=f"network.failed_transport.{state.lower()}_duration",
            sample_key=sample_key,
            minimum_us=minimum_us,
            median_us=median_us,
            maximum_us=maximum_us,
            sigma=0.88,
        )

    def _ntp_timing_components(
        self,
        request: NetworkConnectionRequest,
        *,
        median_rtt_ms: float,
        rtt_sigma: float,
    ) -> tuple[float, float, float, timedelta]:
        """Sample canonical NTP RTT, server processing, close slack, and reference age."""

        median_rtt_us = max(201, round(median_rtt_ms * 1_000))
        rtt_seconds = self._sample_duration_seconds(
            request,
            relationship_key="network.ntp.response_rtt",
            sample_key="rtt",
            minimum_us=200,
            median_us=median_rtt_us,
            maximum_us=max(median_rtt_us + 3, 300_001),
            sigma=rtt_sigma,
        )
        processing_seconds = self._sample_duration_seconds(
            request,
            relationship_key="network.ntp.server_processing",
            sample_key="processing",
            minimum_us=50,
            median_us=500,
            maximum_us=10_001,
            sigma=0.52,
        )
        close_slack_seconds = self._sample_duration_seconds(
            request,
            relationship_key="network.ntp.transport_close_slack",
            sample_key="close",
            minimum_us=1_000,
            median_us=2_700,
            maximum_us=8_001,
            sigma=0.64,
        )
        reference_age = self._timing_runtime.sampler.sample_timedelta(
            TruncatedLognormalDistribution(
                median=75_000_000.0,
                sigma=0.72,
                minimum=30_000_000.0,
                maximum=300_000_001.0,
            ),
            relationship_key="network.ntp.reference_age",
            scope=self._timing_scope(request),
            sample_key="reference",
        )
        return rtt_seconds, processing_seconds, close_slack_seconds, reference_age

    def _ntp_clock_time(
        self,
        request: NetworkConnectionRequest,
        canonical_time: datetime,
        *,
        role: str,
        identity: str,
    ) -> datetime:
        """Project an NTP packet field through one stable endpoint clock."""

        maximum_offset = 35.0 if role == "client" else 25.0
        maximum_wander = 5.0
        spec = SourceClockSpec(
            offset_microseconds=TriangularDistribution(
                minimum=-maximum_offset,
                mode=0.0,
                maximum=maximum_offset,
            ),
            drift_ppm=ConstantDistribution(0.0),
            wander=ClockWanderSpec(
                knot_distribution_microseconds=TriangularDistribution(
                    minimum=-maximum_wander,
                    mode=0.0,
                    maximum=maximum_wander,
                ),
                knot_interval=timedelta(minutes=5),
            ),
        )
        return self._timing_runtime.clocks.project(
            ensure_utc(canonical_time),
            key=SourceClockKey(kind="ntp_endpoint", identity=identity, profile=role),
            spec=spec,
        )

    def _foreground_teardown_delay_seconds(
        self,
        request: NetworkConnectionRequest,
        minimum_seconds: float,
        maximum_seconds: float,
    ) -> float:
        """Sample process teardown after a connection-owned foreground action."""

        minimum_us = max(1, round(minimum_seconds * 1_000_000))
        maximum_us = max(minimum_us + 3, round(maximum_seconds * 1_000_000) + 1)
        return self._sample_duration_seconds(
            request,
            relationship_key="network.foreground_process.teardown_delay",
            sample_key="process_terminate",
            minimum_us=minimum_us,
            median_us=minimum_us + max(1, round((maximum_us - minimum_us) * 0.18)),
            maximum_us=maximum_us,
            sigma=0.78,
        )

    def _cap_to_owning_session(
        self,
        *,
        start: datetime,
        duration: float | None,
        source_system: Any,
        pid: int,
        stable_id: str,
    ) -> float | None:
        """Bound process-owned transport lifetime by an authoritative session end."""

        if source_system is None or pid <= 0:
            return duration
        end_plan = self._executor.state_manager.process_session_end_plan(
            source_system.hostname,
            pid,
        )
        if end_plan is None or not end_plan.is_authoritative:
            return duration
        canonical_start = ensure_utc(start)
        deadline = ensure_utc(end_plan.canonical_end)
        if canonical_start >= deadline:
            process = self._executor.state_manager.get_process(source_system.hostname, pid)
            process_detail = (
                f" image={process.image!r} logon_id={process.logon_id}"
                if process is not None
                else ""
            )
            raise StateError(
                "Process-owned network activity cannot begin at or after its authoritative "
                f"session end: {source_system.hostname} pid={pid} "
                f"start={canonical_start.isoformat()} end={deadline.isoformat()}"
                f"{process_detail}"
            )
        available_us = round((deadline - canonical_start).total_seconds() * 1_000_000)
        if available_us <= 3:
            self._timing_runtime.audit.record_saturation("network.authoritative_session_close_gap")
            raise StateError(
                "Process-owned network activity has no microsecond interior before its "
                f"authoritative session end: {source_system.hostname} pid={pid} "
                f"start={canonical_start.isoformat()} end={deadline.isoformat()}"
            )
        maximum_gap_us = min(1_500_001, available_us)
        minimum_gap_us = min(100_000, max(0, maximum_gap_us // 8))
        if maximum_gap_us <= minimum_gap_us + 2:
            minimum_gap_us = max(0, maximum_gap_us - 3)
        scope = TimingScope(
            stable_id=stable_id,
            host=source_system.hostname,
            source="network",
            lifecycle_id=f"pid:{pid}",
        )
        close_gap = self._timing_runtime.sampler.sample_timedelta(
            TruncatedLognormalDistribution(
                median=float(
                    min(
                        maximum_gap_us - 1,
                        minimum_gap_us + max(1, (maximum_gap_us - minimum_gap_us) // 5),
                    )
                ),
                sigma=0.76,
                minimum=float(minimum_gap_us),
                maximum=float(maximum_gap_us),
            ),
            relationship_key="network.authoritative_session_close_gap",
            scope=scope,
            sample_key=deadline.isoformat(),
        )
        latest_duration = (deadline - close_gap - canonical_start).total_seconds()
        return latest_duration if duration is None else min(duration, latest_duration)

    def _reconcile_application_payload(
        self,
        event: _NetworkOccurrenceDraft,
        generator_module: ModuleType,
    ) -> bool:
        """Fit canonical application objects and framing inside transport payload."""

        network = event.network
        if network is None or network.protocol != "tcp" or network.conn_state != "SF":
            return False

        orig_floor = 0
        resp_floor = 0
        if event.http is not None:
            http_orig, http_resp = generator_module._http_flow_payload_bytes(event.http)
            orig_floor = max(orig_floor, http_orig)
            resp_floor = max(resp_floor, http_resp)

        grouped: dict[bool, list[Any]] = {True: [], False: []}
        for transfer in (event.file_transfer, *event.file_transfers):
            if transfer is not None and transfer not in grouped[transfer.is_orig]:
                grouped[transfer.is_orig].append(transfer)
        for is_orig, transfers in grouped.items():
            if not transfers:
                continue
            accounted_bytes = [
                transfer.total_bytes
                if transfer.total_bytes is not None
                else transfer.seen_bytes + transfer.missing_bytes
                for transfer in transfers
            ]
            total_bytes = sum(accounted_bytes)
            framing_bytes = sum(
                max(128, 96 * max(1, (max(1, size) + 65_535) // 65_536))
                if transfer.source.upper() == "SMB"
                else 192
                for transfer, size in zip(transfers, accounted_bytes, strict=True)
            )
            file_floor = total_bytes + framing_bytes
            if is_orig:
                orig_floor = max(orig_floor, file_floor)
            else:
                resp_floor = max(resp_floor, file_floor)

        previous = (network.orig_bytes or 0, network.resp_bytes or 0)
        network.orig_bytes = max(previous[0], orig_floor)
        network.resp_bytes = max(previous[1], resp_floor)
        if (network.orig_bytes, network.resp_bytes) == previous:
            return False

        accounting_rng = generator_module.random.Random(
            _stable_seed(
                "network_application_payload_accounting:"
                f"{network.src_ip}:{network.src_port}:{network.dst_ip}:{network.dst_port}:"
                f"{network.protocol}:{network.zeek_uid}"
            )
        )
        network.orig_pkts, network.resp_pkts = (
            generator_module._tcp_packet_counts_from_payload_and_history(
                network.orig_bytes,
                network.resp_bytes,
                network.history,
                accounting_rng,
            )
        )
        network.orig_ip_bytes = generator_module._tcp_ip_byte_count(
            network.orig_bytes,
            network.orig_pkts,
            accounting_rng,
        )
        network.resp_ip_bytes = generator_module._tcp_ip_byte_count(
            network.resp_bytes,
            network.resp_pkts,
            accounting_rng,
        )
        return True

    def _plan_http_multipart_endpoint_reads(
        self,
        event: Any,
        source_system: Any | None,
        target_system: Any | None,
        source_pid: int,
        source_process: Any | None,
        endpoint_time: datetime,
    ) -> _HttpMultipartEndpointReadPlan | None:
        """Freeze exact endpoint-read builders and State activity patches before commit."""

        http = event.protocol.http
        network = event.network
        if http is None or network is None:
            return None

        from evidenceforge.events.base import OccurrenceBuilder
        from evidenceforge.events.contexts import AuthContext, FileContext, ProcessContext
        from evidenceforge.events.contracts import (
            EffectOccurrenceKind,
            EffectOccurrenceOwner,
            OwnedEffectOccurrencePlan,
        )
        from evidenceforge.generation.state_manager import ProcessActivityPatch

        effective_source_pid = (
            source_pid if source_pid > 0 else int(getattr(source_process, "pid", -1) or -1)
        )
        directions = (
            (http.request_multipart, source_system, effective_source_pid, source_process),
            (http.response_multipart, target_system, network.responding_pid, None),
        )
        reads: list[tuple[Any, int, Any, Any, Any, Any, datetime, str, str]] = []
        for multipart, system, pid, canonical_process in directions:
            if multipart is None or system is None or pid <= 0:
                continue
            if multipart.local_reads_emitted:
                continue
            running = self._executor.state_manager.get_process(system.hostname, pid)
            if running is None and canonical_process is None:
                continue
            process_identity = self._executor.state_manager.get_process_identity(
                system.hostname,
                pid,
            )
            if process_identity is None:
                raise StateError(
                    "HTTP multipart local read has no exact State process actor before root seal"
                )
            local_parts = [part for part in multipart.leaf_parts() if part.local_source_path]
            for index, part in enumerate(local_parts):
                transfer_anchor = endpoint_time
                read_time = transfer_anchor - timedelta(milliseconds=max(1, 150 - min(index, 100)))
                process_start = (
                    running.start_time
                    if running is not None
                    else canonical_process.start_time
                    if canonical_process is not None
                    else None
                )
                if process_start is not None:
                    read_time = max(
                        read_time,
                        process_start + timedelta(milliseconds=1 + index),
                    )
                username = (
                    running.username
                    if running is not None
                    else canonical_process.username
                    if canonical_process is not None
                    else ""
                )
                logon_id = (
                    running.logon_id
                    if running is not None
                    else canonical_process.logon_id
                    if canonical_process is not None
                    else ""
                )
                reads.append(
                    (
                        system,
                        pid,
                        running,
                        canonical_process,
                        process_identity,
                        part,
                        read_time,
                        username,
                        logon_id,
                    )
                )

        if not reads:
            return None
        plan = OwnedEffectOccurrencePlan(
            owner=EffectOccurrenceOwner.HTTP_MULTIPART_LOCAL_READ,
            kind=EffectOccurrenceKind.FILE,
            root_action_id=network.stable_id,
            instance_key=stable_uuid(
                "http-multipart-local-read-instance",
                network.stable_id,
                *(
                    f"{system.hostname.casefold()}:{pid}:{part.local_source_path.casefold()}:"
                    f"{read_time.isoformat()}"
                    for system, pid, _running, _canonical, _identity, part, read_time, _user, _logon in reads
                ),
            ),
            occurrence_count=len(reads),
        )
        builders: list[OccurrenceBuilder] = []
        activity_by_object_id: dict[str, ProcessActivityPatch] = {}
        for ordinal, (
            system,
            pid,
            running,
            canonical_process,
            process_identity,
            part,
            read_time,
            username,
            logon_id,
        ) in enumerate(reads):
            builders.append(
                OccurrenceBuilder(
                    timestamp=read_time,
                    event_type="file_read",
                    src_host=self._executor._build_host_context(system),
                    auth=AuthContext(
                        username=username,
                        logon_id=logon_id,
                    ),
                    process=ProcessContext(
                        pid=pid,
                        parent_pid=(
                            running.parent_pid
                            if running is not None
                            else canonical_process.parent_pid
                        ),
                        image=(running.image if running is not None else canonical_process.image),
                        command_line=(
                            running.command_line
                            if running is not None
                            else canonical_process.command_line
                        ),
                        username=username,
                        logon_id=logon_id,
                        start_time=(
                            running.start_time
                            if running is not None
                            else canonical_process.start_time
                        ),
                    ),
                    file=FileContext(path=part.local_source_path, action="read", pid=pid),
                    effect_provenance=plan.provenance(ordinal),
                )
            )
            prior = activity_by_object_id.get(process_identity.object_id)
            if prior is not None and prior.identity != process_identity:
                raise StateError("HTTP multipart process actor identity changed during planning")
            activity_frontier = network.closed_at or network.started_at
            if prior is None or activity_frontier > prior.activity_time:
                activity_by_object_id[process_identity.object_id] = ProcessActivityPatch(
                    process_identity,
                    activity_frontier,
                )
        return _HttpMultipartEndpointReadPlan(
            plan=plan,
            builders=tuple(builders),
            process_activity=tuple(activity_by_object_id.values()),
        )

    @staticmethod
    def _merge_process_activity_patches(
        existing: tuple[Any, ...],
        additions: tuple[Any, ...],
    ) -> tuple[Any, ...]:
        """Merge exact actor frontiers without changing first-occurrence ordering."""

        merged: dict[str, Any] = {}
        for patch in (*existing, *additions):
            object_id = patch.identity.object_id
            prior = merged.get(object_id)
            if prior is not None and prior.identity != patch.identity:
                raise StateError("Network process activity actor identity changed during merge")
            if prior is None or patch.activity_time > prior.activity_time:
                merged[object_id] = patch
        return tuple(merged.values())

    def execute(self, request: NetworkConnectionRequest) -> str:
        """Expand one request while retaining exact cancellation ownership."""

        boundary = _PreparedNetworkBoundary()
        try:
            boundary.claim_identity_capture(request.identity_capture)
            result = self._execute(request, boundary)
        except BaseException as error:
            boundary.cancel(error)
            raise
        if not boundary.transferred:
            boundary.cancel(StateError("Network request ended before prepared publication"))
        return result

    def _execute(
        self,
        request: NetworkConnectionRequest,
        boundary: _PreparedNetworkBoundary,
    ) -> str:
        """Plan and publish one canonical network transaction."""
        from evidenceforge.generation.actions.proxy_transaction import (
            ExplicitProxyOpenPreparation,
            ExplicitProxyRequestPreparation,
            ProxyTransactionActionBundle,
            ProxyTransactionRequest,
        )
        from evidenceforge.generation.activity import generator as generator_module

        executor = self._executor
        prepared_application_token = request.prepared_application_token
        explicit_proxy_request_preparation = request.explicit_proxy_request_preparation
        if prepared_application_token is not None:
            from evidenceforge.generation.proxy_channels import ExplicitProxyAdmissionToken

            if not isinstance(prepared_application_token, ExplicitProxyAdmissionToken):
                raise StateError("Network request has no authentic proxy request admission")
            boundary.track_application(
                executor._proxy_channel_manager,
                prepared_application_token,
            )
            if (
                prepared_application_token.kind != "request"
                or not executor._proxy_channel_manager.authenticates_admission_token(
                    prepared_application_token
                )
            ):
                raise StateError("Network request has no authentic proxy request admission")
        elif explicit_proxy_request_preparation is not None:
            if (
                not isinstance(
                    explicit_proxy_request_preparation,
                    ExplicitProxyRequestPreparation,
                )
                or not executor._proxy_channel_manager.authenticates_request_snapshot(
                    explicit_proxy_request_preparation.snapshot
                )
                or explicit_proxy_request_preparation.affinity.digest
                != explicit_proxy_request_preparation.snapshot.affinity_digest
            ):
                raise StateError("Network request has no authentic proxy request snapshot")
        src_ip = request.src_ip
        dst_ip = request.dst_ip
        time = request.time
        dst_port = request.dst_port
        proto = request.proto
        service = request.service
        duration = request.duration
        orig_bytes = request.orig_bytes
        resp_bytes = request.resp_bytes
        explicit_orig_bytes = request.orig_bytes
        explicit_resp_bytes = request.resp_bytes
        src_port = request.src_port
        emit_dns = request.emit_dns
        pid = request.pid
        source_system = request.source_system
        conn_state = request.conn_state
        # Resolver normalization mutates its working context. Keep that mutation
        # inside the prepared occurrence so a rejected transaction cannot rewrite
        # the caller-owned request object.
        dns = copy.deepcopy(request.dns)
        email = request.email
        smtp = request.smtp
        x509 = request.x509
        x509_chain = request.x509_chain
        ids_alerts = list(request.ids_alerts)
        http = request.http
        file_transfer = request.file_transfer
        file_transfers = request.file_transfers
        pe = request.pe
        ocsp = request.ocsp
        proxy = request.proxy
        firewall = request.firewall
        hostname = request.hostname
        proxy_bypass = request.proxy_bypass
        process_image = request.process_image
        preserve_dst_ip = request.preserve_dst_ip
        preserve_http_outcome = request.preserve_http_outcome
        suppress_application_side_effects = request.suppress_application_side_effects
        suppress_source_pid_inference = request.suppress_source_pid_inference
        preserve_explicit_payload = request.preserve_explicit_payload
        suppress_prereq_dns = request.suppress_prereq_dns
        packet_overhead_bytes = request.packet_overhead_bytes
        responding_pid = request.responding_pid
        ssh_attempted_username = request.ssh_attempted_username
        parent_action_group_id = request.parent_action_group_id
        preserve_start_time = request.preserve_start_time
        caller_supplied_pid = pid > 0

        from evidenceforge.events.contexts import NetworkTransactionDraft

        if http is not None:
            http = generator_module._normalize_http_context_for_source_native_response(http)

        caller_provided_duration = duration is not None
        caller_provided_conn_state = conn_state is not None
        caller_provided_payload = (
            service is not None
            and duration is not None
            and (orig_bytes or 0) > 0
            and (resp_bytes or 0) > 0
        )
        ntp_timing: tuple[float, float, float, timedelta] | None = None
        command_http_needs_response_size = False
        deferred_kerberos_duration_proto: str | None = None

        def independent_discovery_rng(purpose: str) -> Any:
            """Return a pure pre-boundary RNG for prerequisite/routing discovery.

            A committed DNS prerequisite or delegated proxy transaction may own
            the discovered hostname/destination. If neither is emitted, the
            value is still pure request-derived input to the later prepared root;
            the generator's owner RNG is never advanced by discovery alone.
            """

            return generator_module.random.Random(
                generator_module._stable_seed(
                    f"network_discovery:{purpose}:{request.stable_id}:{src_ip}:{dst_ip}"
                )
            )

        if http is not None and proto == "tcp" and conn_state is None:
            conn_state = "SF"
        process_exe = (process_image or "").rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        is_tcp_probe = process_exe in {"nmap", "nmap.exe"}
        if source_system is None and hasattr(executor, "_ip_to_system"):
            source_system = executor._ip_to_system.get(src_ip)
        if service == "kerberos" and dst_port == 88 and proto == "tcp":
            from evidenceforge.generation.activity.kerberos_realism import (
                pick_kerberos_transport,
            )

            proto = pick_kerberos_transport(
                generator_module.random.Random(
                    generator_module._stable_seed(
                        "kerberos_transport:"
                        f"{src_ip}:{dst_ip}:{time.isoformat()}:{src_port or ''}:{pid}"
                    )
                )
            )
        if service == "kerberos" and dst_port == 88 and proto == "tcp":
            deferred_kerberos_duration_proto = "tcp"
        if service == "kerberos" and dst_port == 88 and proto == "udp":
            udp_kerberos_rng = generator_module.random.Random(
                generator_module._stable_seed(
                    "kerberos_udp_shape:"
                    f"{src_ip}:{dst_ip}:{time.isoformat()}:{src_port or ''}:{pid}"
                )
            )
            deferred_kerberos_duration_proto = "udp"
            orig_bytes = min(
                max(orig_bytes or udp_kerberos_rng.randint(180, 900), 160),
                udp_kerberos_rng.randint(700, 1300),
            )
            resp_bytes = min(
                max(resp_bytes or udp_kerberos_rng.randint(120, 1200), 80),
                udp_kerberos_rng.randint(600, 1400),
            )
            if conn_state not in {None, "SF", "S0", "REJ", "OTH"}:
                conn_state = "SF" if resp_bytes else "S0"

        if (
            http is None
            and pid > 0
            and source_system is not None
            and proto == "tcp"
            and (dst_port in {80, 443, 8080} or service is None or service in {"http", "ssl"})
        ):
            proc = executor.state_manager.get_process(source_system.hostname, pid)
            if proc is not None:
                command_http = generator_module._http_context_from_process_command(
                    proc.image,
                    proc.command_line,
                    # Response sizing belongs to the prepared root. Parse the
                    # command without consuming the owner RNG, then fill an
                    # ordinary non-stable entity after boundary.begin().
                    response_body_len=resp_bytes or 0,
                )
                if command_http is not None:
                    command_http_context, command_host, command_port, command_service = command_http
                    command_http_needs_response_size = bool(
                        not resp_bytes
                        and command_http_context.method != "HEAD"
                        and command_http_context.response_body_len <= 0
                    )
                    command_target = executor._system_for_hostname(command_host)
                    host_lower = command_host.lower().rstrip(".")
                    ad_domain_for_command = (
                        str(
                            getattr(executor, "_ad_domain", "") or "",
                        )
                        .lower()
                        .rstrip(".")
                    )
                    command_is_unknown_internal = command_target is None and (
                        host_lower.endswith(".local")
                        or (
                            ad_domain_for_command
                            and host_lower.endswith(f".{ad_domain_for_command}")
                        )
                    )
                    if not command_is_unknown_internal:
                        http = command_http_context
                        hostname = command_host
                        dst_port = command_port
                        service = command_service
                        if command_target is not None:
                            dst_ip = command_target.ip
                            emit_dns = True

        # Resolve hostname ONCE for DNS/proxy consistency.
        # All downstream uses (causal DNS expansion, proxy hostname)
        # share this single resolved value instead of doing independent lookups.
        #
        # hostname semantics (preserved through all downstream builders):
        #   None  → auto-resolve from REVERSE_DNS or generate random
        #   ""    → suppress resolution (raw-IP C2, exposed hosts w/o public_hostnames)
        #   "x.y" → use this hostname explicitly
        hostname_was_explicit = hostname not in (None, "")
        hostname_from_reverse_dns = False
        if hostname is None:
            reverse_hostname = executor._scenario_fqdn_for_ip(
                dst_ip
            ) or generator_module.REVERSE_DNS.get(dst_ip)
            if reverse_hostname is not None:
                hostname = reverse_hostname
                hostname_from_reverse_dns = True
            elif (
                emit_dns
                and proto == "tcp"
                and dst_port not in (53,)
                and generator_module._is_private_ip(dst_ip)
            ):
                hostname = generator_module._generate_internal_hostname(
                    independent_discovery_rng("internal-hostname"),
                    dst_ip,
                    getattr(executor, "_ad_domain", "corp.local"),
                )
            else:
                hostname = None
        if hostname is None and emit_dns and proto == "tcp" and dst_port not in (53,):
            if not generator_module._is_private_ip(dst_ip):
                hostname = generator_module._generate_random_hostname(
                    independent_discovery_rng("public-hostname"), dst_ip
                )

        proxy_routes = getattr(executor, "_proxy_routes", {})
        proxy_chain = proxy_routes.get(src_ip)
        preserve_explicit_proxy_dst_ip = (
            preserve_dst_ip
            and hostname_was_explicit
            and not proxy_bypass
            and getattr(executor, "_proxy_mode", "transparent") == "explicit"
            and bool(proxy_chain)
            and proto == "tcp"
            and dst_port in (80, 443)
        )

        if (
            hostname
            and hostname_was_explicit
            and not preserve_dst_ip
            and not preserve_explicit_proxy_dst_ip
            and not (service == "dns" and proto in ("udp", "tcp") and dst_port == 53)
        ):
            from evidenceforge.generation.activity.dns_registry import get_domain_ips

            src_host = source_system.hostname if source_system else src_ip
            resolver = getattr(executor, "_network_resolver", None)
            resolved = resolver.resolve_host(hostname, src_host=src_host) if resolver else None
            if (
                resolved is not None
                and resolved.source == "scenario_identity"
                and resolved.ip
                and dst_ip != resolved.ip
            ):
                dst_ip = resolved.ip
            elif resolved is not None and resolved.source == "stable_fallback":
                pass
            else:
                from evidenceforge.generation.activity.dns_registry import resolve_domain_ip

                domain_ips = get_domain_ips(hostname)
                if domain_ips and dst_ip not in domain_ips:
                    dst_ip = resolve_domain_ip(hostname, src_host=src_host)
                elif not domain_ips and emit_dns and not generator_module._is_private_ip(dst_ip):
                    dst_ip = resolve_domain_ip(hostname, src_host=src_host)

        ad_domain = getattr(executor, "_ad_domain", "corp.local")
        hostname_is_external = (
            bool(hostname)
            and "." in hostname
            and not hostname.endswith(f".{ad_domain}")
            and not hostname.endswith(".local")
        )
        proxyable_external_destination = (
            hostname_is_external or not generator_module._is_private_ip(dst_ip)
        )
        # Role-level server traffic often knows that a request occurred without
        # knowing which local process owned it. Preserve that uncertainty rather
        # than turning a sampled HTTP User-Agent into a fabricated PID-1 child.
        # Explicit caller PIDs remain authoritative, and interactive workstation
        # traffic can still materialize a source-native browser/client process.
        source_roles = {str(role).lower() for role in (getattr(source_system, "roles", None) or [])}
        source_type = (
            str(getattr(source_system, "type", "") or "").lower()
            if source_system is not None
            else ""
        )
        linux_server_without_owner = (
            pid <= 0
            and source_system is not None
            and generator_module._get_os_category(source_system.os) == "linux"
            and (
                source_type in {"server", "domain_controller"}
                or bool(
                    source_roles
                    & {
                        "app_server",
                        "database",
                        "dns_server",
                        "file_server",
                        "forward_proxy",
                        "log_server",
                        "mail_server",
                        "monitoring",
                        "web_server",
                    }
                )
            )
            and proto == "tcp"
            and dst_port in {80, 443}
        )
        if linux_server_without_owner:
            suppress_source_pid_inference = True
        dns_server_ips = set(getattr(executor, "_dns_server_ips", []))
        if (
            proto == "tcp"
            and dst_port in (80, 443)
            and hostname_is_external
            and dst_ip in dns_server_ips
        ):
            src_host = source_system.hostname if source_system else src_ip
            resolver = getattr(executor, "_network_resolver", None)
            resolved = resolver.resolve_host(hostname, src_host=src_host) if resolver else None
            if resolved is not None and resolved.ip:
                dst_ip = resolved.ip
            else:
                from evidenceforge.generation.activity.dns_registry import resolve_domain_ip

                dst_ip = resolve_domain_ip(hostname, src_host=src_host)

        # Infer common payload service from destination port before proxy
        # routing and DNS expansion. Some callers provide only port/protocol or
        # source-common aliases (for example "https"); explicit proxy semantics
        # still need to catch 80/443 before a client-side origin DNS lookup is
        # emitted. Keep the empty-string raw-TCP sentinel unchanged.
        if proto == "tcp" and dst_port in (80, 443) and service != "" and not is_tcp_probe:
            service = "http" if dst_port == 80 else "ssl"
        if proto == "udp" and dst_port == 123 and (service != "" or (resp_bytes or 0) > 0):
            service = "ntp"
            if not generator_module._is_private_ip(dst_ip):
                from evidenceforge.generation.activity.network_params import public_ntp_ips

                configured_ntp_ips = set(public_ntp_ips())
                if configured_ntp_ips and dst_ip not in configured_ntp_ips:
                    selected_ntp_ip = generator_module._select_public_ntp_ip(src_ip, dst_ip, time)
                    if selected_ntp_ip:
                        dst_ip = selected_ntp_ip

        if (
            proto == "tcp"
            and service == "ssl"
            and dst_port == 443
            and emit_dns
            and dns is None
            and http is None
            and not hostname_was_explicit
            and generator_module._is_private_ip(src_ip)
            and not generator_module._is_private_ip(dst_ip)
        ):
            hostname, dst_ip = executor._pick_profiled_tls_destination(
                rng=independent_discovery_rng("profiled-tls-destination"),
                src_ip=src_ip,
                source_system=source_system,
                purpose_tags=("web", "saas", "background"),
            )

        tls_hostname = hostname
        if hostname_from_reverse_dns and not emit_dns and dns is None and http is None:
            # A PTR/reverse-DNS-style fallback is useful for proxy URL rendering
            # but should not become TLS SNI unless the client actually resolved
            # or was explicitly configured to use that hostname.
            tls_hostname = ""

        will_route_explicit_proxy = (
            not proxy_bypass
            and getattr(executor, "_proxy_mode", "transparent") == "explicit"
            and bool(proxy_chain)
            and proto == "tcp"
            and service in ("ssl", "http")
            and dst_port in (80, 443)
            and proxyable_external_destination
            and conn_state not in ("S0", "REJ", "S1", "SH", "SHR", "RSTO", "RSTR")
            and (
                getattr(executor, "_scenario_end_time", None) is None
                or ensure_utc(time) < ensure_utc(executor._scenario_end_time)
            )
        )

        if http is not None and not preserve_http_outcome and not will_route_explicit_proxy:
            http = generator_module._apply_plaintext_http_policy(
                http,
                hostname=hostname,
                dst_ip=dst_ip,
                dst_port=dst_port,
            )

        explicit_proxy = will_route_explicit_proxy
        if explicit_proxy:
            if command_http_needs_response_size and http is not None:
                # The delegated proxy transaction, not this never-opened
                # network root, owns this command-derived response estimate.
                http = replace(
                    http,
                    response_body_len=independent_discovery_rng(
                        "delegated-command-http-response"
                    ).randint(500, 50000),
                )
                command_http_needs_response_size = False
            proxy_request = ProxyTransactionRequest(
                src_ip=src_ip,
                dst_ip=dst_ip,
                time=time,
                dst_port=dst_port,
                proto=proto,
                service=service,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                src_port=src_port,
                pid=pid,
                source_system=source_system,
                conn_state=conn_state,
                dns=dns,
                ids_alerts=ids_alerts,
                http=http,
                file_transfer=file_transfer,
                ocsp=ocsp,
                ocsp_transaction=request.ocsp_transaction,
                proxy=proxy,
                firewall=firewall,
                hostname=hostname,
                process_image=process_image,
                proxy_chain=list(proxy_chain),
                preserve_explicit_proxy_dst_ip=preserve_explicit_proxy_dst_ip,
                caller_provided_conn_state=caller_provided_conn_state,
                ad_domain=ad_domain,
                parent_action_group_id=parent_action_group_id,
                suppress_source_pid_inference=suppress_source_pid_inference,
            )
            return ProxyTransactionActionBundle(
                request=proxy_request,
                executor=executor,
            ).execute()

        # Emit DNS lookup before connection via causal expansion.
        # The DnsBeforeConnection rule handles caching, SERVFAIL, multi-answer, etc.
        # Only internal hosts generate DNS lookups — external source IPs (e.g.,
        # attacker IPs in storylines) don't query the victim's internal resolver.
        src_ip_is_local = generator_module._is_modeled_local_ip(executor, src_ip)
        dst_ip_is_local = generator_module._is_modeled_local_ip(executor, dst_ip)
        force_visible_prereq_dns = (
            source_system is not None
            and "forward_proxy" in (source_system.roles or [])
            and hostname_is_external
            and proto == "tcp"
            and dst_port in (80, 443)
            and src_ip_is_local
            and not suppress_prereq_dns
        )
        # Same-host connections are valid for host-based logs (eCAR FLOW)
        # but invisible to network sensors (Zeek/Snort)
        local_only = src_ip == dst_ip

        # Validate connection is not fundamentally invalid (localhost, link-local, multicast)
        is_invalid, reason = generator_module._is_invalid_network_connection(src_ip, dst_ip)
        if is_invalid:
            generator_module.logger.warning(
                "Skipping invalid network connection: %s:%s -> %s:%s proto=%s. "
                "Reason: %s. Check that all systems have routable IPs in the scenario.",
                src_ip,
                src_port or "?",
                dst_ip,
                dst_port,
                proto,
                reason,
            )
            return ""

        is_fw_deny = firewall is not None and firewall.action == "deny"

        resolved_source_system = source_system
        if (
            resolved_source_system is None
            and hasattr(executor, "_ip_to_system")
            and src_ip in executor._ip_to_system
        ):
            resolved_source_system = executor._ip_to_system[src_ip]

        http_application_layer_only = False
        reused_http_uid = ""
        reused_http_conn_id = ""
        http_channel_affinity: HttpChannelAffinity | None = None
        if prepared_application_token is not None:
            from evidenceforge.generation.proxy_channels import (
                ExplicitProxyRequestReuse,
                ExplicitProxyTerminalRequest,
            )

            reuse = prepared_application_token.result
            if not isinstance(reuse, (ExplicitProxyRequestReuse, ExplicitProxyTerminalRequest)):
                raise StateError("Proxy request admission has no reusable transport")
            parent = executor.state_manager.get_connection_by_transaction_id(
                reuse.tunnel.client_transport_id
            )
            if parent is None:
                raise StateError("Proxy request admission references no canonical client transport")
            if (
                src_ip != parent.src_ip
                or src_port != parent.src_port
                or dst_ip != parent.dst_ip
                or dst_port != parent.dst_port
                or proto != parent.protocol
            ):
                raise StateError("Proxy request admission changed its client transport tuple")
            time = reuse.canonical_request_time
            duration = (
                reuse.canonical_complete_time - reuse.canonical_request_time
            ).total_seconds()
            reused_http_uid = parent.zeek_uid
            reused_http_conn_id = parent.conn_id
            http_application_layer_only = True
            preserve_start_time = True
        elif explicit_proxy_request_preparation is not None:
            tunnel = explicit_proxy_request_preparation.snapshot.tunnel
            parent = executor.state_manager.get_connection_by_transaction_id(
                tunnel.client_transport_id
            )
            if parent is None:
                raise StateError("Proxy request snapshot references no canonical client transport")
            if (
                src_ip != parent.src_ip
                or src_port != parent.src_port
                or dst_ip != parent.dst_ip
                or dst_port != parent.dst_port
                or proto != parent.protocol
            ):
                raise StateError("Proxy request snapshot changed its client transport tuple")
            reused_http_uid = parent.zeek_uid
            reused_http_conn_id = parent.conn_id
            http_application_layer_only = True
            preserve_start_time = True
        if (
            http is not None
            and proxy is None
            and not request.suppress_direct_http_channel
            and proto == "tcp"
            and service in {"http", "ssl"}
            and dst_port > 0
        ):
            http_channel_affinity = HttpChannelAffinity.from_request(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                http_host=http.host,
                resolved_hostname=hostname or "",
                user_agent=http.user_agent or "",
                transport_security="tls" if service == "ssl" else "cleartext",
            )
            if http.trans_depth > 1:
                requested_http_time = http.canonical_request_time or time
                http_timing = generator_module.get_timing_window(
                    "source.zeek_http_request",
                    default_min_ms=1,
                    default_max_ms=35,
                    default_position="after",
                    default_class="same_observation",
                )
                request_file_floor = generator_module.http_response_parent_duration_floor(
                    http.request_body_len or 0
                )
                response_file_floor = generator_module.http_response_parent_duration_floor(
                    http.response_body_len or 0
                )
                required_http_duration = max(
                    0.0,
                    duration or 0.0,
                    (http_timing.max_ms + 5) / 1000 + 0.025,
                    request_file_floor + 0.55 if request_file_floor > 0 else 0.0,
                    response_file_floor + 0.55 if response_file_floor > 0 else 0.0,
                )
                reuse_token = executor._http_channel_manager.prepare_reuse(
                    http_channel_affinity,
                    requested_at=requested_http_time,
                    required_until=requested_http_time + timedelta(seconds=required_http_duration),
                    request_body_bytes=http.request_body_len or 0,
                    response_body_bytes=http.response_body_len or 0,
                )
                boundary.track_application(executor._http_channel_manager, reuse_token)
                reuse = reuse_token.result if reuse_token is not None else None
                if reuse is not None:
                    time = reuse.canonical_request_time
                    src_port = reuse.src_port
                    reused_http_uid = reuse.zeek_uid
                    reused_http_conn_id = reuse.conn_id
                    http_application_layer_only = True
                    preserve_start_time = True
                    http = generator_module.replace(
                        http,
                        trans_depth=reuse.trans_depth,
                        canonical_request_time=reuse.canonical_request_time,
                    )
                if not http_application_layer_only:
                    http = generator_module.replace(http, trans_depth=1)

        # A reused HTTPS request is an application child of the immutable TLS
        # parent. TLS-specific planning below excludes the child, while HTTP
        # and file analysis remain ordinary application evidence.

        kerberos_dc_hostname = None
        if proto in {"tcp", "udp"} and dst_port == 88:
            kerberos_dc = executor._dc_system_for_ip(dst_ip)
            if kerberos_dc is not None:
                kerberos_dc_hostname = str(getattr(kerberos_dc, "hostname", "") or "")

        source_os_category = (
            generator_module._get_os_category(resolved_source_system.os)
            if resolved_source_system is not None
            else "windows"
        )

        if proto == "icmp":
            src_port = 0
            dst_port = 0
        elif src_port is None:
            if kerberos_dc_hostname:
                src_port = executor._find_reserved_kerberos_source_port(
                    src_ip,
                    kerberos_dc_hostname,
                    time,
                    dst_ip=dst_ip,
                )
            if src_port is None and kerberos_dc_hostname:
                src_port = executor._allocate_ephemeral_port(
                    src_ip, dst_ip, dst_port, proto, time, source_os_category
                )
        if kerberos_dc_hostname and src_port is not None and src_port > 0:
            executor._reserve_kerberos_source_port(src_ip, kerberos_dc_hostname, time, src_port)

        if (
            service == "dns"
            and proto in ("udp", "tcp")
            and dst_port == 53
            and not suppress_source_pid_inference
        ):
            dns_pid = executor._infer_connection_pid(
                resolved_source_system, service, dst_port, proto
            )
            if dns_pid > 0:
                pid = dns_pid
        elif pid <= 0 and not suppress_source_pid_inference:
            pid = executor._infer_connection_pid(resolved_source_system, service, dst_port, proto)

        resolved_process = None
        if service == "dns" and proto in ("udp", "tcp") and dst_port == 53:
            query_len = len(dns.query) if dns is not None and dns.query else 12
            query_type = (dns.query_type if dns is not None else "").upper()
            min_query_payload = max(40, query_len + 16)
            if query_type in {"TXT", "NULL"}:
                min_query_payload += 18
            elif query_type == "SRV":
                min_query_payload += 10
            if orig_bytes is None or orig_bytes < min_query_payload:
                orig_bytes = min_query_payload
            if dns is not None and dns.rtt is not None:
                duration = max(duration or 0.001, dns.rtt)

        if pid > 0 and resolved_source_system:
            resolved_process = executor.state_manager.get_process(
                resolved_source_system.hostname, pid
            )
            drop_explicit_pid_without_inference = False
            if (
                resolved_process
                and resolved_process.start_time
                and time < resolved_process.start_time
            ):
                generator_module.logger.debug(
                    "Dropping future connection PID attribution: "
                    "host=%s pid=%s process_start=%s connection_time=%s dst=%s:%s",
                    resolved_source_system.hostname,
                    pid,
                    resolved_process.start_time,
                    time,
                    dst_ip,
                    dst_port,
                )
                pid = -1
                resolved_process = None
                drop_explicit_pid_without_inference = caller_supplied_pid
            elif executor._process_termination_recorded(
                resolved_source_system.hostname,
                pid,
                resolved_process.start_time if resolved_process is not None else None,
            ):
                generator_module.logger.debug(
                    "Dropping terminated process connection attribution: host=%s pid=%s dst=%s:%s",
                    resolved_source_system.hostname,
                    pid,
                    dst_ip,
                    dst_port,
                )
                pid = -1
                resolved_process = None
                drop_explicit_pid_without_inference = caller_supplied_pid
            elif (
                (
                    owning_end_plan := executor.state_manager.process_session_end_plan(
                        resolved_source_system.hostname, pid
                    )
                )
                is not None
                and owning_end_plan.is_authoritative
                and ensure_utc(time) >= ensure_utc(owning_end_plan.canonical_end)
            ):
                generator_module.logger.debug(
                    "Dropping connection PID after its owning session ended: "
                    "host=%s pid=%s session_end=%s connection_time=%s dst=%s:%s",
                    resolved_source_system.hostname,
                    pid,
                    owning_end_plan.canonical_end,
                    time,
                    dst_ip,
                    dst_port,
                )
                pid = -1
                resolved_process = None
                drop_explicit_pid_without_inference = caller_supplied_pid
            elif (
                resolved_process
                and resolved_process.start_time
                and executor._foreground_process_expired_for_attribution(
                    resolved_source_system,
                    resolved_process,
                    time,
                )
            ):
                generator_module.logger.debug(
                    "Dropping expired foreground process attribution: "
                    "host=%s pid=%s image=%s dst=%s:%s",
                    resolved_source_system.hostname,
                    pid,
                    resolved_process.image,
                    dst_ip,
                    dst_port,
                )
                pid = -1
                resolved_process = None
                drop_explicit_pid_without_inference = caller_supplied_pid
            elif resolved_process is None and pid != 4:
                generator_module.logger.debug(
                    "Dropping stale connection PID attribution: host=%s pid=%s dst=%s:%s",
                    resolved_source_system.hostname,
                    pid,
                    dst_ip,
                    dst_port,
                )
                pid = -1
                drop_explicit_pid_without_inference = caller_supplied_pid
            if drop_explicit_pid_without_inference:
                suppress_source_pid_inference = True

        if (
            resolved_source_system is not None
            and http is not None
            and not suppress_source_pid_inference
        ):
            # Direct client-to-proxy listener traffic owns a real client process
            # prerequisite (for example curl/wget/browser), independent of whether
            # the later transport root is admitted. Resolve or start that process
            # before NetworkRuntime.begin(), then carry only its stable identity
            # into the prepared root. The existing helper remains the sole owner of
            # source-native UA/process compatibility and prerequisite publication.
            attribution = _NetworkOccurrenceDraft(
                timestamp=time,
                http=http,
                network=NetworkTransactionDraft(
                    src_ip=src_ip,
                    src_port=src_port or 0,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=proto,
                    service=service or "",
                    duration=duration,
                    initiating_pid=pid,
                ),
            )
            if pid > 0:
                executor._set_connection_process_context(
                    attribution,
                    source_system=resolved_source_system,
                    pid=pid,
                    image=process_image,
                )
            executor._repair_explicit_proxy_listener_process_attribution(
                attribution,
                source_system=resolved_source_system,
                time=time,
            )
            if attribution.network.initiating_pid != pid:
                pid = attribution.network.initiating_pid
                process_image = (
                    attribution.process.image if attribution.process is not None else None
                )
                resolved_process = (
                    executor.state_manager.get_process(resolved_source_system.hostname, pid)
                    if pid > 0
                    else None
                )
            http = attribution.http

        if pid <= 0 and resolved_source_system is not None and not suppress_source_pid_inference:
            pid, process_image = executor._ensure_high_confidence_connection_owner(
                source_system=resolved_source_system,
                time=time,
                service=service,
                dst_port=dst_port,
                proto=proto,
                hostname=hostname,
                http=http,
                ssh_attempted_username=ssh_attempted_username,
            )
            if pid > 0:
                resolved_process = executor.state_manager.get_process(
                    resolved_source_system.hostname,
                    pid,
                )

        if (
            ssh_attempted_username is None
            and proto == "tcp"
            and dst_port == 22
            and resolved_process is not None
        ):
            ssh_attempted_username = generator_module._extract_ssh_attempted_username(
                resolved_process.command_line
            )

        # Preserve the initiating application on the canonical DNS occurrence
        # after connection ownership has been resolved. The DNS bundle still
        # assigns resolver-service ownership to its separate UDP/53 transport.
        if force_visible_prereq_dns:
            executor._emit_dns_lookup(
                src_ip,
                dst_ip,
                time - generator_module.timedelta(seconds=2),
                hostname=hostname,
                force_address=True,
                bypass_cache=True,
                source_system=resolved_source_system,
                source_pid=pid,
                source_process_image=process_image or "",
            )
        elif (
            (emit_dns or (hostname and not hostname_from_reverse_dns and not suppress_prereq_dns))
            and proto == "tcp"
            and dst_port not in (53,)
            and src_ip_is_local
        ):
            executor._expand_and_emit(
                "connection",
                time,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=proto,
                service=service,
                hostname=hostname,
                source_system=resolved_source_system,
                source_pid=pid,
                source_image=process_image or "",
            )

        if (
            dns is None
            and resolved_source_system is not None
            and "forward_proxy" in (resolved_source_system.roles or [])
            and hostname_is_external
            and proto == "tcp"
            and dst_port in (80, 443)
            and src_ip_is_local
            and not suppress_prereq_dns
        ):
            executor._emit_dns_lookup(
                src_ip,
                dst_ip,
                time - generator_module.timedelta(seconds=2),
                hostname=hostname,
                force_address=True,
                bypass_cache=True,
            )

        kerberos_prerequisite_success = conn_state not in {
            "S0",
            "S1",
            "SH",
            "SHR",
            "REJ",
            "OTH",
        } and ((resp_bytes or 0) > 0 or conn_state in {None, "SF"})
        if (
            kerberos_prerequisite_success
            and not suppress_application_side_effects
            and service == "kerberos"
            and dst_port == 88
            and proto in {"tcp", "udp"}
            and src_port is not None
            and src_port > 0
        ):
            executor._emit_dc_audit_for_kerberos_connection(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                time=time,
                dst_port=dst_port,
                proto=proto,
                conn_state=conn_state or "SF",
                service=service,
                source_system=resolved_source_system,
            )

        state_source_system = resolved_source_system.hostname if resolved_source_system else ""
        state_source_hostname = ""
        if resolved_source_system:
            state_source_hostname = executor._build_host_context(resolved_source_system).fqdn

        # Phase 1: Open the sole State/RNG/runtime/timing preparation. All explicit
        # DNS, owner, and Kerberos prerequisites above are already committed.
        owner_rng = generator_module._get_rng()
        network_preparation = boundary.begin(
            executor=executor,
            owner_rng=owner_rng,
            stable_id=request.stable_id,
            linearization_time=ensure_utc(time),
            action_group_id=parent_action_group_id or request.stable_id,
        )
        rng = network_preparation.rng
        if explicit_proxy_request_preparation is not None:
            prepared_application_token, proxy = explicit_proxy_request_preparation.prepare(
                manager=executor._proxy_channel_manager,
                timing_runtime=boundary.timing_preparation.planning_runtime,
            )
            boundary.track_application(
                executor._proxy_channel_manager,
                prepared_application_token,
            )
            from evidenceforge.generation.proxy_channels import (
                ExplicitProxyRequestReuse,
                ExplicitProxyTerminalRequest,
            )

            deferred_reuse = prepared_application_token.result
            if not isinstance(
                deferred_reuse,
                (ExplicitProxyRequestReuse, ExplicitProxyTerminalRequest),
            ):
                raise StateError("Deferred proxy request has no reusable transport result")
            time = deferred_reuse.canonical_request_time
            duration = (
                deferred_reuse.canonical_complete_time - deferred_reuse.canonical_request_time
            ).total_seconds()

        # Root-only sizing and duration draws start here so a rejected root can
        # cancel them with the network/timing preparation. The earlier DNS,
        # owner, and Kerberos audit/port work is intentionally independent and
        # may already have committed its own canonical prerequisite truth.
        if command_http_needs_response_size and http is not None:
            http = replace(http, response_body_len=rng.randint(500, 50000))
        if deferred_kerberos_duration_proto is not None:
            sampled_kerberos_duration = (
                self._kerberos_tcp_duration_seconds(request)
                if deferred_kerberos_duration_proto == "tcp"
                else self._kerberos_udp_duration_seconds(request)
            )
            duration = (
                min(duration, sampled_kerberos_duration)
                if duration is not None
                else sampled_kerberos_duration
            )
        if service == "dns" and proto in ("udp", "tcp") and dst_port == 53 and dns is not None:
            ad_domain = getattr(executor, "_ad_domain", "corp.local")
            dns.AA = generator_module._dns_is_internal_name(dns.query or "", ad_domain)
            if not is_fw_deny:
                dns_has_protocol_response = bool(
                    dns.rtt is not None
                    or dns.answers
                    or dns.rcode.upper() in {"NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"}
                    or dns.rcode_num in {0, 2, 3, 5}
                )
                if dns_has_protocol_response and dns.rtt is None:
                    dns.rtt = self._dns_rtt_seconds(
                        request,
                        is_public_resolver=not generator_module._is_private_ip(dst_ip),
                    )
                duration, orig_bytes, resp_bytes = generator_module._dns_payload_accounting(
                    dns=dns,
                    duration=duration,
                    orig_bytes=orig_bytes,
                    resp_bytes=resp_bytes,
                )
                if dns.rtt is not None:
                    duration = self._dns_transport_duration_seconds(request, dns.rtt)
        elif service == "dns" and proto in ("udp", "tcp") and dst_port == 53:
            if hostname and resp_bytes is not None and resp_bytes > 0:
                dns_query = (
                    hostname
                    or generator_module.REVERSE_DNS.get(dst_ip)
                    or f"host-{dst_ip.replace('.', '-')}"
                )
                fallback_dns = generator_module.DnsContext(
                    query=dns_query,
                    trans_id=0,
                    qtype=1,
                    query_type="A",
                    rcode="NOERROR",
                    rcode_num=0,
                    answers=[dst_ip],
                    rtt=duration,
                )
                duration, orig_bytes, resp_bytes = generator_module._dns_payload_accounting(
                    dns=fallback_dns,
                    duration=duration,
                    orig_bytes=orig_bytes,
                    resp_bytes=resp_bytes,
                )
            else:
                duration = self._sample_duration_seconds(
                    request,
                    relationship_key="network.dns.contextless_duration",
                    sample_key="dns_default",
                    minimum_us=2_000,
                    median_us=14_000,
                    maximum_us=80_001,
                    sigma=0.78,
                )
                orig_bytes = min(max(orig_bytes or 40, 40), 260)
                if resp_bytes is None:
                    resp_bytes = 120
                elif resp_bytes <= 0:
                    resp_bytes = 0
                else:
                    resp_bytes = min(max(resp_bytes, 70), 512)
        if pid > 0 and resolved_source_system is not None and resolved_process is not None:
            adjusted_time = executor._clamp_after_visible_process_create(
                resolved_source_system,
                pid,
                time,
                "source.windows_wfp_connection",
                timing_runtime=self._timing_runtime,
            )
            if preserve_start_time and adjusted_time > time:
                # Higher-level action bundles already own this transport's phase
                # anchor. A late endpoint process observation must not move the
                # canonical connection behind a dependent sibling; retain the
                # transport and omit unsafe process attribution instead.
                pid = -1
                resolved_process = None
                process_image = None
                suppress_source_pid_inference = True
            else:
                time = adjusted_time
        if src_port is None:
            reuse_window = generator_module._RECENT_CONNECTION_REUSE_WINDOW_SECONDS
            for _ in range(128):
                candidate_port = generator_module._ephemeral_port(rng, source_os_category)
                candidate_keys = executor._connection_tuple_key_variants(
                    src_ip,
                    candidate_port,
                    dst_ip,
                    dst_port,
                    proto,
                )
                runtime_recent = any(
                    (
                        seen_at := network_preparation.read_point(
                            NetworkRuntimePointFamily.RECENT_TUPLE,
                            key,
                            None,
                            at=ensure_utc(time),
                        )
                    )
                    is not None
                    and abs(time.timestamp() - float(seen_at)) <= reuse_window
                    for key in candidate_keys
                )
                if not runtime_recent and not executor.state_manager.connection_tuple_recently_used(
                    src_ip,
                    candidate_port,
                    dst_ip,
                    dst_port,
                    proto,
                    time,
                    reuse_window=reuse_window,
                ):
                    src_port = candidate_port
                    break
            if src_port is None:
                src_port = generator_module._ephemeral_port(rng, source_os_category)

        committed_suppressed = False
        if (
            service == "dns"
            and proto in ("udp", "tcp")
            and dst_port == 53
            and dns is None
            and hostname
        ):
            ad_domain = getattr(executor, "_ad_domain", "corp.local")
            dns_cache_key = (src_ip, dst_ip, hostname, "A")
            cache_ttl = generator_module._dns_base_ttl(
                hostname,
                generator_module._dns_is_internal_name(hostname, ad_domain),
            )
            cached = network_preparation.read_point(
                NetworkRuntimePointFamily.DIRECT_DNS_TTL,
                dns_cache_key,
                None,
                at=ensure_utc(time),
            )
            if cached is not None:
                committed_suppressed = True
            else:
                network_preparation.stage_point(
                    NetworkRuntimePointFamily.DIRECT_DNS_TTL,
                    dns_cache_key,
                    (time.timestamp(), time.timestamp() + cache_ttl),
                    expires_at=ensure_utc(time) + timedelta(seconds=cache_ttl),
                )

        # Allocate one physical identity, or reuse the immutable parent identity
        # without consuming a second allocator slot for an application child.
        if reused_http_conn_id:
            conn_id = reused_http_conn_id
            uid = reused_http_uid
        else:
            identity = network_preparation.reserve_physical_identity()
            conn_id = identity.conn_id
            uid = identity.zeek_uid

        # Protocol-aware connection state selection

        # REJ/S0 are source-native observations with no rendered duration, but the
        # canonical physical transaction still needs a terminal interval for State
        # and lifecycle authority. Preserve the already planned attempt budget so
        # finalization can close internal truth without inventing a second draw.
        canonical_terminal_duration = duration

        dns_has_response = (
            proto == "udp"
            and service == "dns"
            and dns is not None
            and (
                dns.rtt is not None
                or bool(dns.answers)
                or dns.rcode.upper() in {"NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"}
            )
        )

        # ICMP is connectionless — always OTH regardless of what the caller passed
        if proto == "icmp":
            conn_state = "OTH"
            history = "-"
            src_port = 0  # ICMP has no ports; Zeek emits 0
            dst_port = 0
            if resp_bytes and resp_bytes > 0:
                request_size = generator_module._icmp_echo_payload_size(rng, orig_bytes)
                response_size = request_size
                orig_bytes = request_size
                resp_bytes = response_size
                duration = generator_module._icmp_echo_duration(rng, duration)
            else:
                orig_bytes = generator_module._icmp_echo_payload_size(rng, orig_bytes)
                resp_bytes = 0
                duration = generator_module._icmp_echo_duration(rng, duration)
        elif dns_has_response:
            conn_state = "SF"
            history = "Dd"
            orig_bytes = max(orig_bytes or 0, 28)
            resp_bytes = max(resp_bytes or 0, 40)
            if dns.rtt is not None and (duration is None or duration < dns.rtt):
                duration = dns.rtt
        elif conn_state is not None:
            # Explicit conn_state for TCP/UDP (e.g., UFW BLOCK → REJ)
            if proto == "udp":
                history = {
                    "SF": "Dd" if resp_bytes else "D",
                    "S0": "D",
                    "REJ": "D",
                    "OTH": "D",
                }.get(conn_state, "Dd" if resp_bytes else "D")
            else:
                if conn_state == "SF":
                    history = generator_module._tcp_success_history(rng)
                else:
                    history = {
                        "REJ": "Sr",
                        "S0": "S",
                        "OTH": rng.choice(("DAd", "DdA", "ADad")),
                        "S2": "ShADadF",
                        "S3": "ShADadf",
                        "RSTO": "ShADaR",
                        "RSTR": "ShADadr",
                        "S1": "Sh",
                    }.get(conn_state, generator_module._tcp_success_history(rng))
            if conn_state in ("S0", "REJ"):
                duration = None
                resp_bytes = 0
                if service == "dns" and proto == "udp" and dst_port == 53:
                    orig_bytes = max(orig_bytes or 0, 40)
                else:
                    orig_bytes = 0
            elif conn_state in ("S2", "S3"):
                if duration is not None:
                    duration = self._failed_transport_duration_seconds(
                        request,
                        state=conn_state,
                        duration=duration,
                        sample_key="explicit_half_close",
                    )
                if resp_bytes:
                    resp_bytes = int(resp_bytes * rng.uniform(0.2, 0.7))
            elif conn_state in ("RSTO", "RSTR"):
                if duration is not None:
                    duration = self._failed_transport_duration_seconds(
                        request,
                        state=conn_state,
                        duration=duration,
                        sample_key="explicit_reset",
                    )
                if resp_bytes:
                    resp_bytes = int(resp_bytes * rng.uniform(0.1, 0.5))
        elif proto == "udp":
            # DNS connections with responses must not be S0 (no-response)
            if service == "kerberos" and resp_bytes and resp_bytes > 0:
                conn_state, history = "SF", "Dd"
            elif service == "dns" and resp_bytes and resp_bytes > 0:
                # ~5% retransmissions, ~2% multi-packet responses (large TXT/DNSSEC)
                dns_roll = rng.random()
                if dns_roll < 0.05:
                    conn_state, history = "SF", "DDd"  # Retransmitted query
                elif dns_roll < 0.07:
                    conn_state, history = "SF", "Ddd"  # Multi-packet response
                else:
                    conn_state, history = "SF", "Dd"
            elif service == "ntp" and resp_bytes and resp_bytes > 0:
                conn_state, history = "SF", "Dd"
            else:
                entry = rng.choices(
                    generator_module._UDP_CONN_ENTRIES,
                    weights=generator_module._UDP_CONN_WEIGHTS,
                    k=1,
                )[0]
                conn_state, _, history = entry
            if conn_state == "S0":
                duration = None
                resp_bytes = 0
        else:
            if duration is not None:
                tcp_entries = generator_module._TCP_CONN_ENTRIES
                tcp_weights = generator_module._TCP_CONN_WEIGHTS
                if caller_provided_payload:
                    candidates = [
                        entry
                        for entry in generator_module._TCP_CONN_ENTRIES
                        if entry[0] not in {"S0", "S1", "SH", "SHR", "REJ"}
                    ]
                    if candidates:
                        tcp_entries = candidates
                        tcp_weights = [entry[1] for entry in candidates]
                entry = rng.choices(tcp_entries, weights=tcp_weights, k=1)[0]
                conn_state, _, history = entry
                if conn_state == "OTH":
                    history = rng.choice(("DAd", "DdA", "ADad"))
            else:
                conn_state = "S0"
                history = "S"
            if conn_state in ("S0", "REJ"):
                duration = None
                resp_bytes = 0
                # S0/REJ: Zeek orig_bytes/resp_bytes are payload (application
                # data), not packet overhead.  No handshake completed → zero payload.
                orig_bytes = 0
            elif conn_state in ("S1", "SH", "SHR"):
                # S1/SH/SHR = partial handshake, no application data transferred.
                # Zeek orig_bytes/resp_bytes are payload bytes (always 0 for
                # handshake-only states); IP-byte totals are computed from packet
                # counts + header overhead downstream.
                orig_bytes = 0
                resp_bytes = 0
                if duration is not None:
                    duration = self._failed_transport_duration_seconds(
                        request,
                        state=conn_state,
                        duration=duration,
                        sample_key="selected_handshake",
                    )
            elif conn_state in ("S2", "S3"):
                # S2/S3 = half-closed: connection established, one side sent FIN
                # but the other never replied. Some data transferred before close.
                if duration is not None:
                    duration = self._failed_transport_duration_seconds(
                        request,
                        state=conn_state,
                        duration=duration,
                        sample_key="selected_half_close",
                    )
                if resp_bytes:
                    resp_bytes = int(resp_bytes * rng.uniform(0.2, 0.7))
            elif conn_state in ("RSTO", "RSTR"):
                if duration is not None:
                    duration = self._failed_transport_duration_seconds(
                        request,
                        state=conn_state,
                        duration=duration,
                        sample_key="selected_reset",
                    )
                if resp_bytes:
                    resp_bytes = int(resp_bytes * rng.uniform(0.1, 0.5))
            elif conn_state == "OTH":
                # OTH/Cc = midstream capture fragment — minimal data visible
                orig_bytes = rng.randint(0, 200)
                resp_bytes = rng.randint(0, 200)
                if duration is not None:
                    duration = self._failed_transport_duration_seconds(
                        request,
                        state=conn_state,
                        duration=duration,
                        sample_key="selected_midstream",
                    )

        if (
            not suppress_application_side_effects
            and not http_application_layer_only
            and proto == "tcp"
            and dst_port == 443
            and conn_state == "SF"
        ):
            # A completed TLS session with ssl.log/SNI evidence must include
            # at least a ClientHello and server handshake payload at conn.log
            # accounting level, even when the logical request body is empty.
            if http is not None:
                request_body_len = generator_module._http_context_flow_body_len(http, "request")
                response_body_len = generator_module._http_context_flow_body_len(http, "response")
                request_records = max(1, (request_body_len + 16_383) // 16_384)
                response_records = max(1, (response_body_len + 16_383) // 16_384)
                orig_bytes = (
                    request_body_len + rng.randint(350, 950) + request_records * rng.randint(22, 38)
                )
                resp_bytes = (
                    response_body_len
                    + rng.randint(1200, 5200)
                    + response_records * rng.randint(22, 38)
                )
            else:
                orig_bytes = max(orig_bytes or 0, rng.randint(180, 900))
                resp_bytes = max(resp_bytes or 0, rng.randint(900, 4500))
            tls_min_window = generator_module.get_timing_window(
                "network.tls_completed_min_duration",
                default_min_ms=800,
                default_max_ms=2500,
                default_position="after",
                default_class="same_observation",
            )
            tls_min_duration = tls_min_window.min_ms / 1000
            if duration is None or duration < tls_min_duration:
                max_extra = max(
                    0.016, min(0.65, (tls_min_window.max_ms - tls_min_window.min_ms) / 1000)
                )
                duration = tls_min_duration + self._tls_floor_slack_seconds(request, max_extra)
            else:
                duration += self._tls_completed_extension_seconds(request)

        if not suppress_application_side_effects and http is not None and conn_state == "SF":
            http_timing = generator_module.get_timing_window(
                "source.zeek_http_request",
                default_min_ms=1,
                default_max_ms=35,
                default_position="after",
                default_class="same_observation",
            )
            http_min_duration = (http_timing.max_ms + 5) / 1000
            if duration is None or duration < http_min_duration:
                duration = http_min_duration + self._http_floor_slack_seconds(request)

        if not caller_provided_duration:
            duration = self._generator_owned_duration_seconds(request, duration)
        kerberos_audit_count = 0
        if (
            not suppress_application_side_effects
            and service == "kerberos"
            and dst_port == 88
            and proto in {"tcp", "udp"}
            and kerberos_dc_hostname
            and src_port is not None
            and src_port > 0
            and not (proto == "tcp" and conn_state in {"S0", "S1", "SH", "SHR", "REJ", "OTH"})
        ):
            kerberos_audit_count = executor._kerberos_audit_count_for_connection(
                src_ip,
                kerberos_dc_hostname,
                src_port,
                time,
            )
            if kerberos_audit_count > 0:
                conn_state = "SF"
                min_orig_bytes = kerberos_audit_count * rng.randint(260, 520)
                min_resp_bytes = kerberos_audit_count * rng.randint(320, 760)
                orig_bytes = max(orig_bytes or 0, min_orig_bytes)
                resp_bytes = max(resp_bytes or 0, min_resp_bytes)
                min_duration = self._kerberos_audit_floor_seconds(
                    request,
                    kerberos_audit_count,
                )
                duration = max(duration or 0.0, min_duration)
                if proto == "udp":
                    history = "Dd" * kerberos_audit_count
                else:
                    history = generator_module._tcp_success_history(rng)

        if proto == "tcp":
            orig_bytes, resp_bytes = generator_module._tcp_payload_bytes_consistent_with_history(
                orig_bytes,
                resp_bytes,
                history,
            )

        # Calculate packet counts — enforce consistency with history
        if proto == "udp" and history:
            orig_pkts = max(
                history.count("D"), generator_module.math.ceil((orig_bytes or 0) / 1232)
            )
            resp_pkts = max(
                history.count("d"), generator_module.math.ceil((resp_bytes or 0) / 1232)
            )
            if orig_pkts > 0 and orig_bytes:
                orig_bytes = max(orig_bytes, orig_pkts * 28)
            if resp_pkts > 0 and resp_bytes:
                resp_bytes = max(resp_bytes, resp_pkts * 28)
            elif resp_pkts == 0:
                resp_bytes = 0
        elif proto == "tcp" and history and history != "-":
            orig_pkts, resp_pkts = generator_module._tcp_packet_counts_from_payload_and_history(
                orig_bytes,
                resp_bytes,
                history,
                rng,
            )
            if dst_port == 443 and conn_state == "SF":
                orig_pkts += rng.choices([0, 1, 2, 3, 5], weights=[45, 25, 15, 10, 5], k=1)[0]
                resp_pkts += rng.choices([0, 1, 2, 4, 8], weights=[35, 25, 20, 15, 5], k=1)[0]
        elif proto == "icmp":
            orig_pkts = 1
            resp_pkts = 1 if resp_bytes and resp_bytes > 0 else 0
        else:
            orig_pkts = max(1, (orig_bytes // 1500)) if orig_bytes else 1
            resp_pkts = max(1, (resp_bytes // 1500)) if resp_bytes else 0
        if kerberos_audit_count > 0:
            orig_pkts = max(orig_pkts, kerberos_audit_count)
            resp_pkts = max(resp_pkts, kerberos_audit_count)

        if proto == "udp" and dst_port == 123:
            orig_bytes, resp_bytes, duration = generator_module._ntp_payload_accounting(
                src_ip=src_ip,
                dst_ip=dst_ip,
                time=time,
                conn_state=conn_state,
                history=history,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                duration=duration,
            )
            orig_pkts = max(1, (history or "").count("D"))
            resp_pkts = (history or "").count("d") if (resp_bytes or 0) > 0 else 0
            if conn_state == "SF" and resp_pkts > 0 and (resp_bytes or 0) > 0:
                ntp_stratum, _ntp_ref_id = generator_module._ntp_stratum_and_ref_id(dst_ip)
                median_rtt_ms, rtt_sigma = generator_module._NTP_STRATUM_TIMING.get(
                    ntp_stratum,
                    (10.0, 0.7),
                )
                ntp_timing = self._ntp_timing_components(
                    request,
                    median_rtt_ms=median_rtt_ms,
                    rtt_sigma=rtt_sigma,
                )
                ntp_transport_duration = sum(ntp_timing[:3])
                if duration is None or duration < ntp_transport_duration:
                    duration = ntp_transport_duration

        if packet_overhead_bytes is not None:
            overhead = packet_overhead_bytes
        elif proto == "udp":
            overhead = rng.choices(
                generator_module._UDP_OVERHEAD_VALUES,
                weights=generator_module._UDP_OVERHEAD_WEIGHTS,
                k=1,
            )[0]
        elif proto == "icmp":
            overhead = 28
        else:
            overhead = rng.choices(
                generator_module._TCP_OVERHEAD_VALUES,
                weights=generator_module._TCP_OVERHEAD_WEIGHTS,
                k=1,
            )[0]
        # Zeek count fields are source-observed IP payload totals. TCP gets
        # per-side header/control texture; UDP/ICMP keeps protocol-specific
        # fixed accounting for source-native packet sizes.
        if proto == "tcp":
            orig_ip_bytes = generator_module._tcp_ip_byte_count(
                orig_bytes,
                orig_pkts,
                rng,
                overhead_override=packet_overhead_bytes,
            )
            resp_ip_bytes = generator_module._tcp_ip_byte_count(
                resp_bytes,
                resp_pkts,
                rng,
                overhead_override=packet_overhead_bytes,
            )
        else:
            orig_ip_bytes = (orig_bytes or 0) + orig_pkts * overhead
            resp_ip_bytes = (resp_bytes or 0) + resp_pkts * overhead

        ip_proto = 6 if proto == "tcp" else 17 if proto == "udp" else 1

        # Capture loss is source-observation truth, not a canonical connection property.
        missed_bytes = 0
        if proto == "tcp" and duration and duration > 10.0:
            # Preserve this planner's RNG scope while source observation takes
            # ownership of the resulting loss; unrelated protocol choices must
            # not change merely because the fact moved to its canonical owner.
            capture_loss_shape_roll = rng.random()
            if capture_loss_shape_roll < 0.03:
                rng.randint(500, 50000)

        if not preserve_start_time:
            time = generator_module._zeek_conn_observation_time(
                time,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                proto,
                service or "",
            )
        if proto == "icmp":
            zeek_type = src_port if src_port else 8
            zeek_code = dst_port if dst_port else 0
            icmp_key = (src_ip, zeek_type, dst_ip, zeek_code)
            requested_ts_us = int(round(time.timestamp() * 1_000_000))
            next_ts_us = network_preparation.read_point(
                NetworkRuntimePointFamily.ICMP_OBSERVATION,
                icmp_key,
                requested_ts_us,
                at=ensure_utc(time),
            )
            adjusted_ts_us = max(requested_ts_us, int(next_ts_us))
            gap_seed = _stable_seed(
                f"icmp_observation_gap:{src_ip}:{zeek_type}:{dst_ip}:{zeek_code}:{adjusted_ts_us}"
            )
            network_preparation.stage_point(
                NetworkRuntimePointFamily.ICMP_OBSERVATION,
                icmp_key,
                adjusted_ts_us + 7_000 + (gap_seed % 77_000),
                expires_at=min(
                    boundary.network_runtime.window_end,
                    ensure_utc(time) + timedelta(days=1),
                ),
            )
            if adjusted_ts_us != requested_ts_us:
                time += timedelta(microseconds=adjusted_ts_us - requested_ts_us)
        else:
            if pid > 0 and resolved_source_system is not None:
                final_end_plan = executor.state_manager.process_session_end_plan(
                    resolved_source_system.hostname,
                    pid,
                )
                if (
                    final_end_plan is not None
                    and final_end_plan.is_authoritative
                    and ensure_utc(time) >= ensure_utc(final_end_plan.canonical_end)
                ):
                    generator_module.logger.debug(
                        "Dropping connection PID after source timing crossed its session end: "
                        "host=%s pid=%s session_end=%s connection_time=%s dst=%s:%s",
                        resolved_source_system.hostname,
                        pid,
                        final_end_plan.canonical_end,
                        time,
                        dst_ip,
                        dst_port,
                    )
                    pid = -1
                    resolved_process = None
                    process_image = None
            duration = self._cap_to_owning_session(
                start=time,
                duration=duration,
                source_system=resolved_source_system,
                pid=pid,
                stable_id=request.stable_id,
            )
        # Port-based service correction (Zeek detects service from payload, not scenario labels)
        _PORT_SERVICE = {
            80: "http",
            443: "ssl",
            22: "ssh",
            53: "dns",
            25: "smtp",
            587: "smtp",
            88: "kerberos",
            389: "ldap",
            445: "smb",
        }
        if (
            service
            and dst_port in _PORT_SERVICE
            and service != _PORT_SERVICE[dst_port]
            and not is_tcp_probe
        ):
            service = _PORT_SERVICE[dst_port]
        if (
            proto == "tcp"
            and conn_state in {"S0", "REJ", "S1", "SH", "SHR"}
            and service != "dns"
            and http is None
        ):
            service = ""
        if (
            proto == "udp"
            and conn_state in {"S0", "REJ", "OTH"}
            and (orig_bytes or 0) == 0
            and (resp_bytes or 0) == 0
            and service != "dns"
        ):
            service = ""

        # Phase 2: Resolve event-side ownership into an action-owned draft. The
        # canonical OccurrenceBuilder is constructed only after the transaction is
        # finalized below.
        # Resolve source system for src_host (needed by eCAR emitter for hostname/routing)
        src_host_ctx = None
        if resolved_source_system:
            src_host_ctx = executor._build_host_context(resolved_source_system)

        # Resolve destination system for dst_host
        dst_host_ctx = None
        if hasattr(executor, "_ip_to_system") and dst_ip in executor._ip_to_system:
            dst_host_ctx = executor._build_host_context(executor._ip_to_system[dst_ip])
        elif executor.dispatcher and executor.dispatcher.visibility_engine:
            real_dst_ip = executor.dispatcher.visibility_engine._vip_to_real_ip.get(dst_ip)
            if real_dst_ip and real_dst_ip in executor._ip_to_system:
                dst_host_ctx = executor._build_host_context(executor._ip_to_system[real_dst_ip])

        # Resolve the canonical initiating process when its PID is known.
        process_ctx = None
        if pid > 0 and resolved_source_system:
            running = resolved_process or executor.state_manager.get_process(
                resolved_source_system.hostname, pid
            )
            if running is not None:
                process_ctx = generator_module.ProcessContext(
                    pid=pid,
                    parent_pid=running.parent_pid,
                    image=running.image,
                    command_line=running.command_line,
                    username=running.username,
                    logon_id=running.logon_id,
                    start_time=running.start_time,
                    parent_start_time=executor._lookup_parent_start_time(
                        resolved_source_system.hostname, running.parent_pid
                    ),
                )
            elif process_image:
                process_ctx = generator_module.ProcessContext(
                    pid=pid,
                    parent_pid=0,
                    image=process_image,
                    command_line="",
                    username="",
                )

        target_system = None
        if dst_host_ctx is not None and hasattr(executor, "_ip_to_system"):
            target_system = executor._ip_to_system.get(dst_host_ctx.ip)
        target_has_ssh = target_system is not None and "ssh" in {
            str(service_name).lower() for service_name in (target_system.services or [])
        }
        target_has_smb = False
        if target_system is not None:
            world_planner = getattr(executor, "_world_planner", None)
            world_model = getattr(world_planner, "world_model", None)
            target_world = (
                world_model.hosts.get(target_system.hostname) if world_model is not None else None
            )
            if target_world is not None:
                from evidenceforge.generation.world_model import HostCapability

                target_has_smb = target_world.supports(HostCapability.SMB_SERVER)
            else:
                smb_server_services = {"lanmanserver", "samba", "smb-server", "smbd"}
                target_has_smb = bool(
                    {
                        str(service_name).casefold().replace("_", "-")
                        for service_name in (target_system.services or [])
                    }.intersection(smb_server_services)
                )
        generic_ssh_preauth_pid: int | None = None
        prepared_responder = None
        if (
            target_system is not None
            and dst_host_ctx is not None
            and dst_host_ctx.os_category == "windows"
            and responding_pid <= 0
        ):
            responding_pid = executor._resolve_windows_inbound_service_pid(
                target_system,
                dst_port,
                time,
            )
        if (
            dst_host_ctx is not None
            and dst_host_ctx.os_category == "linux"
            and target_system is not None
            and proto == "tcp"
            and dst_port == 22
            and conn_state == "SF"
            and (service in {"", "ssh"} or target_has_ssh)
        ):
            infer_generic_ssh_preauth = responding_pid <= 0
            prepared_responder = executor.prepare_network_responder(
                kind="ssh",
                target_system=target_system,
                time=time,
                close_time=(
                    time + generator_module.timedelta(seconds=max(0.0, duration))
                    if duration is not None
                    else None
                ),
                source_ip=src_ip,
                source_port=src_port,
                target_user=ssh_attempted_username,
                responding_pid=responding_pid,
                network_preparation=network_preparation,
                source_timing_preparation=boundary.timing_preparation,
                runtime_expires_at=boundary.network_runtime.window_end,
            )
            responding_pid = prepared_responder.responding_pid
            if infer_generic_ssh_preauth:
                generic_ssh_preauth_pid = responding_pid
        if (
            dst_host_ctx is not None
            and dst_host_ctx.os_category == "linux"
            and target_system is not None
            and target_has_smb
            and proto == "tcp"
            and dst_port == 445
            and conn_state == "SF"
            and service in {"", "smb"}
        ):
            prepared_responder = executor.prepare_network_responder(
                kind="smb",
                target_system=target_system,
                time=time,
                close_time=(
                    time + generator_module.timedelta(seconds=max(0.0, duration))
                    if duration is not None
                    else None
                ),
                source_ip=src_ip,
                source_port=src_port,
                target_user=None,
                responding_pid=responding_pid,
                network_preparation=network_preparation,
                source_timing_preparation=boundary.timing_preparation,
                runtime_expires_at=boundary.network_runtime.window_end,
            )
            responding_pid = prepared_responder.responding_pid

        event = _NetworkOccurrenceDraft(
            timestamp=time,
            parent_action_group_id=parent_action_group_id,
            src_host=src_host_ctx,
            dst_host=dst_host_ctx,
            local_only=local_only,
            process=process_ctx,
            network=NetworkTransactionDraft(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                service=service or "",
                zeek_uid=uid,
                conn_id=conn_id,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                orig_pkts=orig_pkts,
                resp_pkts=resp_pkts,
                orig_ip_bytes=orig_ip_bytes,
                resp_ip_bytes=resp_ip_bytes,
                conn_state=conn_state,
                history=history,
                local_orig=src_ip_is_local,
                local_resp=dst_ip_is_local,
                ip_proto=ip_proto,
                missed_bytes=missed_bytes,
                initiating_pid=pid,
                responding_pid=responding_pid,
                application_layer_only=http_application_layer_only,
            ),
        )

        # Caller-provided context overrides
        if ids_alerts:
            event.ids_alerts = list(ids_alerts)
        if email is not None:
            event.email = email
        if smtp is not None:
            event.smtp = smtp
        if request.ssl is not None and not http_application_layer_only:
            event.ssl = request.ssl
        if x509 is not None and not http_application_layer_only:
            event.x509 = x509
        if x509_chain and not http_application_layer_only:
            event.x509_chain = list(x509_chain)
        if request.tls_presentation is not None and not http_application_layer_only:
            event.tls_presentation = request.tls_presentation
            if not event.x509_chain:
                event.x509_chain = executor._tls_certificate_planner.x509_contexts(
                    request.tls_presentation
                )
            executor._tls_certificate_planner.validate_projection(
                request.tls_presentation,
                event.x509_chain,
            )
            event.x509 = event.x509_chain[0]
            if event.ssl is not None:
                event.ssl = replace(
                    event.ssl,
                    cert_chain_fuids=tuple(cert.fuid for cert in event.x509_chain),
                )
        if http is not None:
            event.http = http
        if file_transfer is not None:
            event.file_transfer = file_transfer
        if file_transfers:
            event.file_transfers = list(file_transfers)
        if pe is not None:
            event.pe = pe
        if request.pe_analyses:
            event.pe_analyses = list(request.pe_analyses)
        if ocsp is not None:
            event.ocsp = ocsp
        if request.ocsp_transaction is not None:
            event.ocsp_transaction = request.ocsp_transaction
        if proxy is not None:
            event.proxy = proxy
        if firewall is not None:
            event.firewall = firewall

        # DNS context for Zeek dns.log fan-out
        if dns is not None:
            event.dns = dns
            if (
                event.firewall is not None
                and event.firewall.action == "deny"
                and proto in ("udp", "tcp")
                and dst_port == 53
            ):
                event.dns.rcode = "NOERROR"
                event.dns.rcode_num = 0
                event.dns.answers = []
                event.dns.TTLs = []
                event.dns.rtt = None
                event.network.conn_state = "S0"
                event.network.history = "D" if proto == "udp" else "S"
                event.network.duration = None
                event.network.resp_bytes = 0
                event.network.resp_pkts = 0
                event.network.resp_ip_bytes = None
            else:
                executor._normalize_dns_context_for_resolver(
                    event.dns,
                    resolver_ip=dst_ip,
                    time=time,
                )
                if self._stage_dns_observation(
                    network_preparation,
                    src_ip=src_ip,
                    resolver_ip=dst_ip,
                    dns=event.dns,
                    time=time,
                ):
                    committed_suppressed = True
        elif (
            service == "dns"
            and proto in ("udp", "tcp")
            and dst_port == 53
            and hostname
            and (hostname_was_explicit or dst_ip in dns_server_ips)
            and not is_fw_deny
        ):
            dns_query = (
                hostname
                or generator_module.REVERSE_DNS.get(dst_ip)
                or f"host-{dst_ip.replace('.', '-')}"
            )
            dns_is_internal = generator_module._dns_is_internal_name(
                dns_query,
                getattr(executor, "_ad_domain", ""),
            )
            had_response_payload = bool(resp_bytes)
            dns_answers = [dst_ip] if had_response_payload else []
            synthesized_rtt = self._dns_rtt_seconds(
                request,
                is_public_resolver=not generator_module._is_private_ip(dst_ip),
            )
            event.dns = generator_module.DnsContext(
                query=dns_query,
                trans_id=rng.randint(1, 65535),
                qtype=1,
                query_type="A",
                rcode="NOERROR" if had_response_payload else "SERVFAIL",
                rcode_num=0 if had_response_payload else 2,
                answers=dns_answers,
                TTLs=executor._dns_observed_ttls(
                    resolver_ip=dst_ip,
                    query=dns_query,
                    qtype_name="A",
                    answers=dns_answers,
                    is_internal=dns_is_internal,
                    base_ttl=generator_module._dns_base_ttl(dns_query, dns_is_internal),
                    time=time,
                ),
                rtt=synthesized_rtt,
                AA=dns_is_internal,
            )
            if self._stage_dns_observation(
                network_preparation,
                src_ip=src_ip,
                resolver_ip=dst_ip,
                dns=event.dns,
                time=time,
            ):
                committed_suppressed = True
            if not had_response_payload:
                event.network.conn_state = "SF"
                event.network.history = "Dd"
                event.network.resp_bytes = rng.randint(80, 220)
                if proto == "udp":
                    event.network.orig_pkts = event.network.history.count("D")
                    event.network.resp_pkts = event.network.history.count("d")
                    event.network.orig_bytes = max(
                        event.network.orig_bytes or 0,
                        event.network.orig_pkts * 28,
                    )
                    event.network.orig_ip_bytes = (
                        event.network.orig_bytes + event.network.orig_pkts * overhead
                    )
                    event.network.resp_ip_bytes = (
                        event.network.resp_bytes + event.network.resp_pkts * overhead
                    )
                else:
                    event.network.resp_pkts = max(event.network.resp_pkts or 0, 1)
                    event.network.resp_ip_bytes = event.network.resp_bytes + overhead
            event.network.duration = max(
                event.network.duration or 0.0,
                self._dns_transport_duration_seconds(request, synthesized_rtt),
            )

        # Proxy context: attach only for established outbound internet traffic.
        # Forward proxies only see egress that completes (not blocked/denied flows).
        if (
            not local_only
            and service in ("ssl", "http")
            and dst_port in (80, 443)
            and event.proxy is None
            and not generator_module._is_private_ip(dst_ip)
            and conn_state not in ("S0", "REJ", "S1", "SH", "SHR", "RSTO", "RSTR")
        ):
            proxy_routes = getattr(executor, "_proxy_routes", {})
            chain = proxy_routes.get(src_ip)
            if chain:
                from evidenceforge.events.contexts import ProxyContext

                proxy_sys = chain[0]
                proxy_fqdn = getattr(proxy_sys, "hostname", "")
                # Build proxy FQDN from hostname + domain
                ad_domain = getattr(executor, "_ad_domain", "")
                if ad_domain and "." not in proxy_fqdn:
                    proxy_fqdn = f"{proxy_fqdn}.{ad_domain}"
                # Hostname was resolved once at the top of generate_connection().
                proxy_hostname = hostname
                if proxy_hostname is None and dns is not None and dns.query:
                    proxy_hostname = dns.query
                if proxy_hostname is None:
                    proxy_hostname = generator_module.REVERSE_DNS.get(dst_ip)
                if proxy_hostname is None:
                    proxy_hostname = generator_module._generate_random_hostname(rng, dst_ip)
                # Suppressed hostname → use raw IP for proxy logging
                if proxy_hostname == "":
                    proxy_hostname = dst_ip
                from evidenceforge.generation.activity.dns_registry import get_domain_tags
                from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

                domain_tags = get_domain_tags(proxy_hostname)
                user_agent = ""

                # When a pre-built HttpContext exists (from browsing session
                # generator), derive proxy fields from it.  The proxy emitter
                # handles CONNECT tunnel deduplication automatically.
                if event.http is not None:
                    from evidenceforge.generation.activity.http_content import (
                        normalize_mime_type_for_path,
                    )

                    scheme = "https" if dst_port == 443 else "http"
                    proxy_method = event.http.method
                    url = f"{scheme}://{proxy_hostname}{event.http.uri}"
                    if event.http.resp_mime_types or event.http.status_code == 304:
                        proxy_content_type = normalize_mime_type_for_path(
                            event.http.uri,
                            (
                                event.http.resp_mime_types[0]
                                if event.http.resp_mime_types
                                else "text/html"
                            ),
                        )
                    else:
                        proxy_content_type = "text/html"
                    proxy_ua_override = None  # session UA is already on HttpContext
                    user_agent = event.http.user_agent
                    proxy_referrer = event.http.referrer
                elif dst_port == 443:
                    # Legacy single-connection HTTPS path
                    _src_os = (
                        generator_module._get_os_category(source_system.os)
                        if source_system
                        else None
                    )
                    (
                        path,
                        proxy_content_type,
                        proxy_method,
                        proxy_ua_override,
                        referrer_policy,
                    ) = pick_proxy_uri(
                        rng,
                        proxy_hostname,
                        domain_tags,
                        source_os=_src_os,
                        source_system_type=getattr(source_system, "type", None),
                        allow_canonical_protocol_templates=False,
                    )
                    url = f"https://{proxy_hostname}{path}"
                    from evidenceforge.generation.activity.referrer import pick_referrer

                    proxy_referrer = (
                        ""
                        if referrer_policy == "none"
                        else pick_referrer(rng, proxy_hostname, context="general", port=443)
                    )
                else:
                    _src_os = (
                        generator_module._get_os_category(source_system.os)
                        if source_system
                        else None
                    )
                    (
                        path,
                        proxy_content_type,
                        proxy_method,
                        proxy_ua_override,
                        referrer_policy,
                    ) = pick_proxy_uri(
                        rng,
                        proxy_hostname,
                        domain_tags,
                        source_os=_src_os,
                        source_system_type=getattr(source_system, "type", None),
                        allow_canonical_protocol_templates=False,
                    )
                    url = f"http://{proxy_hostname}{path}"
                    from evidenceforge.generation.activity.referrer import pick_referrer

                    proxy_referrer = (
                        ""
                        if referrer_policy == "none"
                        else pick_referrer(rng, proxy_hostname, context="general", port=80)
                    )
                from evidenceforge.generation.activity.proxy_uri import is_browser_like_proxy_domain

                apply_domain_user_agent = event.http is None or (
                    not generator_module._is_tool_http_user_agent(event.http.user_agent)
                    and not is_browser_like_proxy_domain(proxy_hostname, domain_tags=domain_tags)
                )
                user_agent = executor._proxy_user_agent_for_context(
                    rng,
                    source_system,
                    hostname=proxy_hostname,
                    domain_tags=domain_tags,
                    existing_user_agent=user_agent,
                    override_user_agent=proxy_ua_override,
                    apply_domain_override=apply_domain_user_agent,
                    source_identity=src_ip,
                )
                proxy_referrer = generator_module._source_native_http_referrer(
                    user_agent,
                    proxy_referrer,
                    request_scheme="https" if dst_port == 443 else "http",
                    request_port=dst_port,
                )
                cache_roll = rng.random()
                proxy_cacheable = generator_module._proxy_request_allows_cache_hit(
                    method=proxy_method,
                    url=url,
                    content_type=proxy_content_type,
                    domain_tags=domain_tags,
                )
                if event.http is not None:
                    if event.http.status_code == 304:
                        cache_result = "REVALIDATED"
                    elif proxy_cacheable and cache_roll < 0.30 and event.http.status_code < 400:
                        cache_result = "HIT"
                    else:
                        cache_result = "MISS"
                elif proxy_cacheable and cache_roll < 0.30:
                    cache_result = "HIT"
                elif cache_roll < 0.91:
                    cache_result = "MISS"
                elif cache_roll < 0.945:
                    cache_result = "DENIED"
                elif cache_roll < 0.975:
                    cache_result = "AUTH_REQUIRED"
                else:
                    cache_result = "GATEWAY_ERROR"
                # Proxy sc_bytes/cs_bytes are source-side accounting fields:
                # payload plus HTTP/proxy headers for allowed responses,
                # or proxy-generated error pages for failures.
                _cs = (orig_bytes or 0) + rng.randint(*generator_module._PROXY_CS_OVERHEAD)
                _response_bytes = (
                    event.http.response_body_len if event.http is not None else (resp_bytes or 0)
                )
                if cache_result == "DENIED":
                    _sc = rng.randint(500, 2000)  # proxy error page
                elif cache_result == "AUTH_REQUIRED":
                    _sc = rng.randint(300, 1200)
                elif cache_result == "GATEWAY_ERROR":
                    _sc = rng.randint(250, 1800)
                elif cache_result == "HIT":
                    _sc = _response_bytes + rng.randint(*generator_module._PROXY_SC_OVERHEAD)
                else:
                    _sc = _response_bytes + rng.randint(*generator_module._PROXY_SC_OVERHEAD)
                proxy_status_code = (
                    event.http.status_code
                    if event.http is not None
                    else {
                        "DENIED": 403,
                        "AUTH_REQUIRED": 407,
                        "GATEWAY_ERROR": rng.choice([502, 503, 504]),
                    }.get(cache_result, 200)
                )
                event.proxy = ProxyContext(
                    client_ip=src_ip,
                    username=executor._proxy_username_for_source(
                        source_system=source_system,
                        user_agent=user_agent,
                        cache_result=cache_result,
                        hostname=proxy_hostname,
                        time=event.timestamp,
                    ),
                    method=proxy_method,
                    url=url,
                    host=proxy_hostname,
                    status_code=proxy_status_code,
                    sc_bytes=_sc,
                    cs_bytes=_cs,
                    time_taken=generator_module._proxy_time_taken_ms(
                        duration,
                        rng,
                        method=proxy_method,
                        status_code=proxy_status_code,
                        cache_result=cache_result,
                        timing_runtime=self._timing_runtime,
                        stable_id=f"{request.stable_id}:proxy-context",
                    ),
                    user_agent=user_agent,
                    content_type=proxy_content_type,
                    cache_result=cache_result,
                    referrer=proxy_referrer,
                    proxy_fqdn=proxy_fqdn,
                    proxy_action=generator_module._proxy_action_for_context(
                        method=proxy_method,
                        url=url,
                        status_code=proxy_status_code,
                        cache_result=cache_result,
                        dst_port=dst_port,
                    ),
                )

        # Zeek protocol-layer contexts: populate SSL/HTTP/files for fan-out
        # Skip for local-only events (no network sensor will see them)
        rng = network_preparation.rng
        if (
            not suppress_application_side_effects
            and not http_application_layer_only
            and not local_only
            and service == "ssl"
            and proto == "tcp"
            and conn_state == "SF"
        ):
            executor._attach_ssl_context(
                event,
                hostname=tls_hostname,
                dns=dns,
                dst_ip=dst_ip,
                rng=rng,
                allow_failure=not caller_provided_conn_state,
                timing_stable_id=request.stable_id,
                network_preparation=network_preparation,
                timing_runtime=self._timing_runtime,
                network_point_expires_at=boundary.network_runtime.window_end,
            )
        if (
            proto == "tcp"
            and event.network.conn_state in {"S0", "REJ", "SH", "SHR"}
            and event.network.service in {"http", "ssl"}
            and event.http is None
            and event.ssl is None
        ):
            event.network.service = ""

        elif (
            not local_only
            and not suppress_application_side_effects
            and service == "http"
            and proto == "tcp"
            and conn_state == "SF"
            and event.http is None  # Skip auto-generation if caller provided HttpContext
        ):
            # Use the already-resolved hostname for HTTP Host header and URI templates.
            # Honor hostname="" (suppressed) — use raw IP instead of REVERSE_DNS.
            host = (
                hostname
                if hostname is not None
                else generator_module.REVERSE_DNS.get(dst_ip, dst_ip)
            )
            if host == "":
                host = dst_ip
            if dst_port not in (80, 443):
                host = f"{host}:{dst_port}"
            from evidenceforge.generation.activity.dns_registry import get_domain_tags
            from evidenceforge.generation.activity.http_content import (
                apply_transfer_size_variance,
                coerce_response_size_for_mime,
                http_status_message,
                is_stable_resource_path,
                response_mime_types_for_status,
                response_size_for_status,
            )
            from evidenceforge.generation.activity.proxy_uri import (
                pick_proxy_uri,
                plaintext_http_redirect_status,
            )

            web_host = (
                hostname
                if hostname is not None
                else generator_module.REVERSE_DNS.get(dst_ip, dst_ip)
            )
            if web_host == "":
                web_host = dst_ip
            web_domain_tags = get_domain_tags(web_host)
            _src_os_http = (
                generator_module._get_os_category(source_system.os) if source_system else None
            )
            uri, mime_type, http_method, http_ua_override, http_referrer_policy = pick_proxy_uri(
                rng,
                web_host,
                web_domain_tags,
                source_os=_src_os_http,
                source_system_type=getattr(source_system, "type", None),
                allow_canonical_protocol_templates=False,
            )
            ua = executor._proxy_user_agent_for_context(
                rng,
                source_system,
                hostname=web_host,
                domain_tags=web_domain_tags,
                existing_user_agent="",
                override_user_agent=http_ua_override,
                apply_domain_override=True,
                source_identity=src_ip,
            )
            redirect_status = plaintext_http_redirect_status(
                web_host,
                port=dst_port,
                path=uri,
                dst_ip=dst_ip,
            )
            if redirect_status is not None:
                status_code = redirect_status
                status_msg = http_status_message(status_code)
            else:
                status_code, status_msg = generator_module._get_http_status(
                    dst_ip,
                    uri,
                    publish_cache=False,
                )

            if status_code in {204, 304}:
                resp_body_len = 0
            else:
                if status_code >= 300 or is_stable_resource_path(uri):
                    resp_body_len = apply_transfer_size_variance(
                        response_size_for_status(status_code, host, uri),
                        status_code=status_code,
                        host=host,
                        uri=uri,
                        content_type=mime_type,
                        variant_key=f"{src_ip}:{ua}",
                    )
                else:
                    resp_body_len = coerce_response_size_for_mime(rng, mime_type, resp_bytes)
            if event.network.conn_state == "SF" and resp_body_len > (event.network.resp_bytes or 0):
                event.network.resp_bytes = resp_body_len
                min_resp_pkts = max(1, generator_module.math.ceil(resp_body_len / 1460))
                event.network.resp_pkts = max(event.network.resp_pkts or 0, min_resp_pkts)
                min_resp_ip_bytes = resp_body_len + event.network.resp_pkts * 40
                event.network.resp_ip_bytes = max(
                    event.network.resp_ip_bytes or 0,
                    min_resp_ip_bytes,
                )
            from evidenceforge.generation.activity.referrer import pick_referrer

            _http_referer = (
                ""
                if http_referrer_policy == "none"
                else pick_referrer(rng, host, context="general", port=dst_port)
            )
            _http_referer = generator_module._source_native_http_referrer(
                ua,
                _http_referer,
                request_scheme="https" if dst_port == 443 else "http",
                request_port=dst_port,
            )
            event.http = generator_module.HttpContext(
                method=http_method,
                host=host,
                uri=uri,
                version="1.1",
                user_agent=ua,
                request_body_len=rng.randint(50, 2000) if http_method == "POST" else 0,
                response_body_len=resp_body_len,
                status_code=status_code,
                status_msg=status_msg,
                referrer=_http_referer,
                resp_mime_types=response_mime_types_for_status(
                    status_code,
                    mime_type,
                    resp_body_len,
                    method=http_method,
                ),
                tags=[],
            )

        if not suppress_application_side_effects:
            generator_module._attach_http_file_transfers(
                event,
                dst_ip=dst_ip,
                rng=rng,
                timing_runtime=self._timing_runtime,
                timing_scope=self._timing_scope(request),
                deployment_registry=getattr(executor.dispatcher, "deployment_registry", None),
            )

        # NTP context for Zeek ntp.log fan-out. Zeek ntp.log records server response
        # fields, so only attach the context when the matching conn.log row has a
        # responder payload.
        if (
            not local_only
            and service == "ntp"
            and proto == "udp"
            and event.network.conn_state == "SF"
            and (event.network.resp_pkts or 0) > 0
            and (event.network.resp_bytes or 0) > 0
        ):
            from evidenceforge.events.contexts import NtpContext

            stratum, ref_id = generator_module._ntp_stratum_and_ref_id(dst_ip)
            association = executor._ntp_association_profile(
                event.network.src_ip,
                dst_ip,
                network_preparation=network_preparation,
                expires_at=boundary.network_runtime.window_end,
            )
            poll_seconds = float(association["poll"])
            parser_key = (event.network.src_ip, dst_ip)
            last_parser_time = network_preparation.read_point(
                NetworkRuntimePointFamily.NTP_PARSER,
                parser_key,
                None,
                at=ensure_utc(event.timestamp),
            )
            parser_gap = (
                None
                if last_parser_time is None
                else (event.timestamp - last_parser_time).total_seconds()
            )
            if parser_gap is None or parser_gap >= generator_module._ntp_parser_min_gap_seconds(
                poll_seconds
            ):
                network_preparation.stage_point(
                    NetworkRuntimePointFamily.NTP_PARSER,
                    parser_key,
                    event.timestamp,
                    expires_at=min(
                        boundary.network_runtime.window_end,
                        ensure_utc(event.timestamp)
                        + timedelta(
                            seconds=generator_module._ntp_parser_min_gap_seconds(poll_seconds)
                        ),
                    ),
                )
                server_response = executor._ntp_server_response_profile(
                    dst_ip,
                    network_preparation=network_preparation,
                    timing_runtime=self._timing_runtime,
                    expires_at=boundary.network_runtime.window_end,
                )
                observed_response = generator_module._ntp_observed_response_fields(
                    server_response,
                    dst_ip=dst_ip,
                    event_time=event.timestamp,
                    timing_runtime=self._timing_runtime,
                )
                if ntp_timing is None:
                    median_rtt_ms, rtt_sigma = generator_module._NTP_STRATUM_TIMING.get(
                        stratum,
                        (10.0, 0.7),
                    )
                    ntp_timing = self._ntp_timing_components(
                        request,
                        median_rtt_ms=median_rtt_ms,
                        rtt_sigma=rtt_sigma,
                    )
                rtt_sec, proc_sec, close_slack_sec, reference_age = ntp_timing
                ntp_duration = rtt_sec + proc_sec + close_slack_sec
                if event.network.duration is None or event.network.duration < ntp_duration:
                    event.network.duration = ntp_duration
                canonical_server_receive = event.timestamp + timedelta(seconds=rtt_sec / 2)
                canonical_server_transmit = canonical_server_receive + timedelta(seconds=proc_sec)
                reference_time = self._ntp_clock_time(
                    request,
                    event.timestamp - reference_age,
                    role="server",
                    identity=dst_ip,
                )
                origin_time = self._ntp_clock_time(
                    request,
                    event.timestamp,
                    role="client",
                    identity=event.network.src_ip,
                )
                receive_time = self._ntp_clock_time(
                    request,
                    canonical_server_receive,
                    role="server",
                    identity=dst_ip,
                )
                transmit_time = self._ntp_clock_time(
                    request,
                    canonical_server_transmit,
                    role="server",
                    identity=dst_ip,
                )
                event.ntp = NtpContext(
                    version=int(association["version"]),
                    mode=4,  # server response
                    stratum=stratum,
                    poll=poll_seconds,
                    precision=observed_response["precision"],
                    root_delay=observed_response["root_delay"],
                    root_disp=observed_response["root_disp"],
                    ref_id=ref_id,
                    ref_ts=round(reference_time.timestamp(), 6),
                    org_ts=round(origin_time.timestamp(), 6),
                    rec_ts=round(receive_time.timestamp(), 6),
                    xmt_ts=round(transmit_time.timestamp(), 6),
                )
            else:
                event.network.service = ""

        # Enforce conn_state/HTTP consistency: if HTTP context exists,
        # the connection must have completed successfully (SF). A connection
        # with a handshake-only, reset, or half-close state cannot have served
        # a Zeek HTTP transaction with request/response body accounting.
        if (
            event.http is not None
            and event.network.protocol == "tcp"
            and event.network.conn_state != "SF"
        ):
            event.network.conn_state = "SF"
            event.network.history = generator_module._tcp_success_history(rng)
            if event.network.duration is None:
                event.network.duration = self._http_default_duration_seconds(request)

        if (
            event.http is not None
            and event.network.protocol == "tcp"
            and event.network.conn_state == "SF"
        ):
            http_timing = generator_module.get_timing_window(
                "source.zeek_http_request",
                default_min_ms=1,
                default_max_ms=35,
                default_position="after",
                default_class="same_observation",
            )
            http_min_duration = (http_timing.max_ms + 5) / 1000
            if event.network.duration is None or event.network.duration < http_min_duration:
                event.network.duration = http_min_duration + self._http_floor_slack_seconds(request)

        if event.network.protocol == "tcp" and event.network.conn_state == "SF":
            if event.http is not None:
                method = (event.http.method or "GET").upper()
                if event.network.service == "http" and method != "CONNECT":
                    event.network.orig_bytes, event.network.resp_bytes = (
                        generator_module._http_flow_payload_bytes(event.http)
                    )
                else:
                    request_body_len = generator_module._http_context_flow_body_len(
                        event.http, "request"
                    )
                    response_body_len = generator_module._http_context_flow_body_len(
                        event.http, "response"
                    )
                    request_overhead = rng.randint(180, 620)
                    response_overhead = rng.randint(180, 900)
                    if event.http.status_code in {204, 304} or method == "HEAD":
                        response_overhead = rng.randint(90, 360)
                    event.network.orig_bytes = max(
                        event.network.orig_bytes or 0,
                        request_body_len + request_overhead,
                        rng.randint(180, 520),
                    )
                    event.network.resp_bytes = max(
                        event.network.resp_bytes or 0,
                        response_body_len + response_overhead,
                        rng.randint(90, 450),
                    )
            if (
                event.network.service == "ssl"
                and not suppress_application_side_effects
                and not http_application_layer_only
            ):
                event.network.orig_bytes = max(event.network.orig_bytes or 0, rng.randint(180, 900))
                event.network.resp_bytes = max(
                    event.network.resp_bytes or 0, rng.randint(900, 4500)
                )
            event.network.orig_pkts, event.network.resp_pkts = (
                generator_module._tcp_packet_counts_from_payload_and_history(
                    event.network.orig_bytes,
                    event.network.resp_bytes,
                    event.network.history,
                    rng,
                )
            )
            if (
                event.network.service == "ssl"
                and not suppress_application_side_effects
                and not http_application_layer_only
            ):
                event.network.orig_pkts += rng.choices(
                    [0, 1, 2, 3, 5],
                    weights=[45, 25, 15, 10, 5],
                    k=1,
                )[0]
                event.network.resp_pkts += rng.choices(
                    [0, 1, 2, 4, 8],
                    weights=[35, 25, 20, 15, 5],
                    k=1,
                )[0]
            event.network.orig_ip_bytes = generator_module._tcp_ip_byte_count(
                event.network.orig_bytes,
                event.network.orig_pkts,
                rng,
            )
            event.network.resp_ip_bytes = generator_module._tcp_ip_byte_count(
                event.network.resp_bytes,
                event.network.resp_pkts,
                rng,
            )

        if (
            not suppress_application_side_effects
            and not http_application_layer_only
            and not local_only
            and event.network.service == "ssl"
            and event.network.conn_state == "SF"
            and event.ssl is None
        ):
            executor._attach_ssl_context(
                event,
                hostname=tls_hostname,
                dns=dns,
                dst_ip=dst_ip,
                rng=rng,
                allow_failure=False,
                timing_stable_id=request.stable_id,
                network_preparation=network_preparation,
                timing_runtime=self._timing_runtime,
                network_point_expires_at=boundary.network_runtime.window_end,
            )

        generator_module._align_tcp_network_payload_with_history(event.network, rng)
        if preserve_explicit_payload:
            generator_module._preserve_explicit_tcp_payload_overrides(
                event.network,
                explicit_orig_bytes=explicit_orig_bytes,
                explicit_resp_bytes=explicit_resp_bytes,
                rng=rng,
            )
        if (
            not event.network.application_layer_only
            and executor._ensure_tls_conn_covers_certificate_bytes(
                event,
                timing_runtime=self._timing_runtime,
            )
        ):
            pass

        self._reconcile_application_payload(event, generator_module)

        scenario_end = getattr(executor, "_scenario_end_time", None)
        if scenario_end is not None and ensure_utc(request.time) == ensure_utc(scenario_end):
            # Output/application owners retain their historical exclusive end
            # fence, while the public generator still returns the committed UID
            # for one call exactly on that boundary. Keep the invisible physical
            # interval inside NetworkRuntime's one-microsecond sentinel.
            event.timestamp = ensure_utc(scenario_end)
            event.network.duration = min(event.network.duration or 0.000001, 0.000001)
            time = event.timestamp

        pid = event.network.initiating_pid
        process_ctx = event.process
        if pid > 0 and resolved_source_system is not None and process_ctx is not None:
            adjusted_time = executor._clamp_after_visible_process_create(
                resolved_source_system,
                pid,
                event.timestamp,
                "source.windows_wfp_connection",
                timing_runtime=self._timing_runtime,
            )
            if adjusted_time > event.timestamp:
                if preserve_start_time:
                    executor._set_connection_process_context(
                        event,
                        source_system=resolved_source_system,
                        pid=-1,
                    )
                    pid = -1
                    process_ctx = None
                else:
                    event.timestamp = adjusted_time
                    time = adjusted_time

        # Finalize the canonical source-visible interval only after every protocol,
        # payload, and process-visibility adjustment has settled. Dispatch creates
        # source-local event copies with collection delay, so the immutable interval
        # must live on the finalized transaction rather than be re-derived from those copies.
        canonical_duration = event.network.duration
        if canonical_duration is None and event.network.conn_state in {"REJ", "S0"}:
            canonical_duration = max(0.000001, canonical_terminal_duration or 0.000001)
        event.network.duration = self._cap_to_owning_session(
            start=event.timestamp,
            duration=canonical_duration,
            source_system=resolved_source_system,
            pid=pid,
            stable_id=request.stable_id,
        )
        event.network.source_visible_start_time = event.timestamp
        event.network.source_visible_close_time = (
            event.timestamp + generator_module.timedelta(seconds=max(0.0, event.network.duration))
            if event.network.duration is not None
            else None
        )
        if (
            event.network.service
            and event.network.protocol != "icmp"
            and (event.network.orig_bytes or 0) + (event.network.resp_bytes or 0) == 0
        ):
            # Zeek's conn.log service field records a protocol analyzer that
            # confirmed payload parsing, not a well-known-port guess. Retain
            # the requested service while planning children, then clear it at
            # the canonical boundary when no application bytes were observed.
            event.network.service = ""
        canonical_start = event.network.source_visible_start_time
        canonical_close = event.network.source_visible_close_time
        application_request_time: datetime | None = None
        if any((event.dns, event.http, event.ssl, event.smtp, event.proxy)):
            if event.http is not None and event.http.canonical_request_time is not None:
                application_request_time = event.http.canonical_request_time
            elif event.http is not None:
                minimum_request_gap = timedelta(milliseconds=1)
                if canonical_close is not None:
                    available = canonical_close - canonical_start
                    minimum_request_gap = min(minimum_request_gap, available * 0.45)
                if event.network.application_layer_only:
                    application_request_time = max(
                        event.timestamp,
                        canonical_start + minimum_request_gap,
                    )
                else:
                    delay_ms = 12 + (
                        _stable_seed(
                            "http_request_after_transport:"
                            f"{event.network.src_ip}:{event.network.src_port}:"
                            f"{event.network.dst_ip}:{event.network.dst_port}:"
                            f"{canonical_start.isoformat()}"
                        )
                        % 74
                    )
                    application_request_time = canonical_start + timedelta(milliseconds=delay_ms)
                if canonical_close is not None:
                    available = canonical_close - canonical_start
                    application_request_time = min(
                        application_request_time,
                        canonical_start + available * 0.45,
                    )
                application_request_time = max(
                    application_request_time,
                    canonical_start + minimum_request_gap,
                )
                event.http = replace(
                    event.http,
                    canonical_request_time=application_request_time,
                )
            else:
                application_request_time = canonical_start

        phase_times: list[tuple[str, datetime]] = [("transport_start", canonical_start)]
        if any((event.dns, event.http, event.ssl, event.smtp, event.proxy)) and not (
            event.network.application_layer_only
        ):
            phase_times.append(("application_request", application_request_time or canonical_start))
        if (
            canonical_close is not None
            and (event.network.resp_bytes or 0) > 0
            and canonical_close > canonical_start
            and not event.network.application_layer_only
        ):
            response_time = canonical_start + timedelta(
                seconds=(canonical_close - canonical_start).total_seconds() * 0.75
            )
            if application_request_time is not None:
                response_time = max(response_time, application_request_time)
            phase_times.append(("application_response", response_time))
        if canonical_close is not None:
            phase_times.append(("transport_close", canonical_close))
        if event.firewall is not None and event.firewall.action == "deny":
            transaction_outcome = "denied"
        elif event.network.conn_state in {"SF", "S1", "S2", "S3", "OTH"}:
            transaction_outcome = "success"
        else:
            transaction_outcome = "failure"
        event.network.finalize_transaction(
            request.stable_id,
            hostname=hostname or event.network.dst_ip,
            outcome=transaction_outcome,
            phase_times=tuple(phase_times),
        )
        from evidenceforge.generation.actions.ids_alert import (
            ids_alert_matches_transaction,
            normalize_ids_alerts,
        )

        transaction = event.network.transaction
        if transaction is None:
            raise ValueError("Network transaction disappeared after finalization")
        attached_files = tuple(
            candidate
            for candidate in (event.file_transfer, *event.file_transfers)
            if candidate is not None
        )
        event.ids_alerts = list(
            normalize_ids_alerts(
                [
                    alert
                    for alert in event.ids_alerts
                    if ids_alert_matches_transaction(
                        alert,
                        transaction,
                        http=event.http,
                        dns=event.dns,
                        ssl=event.ssl,
                        file_transfers=attached_files,
                    )
                ]
            )
        )
        event = event.build_event(generator_module)

        # Automatic weird.log synthesis is intentionally disabled for now. The
        # Zeek weird type space is broad and state-sensitive; poorly matched
        # weird rows are more damaging than sparse weird.log output. Explicit
        # WeirdContext events still render through ZeekWeirdEmitter. Keep one
        # RNG draw to avoid reshaping unrelated deterministic traffic choices.
        if not generator_module._AUTO_WEIRD_ENABLED:
            rng.random()

        application_window_end = getattr(executor, "_scenario_end_time", None)
        transport_inside_application_window = event.network.closed_at is not None and (
            application_window_end is None
            or (
                event.network.started_at < ensure_utc(application_window_end)
                and event.network.closed_at <= ensure_utc(application_window_end)
            )
        )
        if (
            http_channel_affinity is not None
            and event.http is not None
            and event.network.conn_state == "SF"
            and not event.network.application_layer_only
            and event.network.duration is not None
            and transport_inside_application_window
        ):
            assert event.network.closed_at is not None
            http_open_token = executor._http_channel_manager.prepare_open_transport(
                http_channel_affinity,
                transport_id=event.network.stable_id,
                zeek_uid=event.network.zeek_uid,
                conn_id=event.network.conn_id,
                src_port=event.network.src_port,
                opened_at=event.network.started_at,
                closes_at=event.network.closed_at,
                initial_request_time=event.http.canonical_request_time or event.network.started_at,
                orig_budget=max(
                    event.network.orig_bytes or 0,
                    event.http.request_body_len or 0,
                ),
                resp_budget=max(
                    event.network.resp_bytes or 0,
                    event.http.response_body_len or 0,
                ),
                initial_request_body_bytes=event.http.request_body_len or 0,
                initial_response_body_bytes=event.http.response_body_len or 0,
            )
            boundary.track_application(executor._http_channel_manager, http_open_token)

        explicit_proxy_open = request.explicit_proxy_open_preparation
        if explicit_proxy_open is not None:
            if not isinstance(explicit_proxy_open, ExplicitProxyOpenPreparation):
                raise StateError("Network request has an invalid explicit-proxy open preparation")
            if event.network.application_layer_only:
                raise StateError("Explicit-proxy open requires a physical origin transport")
            client_root = explicit_proxy_open.client_root
            client_receipt = explicit_proxy_open.client_receipt
            if not executor._lifecycle_authority.authenticates_prepared_network_receipt(
                client_root,
                client_receipt,
            ):
                raise StateError("Explicit-proxy open has no authentic client prerequisite")
            client = client_root.result.transaction
            if client.stable_id != explicit_proxy_open.client_transport_id:
                raise StateError("Explicit-proxy open changed its client prerequisite identity")
            proxy_open_token = explicit_proxy_open.prepare_token(
                manager=executor._proxy_channel_manager,
                origin_transaction=event.network,
            )
            if proxy_open_token is None:
                raise StateError("Explicit-proxy manager rejected the prepared origin transport")
            boundary.track_application(
                executor._proxy_channel_manager,
                proxy_open_token,
                prerequisite_receipts=(client_receipt,),
            )

        lifecycle_mode = request.lifecycle_plan_mode(event.network)
        materialization_mode = (
            ConnectionMaterializationMode.APPLICATION_CHILD
            if event.network.application_layer_only
            else ConnectionMaterializationMode.PHYSICAL
        )
        process_activity = ()
        session_activity = ()
        process_holds = ()
        if (
            materialization_mode is ConnectionMaterializationMode.PHYSICAL
            and pid > 0
            and resolved_source_system is not None
        ):
            from evidenceforge.events.lifecycle import LifecycleEntityRef, LifecycleHold
            from evidenceforge.generation.state_manager import (
                ProcessActivityPatch,
                SessionActivityPatch,
            )

            process_identity = executor.state_manager.get_process_identity(
                resolved_source_system.hostname,
                pid,
            )
            activity_time = event.network.closed_at or event.network.started_at
            lifecycle_process = (
                None
                if process_identity is None
                else executor._lifecycle_authority.registry.get_process(process_identity.object_id)
            )
            if (
                process_identity is not None
                and lifecycle_process is not None
                and lifecycle_process.closed_at is None
            ):
                session_identity = (
                    executor.state_manager.get_session_identity(process_identity.logon_id)
                    if process_identity.logon_id
                    else None
                )
                if not process_identity.logon_id or session_identity is not None:
                    process_activity = (ProcessActivityPatch(process_identity, activity_time),)
                    session_activity = (
                        ()
                        if session_identity is None
                        else (SessionActivityPatch(session_identity, activity_time),)
                    )
                    hold_action_id = generator_module.stable_uuid(
                        "network-process-hold-action",
                        event.network.stable_id,
                        process_identity.object_id,
                    )
                    process_holds = (
                        LifecycleHold(
                            hold_id=generator_module.stable_uuid(
                                "network-process-hold",
                                event.network.stable_id,
                                process_identity.object_id,
                            ),
                            subject=LifecycleEntityRef("process", process_identity.object_id),
                            acquired_at=event.network.started_at,
                            hold_until=activity_time,
                            action_id=hold_action_id,
                            reason="canonical_transport_close",
                        ),
                    )

        multipart_reads = self._plan_http_multipart_endpoint_reads(
            event,
            resolved_source_system or source_system,
            target_system,
            pid,
            process_ctx,
            request.time,
        )
        if multipart_reads is not None:
            process_activity = self._merge_process_activity_patches(
                process_activity,
                multipart_reads.process_activity,
            )
            if materialization_mode is ConnectionMaterializationMode.PHYSICAL:
                from evidenceforge.events.lifecycle import LifecycleEntityRef, LifecycleHold

                held_object_ids = {hold.subject.object_id for hold in process_holds}
                additional_holds = []
                for patch in process_activity:
                    if patch.identity.object_id in held_object_ids:
                        continue
                    held_object_ids.add(patch.identity.object_id)
                    hold_action_id = generator_module.stable_uuid(
                        "network-multipart-process-hold-action",
                        event.network.stable_id,
                        patch.identity.object_id,
                    )
                    additional_holds.append(
                        LifecycleHold(
                            hold_id=generator_module.stable_uuid(
                                "network-multipart-process-hold",
                                event.network.stable_id,
                                patch.identity.object_id,
                            ),
                            subject=LifecycleEntityRef("process", patch.identity.object_id),
                            acquired_at=event.network.started_at,
                            hold_until=event.network.closed_at or event.network.started_at,
                            action_id=hold_action_id,
                            reason="http_multipart_local_read",
                        )
                    )
                process_holds = (*process_holds, *additional_holds)

        if (
            materialization_mode is ConnectionMaterializationMode.PHYSICAL
            and event.network.protocol != "icmp"
            and event.network.src_port > 0
        ):
            tuple_seen_at = (event.network.closed_at or event.network.started_at).timestamp()
            tuple_expiry = min(
                boundary.network_runtime.window_end,
                (event.network.closed_at or event.network.started_at)
                + timedelta(seconds=generator_module._RECENT_CONNECTION_REUSE_WINDOW_SECONDS),
            )
            for tuple_key in executor._connection_tuple_key_variants(
                event.network.src_ip,
                event.network.src_port,
                event.network.dst_ip,
                event.network.dst_port,
                event.network.protocol,
            ):
                network_preparation.stage_point(
                    NetworkRuntimePointFamily.RECENT_TUPLE,
                    tuple_key,
                    tuple_seen_at,
                    expires_at=tuple_expiry,
                )

        commit_result = NetworkConnectionCommitResult(
            transaction=event.network,
            lifecycle_mode=lifecycle_mode,
            effective_dst_ip=event.network.dst_ip,
            http=event.protocol.http,
            file_transfers=event.protocol.file_transfers,
        )
        root = network_preparation.seal(
            transaction=event.network,
            lifecycle_mode=lifecycle_mode,
            materialization_mode=materialization_mode,
            source_system=state_source_system,
            source_hostname=state_source_hostname,
            hostname=hostname or event.network.dst_ip,
            initiating_pid=pid,
            batch=(prepared_responder.batch if prepared_responder is not None else None),
            process_activity=process_activity,
            session_activity=session_activity,
            result=commit_result,
        )
        boundary.root = root

        lifecycle_token = None
        if materialization_mode is ConnectionMaterializationMode.PHYSICAL:
            from evidenceforge.generation.lifecycle_production_adapters import (
                closed_transport_publication_plan,
                lifecycle_production_adapter_for,
            )

            lifecycle_adapter = lifecycle_production_adapter_for(executor)
            if lifecycle_adapter is None:
                raise StateError("Prepared network publication requires lifecycle authority")
            authority_hostname = state_source_system or event.network.src_ip
            source_lifecycle_hostname = state_source_system or event.network.src_ip
            destination_lifecycle_hostname = (
                target_system.hostname
                if target_system is not None
                else (hostname or event.network.dst_ip)
            )
            lifecycle_plan = closed_transport_publication_plan(
                transaction=event.network,
                authority_hostname=authority_hostname,
                src_hostname=source_lifecycle_hostname,
                dst_hostname=destination_lifecycle_hostname,
                action_id=generator_module.stable_uuid(
                    "network-transport-lifecycle",
                    event.network.stable_id,
                ),
            )
            lifecycle_token = lifecycle_adapter.prepare_closed_transport_publication(
                lifecycle_plan,
                start_members=executor._lifecycle_authority.connection_composite_start_members(
                    root.state_plan
                ),
                process_holds=process_holds,
            )
            boundary.lifecycle_adapter = lifecycle_adapter
            boundary.lifecycle_token = lifecycle_token

        prepared_dispatch = None
        prepared_multipart_dispatches = ()
        if lifecycle_mode != "deferred_session" and (
            not committed_suppressed or multipart_reads is not None
        ):
            from evidenceforge.events.dispatcher import PreparedDispatchStateIntent

            if not committed_suppressed:
                prepared_dispatch = executor.dispatcher.prepare_builder(
                    event,
                    state_intent=PreparedDispatchStateIntent.EXTERNAL_TRANSPORT,
                    lifecycle_ticket=root,
                    source_timing_preparation=boundary.timing_preparation,
                )
            prepared_multipart_dispatches = (
                ()
                if multipart_reads is None
                else tuple(
                    executor.dispatcher.prepare_builder(
                        builder,
                        state_intent=PreparedDispatchStateIntent.EXTERNAL_NETWORK_DEPENDENT,
                        lifecycle_ticket=root,
                        source_timing_preparation=boundary.timing_preparation,
                    )
                    for builder in multipart_reads.builders
                )
            )

        boundary.seal_timing()
        if prepared_dispatch is not None:
            executor.dispatcher.validate_prepared(prepared_dispatch)
        if prepared_responder is not None:
            for responder_process in prepared_responder.processes:
                executor.dispatcher.validate_prepared(responder_process.publication)
        prepared_multipart_batch = None
        if multipart_reads is not None:
            prepared_multipart_batch = executor.dispatcher.prepare_network_dependent_batch(
                root,
                multipart_reads.plan,
                prepared_multipart_dispatches,
            )
            boundary.track_network_dependent_batch(
                executor.dispatcher,
                prepared_multipart_batch,
            )
        boundary.validate_network_dependent_batch()
        boundary.validate_identity_capture_claim()
        boundary.transfer()
        materialized = executor._lifecycle_authority.materialize_prepared_network_transaction(
            root,
            owner_rng,
            source_timing_preparation=boundary.timing_preparation,
            lifecycle_token=lifecycle_token,
            application_token=boundary.application_token,
            prerequisite_receipts=boundary.prerequisite_receipts,
        )
        if not executor._lifecycle_authority.authenticates_prepared_network_receipt(
            root,
            materialized.receipt,
        ):
            raise AssertionError("Prepared network authority returned an invalid receipt")

        from evidenceforge.generation.actions.network_connection import (
            NetworkConnectionPublicationOutcome,
        )

        outcome = (
            NetworkConnectionPublicationOutcome.COMMITTED_SUPPRESSED
            if committed_suppressed
            else NetworkConnectionPublicationOutcome.PUBLISHED
        )
        application_result = materialized.connection.application
        boundary.publish_committed_capture_no_fail(
            root=root,
            receipt=materialized.receipt,
            application_receipt=(
                getattr(application_result, "receipt", None)
                if application_result is not None
                else None
            ),
            outcome=outcome,
        )

        executor._last_connection_effective_dst_ip = event.network.dst_ip
        executor._last_connection_effective_tuple = None
        executor._last_connection_effective_time = None
        executor._last_connection_effective_transaction_id = ""
        if materialization_mode is ConnectionMaterializationMode.PHYSICAL:
            executor._last_connection_effective_tuple = (
                event.network.src_ip,
                event.network.src_port,
                event.network.dst_ip,
                event.network.dst_port,
                event.network.protocol,
            )
            executor._last_connection_effective_time = event.timestamp
            executor._last_connection_effective_transaction_id = event.network.stable_id
            executor._last_connection_http_context = event.protocol.http
            executor._last_connection_file_transfers = event.protocol.file_transfers
        if committed_suppressed:
            if prepared_multipart_batch is not None:
                executor.dispatcher.publish_prepared_network_dependent_batch(
                    prepared_multipart_batch,
                    materialization_receipt=materialized.receipt,
                )
            # The typed capture exposes the committed internal root, while the
            # long-standing public compatibility contract reports no emitted
            # connection identity for a suppressed observation.
            return ""

        if prepared_responder is not None and target_system is not None:
            executor.publish_prepared_network_responder(
                prepared_responder,
                materialization_receipt=materialized.receipt,
                target_system=target_system,
                close_time=event.network.closed_at,
            )
        assert prepared_dispatch is not None
        network_identifiers_by_format = (
            executor.dispatcher.publish_prepared(
                prepared_dispatch,
                materialization_receipt=materialized.receipt,
            )
            or {}
        )
        if prepared_multipart_batch is not None:
            executor.dispatcher.publish_prepared_network_dependent_batch(
                prepared_multipart_batch,
                materialization_receipt=materialized.receipt,
            )
        executor._maybe_emit_ocsp_transaction(event)
        if generic_ssh_preauth_pid is not None and target_system is not None:
            executor._emit_generic_ssh_preauth_failure_syslog(
                target_system=target_system,
                target_host=dst_host_ctx,
                time=event.timestamp,
                source_ip=src_ip,
                source_port=src_port,
                sshd_pid=generic_ssh_preauth_pid,
                attempted_username=ssh_attempted_username,
                duration=event.network.duration,
            )
        generator_module.logger.debug(
            f"Generated connection: {src_ip} -> {dst_ip}:{dst_port} (UID: {uid})"
        )

        # Emit 5156 (WFP connection) on Windows source hosts when process ownership is known.
        # Unknown ownership is not PID 4 by default; rendering it as System makes ordinary
        # user/proxy flows look kernel-originated.
        wfp_system = resolved_source_system or source_system
        wfp_application = event.process.image if event.process is not None else None
        if (
            wfp_system
            and generator_module._get_os_category(wfp_system.os) == "windows"
            and (pid > 0 or wfp_application is not None)
            and not event.network.application_layer_only
        ):
            executor.generate_wfp_connection(
                system=wfp_system,
                time=time,
                network=event.network,
                pid=pid,
                application=wfp_application,
                parent_action_group_id=parent_action_group_id,
            )

        if (
            target_system is not None
            and dst_host_ctx is not None
            and dst_host_ctx.os_category == "windows"
            and not event.network.application_layer_only
            and executor._should_emit_windows_inbound_wfp(event, target_system)
        ):
            inbound_pid = event.network.responding_pid
            inbound_application = executor._lookup_process_name(
                target_system.hostname,
                inbound_pid,
                "windows",
            )
            executor.generate_wfp_connection(
                system=target_system,
                time=time,
                network=event.network,
                pid=inbound_pid,
                application=inbound_application,
                parent_action_group_id=parent_action_group_id,
            )

        if pid > 0 and resolved_source_system is not None and process_ctx is not None:
            running = executor.state_manager.get_process(resolved_source_system.hostname, pid)
            if executor._process_termination_recorded(
                resolved_source_system.hostname,
                pid,
                running.start_time if running is not None else None,
            ):
                identifier_publisher = getattr(
                    executor.dispatcher,
                    "publish_network_identifiers",
                    None,
                )
                if callable(identifier_publisher):
                    identifier_publisher(uid, network_identifiers_by_format)
                return uid
            lifetime = (
                executor._foreground_process_lifetime_for_attribution(
                    resolved_source_system, running
                )
                if running is not None
                else None
            )
            if lifetime is not None and generator_module.re.match(
                r"^[a-zA-Z0-9._$-]+$", running.username
            ):
                known_users = getattr(executor, "_users_by_username", {})
                process_user = known_users.get(running.username) or generator_module.User(
                    username=running.username,
                    full_name=running.username,
                    email=f"{running.username}@example.local",
                )
                min_delay = min(max(lifetime[0], 0.5), 4.0)
                max_delay = max(min_delay + 0.5, min(lifetime[1] + 8.0, 45.0))
                executor.generate_process_termination(
                    user=process_user,
                    system=resolved_source_system,
                    time=time
                    + generator_module.timedelta(
                        seconds=self._foreground_teardown_delay_seconds(
                            request,
                            min_delay,
                            max_delay,
                        )
                    ),
                    pid=pid,
                    process_name=running.image,
                    logon_id=running.logon_id,
                )

        identifier_publisher = getattr(
            executor.dispatcher,
            "publish_network_identifiers",
            None,
        )
        if callable(identifier_publisher):
            identifier_publisher(uid, network_identifiers_by_format)
        return uid
