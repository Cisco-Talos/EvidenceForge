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

"""Explicit forward-proxy transaction action bundle."""

from __future__ import annotations

import random
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol

from evidenceforge.events.contexts import (
    DnsContext,
    FileTransferContext,
    FirewallContext,
    HttpContext,
    IdsAlertPlan,
    OcspContext,
    PeContext,
    ProxyContext,
)
from evidenceforge.events.cryptography import OcspTransactionPlan
from evidenceforge.events.network import NetworkTransactionPlan
from evidenceforge.events.proxy import ProxyTerminalOutcome, ProxyTransactionPlan
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.file_transfer import (
    HttpResponseFileTransferActionBundle,
    HttpResponseFileTransferRequest,
)
from evidenceforge.generation.actions.network_connection import (
    NetworkConnectionActionBundle,
    NetworkConnectionIdentityCapture,
    NetworkConnectionRequest,
)
from evidenceforge.generation.activity.network_params import proxy_connect_status_message
from evidenceforge.generation.proxy_channels import (
    ExplicitProxyAdmissionReceipt,
    ExplicitProxyAdmissionToken,
    ExplicitProxyChannelAffinity,
    ExplicitProxyChannelManager,
    ExplicitProxyRequestReuse,
    ExplicitProxyRequestSnapshot,
    ExplicitProxyTerminalRequest,
    ProxyChannelOutcome,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc

if TYPE_CHECKING:
    from evidenceforge.generation.lifecycle_authority import LifecyclePreparedNetworkReceipt
    from evidenceforge.generation.network_runtime import PreparedNetworkTransactionRoot
    from evidenceforge.generation.source_timing import SourceTimingPlanningRuntime
    from evidenceforge.generation.timing import TimingRuntime


@dataclass(frozen=True, slots=True)
class ProxyTransactionRequest:
    """Intent for one explicit forward-proxy transaction."""

    src_ip: str
    dst_ip: str
    time: datetime
    dst_port: int
    proto: str
    service: str | None
    duration: float | None
    orig_bytes: int | None
    resp_bytes: int | None
    src_port: int | None
    pid: int
    source_system: System | None
    conn_state: str | None
    dns: DnsContext | None
    http: HttpContext | None
    file_transfer: FileTransferContext | None
    ocsp: OcspContext | None
    proxy: ProxyContext | None
    firewall: FirewallContext | None
    hostname: str | None
    process_image: str | None
    proxy_chain: list[System]
    preserve_explicit_proxy_dst_ip: bool
    caller_provided_conn_state: bool
    ad_domain: str
    ocsp_transaction: OcspTransactionPlan | None = None
    parent_action_group_id: str | None = None
    source: str = "activity_generator"
    ids_alerts: tuple[IdsAlertPlan, ...] = ()
    suppress_source_pid_inference: bool = False

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        proxy_host = self.proxy_chain[0].hostname if self.proxy_chain else ""
        seed = _stable_seed(
            "action_bundle:proxy_transaction:"
            f"{self.src_ip}:{self.src_port or ''}:{proxy_host}:"
            f"{self.dst_ip}:{self.dst_port}:{self.proto}:{self.service or ''}:"
            f"{self.hostname or ''}:{self.pid}:{self.duration or ''}:"
            f"{self.orig_bytes or ''}:{self.resp_bytes or ''}:"
            f"{self.conn_state or ''}:{self.time.isoformat()}:"
            f"{self.parent_action_group_id or ''}:{self.source}:"
            f"{self.suppress_source_pid_inference}"
        )
        return f"proxy-transaction-{seed:016x}"


@dataclass(frozen=True, slots=True)
class ExplicitProxyOpenPreparation:
    """Pure inputs for coupling one proxy open to its prepared origin root."""

    affinity: ExplicitProxyChannelAffinity
    client_root: PreparedNetworkTransactionRoot
    client_receipt: LifecyclePreparedNetworkReceipt
    phase_plan: ProxyTransactionPlan
    proxy_context: ProxyContext
    tunnel_group_id: str
    planned_request_count: int

    @property
    def client_transport_id(self) -> str:
        """Return the exact committed client prerequisite transport identity."""

        return self.client_root.result.transaction.stable_id

    def prepare_token(
        self,
        *,
        manager: ExplicitProxyChannelManager,
        origin_transaction: NetworkTransactionPlan,
    ) -> ExplicitProxyAdmissionToken | None:
        """Prepare the manager token consumed by the origin network authority."""

        client = self.client_root.result.transaction
        if client.closed_at is None or origin_transaction.closed_at is None:
            raise ValueError("Explicit-proxy transports must have closed canonical intervals")
        owns_initial_request = (
            self.planned_request_count > 0 and self.proxy_context.method != "CONNECT"
        )
        if owns_initial_request:
            setup_started_at = (
                self.phase_plan.tunnel_request_at or self.phase_plan.client_connect_at
            )
            setup_completed_at = self.phase_plan.client_flush_at
            setup_request_bytes = self.phase_plan.tunnel_setup_cs_bytes + max(
                0,
                int(self.proxy_context.cs_bytes or 0),
            )
            setup_response_bytes = self.phase_plan.tunnel_setup_sc_bytes + max(
                0,
                int(self.proxy_context.sc_bytes or 0),
            )
            future_request_count = max(0, self.planned_request_count - 1)
        else:
            setup_started_at = self.phase_plan.client_connect_at
            setup_completed_at = client.closed_at
            setup_request_bytes = max(0, client.orig_bytes or 0)
            setup_response_bytes = max(0, client.resp_bytes or 0)
            future_request_count = 0
        aggregate_request_bytes = (
            max(0, (client.orig_bytes or 0) - setup_request_bytes) if future_request_count else 0
        )
        aggregate_response_bytes = (
            max(0, (client.resp_bytes or 0) - setup_response_bytes) if future_request_count else 0
        )
        return manager.prepare_open_tunnel(
            replace(self.affinity, origin_ip=origin_transaction.dst_ip),
            client_transport_id=client.stable_id,
            origin_transport_id=origin_transaction.stable_id,
            client_zeek_uid=client.zeek_uid,
            origin_zeek_uid=origin_transaction.zeek_uid,
            tunnel_group_id=self.tunnel_group_id,
            client_source_port=client.src_port,
            origin_source_port=origin_transaction.src_port,
            opened_at=client.started_at,
            closes_at=client.closed_at,
            setup_started_at=setup_started_at,
            setup_completed_at=setup_completed_at,
            setup_request_wire_bytes=setup_request_bytes,
            setup_response_wire_bytes=setup_response_bytes,
            planned_request_count=future_request_count,
            aggregate_request_wire_bytes=aggregate_request_bytes,
            aggregate_response_wire_bytes=aggregate_response_bytes,
        )


class ProxyReuseUnavailableError(StateError):
    """The snapshotted tunnel cannot accept the deferred reused request."""


def _proxy_manager_outcome(terminal_outcome: ProxyTerminalOutcome) -> ProxyChannelOutcome:
    """Map proxy terminal truth to the manager's reuse/retirement contract."""

    if terminal_outcome in {"success", "cache_hit"}:
        return "success"
    if terminal_outcome == "denied":
        return "denied"
    if terminal_outcome == "authentication_required":
        return "authentication_required"
    return "gateway_failure"


def _aligned_reused_plan(
    plan: ProxyTransactionPlan,
    reuse: ExplicitProxyRequestReuse | ExplicitProxyTerminalRequest,
) -> ProxyTransactionPlan:
    """Align every reused phase to the manager's deterministic commit time."""

    delta = reuse.canonical_request_time - plan.request_at
    if not delta:
        return plan

    def shifted(value: datetime | None) -> datetime | None:
        return value + delta if value is not None else None

    return replace(
        plan,
        client_connect_at=plan.client_connect_at + delta,
        tunnel_request_at=shifted(plan.tunnel_request_at),
        request_at=plan.request_at + delta,
        decision_at=plan.decision_at + delta,
        dns_query_at=shifted(plan.dns_query_at),
        dns_response_at=shifted(plan.dns_response_at),
        origin_connect_at=shifted(plan.origin_connect_at),
        tls_complete_at=shifted(plan.tls_complete_at),
        origin_request_at=shifted(plan.origin_request_at),
        origin_response_at=shifted(plan.origin_response_at),
        origin_close_at=shifted(plan.origin_close_at),
        client_flush_at=plan.client_flush_at + delta,
        close_at=plan.close_at + delta,
    )


@dataclass(frozen=True, slots=True)
class ExplicitProxyRequestPreparation:
    """Immutable pre-boundary inputs for one deferred reused request."""

    affinity: ExplicitProxyChannelAffinity
    snapshot: ExplicitProxyRequestSnapshot
    stable_id: str
    parent_action_group_id: str | None
    proxy_hostname: str
    request_time: datetime
    proxy_context: ProxyContext
    request_wire_bytes: int
    response_wire_bytes: int
    upload_body_bytes: int
    scenario_end: datetime | None

    def __post_init__(self) -> None:
        """Normalize immutable times and validate directional request accounting."""

        if not self.stable_id.strip():
            raise ValueError("Explicit-proxy request preparation requires a stable_id")
        if (
            min(
                self.request_wire_bytes,
                self.response_wire_bytes,
                self.upload_body_bytes,
            )
            < 0
        ):
            raise ValueError("Explicit-proxy request preparation bytes must be non-negative")
        object.__setattr__(self, "request_time", ensure_utc(self.request_time))
        if self.scenario_end is not None:
            object.__setattr__(self, "scenario_end", ensure_utc(self.scenario_end))

    def prepare(
        self,
        *,
        manager: ExplicitProxyChannelManager,
        timing_runtime: SourceTimingPlanningRuntime,
    ) -> tuple[ExplicitProxyAdmissionToken, ProxyContext]:
        """Plan phases and reserve the exact request inside the active root boundary."""

        from evidenceforge.generation.actions.proxy_phase_planner import ProxyPhasePlanner

        if not manager.authenticates_request_snapshot(self.snapshot):
            raise StateError("Deferred proxy request has no authentic current-tunnel snapshot")
        plan = ProxyPhasePlanner(timing_runtime).plan_reused_intent(
            stable_id=self.stable_id,
            parent_action_group_id=self.parent_action_group_id,
            proxy_hostname=self.proxy_hostname,
            proxy=self.proxy_context,
            request_at=self.request_time,
        )
        if self.scenario_end is not None and plan.close_at > self.scenario_end:
            raise ProxyReuseUnavailableError("Deferred proxy request exceeds the generation window")
        token = manager.prepare_request(
            self.affinity,
            requested_at=plan.request_at,
            completed_at=plan.close_at,
            request_wire_bytes=self.request_wire_bytes,
            response_wire_bytes=self.response_wire_bytes,
            upload_body_bytes=self.upload_body_bytes,
            outcome=_proxy_manager_outcome(plan.terminal_outcome),
            expected_snapshot=self.snapshot,
        )
        if token is None:
            raise ProxyReuseUnavailableError(
                "Deferred proxy request no longer fits its exact tunnel"
            )
        if not manager.authenticates_admission_token(token):
            manager.cancel_prepared_admission(token)
            raise StateError("Deferred proxy request returned no authentic manager token")
        reuse = token.result
        if not isinstance(reuse, (ExplicitProxyRequestReuse, ExplicitProxyTerminalRequest)):
            manager.cancel_prepared_admission(token)
            raise StateError("Deferred proxy request returned an incompatible result")
        aligned = _aligned_reused_plan(plan, reuse)
        return token, replace(
            self.proxy_context,
            transaction=aligned,
            time_taken=aligned.time_taken_ms,
        )


class ProxyTransactionExecutor(Protocol):
    """Runtime hooks supplied by the current activity generator."""

    state_manager: StateManager
    dispatcher: Any
    timing_runtime: TimingRuntime
    _proxy_channel_manager: ExplicitProxyChannelManager
    _proxy_auth_policy: Any
    _scenario_end_time: datetime

    def _build_proxy_context(
        self,
        *,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        service: str | None,
        duration: float | None,
        orig_bytes: int | None,
        resp_bytes: int | None,
        hostname: str | None,
        source_system: System | None,
        proxy_sys: System,
        http: HttpContext | None,
        explicit_mode: bool = False,
    ) -> ProxyContext:
        """Build proxy context for a logical origin request."""
        ...

    def _proxy_fqdn(self, proxy_sys: System) -> str:
        """Return the FQDN used for proxy access logs."""
        ...

    def _caller_explicit_proxy_process_image(
        self,
        *,
        source_system: System | None,
        pid: int,
        process_image: str | None,
        time: datetime,
        proxy_context: ProxyContext,
        proxy_sys: System,
        dst_port: int,
        http: HttpContext | None = None,
    ) -> str | None:
        """Return a caller process image when valid proxy client telemetry owns it."""
        ...

    def _ensure_explicit_proxy_client_process(
        self,
        *,
        source_system: System | None,
        time: datetime,
        proxy_context: ProxyContext,
        proxy_sys: System,
        dst_port: int,
    ) -> tuple[int, str]:
        """Create or reuse a source-native proxy client process."""
        ...

    def _allocate_ephemeral_port(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str,
        time: datetime,
        os_category: str,
    ) -> int:
        """Allocate a source port for a connection tuple."""
        ...

    def _os_for_ip(self, ip: str) -> str:
        """Return an OS category for a source IP."""
        ...

    def _clamp_after_visible_process_create(
        self,
        source_system: System,
        pid: int,
        event_time: datetime,
        source_key: str,
    ) -> datetime:
        """Move an event after the visible process-create timestamp when needed."""
        ...

    def _emit_dns_lookup(
        self,
        src_ip: str,
        dst_ip: str,
        time: datetime,
        *,
        hostname: str | None = None,
        force_address: bool = False,
        bypass_cache: bool = False,
        planned_query_time: datetime | None = None,
        planned_rtt_seconds: float | None = None,
        parent_action_group_id: str | None = None,
    ) -> None:
        """Emit correlated DNS evidence."""
        ...

    def _email_dns_system_for_hostname(self, hostname: str | None) -> System | None:
        """Return the configured mail server system that owns an email DNS hostname."""
        ...

    def generate_connection(
        self,
        *,
        src_ip: str,
        dst_ip: str,
        time: datetime,
        dst_port: int = 443,
        proto: str = "tcp",
        service: str | None = None,
        duration: float | None = None,
        orig_bytes: int | None = None,
        resp_bytes: int | None = None,
        src_port: int | None = None,
        emit_dns: bool = False,
        pid: int = -1,
        source_system: System | None = None,
        conn_state: str | None = None,
        dns: DnsContext | None = None,
        ids_alerts: list[IdsAlertPlan] | None = None,
        http: HttpContext | None = None,
        file_transfer: FileTransferContext | None = None,
        pe: PeContext | None = None,
        ocsp: OcspContext | None = None,
        ocsp_transaction: OcspTransactionPlan | None = None,
        proxy: ProxyContext | None = None,
        firewall: FirewallContext | None = None,
        hostname: str | None = None,
        proxy_bypass: bool = False,
        suppress_direct_http_channel: bool = False,
        preserve_http_outcome: bool = False,
        process_image: str | None = None,
        parent_action_group_id: str | None = None,
        preserve_start_time: bool = False,
        identity_capture: NetworkConnectionIdentityCapture | None = None,
    ) -> str:
        """Generate a canonical connection event."""
        ...


@dataclass(frozen=True, slots=True)
class ProxyTransactionActionBundle:
    """Action bundle for one explicit forward-proxy transaction."""

    request: ProxyTransactionRequest
    executor: ProxyTransactionExecutor

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor for this proxy transaction."""

        return ActionAnchor(
            family="proxy_transaction",
            stable_id=self.request.stable_id,
            source=self.request.source,
        )

    def execute(self) -> str:
        """Expand and dispatch explicit proxy client and origin evidence."""

        # Import lazily to avoid a module-load cycle with ActivityGenerator.
        from evidenceforge.generation.activity import generator as generator_utils
        from evidenceforge.generation.activity.dns_registry import resolve_domain_ip

        request = self.request
        executor = self.executor
        proxy_sys = request.proxy_chain[0]
        listener_port = int(getattr(executor, "_proxy_listener_port", 8080))
        dst_ip = request.dst_ip
        src_port = request.src_port

        planned_request_count = max(
            1,
            int(request.http.flow_transaction_count or 1) if request.http is not None else 1,
        )
        request_local_orig_bytes = request.orig_bytes
        request_local_resp_bytes = request.resp_bytes
        planned_http_orig_bytes = request.orig_bytes
        planned_http_resp_bytes = request.resp_bytes
        if request.http is not None and planned_request_count > 1:
            planned_http_orig_bytes, planned_http_resp_bytes = (
                generator_utils._http_flow_payload_bytes(request.http)
            )
            request_local_http = replace(
                request.http,
                flow_request_body_len=request.http.request_body_len,
                flow_response_body_len=request.http.response_body_len,
                flow_transaction_count=1,
            )
            request_local_orig_bytes, request_local_resp_bytes = (
                generator_utils._http_flow_payload_bytes(request_local_http)
            )

        proxy_context = request.proxy or executor._build_proxy_context(
            src_ip=request.src_ip,
            dst_ip=dst_ip,
            dst_port=request.dst_port,
            service=request.service,
            duration=request.duration,
            orig_bytes=request_local_orig_bytes,
            resp_bytes=request_local_resp_bytes,
            hostname=request.hostname,
            source_system=request.source_system,
            proxy_sys=proxy_sys,
            http=request.http,
            explicit_mode=True,
            time=request.time,
        )
        if proxy_context.method == "CONNECT" and proxy_context.status_code >= 400:
            proxy_context = self._shape_failed_connect(proxy_context)
        proxy_context = self._finalize_proxy_byte_semantics(proxy_context)
        if (
            proxy_context.host
            and "." in proxy_context.host
            and not generator_utils._is_ip_literal(proxy_context.host)
            and not proxy_context.host.endswith(f".{request.ad_domain}")
            and not proxy_context.host.endswith(".local")
        ):
            email_dns_system = executor._email_dns_system_for_hostname(proxy_context.host)
            email_dns_ip = (
                str(getattr(email_dns_system, "ip", "") or "") if email_dns_system else ""
            )
            if email_dns_ip:
                dst_ip = email_dns_ip
            else:
                resolver = getattr(executor, "_network_resolver", None)
                if resolver is not None:
                    resolved = resolver.resolve_host(
                        proxy_context.host, src_host=proxy_sys.hostname
                    )
                    if resolved.source == "scenario_identity" and resolved.ip:
                        dst_ip = resolved.ip
                    elif not request.preserve_explicit_proxy_dst_ip:
                        dst_ip = resolved.ip or dst_ip
                elif not request.preserve_explicit_proxy_dst_ip:
                    dst_ip = resolve_domain_ip(proxy_context.host, src_host=proxy_sys.hostname)

        affinity = self._channel_affinity(
            proxy_context=proxy_context,
            proxy_sys=proxy_sys,
            listener_port=listener_port,
            origin_ip=dst_ip,
        )
        reuse_safe = (
            request.dst_port == 443
            and request.http is not None
            and request.http.trans_depth > 1
            and proxy_context.method != "CONNECT"
            and request.dns is None
            and not any(alert.origin == "built_in" for alert in request.ids_alerts)
            and request.firewall is None
            and request.proxy is None
        )
        if reuse_safe:
            reused = self._prepare_reused_tunnel(
                affinity=affinity,
                proxy_context=proxy_context,
            )
            if reused is not None:
                try:
                    return self._publish_reused_tunnel_proxy_request(
                        preparation=reused,
                        proxy_sys=proxy_sys,
                        listener_port=listener_port,
                    )
                except ProxyReuseUnavailableError:
                    pass

        client_pid, client_process_image = self._resolve_client_process(proxy_context, proxy_sys)
        suppress_client_pid_inference = request.suppress_source_pid_inference or (
            request.pid > 0 and client_pid <= 0
        )

        if src_port is None:
            src_port = executor._allocate_ephemeral_port(
                request.src_ip,
                proxy_sys.ip,
                listener_port,
                "tcp",
                request.time,
                executor._os_for_ip(request.src_ip),
            )

        client_time = request.time
        if client_pid > 0 and request.source_system is not None:
            process_visible_time = executor._clamp_after_visible_process_create(
                request.source_system,
                client_pid,
                client_time,
                "source.windows_wfp_connection",
            )
            session_end_plan = executor.state_manager.process_session_end_plan(
                request.source_system.hostname,
                client_pid,
            )
            if (
                session_end_plan is not None
                and session_end_plan.is_authoritative
                and process_visible_time >= session_end_plan.canonical_end
            ):
                client_pid = -1
                client_process_image = None
                suppress_client_pid_inference = True
            else:
                client_time = process_visible_time
        from evidenceforge.generation.actions.proxy_phase_planner import ProxyPhasePlanner

        phase_plan = ProxyPhasePlanner(getattr(executor, "timing_runtime", None)).plan(
            request,
            proxy_context,
            client_time,
        )
        proxy_context = replace(
            proxy_context,
            transaction=phase_plan,
            time_taken=phase_plan.time_taken_ms,
        )
        scenario_end = getattr(executor, "_scenario_end_time", None)
        request_localized_transport = False
        if (
            planned_request_count > 1
            and request.dst_port == 443
            and request.http is not None
            and proxy_context.method != "CONNECT"
            and phase_plan.terminal_outcome == "success"
            and (scenario_end is None or phase_plan.close_at <= ensure_utc(scenario_end))
            and not executor._proxy_channel_manager.has_future_reuse_headroom(
                opened_at=phase_plan.client_connect_at,
                closes_at=phase_plan.close_at,
                setup_completed_at=phase_plan.client_flush_at,
            )
        ):
            # The manager has ruled out reuse before the client transport owns
            # bytes. Keep this leg request-local so later physical legs cannot
            # repeat payload that was speculatively reserved here.
            planned_request_count = 1
            planned_http_orig_bytes = request_local_orig_bytes
            planned_http_resp_bytes = request_local_resp_bytes
            request_localized_transport = True
        client_http = self._build_client_http(proxy_context)
        child_cs_bytes = max(1, int(proxy_context.cs_bytes or 1))
        child_sc_bytes = max(0, int(proxy_context.sc_bytes or 0))
        client_orig_bytes = child_cs_bytes
        client_resp_bytes = child_sc_bytes
        if phase_plan.terminal_outcome == "success" and request.dst_port == 443:
            if proxy_context.method == "CONNECT":
                framing_rng = random.Random(
                    _stable_seed(
                        "proxy_client_tunnel_framing:"
                        f"{request.src_ip}:{proxy_sys.ip}:{proxy_context.host}:"
                        f"{request.time.timestamp()}:{proxy_context.method}"
                    )
                )
                client_orig_bytes += max(request.orig_bytes or 0, framing_rng.randint(180, 900))
                client_resp_bytes += max(request.resp_bytes or 0, framing_rng.randint(900, 4500))
            else:
                # Inspected HTTPS shares one client/proxy transport. Its ledger
                # reserves the browser group's aggregate payload while each
                # proxy row retains request-local byte semantics.
                aggregate_orig_bytes = max(0, int(planned_http_orig_bytes or 0))
                aggregate_resp_bytes = max(0, int(planned_http_resp_bytes or 0))
                future_orig_bytes = max(
                    0,
                    aggregate_orig_bytes - max(0, int(request_local_orig_bytes or 0)),
                )
                future_resp_bytes = max(
                    0,
                    aggregate_resp_bytes - max(0, int(request_local_resp_bytes or 0)),
                )
                remaining_count = planned_request_count - 1
                future_orig_bytes += remaining_count * generator_utils._PROXY_CS_OVERHEAD[1]
                future_resp_bytes += remaining_count * generator_utils._PROXY_SC_OVERHEAD[1]
                client_orig_bytes = (
                    phase_plan.tunnel_setup_cs_bytes + child_cs_bytes + future_orig_bytes
                )
                client_resp_bytes = (
                    phase_plan.tunnel_setup_sc_bytes + child_sc_bytes + future_resp_bytes
                )

        client_duration = phase_plan.client_duration_seconds
        egress_time = phase_plan.origin_connect_at
        egress_duration = phase_plan.origin_duration_seconds
        will_emit_origin_transaction = (
            phase_plan.terminal_outcome == "success" and egress_time is not None
        )
        egress_http = (
            self._build_egress_http(proxy_context, client_http)
            if will_emit_origin_transaction
            else None
        )
        if request_localized_transport and egress_http is not None:
            egress_http = replace(
                egress_http,
                flow_request_body_len=egress_http.request_body_len,
                flow_response_body_len=egress_http.response_body_len,
                flow_transaction_count=1,
            )
        if egress_http is not None:
            egress_http = replace(
                egress_http,
                canonical_request_time=phase_plan.origin_request_at,
            )
        client_file_transfers: tuple[FileTransferContext, ...] = ()
        client_pes: tuple[PeContext, ...] = ()
        egress_file_transfer = request.file_transfer
        egress_file_transfers: tuple[FileTransferContext, ...] = ()
        egress_pes: tuple[PeContext, ...] = ()
        if egress_http is not None and request.file_transfer is None and egress_time is not None:
            (
                client_http,
                egress_http,
                client_file_transfers,
                client_pes,
                egress_file_transfers,
                egress_pes,
                client_duration,
                egress_duration,
            ) = self._build_proxied_http_file_transfer_pair(
                client_http=client_http,
                egress_http=egress_http,
                client_time=client_time,
                egress_time=egress_time,
                client_duration=client_duration,
                egress_duration=egress_duration,
                client_dst_ip=proxy_sys.ip,
                egress_dst_ip=dst_ip,
                proxy_context=proxy_context,
            )

        client_identity = NetworkConnectionIdentityCapture()
        client_uid = executor.generate_connection(
            src_ip=request.src_ip,
            dst_ip=proxy_sys.ip,
            time=client_time,
            dst_port=listener_port,
            proto="tcp",
            service="http",
            duration=client_duration,
            orig_bytes=client_orig_bytes,
            resp_bytes=client_resp_bytes,
            src_port=src_port,
            emit_dns=False,
            pid=client_pid,
            source_system=request.source_system,
            conn_state=request.conn_state or "SF",
            ids_alerts=list(request.ids_alerts),
            http=client_http,
            file_transfers=client_file_transfers,
            pe_analyses=client_pes,
            proxy=proxy_context,
            hostname="",
            proxy_bypass=True,
            suppress_direct_http_channel=True,
            preserve_http_outcome=True,
            process_image=client_process_image,
            suppress_source_pid_inference=suppress_client_pid_inference,
            parent_action_group_id=self.anchor.stable_id,
            preserve_start_time=True,
            identity_capture=client_identity,
        )
        client_transaction = client_identity.require()
        client_root = client_identity.require_prepared_root()
        client_receipt = client_identity.require_receipt()
        client_transport_id = client_transaction.stable_id
        client_leg_file_transfers = client_root.result.file_transfers

        if egress_time is None or egress_duration is None:
            return client_uid

        egress_resp_bytes = request.resp_bytes
        if egress_http is not None:
            egress_resp_bytes = max(request.resp_bytes or 0, egress_http.response_body_len)
        if (
            request.dst_port == 443
            and request.http is not None
            and proxy_context.cache_result == "MISS"
        ):
            egress_resp_bytes = max(request.resp_bytes or 0, request.http.response_body_len)
        if phase_plan.dns_query_at is not None and proxy_context.host:
            executor._emit_dns_lookup(
                proxy_sys.ip,
                dst_ip,
                egress_time,
                hostname=proxy_context.host,
                force_address=True,
                bypass_cache=True,
                planned_query_time=phase_plan.dns_query_at,
                planned_rtt_seconds=phase_plan.dns_rtt_seconds,
                parent_action_group_id=self.anchor.stable_id,
            )

        explicit_proxy_open_preparation = None
        if (
            request.dst_port == 443
            and phase_plan.terminal_outcome == "success"
            and (scenario_end is None or phase_plan.close_at <= ensure_utc(scenario_end))
        ):
            explicit_proxy_open_preparation = ExplicitProxyOpenPreparation(
                affinity=affinity,
                client_root=client_root,
                client_receipt=client_receipt,
                phase_plan=phase_plan,
                proxy_context=proxy_context,
                tunnel_group_id=self.anchor.stable_id,
                planned_request_count=planned_request_count,
            )

        origin_identity = NetworkConnectionIdentityCapture()
        _origin_uid = NetworkConnectionActionBundle(
            executor,
            NetworkConnectionRequest(
                src_ip=proxy_sys.ip,
                dst_ip=dst_ip,
                time=egress_time,
                dst_port=request.dst_port,
                proto=request.proto,
                service=request.service,
                duration=egress_duration,
                orig_bytes=request.orig_bytes,
                resp_bytes=egress_resp_bytes,
                emit_dns=False,
                pid=-1,
                source_system=proxy_sys,
                conn_state=phase_plan.origin_conn_state,
                dns=request.dns,
                ids_alerts=request.ids_alerts,
                http=egress_http,
                file_transfer=egress_file_transfer,
                file_transfers=egress_file_transfers,
                pe_analyses=egress_pes,
                ocsp=request.ocsp,
                ocsp_transaction=request.ocsp_transaction,
                firewall=request.firewall,
                hostname=proxy_context.host,
                proxy_bypass=True,
                suppress_direct_http_channel=True,
                preserve_http_outcome=True,
                suppress_prereq_dns=True,
                parent_action_group_id=self.anchor.stable_id,
                preserve_start_time=True,
                identity_capture=origin_identity,
                explicit_proxy_open_preparation=explicit_proxy_open_preparation,
            ),
        ).execute()
        origin_transaction = origin_identity.require()
        origin_root = origin_identity.require_prepared_root()
        egress_leg_file_transfers = origin_root.result.file_transfers
        executor._last_connection_file_transfers = (
            client_leg_file_transfers + egress_leg_file_transfers
        )
        executor._last_connection_effective_dst_ip = origin_root.result.effective_dst_ip
        if explicit_proxy_open_preparation is not None:
            application_receipt = origin_identity.require_application_receipt()
            if (
                not isinstance(application_receipt, ExplicitProxyAdmissionReceipt)
                or not executor._proxy_channel_manager.authenticates_admission_receipt(
                    application_receipt
                )
                or application_receipt.current_transport_id != origin_transaction.stable_id
                or application_receipt.prerequisite_transport_ids != (client_transport_id,)
            ):
                raise AssertionError("Prepared proxy origin returned no authentic manager receipt")
        return client_uid

    def _channel_affinity(
        self,
        *,
        proxy_context: ProxyContext,
        proxy_sys: System,
        listener_port: int,
        origin_ip: str,
    ) -> ExplicitProxyChannelAffinity:
        """Return the exact semantic boundary for permitted tunnel reuse."""

        policy = getattr(self.executor, "_proxy_auth_policy", None)
        if policy is not None and hasattr(policy, "model_dump_json"):
            policy_shape = str(policy.model_dump_json(exclude_none=False))
        else:
            policy_shape = type(policy).__qualname__ if policy is not None else "default"
        policy_id = (
            f"{policy_shape}|action={proxy_context.proxy_action}|proxy={proxy_context.proxy_fqdn}"
        )
        return ExplicitProxyChannelAffinity(
            client_ip=self.request.src_ip,
            proxy_ip=proxy_sys.ip,
            proxy_port=listener_port,
            origin_host=proxy_context.host or origin_ip,
            origin_ip=origin_ip,
            origin_port=self.request.dst_port,
            user_agent=proxy_context.user_agent,
            auth_identity=proxy_context.username,
            policy_id=policy_id,
        )

    def _prepare_reused_tunnel(
        self,
        *,
        affinity: ExplicitProxyChannelAffinity,
        proxy_context: ProxyContext,
    ) -> ExplicitProxyRequestPreparation | None:
        """Capture immutable current-tunnel truth without timing or reservation mutation."""

        scenario_end = getattr(self.executor, "_scenario_end_time", None)
        if scenario_end is not None and ensure_utc(self.request.time) >= ensure_utc(scenario_end):
            return None
        snapshot = self.executor._proxy_channel_manager.snapshot_request(
            affinity,
            requested_at=self.request.time,
        )
        if snapshot is None:
            return None
        child_cs_bytes = max(0, int(proxy_context.cs_bytes or 0))
        child_sc_bytes = max(0, int(proxy_context.sc_bytes or 0))
        proxy_hostname = self.request.proxy_chain[0].hostname if self.request.proxy_chain else ""
        return ExplicitProxyRequestPreparation(
            affinity=affinity,
            snapshot=snapshot,
            stable_id=self.request.stable_id,
            parent_action_group_id=self.request.parent_action_group_id,
            proxy_hostname=proxy_hostname,
            request_time=self.request.time,
            proxy_context=proxy_context,
            request_wire_bytes=child_cs_bytes,
            response_wire_bytes=child_sc_bytes,
            upload_body_bytes=max(0, int(proxy_context.request_body_bytes or 0)),
            scenario_end=scenario_end,
        )

    def _publish_reused_tunnel_proxy_request(
        self,
        *,
        preparation: ExplicitProxyRequestPreparation,
        proxy_sys: System,
        listener_port: int,
    ) -> str:
        """Publish one proxy request as an authority-owned application child root."""

        request = self.request
        tunnel = preparation.snapshot.tunnel
        parent = self.executor.state_manager.get_connection_by_transaction_id(
            tunnel.client_transport_id
        )
        if parent is None:
            raise StateError("Deferred explicit-proxy request has no canonical client parent")
        capture = NetworkConnectionIdentityCapture()
        uid = NetworkConnectionActionBundle(
            self.executor,
            NetworkConnectionRequest(
                src_ip=parent.src_ip,
                dst_ip=parent.dst_ip,
                time=preparation.request_time,
                dst_port=parent.dst_port or listener_port,
                proto=parent.protocol,
                service="http",
                duration=max(0.000001, float(request.duration or 0.000001)),
                orig_bytes=preparation.request_wire_bytes,
                resp_bytes=preparation.response_wire_bytes,
                src_port=parent.src_port,
                pid=-1,
                source_system=request.source_system,
                conn_state="SF",
                proxy=preparation.proxy_context,
                hostname="",
                proxy_bypass=True,
                suppress_direct_http_channel=True,
                preserve_http_outcome=True,
                suppress_application_side_effects=True,
                suppress_source_pid_inference=True,
                preserve_explicit_payload=True,
                parent_action_group_id=tunnel.tunnel_group_id,
                preserve_start_time=True,
                identity_capture=capture,
                explicit_proxy_request_preparation=preparation,
            ),
        ).execute()
        application_receipt = capture.require_application_receipt()
        if (
            uid != tunnel.client_zeek_uid
            or not isinstance(application_receipt, ExplicitProxyAdmissionReceipt)
            or not self.executor._proxy_channel_manager.authenticates_admission_receipt(
                application_receipt
            )
            or application_receipt.current_transport_id != tunnel.client_transport_id
            or application_receipt.prerequisite_transport_ids
        ):
            raise AssertionError("Prepared proxy request returned no authentic manager receipt")
        return uid

    def _build_client_http(self, proxy_context: ProxyContext) -> HttpContext:
        """Build the client-to-proxy HTTP context."""

        request = self.request
        phase_plan = proxy_context.transaction
        request_time = (
            (phase_plan.tunnel_request_at or phase_plan.request_at)
            if phase_plan is not None
            else request.time
        )
        if request.dst_port == 443:
            tunnel_status_code = proxy_context.tunnel_status_code
            if tunnel_status_code is None:
                tunnel_status_code = proxy_context.status_code
            return HttpContext(
                method="CONNECT",
                host=proxy_context.host,
                uri=f"{proxy_context.host}:443",
                version="1.1",
                user_agent=proxy_context.user_agent,
                request_body_len=0,
                response_body_len=(
                    proxy_context.response_body_bytes if tunnel_status_code >= 400 else 0
                ),
                canonical_request_time=request_time,
                status_code=tunnel_status_code,
                status_msg=proxy_connect_status_message(
                    tunnel_status_code,
                    proxy_context.host,
                    proxy_context.user_agent,
                    request.time,
                ),
                tags=[],
                resp_mime_types=["text/html"]
                if tunnel_status_code >= 400 and proxy_context.response_body_bytes > 0
                else [],
            )

        if request.http is not None:
            from evidenceforge.generation.activity.http_content import (
                response_mime_types_for_status,
            )

            status_messages = {
                200: "OK",
                301: "Moved Permanently",
                302: "Found",
                304: "Not Modified",
                403: "Forbidden",
                407: "Proxy Authentication Required",
                500: "Internal Server Error",
                502: "Bad Gateway",
                503: "Service Unavailable",
                504: "Gateway Timeout",
            }
            response_body_len = proxy_context.response_body_bytes
            preserve_request_entity = (
                request.http.request_body_len == proxy_context.request_body_bytes
                or request.http.request_multipart is not None
            )
            request_body_len = (
                request.http.request_body_len
                if request.http.request_multipart is not None
                else proxy_context.request_body_bytes
            )
            preserve_response_entity = (
                request.http.status_code == proxy_context.status_code
                and request.http.response_body_len == response_body_len
                and proxy_context.cache_result not in {"DENIED", "ERROR"}
            )
            return HttpContext(
                method=request.http.method,
                host=proxy_context.host,
                uri=proxy_context.url,
                version=request.http.version,
                user_agent=request.http.user_agent,
                user_agent_known_absent=request.http.user_agent_known_absent,
                request_body_len=request_body_len,
                request_content_type=request.http.request_content_type,
                request_entity=(request.http.request_entity if preserve_request_entity else None),
                request_multipart=(
                    request.http.request_multipart if preserve_request_entity else None
                ),
                response_body_len=response_body_len,
                response_multipart=(
                    request.http.response_multipart if preserve_response_entity else None
                ),
                canonical_request_time=request_time,
                flow_request_body_len=request.http.flow_request_body_len,
                flow_response_body_len=request.http.flow_response_body_len,
                flow_transaction_count=request.http.flow_transaction_count,
                status_code=proxy_context.status_code,
                status_msg=status_messages.get(proxy_context.status_code, request.http.status_msg),
                referrer=request.http.referrer,
                trans_depth=request.http.trans_depth,
                tags=list(request.http.tags),
                resp_mime_types=response_mime_types_for_status(
                    proxy_context.status_code,
                    proxy_context.content_type
                    or (request.http.resp_mime_types[0] if request.http.resp_mime_types else ""),
                    response_body_len,
                    method=request.http.method,
                ),
            )

        return HttpContext(
            method=proxy_context.method,
            host=proxy_context.host,
            uri=proxy_context.url,
            version="1.1",
            user_agent=proxy_context.user_agent,
            request_body_len=proxy_context.request_body_bytes,
            response_body_len=proxy_context.response_body_bytes,
            canonical_request_time=request_time,
            status_code=proxy_context.status_code,
            status_msg="OK" if proxy_context.status_code == 200 else "Forbidden",
            referrer=proxy_context.referrer,
            tags=[],
            resp_mime_types=[proxy_context.content_type] if proxy_context.content_type else [],
        )

    def _shape_failed_connect(
        self,
        proxy_context: ProxyContext,
    ) -> ProxyContext:
        """Plan bounded wire/body accounting for a failed CONNECT request."""

        rng = random.Random(_stable_seed(f"proxy_failed_connect:{self.request.stable_id}"))
        host_len = len(proxy_context.host or "")
        cs_bytes = rng.randint(180 + host_len, 520 + host_len)
        sc_bytes = rng.randint(250, 2000)
        response_body_bytes = max(
            0,
            sc_bytes - rng.randint(120, min(320, sc_bytes)),
        )
        return replace(
            proxy_context,
            cs_bytes=cs_bytes,
            sc_bytes=sc_bytes,
            request_body_bytes=0,
            response_body_bytes=response_body_bytes,
            tunnel_status_code=proxy_context.status_code,
        )

    def _finalize_proxy_byte_semantics(self, proxy_context: ProxyContext) -> ProxyContext:
        """Separate HTTP entity bodies from proxy transfer totals once."""

        request = self.request
        method = proxy_context.method.upper()
        request_body = 0
        if method not in {"GET", "HEAD", "CONNECT", "OPTIONS"}:
            if request.http is not None:
                request_body = max(0, request.http.request_body_len)
            elif request.orig_bytes is not None:
                request_body = max(0, request.orig_bytes)

        if (
            method == "HEAD"
            or 100 <= proxy_context.status_code < 200
            or proxy_context.status_code in {204, 205, 304}
        ):
            response_body = 0
        elif method == "CONNECT" and proxy_context.status_code < 400:
            response_body = 0
        elif request.http is not None and request.http.status_code == proxy_context.status_code:
            response_body = max(0, request.http.response_body_len)
        elif proxy_context.status_code >= 400:
            overhead = min(
                proxy_context.sc_bytes,
                120
                + _stable_seed(
                    f"proxy_error_response_overhead:{request.stable_id}:{proxy_context.status_code}"
                )
                % 201,
            )
            response_body = max(0, proxy_context.sc_bytes - overhead)
        else:
            from evidenceforge.generation.activity import generator as generator_utils

            response_body = generator_utils._proxy_http_response_body_len(
                proxy_context,
                resp_bytes=request.resp_bytes,
                http=request.http,
            )

        request_overhead = 0 if request_body == 0 and proxy_context.cs_bytes > 0 else 80
        response_overhead = 0 if response_body == 0 and proxy_context.sc_bytes > 0 else 50
        return replace(
            proxy_context,
            request_body_bytes=request_body,
            response_body_bytes=response_body,
            cs_bytes=max(proxy_context.cs_bytes, request_body + request_overhead),
            sc_bytes=max(proxy_context.sc_bytes, response_body + response_overhead),
        )

    def _resolve_client_process(
        self,
        proxy_context: ProxyContext,
        proxy_sys: System,
    ) -> tuple[int, str | None]:
        """Resolve or materialize the client-side process that owns the proxy socket."""

        request = self.request
        executor = self.executor
        client_pid = request.pid
        client_process_image = request.process_image
        caller_process_image = executor._caller_explicit_proxy_process_image(
            source_system=request.source_system,
            pid=request.pid,
            process_image=request.process_image,
            time=request.time,
            proxy_context=proxy_context,
            proxy_sys=proxy_sys,
            dst_port=request.dst_port,
            http=request.http,
        )
        if caller_process_image is not None:
            client_process_image = caller_process_image
            if request.source_system is not None:
                executor.state_manager.update_process_activity_time(
                    request.source_system.hostname,
                    request.pid,
                    request.time,
                )
        else:
            client_pid = -1
            client_process_image = None
            if request.suppress_source_pid_inference:
                return client_pid, client_process_image
            owned_client_pid, owned_process_image = executor._ensure_explicit_proxy_client_process(
                source_system=request.source_system,
                time=request.time,
                proxy_context=proxy_context,
                proxy_sys=proxy_sys,
                dst_port=request.dst_port,
            )
            if owned_client_pid > 0:
                client_pid = owned_client_pid
                client_process_image = owned_process_image
        return client_pid, client_process_image

    def _build_proxied_http_file_transfer_pair(
        self,
        *,
        client_http: HttpContext,
        egress_http: HttpContext,
        client_time: datetime,
        egress_time: datetime,
        client_duration: float | None,
        egress_duration: float | None,
        client_dst_ip: str,
        egress_dst_ip: str,
        proxy_context: ProxyContext,
    ) -> tuple[
        HttpContext,
        HttpContext,
        tuple[FileTransferContext, ...],
        tuple[PeContext, ...],
        tuple[FileTransferContext, ...],
        tuple[PeContext, ...],
        float | None,
        float | None,
    ]:
        """Build paired file metadata for a proxied HTTP MISS response body."""

        from evidenceforge.generation.activity.http_content import http_response_has_entity_body

        if (
            not http_response_has_entity_body(
                egress_http.method,
                egress_http.status_code,
                egress_http.response_body_len,
            )
            or not http_response_has_entity_body(
                client_http.method,
                client_http.status_code,
                client_http.response_body_len,
            )
            or client_http.response_body_len != egress_http.response_body_len
        ):
            return (
                client_http,
                egress_http,
                (),
                (),
                (),
                (),
                client_duration,
                egress_duration,
            )

        request = self.request
        proxy_sys = request.proxy_chain[0]
        mime_type = (
            egress_http.resp_mime_types[0]
            if egress_http.resp_mime_types
            else egress_http.response_multipart.media_type
            if egress_http.response_multipart is not None
            else "application/octet-stream"
        )
        content_identity = (
            f"proxy-http-response:{egress_http.host}:{egress_http.uri}:"
            f"{egress_http.status_code}:{egress_http.response_body_len}:{mime_type}"
        )
        egress_result = HttpResponseFileTransferActionBundle(
            HttpResponseFileTransferRequest(
                host=egress_http.host,
                uri=egress_http.uri,
                dst_ip=egress_dst_ip,
                response_body_len=egress_http.response_body_len,
                response_mime_types=list(egress_http.resp_mime_types),
                timestamp=egress_time,
                multipart=egress_http.response_multipart,
                content_identity=content_identity,
                parent_duration=egress_duration,
                source="proxy_transaction",
            ),
            random.Random(
                _stable_seed(
                    "proxy_egress_file_transfer:"
                    f"{request.src_ip}:{proxy_sys.ip}:{egress_http.host}:{egress_http.uri}:"
                    f"{egress_http.response_body_len}:{egress_time.isoformat()}"
                )
            ),
            timing_runtime=self.executor.timing_runtime,
        ).execute()
        client_result = HttpResponseFileTransferActionBundle(
            HttpResponseFileTransferRequest(
                host=client_http.host,
                uri=client_http.uri,
                dst_ip=client_dst_ip,
                response_body_len=client_http.response_body_len,
                response_mime_types=list(client_http.resp_mime_types),
                timestamp=client_time,
                multipart=client_http.response_multipart,
                content_identity=content_identity,
                parent_duration=client_duration,
                source="proxy_transaction",
            ),
            random.Random(
                _stable_seed(
                    "proxy_client_file_transfer:"
                    f"{request.src_ip}:{proxy_sys.ip}:{client_http.host}:{client_http.uri}:"
                    f"{client_http.response_body_len}:{client_time.isoformat()}"
                )
            ),
            timing_runtime=self.executor.timing_runtime,
        ).execute()

        phase_plan = proxy_context.transaction
        client_response_anchor = (
            phase_plan.client_flush_at if phase_plan is not None else egress_time
        )
        client_not_before = client_response_anchor + timedelta(
            milliseconds=2
            + _stable_seed(
                "proxy_client_file_not_before:"
                f"{request.src_ip}:{proxy_sys.ip}:{client_http.host}:"
                f"{client_http.uri}:{client_time.isoformat()}"
            )
            % 29
        )
        client_file_transfers = tuple(
            replace(transfer, observation_not_before=client_not_before)
            for transfer in client_result.file_transfers
        )
        available_client_duration = (
            max(0.001, (phase_plan.close_at - client_not_before).total_seconds() - 0.002)
            if phase_plan is not None
            else client_duration
            or max((transfer.duration for transfer in client_file_transfers), default=0.001)
        )
        client_file_transfers = tuple(
            replace(
                transfer,
                duration=min(
                    max(
                        transfer.duration,
                        egress_result.file_transfers[index].duration
                        if index < len(egress_result.file_transfers)
                        else transfer.duration,
                    ),
                    available_client_duration,
                ),
            )
            for index, transfer in enumerate(client_file_transfers)
        )

        from evidenceforge.generation.activity.http_file_profiles import load_http_file_profiles

        max_files_resp = int(load_http_file_profiles()["multipart"]["max_files_resp"])
        client_referenced = client_file_transfers[:max_files_resp]
        egress_referenced = egress_result.file_transfers[:max_files_resp]

        client_http = replace(
            client_http,
            resp_fuids=tuple(transfer.fuid for transfer in client_referenced),
            resp_filenames=tuple(
                transfer.filename for transfer in client_referenced if transfer.filename
            ),
            resp_mime_types=tuple(
                transfer.mime_type for transfer in client_file_transfers if transfer.mime_type
            )[:max_files_resp],
        )
        egress_http = replace(
            egress_http,
            resp_fuids=tuple(transfer.fuid for transfer in egress_referenced),
            resp_filenames=tuple(
                transfer.filename for transfer in egress_referenced if transfer.filename
            ),
            resp_mime_types=tuple(
                transfer.mime_type
                for transfer in egress_result.file_transfers
                if transfer.mime_type
            )[:max_files_resp],
        )

        return (
            client_http,
            egress_http,
            client_file_transfers,
            client_result.pe_analyses,
            egress_result.file_transfers,
            egress_result.pe_analyses,
            client_duration,
            egress_duration,
        )

    def _build_egress_http(
        self,
        proxy_context: ProxyContext,
        client_http: HttpContext,
    ) -> HttpContext | None:
        """Build the proxy-to-origin HTTP context when the origin leg is HTTP."""

        from evidenceforge.generation.activity import generator as generator_utils

        request = self.request
        egress_http = (
            request.http
            if request.http is not None and proxy_context.cache_result in {"MISS", "REVALIDATED"}
            else None
        )
        if egress_http is not None:
            egress_http = replace(
                egress_http,
                user_agent=proxy_context.user_agent,
                referrer=proxy_context.referrer,
                request_body_len=proxy_context.request_body_bytes,
                response_body_len=proxy_context.response_body_bytes,
            )
        if (
            egress_http is not None
            or request.dst_port != 80
            or proxy_context.cache_result not in {"MISS", "REVALIDATED"}
        ):
            return egress_http

        status_messages = {
            200: "OK",
            301: "Moved Permanently",
            302: "Found",
            304: "Not Modified",
            403: "Forbidden",
            407: "Proxy Authentication Required",
            500: "Internal Server Error",
            502: "Bad Gateway",
            503: "Service Unavailable",
            504: "Gateway Timeout",
        }
        from evidenceforge.generation.activity.http_content import (
            response_mime_types_for_status,
        )

        response_body_len = proxy_context.response_body_bytes
        return HttpContext(
            method=proxy_context.method,
            host=proxy_context.host,
            uri=generator_utils._origin_form_uri_from_proxy_url(proxy_context.url),
            version="1.1",
            user_agent=proxy_context.user_agent,
            request_body_len=proxy_context.request_body_bytes,
            response_body_len=response_body_len,
            status_code=proxy_context.status_code,
            status_msg=status_messages.get(proxy_context.status_code, "OK"),
            referrer=proxy_context.referrer,
            trans_depth=client_http.trans_depth,
            tags=[],
            resp_mime_types=response_mime_types_for_status(
                proxy_context.status_code,
                proxy_context.content_type,
                response_body_len,
                method=proxy_context.method,
            ),
        )
