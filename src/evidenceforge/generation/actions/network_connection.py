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

"""Network connection action bundle."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from threading import Lock
from typing import TYPE_CHECKING, Literal, Protocol

from evidenceforge.events.contexts import (
    DnsContext,
    EmailContext,
    FileTransferContext,
    FirewallContext,
    HttpContext,
    IdsAlertPlan,
    OcspContext,
    PeContext,
    ProxyContext,
    SmtpContext,
    SslContext,
    X509Context,
)
from evidenceforge.events.cryptography import (
    OcspTransactionPlan,
    TlsCertificatePresentationPlan,
)
from evidenceforge.events.network import NetworkTransactionPlan
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.models.scenario import System
from evidenceforge.utils.rng import _stable_seed

if TYPE_CHECKING:
    from evidenceforge.events.dispatcher import PreparedDispatch
    from evidenceforge.generation.actions.proxy_transaction import (
        ExplicitProxyOpenPreparation,
        ExplicitProxyRequestPreparation,
    )
    from evidenceforge.generation.lifecycle_authority import LifecyclePreparedNetworkReceipt
    from evidenceforge.generation.network_runtime import PreparedNetworkTransactionRoot
    from evidenceforge.generation.source_timing import SourceTimingPreparation

TransportLifecycleRequestMode = Literal["network", "deferred_session"]
TransportLifecyclePlanMode = Literal["network", "deferred_session", "application_child"]


class NetworkConnectionPublicationOutcome(StrEnum):
    """Typed internal disposition of one committed canonical network root."""

    PUBLISHED = "published"
    COMMITTED_SUPPRESSED = "committed_suppressed"


def _context_fingerprint(value: object) -> str:
    """Return a compact deterministic fingerprint for optional context objects."""

    if value is None:
        return ""
    if isinstance(value, list | tuple):
        return ";".join(_context_fingerprint(item) for item in value)
    parts = []
    for name in (
        "query",
        "query_type",
        "signature_id",
        "signature",
        "sid",
        "method",
        "host",
        "uri",
        "fuid",
        "url",
        "action",
        "rule_id",
    ):
        if hasattr(value, name):
            parts.append(f"{name}={getattr(value, name)}")
    return "|".join(parts) if parts else value.__class__.__name__


class _NetworkConnectionIdentityCaptureClaim:
    """Exact private one-shot capability for one empty identity capture."""

    __slots__ = ("_active", "_capture", "_nonce")

    def __init__(self, capture: NetworkConnectionIdentityCapture) -> None:
        self._capture = capture
        self._nonce = object()
        self._active = True


class NetworkConnectionIdentityCapture:
    """Occurrence-local handoff for one frozen transaction and lifecycle disposition."""

    __slots__ = (
        "_application_receipt",
        "_claim",
        "_lifecycle_mode",
        "_lock",
        "_outcome",
        "_prepared_dispatch",
        "_prepared_root",
        "_receipt",
        "_source_timing_preparation",
        "_transaction",
    )

    def __init__(self) -> None:
        self._transaction: NetworkTransactionPlan | None = None
        self._lifecycle_mode: TransportLifecyclePlanMode | None = None
        self._prepared_root: PreparedNetworkTransactionRoot | None = None
        self._source_timing_preparation: SourceTimingPreparation | None = None
        self._prepared_dispatch: PreparedDispatch | None = None
        self._receipt: LifecyclePreparedNetworkReceipt | None = None
        self._application_receipt: object | None = None
        self._outcome: NetworkConnectionPublicationOutcome | None = None
        self._claim: _NetworkConnectionIdentityCaptureClaim | None = None
        self._lock = Lock()

    @property
    def transaction(self) -> NetworkTransactionPlan | None:
        """Return the captured canonical transaction, if publication succeeded."""

        return self._transaction

    @property
    def lifecycle_mode(self) -> TransportLifecyclePlanMode | None:
        """Return the captured lifecycle disposition, if publication succeeded."""

        return self._lifecycle_mode

    @property
    def prepared_root(self) -> PreparedNetworkTransactionRoot | None:
        """Return the captured prepared root, if one was published."""

        return self._prepared_root

    @property
    def source_timing_preparation(self) -> SourceTimingPreparation | None:
        """Return the transferred deferred timing preparation, if any."""

        return self._source_timing_preparation

    @property
    def prepared_dispatch(self) -> PreparedDispatch | None:
        """Return the transferred deferred transport dispatch, if any."""

        return self._prepared_dispatch

    @property
    def receipt(self) -> LifecyclePreparedNetworkReceipt | None:
        """Return the full committed network receipt, if any."""

        return self._receipt

    @property
    def application_receipt(self) -> object | None:
        """Return the committed application-manager receipt, if any."""

        return self._application_receipt

    @property
    def outcome(self) -> NetworkConnectionPublicationOutcome | None:
        """Return the internal publication disposition, if any."""

        return self._outcome

    def _claim_empty(self) -> _NetworkConnectionIdentityCaptureClaim:
        """Claim this exact empty carrier before any prerequisite or planning effect."""

        if type(self) is not NetworkConnectionIdentityCapture:
            raise TypeError("Network identity capture must be the exact built-in carrier type")
        with self._lock:
            if self._claim is not None:
                raise ValueError("Network connection identity capture is already claimed")
            if self._transaction is not None:
                raise ValueError("Network connection identity capture was already published")
            claim = _NetworkConnectionIdentityCaptureClaim(self)
            self._claim = claim
            return claim

    def _authenticates_claim(self, claim: _NetworkConnectionIdentityCaptureClaim) -> bool:
        """Return whether this capture still owns the exact active private claim."""

        if type(claim) is not _NetworkConnectionIdentityCaptureClaim:
            return False
        with self._lock:
            return self._claim is claim and claim._capture is self and claim._active

    def _release_claim(self, claim: _NetworkConnectionIdentityCaptureClaim) -> None:
        """Release an uncommitted planner claim so the same empty carrier may retry."""

        with self._lock:
            if self._claim is claim and claim._capture is self:
                claim._active = False
                self._claim = None

    def _publish_claimed(
        self,
        claim: _NetworkConnectionIdentityCaptureClaim,
        transaction: NetworkTransactionPlan,
        *,
        lifecycle_mode: TransportLifecyclePlanMode,
    ) -> None:
        """Populate one prevalidated private claim as a no-fail final assignment."""

        with self._lock:
            assert self._claim is claim and claim._capture is self and claim._active
            self._transaction = transaction
            self._lifecycle_mode = lifecycle_mode
            claim._active = False
            self._claim = None

    def publish(
        self,
        transaction: NetworkTransactionPlan,
        *,
        lifecycle_mode: TransportLifecyclePlanMode = "network",
    ) -> None:
        """Publish exactly one frozen transaction before subordinate evidence runs."""

        if self.transaction is not None:
            raise ValueError("Network connection identity capture was already published")
        if lifecycle_mode not in {"network", "deferred_session", "application_child"}:
            raise ValueError(f"Unsupported transport lifecycle plan mode {lifecycle_mode!r}")
        claim = self._claim_empty()
        self._publish_claimed(claim, transaction, lifecycle_mode=lifecycle_mode)

    def _publish_committed_claimed(
        self,
        claim: _NetworkConnectionIdentityCaptureClaim,
        *,
        root: PreparedNetworkTransactionRoot,
        receipt: LifecyclePreparedNetworkReceipt,
        application_receipt: object | None = None,
        outcome: NetworkConnectionPublicationOutcome,
    ) -> None:
        """Publish one authenticated committed root and its internal disposition."""

        with self._lock:
            assert self._claim is claim and claim._capture is self and claim._active
            self._transaction = root.transaction
            self._lifecycle_mode = root.runtime_token.lifecycle_mode
            self._prepared_root = root
            self._receipt = receipt
            self._application_receipt = application_receipt
            self._outcome = outcome
            claim._active = False
            self._claim = None

    def _publish_deferred_claimed(
        self,
        claim: _NetworkConnectionIdentityCaptureClaim,
        *,
        root: PreparedNetworkTransactionRoot,
        source_timing_preparation: SourceTimingPreparation,
        prepared_dispatch: PreparedDispatch,
    ) -> None:
        """Transfer one uncommitted deferred-session root to its composite owner."""

        with self._lock:
            assert self._claim is claim and claim._capture is self and claim._active
            assert root.runtime_token.lifecycle_mode == "deferred_session"
            self._transaction = root.transaction
            self._lifecycle_mode = "deferred_session"
            self._prepared_root = root
            self._source_timing_preparation = source_timing_preparation
            self._prepared_dispatch = prepared_dispatch
            claim._active = False
            self._claim = None

    def require(self) -> NetworkTransactionPlan:
        """Return the captured transport or fail if the requested transport was omitted."""

        if self.transaction is None:
            raise ValueError("Network connection did not publish a physical transport identity")
        return self.transaction

    def require_lifecycle_mode(self) -> TransportLifecyclePlanMode:
        """Return the frozen effective lifecycle mode for the captured transaction."""

        if self.lifecycle_mode is None:
            raise ValueError("Network connection did not publish a transport lifecycle mode")
        return self.lifecycle_mode

    def require_prepared_root(self) -> PreparedNetworkTransactionRoot:
        """Return the exact prepared root retained for receipt authentication."""

        if self.prepared_root is None:
            raise ValueError("Network connection did not publish a prepared root")
        return self.prepared_root

    def require_receipt(self) -> LifecyclePreparedNetworkReceipt:
        """Return the full authenticated receipt after a committed publication."""

        if self.receipt is None:
            raise ValueError("Network connection did not publish a prepared receipt")
        return self.receipt

    def require_application_receipt(self) -> object:
        """Return the exact signed manager receipt committed with this root."""

        if self.application_receipt is None:
            raise ValueError("Network connection did not publish an application receipt")
        return self.application_receipt

    def require_outcome(self) -> NetworkConnectionPublicationOutcome:
        """Return the typed committed publication disposition."""

        if self.outcome is None:
            raise ValueError("Network connection did not publish an outcome")
        return self.outcome


@dataclass(frozen=True, slots=True)
class NetworkConnectionRequest:
    """Intent for one canonical network connection occurrence."""

    src_ip: str
    dst_ip: str
    time: datetime
    dst_port: int = 443
    proto: str = "tcp"
    service: str | None = None
    duration: float | None = None
    orig_bytes: int | None = None
    resp_bytes: int | None = None
    src_port: int | None = None
    emit_dns: bool = False
    pid: int = -1
    source_system: System | None = None
    conn_state: str | None = None
    dns: DnsContext | None = None
    email: EmailContext | None = None
    smtp: SmtpContext | None = None
    ssl: SslContext | None = None
    x509: X509Context | None = None
    x509_chain: tuple[X509Context, ...] = ()
    tls_presentation: TlsCertificatePresentationPlan | None = None
    ids_alerts: tuple[IdsAlertPlan, ...] = ()
    http: HttpContext | None = None
    file_transfer: FileTransferContext | None = None
    file_transfers: tuple[FileTransferContext, ...] = ()
    pe: PeContext | None = None
    pe_analyses: tuple[PeContext, ...] = ()
    ocsp: OcspContext | None = None
    ocsp_transaction: OcspTransactionPlan | None = None
    proxy: ProxyContext | None = None
    firewall: FirewallContext | None = None
    hostname: str | None = None
    proxy_bypass: bool = False
    suppress_direct_http_channel: bool = False
    process_image: str | None = None
    preserve_dst_ip: bool = False
    preserve_http_outcome: bool = False
    suppress_application_side_effects: bool = False
    suppress_source_pid_inference: bool = False
    preserve_explicit_payload: bool = False
    suppress_prereq_dns: bool = False
    packet_overhead_bytes: int | None = None
    responding_pid: int = -1
    ssh_attempted_username: str | None = None
    parent_action_group_id: str | None = None
    preserve_start_time: bool = False
    transport_lifecycle_mode: TransportLifecycleRequestMode = "network"
    identity_capture: NetworkConnectionIdentityCapture | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    prepared_application_token: object | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    explicit_proxy_open_preparation: ExplicitProxyOpenPreparation | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    explicit_proxy_request_preparation: ExplicitProxyRequestPreparation | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    source: str = "activity_generator"

    def __post_init__(self) -> None:
        """Validate occurrence-local lifecycle routing at the request boundary."""

        if self.transport_lifecycle_mode not in {"network", "deferred_session"}:
            raise ValueError(
                f"Unsupported transport lifecycle request mode {self.transport_lifecycle_mode!r}"
            )
        application_preparation_count = sum(
            value is not None
            for value in (
                self.prepared_application_token,
                self.explicit_proxy_open_preparation,
                self.explicit_proxy_request_preparation,
            )
        )
        if application_preparation_count > 1:
            raise ValueError("Network request cannot own two application preparations")
        if (
            self.explicit_proxy_open_preparation is not None
            or self.explicit_proxy_request_preparation is not None
        ) and not self.suppress_direct_http_channel:
            raise ValueError(
                "Explicit-proxy open preparation must suppress the direct HTTP channel"
            )

    def lifecycle_plan_mode(
        self,
        transaction: NetworkTransactionPlan,
    ) -> TransportLifecyclePlanMode:
        """Resolve physical, deferred-session, or application-child publication."""

        if transaction.application_layer_only:
            return "application_child"
        return self.transport_lifecycle_mode

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        source_hostname = self.source_system.hostname if self.source_system is not None else ""
        seed = _stable_seed(
            "action_bundle:network_connection:"
            f"{self.src_ip}:{self.dst_ip}:{self.time.isoformat()}:{self.dst_port}:"
            f"{self.proto}:{self.service or ''}:{self.duration or ''}:"
            f"{self.orig_bytes or ''}:{self.resp_bytes or ''}:{self.src_port or ''}:"
            f"{self.emit_dns}:{self.pid}:{source_hostname}:{self.conn_state or ''}:"
            f"{_context_fingerprint(self.dns)}:{_context_fingerprint(self.ssl)}:"
            f"{_context_fingerprint(self.ids_alerts)}:"
            f"{_context_fingerprint(self.http)}:{_context_fingerprint(self.file_transfer)}:"
            f"{_context_fingerprint(self.file_transfers)}:"
            f"{_context_fingerprint(self.pe)}:{_context_fingerprint(self.ocsp)}:"
            f"{_context_fingerprint(self.pe_analyses)}:"
            f"{_context_fingerprint(self.proxy)}:"
            f"{_context_fingerprint(self.firewall)}:{self.hostname or ''}:"
            f"{self.proxy_bypass}:{self.process_image or ''}:{self.preserve_dst_ip}:"
            f"{self.preserve_http_outcome}:{self.suppress_application_side_effects}:"
            f"{self.suppress_source_pid_inference}:{self.preserve_explicit_payload}:"
            f"{self.suppress_prereq_dns}:{self.packet_overhead_bytes or ''}:"
            f"{self.responding_pid}:{self.ssh_attempted_username or ''}:"
            f"{self.parent_action_group_id or ''}:{self.preserve_start_time}:{self.source}"
        )
        return f"network-connection-{seed:016x}"


class NetworkConnectionExecutor(Protocol):
    """Services supplied by the activity generator to network planning."""


class NetworkConnectionActionBundle:
    """Expand one network connection into cross-source connection evidence."""

    def __init__(
        self,
        executor: NetworkConnectionExecutor,
        request: NetworkConnectionRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="network_connection",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> str:
        """Emit network, source endpoint, proxy, DNS/TLS/HTTP, and firewall evidence."""

        from evidenceforge.generation.actions.network_transaction_planner import (
            NetworkTransactionPlanner,
        )

        return NetworkTransactionPlanner(self._executor).execute(self._request)
