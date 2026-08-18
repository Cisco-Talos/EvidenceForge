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

import random
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from threading import Lock
from typing import TYPE_CHECKING, Literal, Protocol

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationTransportBinding,
)
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
from evidenceforge.events.identity import ProcessIdentity, SessionIdentity
from evidenceforge.events.lifecycle import LifecycleEntityRef, LifecycleHold, SessionEndPlan
from evidenceforge.events.network import NetworkTransactionPlan
from evidenceforge.events.rdp import (
    RdpLogicalSessionIdentity,
    RdpSessionAffinity,
    RdpSessionSnapshot,
    RdpTransportPlan,
)
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.network_identity import (
    _network_request_stable_id,
    _register_network_request_type,
)
from evidenceforge.generation.deferred_session_composition import (
    DeferredSessionApplicationToken,
    DeferredSessionCompositionCoordinator,
    DeferredSessionKind,
)
from evidenceforge.generation.deferred_session_preseal import (
    DeferredSessionBindingDisposition,
)
from evidenceforge.generation.rdp_sessions import (
    RdpReconnectStateManager,
    RdpSessionAdmissionToken,
)
from evidenceforge.generation.ssh_channels import (
    SshApplicationChannelManager,
    SshChannelAdmissionToken,
    SshChannelAffinity,
    SshOperationKind,
    SshProcessHold,
    SshSessionBinding,
    SshTransportPlan,
)
from evidenceforge.generation.state_manager import (
    ConnectionExistingSessionPatch,
    DeferredSessionStateAuthority,
    MaterializationBatchPlan,
    ProcessActivityPatch,
    SessionActivityPatch,
    StateManager,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System
from evidenceforge.utils.rng import _stable_seed, stable_uuid
from evidenceforge.utils.time import ensure_utc

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


@dataclass(frozen=True, slots=True)
class DeferredSessionStateIntent:
    """Allocation-free State session values supplied by the protocol owner."""

    username: str
    system: str
    source_ip: str
    source_port: int
    start_time: datetime
    lifecycle_group_id: str
    logon_id: str | None = None
    transport_pid: int | None = None
    logon_type: int = 10
    session_kind: str = "rdp"
    logon_guid_required: bool = True
    source_ready_time: datetime | None = None
    closure_owned_by_bundle: bool = False
    end_plan: SessionEndPlan | None = None
    linux_logind_seed: int | None = None
    linux_logind_event_time: datetime | None = None

    def __post_init__(self) -> None:
        """Normalize one exact positive remote-interactive session intent."""

        if not self.username.strip() or not self.system.strip() or not self.source_ip.strip():
            raise ValueError("Deferred State session intent requires complete identity")
        if not 1 <= self.source_port <= 65_535:
            raise ValueError("Deferred State session intent requires a valid source port")
        if self.logon_type != 10 or self.session_kind not in {"rdp", "ssh"}:
            raise ValueError("Deferred State intent requires a Type-10 RDP/SSH session")
        if not self.lifecycle_group_id.strip():
            raise ValueError("Deferred State session intent requires a lifecycle group")
        if type(self.closure_owned_by_bundle) is not bool:
            raise TypeError("Deferred State closure ownership requires an exact bool")
        if (self.linux_logind_seed is None) != (self.linux_logind_event_time is None):
            raise ValueError("Deferred Linux logind preparation requires seed and event time")
        if self.linux_logind_seed is not None and self.session_kind != "ssh":
            raise ValueError("Deferred Linux logind preparation requires SSH ownership")
        object.__setattr__(self, "start_time", ensure_utc(self.start_time))
        if self.source_ready_time is not None:
            object.__setattr__(
                self,
                "source_ready_time",
                ensure_utc(self.source_ready_time),
            )
        if self.linux_logind_event_time is not None:
            object.__setattr__(
                self,
                "linux_logind_event_time",
                ensure_utc(self.linux_logind_event_time),
            )

    def prepare(
        self,
        state_manager: StateManager,
        transaction: NetworkTransactionPlan,
    ) -> tuple[MaterializationBatchPlan, str, str]:
        """Prepare and seal one exact session batch at the current State fence."""

        if transaction.closed_at is None:
            raise StateError("Deferred session State preparation requires a closed transport")
        builder = state_manager.begin_materialization_batch()
        session = builder.plan_session(
            username=self.username,
            system=self.system,
            logon_type=self.logon_type,
            source_ip=self.source_ip,
            source_port=self.source_port,
            session_kind=self.session_kind,
            transport_pid=self.transport_pid,
            start_time=self.start_time,
            logon_id=self.logon_id,
            logon_guid_required=self.logon_guid_required,
            lifecycle_group_id=self.lifecycle_group_id,
            network_close_time=transaction.closed_at,
            source_ready_time=self.source_ready_time or self.start_time,
            closure_owned_by_bundle=self.closure_owned_by_bundle,
            end_plan=self.end_plan,
        )
        if self.linux_logind_seed is not None:
            assert self.linux_logind_event_time is not None
            session = builder.enrich_linux_logind_session(
                session,
                rng=random.Random(self.linux_logind_seed),
                event_time=self.linux_logind_event_time,
            )
        return builder.seal(), session.identity.object_id, session.identity.logon_id


@dataclass(frozen=True, slots=True)
class DeferredExistingSessionStateIntent:
    """Exact preallocated RDP session values awaiting the final network fence."""

    identity: SessionIdentity
    username: str
    system: str
    source_ip: str
    source_port: int
    transport_pid: int | None
    start_time: datetime
    lifecycle_group_id: str
    source_ready_time: datetime | None = None
    session_kind: str = "rdp"
    closure_owned_by_bundle: bool = False
    end_plan: SessionEndPlan | None = None

    def __post_init__(self) -> None:
        """Normalize the intended auth time and reject cross-owner input."""

        if type(self.identity) is not SessionIdentity:
            raise TypeError("Deferred existing-session intent requires an exact identity")
        if self.identity.hostname != self.system:
            raise ValueError("Deferred existing-session intent targets another host")
        if not self.username.strip() or not self.source_ip.strip():
            raise ValueError("Deferred existing-session intent requires principal and source")
        if not 1 <= self.source_port <= 65_535:
            raise ValueError("Deferred existing-session intent requires a valid source port")
        if self.transport_pid is not None and self.transport_pid <= 0:
            raise ValueError("Deferred existing-session transport PID must be positive")
        if not self.lifecycle_group_id.strip():
            raise ValueError("Deferred existing-session intent requires a lifecycle group")
        if self.session_kind not in {"rdp", "ssh"}:
            raise ValueError("Deferred existing-session intent requires RDP/SSH ownership")
        object.__setattr__(self, "start_time", ensure_utc(self.start_time))
        if self.source_ready_time is not None:
            object.__setattr__(
                self,
                "source_ready_time",
                ensure_utc(self.source_ready_time),
            )

    def prepare(
        self,
        state_manager: StateManager,
        transaction: NetworkTransactionPlan,
    ) -> ConnectionExistingSessionPatch:
        """Prepare the exact old-to-new State transition without mutation."""

        if transaction.closed_at is None:
            raise ValueError("Deferred existing-session transport requires a close time")
        return state_manager.prepare_connection_existing_session_start_patch(
            self.identity,
            username=self.username,
            target_system=self.system,
            start_time=self.start_time,
            source_ready_time=self.source_ready_time or self.start_time,
            source_ip=self.source_ip,
            source_port=self.source_port,
            transport_pid=self.transport_pid,
            lifecycle_group_id=self.lifecycle_group_id,
            network_close_time=transaction.closed_at,
            session_kind=self.session_kind,
            closure_owned_by_bundle=self.closure_owned_by_bundle,
            end_plan=self.end_plan,
        )


@dataclass(frozen=True, slots=True)
class DeferredLiveSessionStateIntent:
    """Exact already-published session metadata bound to a new transport."""

    identity: SessionIdentity
    source_ip: str
    source_port: int
    transport_pid: int | None
    source_ready_time: datetime | None
    end_plan: SessionEndPlan | None = None

    def __post_init__(self) -> None:
        """Reject unsupported session kinds and normalize readiness."""

        if type(self.identity) is not SessionIdentity:
            raise TypeError("Deferred live-session intent requires an exact identity")
        if self.identity.session_kind not in {"rdp", "ssh"}:
            raise ValueError("Deferred live-session intent requires an RDP or SSH session")
        if not self.source_ip.strip() or not 1 <= self.source_port <= 65_535:
            raise ValueError("Deferred live-session intent requires a valid source tuple")
        if self.transport_pid is not None and self.transport_pid <= 0:
            raise ValueError("Deferred live-session transport PID must be positive")
        if self.source_ready_time is not None:
            object.__setattr__(
                self,
                "source_ready_time",
                ensure_utc(self.source_ready_time),
            )
        if self.end_plan is not None:
            if type(self.end_plan) is not SessionEndPlan:
                raise TypeError("Deferred live-session end plan has an unsupported type")
            object.__setattr__(
                self,
                "end_plan",
                replace(
                    self.end_plan,
                    canonical_end=ensure_utc(self.end_plan.canonical_end),
                ),
            )

    def prepare(
        self,
        state_manager: StateManager,
        transaction: NetworkTransactionPlan,
    ) -> ConnectionExistingSessionPatch:
        """Prepare one exact metadata transition at the final State fence."""

        if transaction.closed_at is None:
            raise ValueError("Deferred live-session transport requires a close time")
        return state_manager.prepare_connection_live_session_patch(
            self.identity,
            source_ip=self.source_ip,
            source_port=self.source_port,
            transport_pid=self.transport_pid,
            source_ready_time=self.source_ready_time,
            network_close_time=transaction.closed_at,
            end_plan=self.end_plan,
        )


@dataclass(frozen=True, slots=True)
class DeferredSshApplicationIntent:
    """Typed SSH sidecar values resolved only after the network tuple is frozen."""

    manager: SshApplicationChannelManager = field(compare=False, repr=False)
    target_hostname: str
    principal: str
    client_identity: str
    client_session_object_id: str
    receiver_identity: ProcessIdentity
    receiver_state_session_identity: SessionIdentity
    source_identity: ProcessIdentity | None
    source_session_object_id: str
    ready_at: datetime
    auth_method: str
    operation_kind: SshOperationKind
    semantic_operation_id: str

    def __post_init__(self) -> None:
        """Normalize immutable preparation inputs and reject cross-owner values."""

        if type(self.manager) is not SshApplicationChannelManager:
            raise TypeError("Deferred SSH application intent requires its exact manager")
        if type(self.receiver_identity) is not ProcessIdentity:
            raise TypeError("Deferred SSH application intent requires a receiver identity")
        if type(self.receiver_state_session_identity) is not SessionIdentity:
            raise TypeError("Deferred SSH receiver requires its exact State session")
        if self.receiver_identity.logon_id != self.receiver_state_session_identity.logon_id:
            raise ValueError("Deferred SSH receiver State session disagrees with its process")
        if self.source_identity is not None and type(self.source_identity) is not ProcessIdentity:
            raise TypeError("Deferred SSH source identity has an unsupported exact type")
        if type(self.operation_kind) is not SshOperationKind:
            raise TypeError("Deferred SSH application intent requires an operation kind")
        if not all(
            value.strip()
            for value in (
                self.target_hostname,
                self.principal,
                self.client_identity,
                self.client_session_object_id,
                self.auth_method,
                self.semantic_operation_id,
            )
        ):
            raise ValueError("Deferred SSH application intent requires complete identity")
        if self.source_identity is None and self.source_session_object_id:
            raise ValueError("Deferred SSH external source cannot carry a State session")
        if self.source_identity is not None and not self.source_session_object_id:
            raise ValueError("Deferred SSH modeled source requires its State session")
        object.__setattr__(self, "ready_at", ensure_utc(self.ready_at))

    def prepare(
        self,
        session_identity: SessionIdentity,
        transaction: NetworkTransactionPlan,
    ) -> tuple[
        SshChannelAdmissionToken,
        tuple[ProcessActivityPatch, ...],
        tuple[SessionActivityPatch, ...],
        tuple[LifecycleHold, ...],
    ]:
        """Reserve the exact SSH/common admission without publishing either registry."""

        if transaction.closed_at is None:
            raise StateError("Deferred SSH application intent requires a closed transport")
        closes_at = transaction.closed_at
        if (
            session_identity.hostname != self.target_hostname
            or session_identity.principal != self.principal
            or session_identity.session_kind != "ssh"
        ):
            raise StateError("Deferred SSH application intent targets another State session")
        if not transaction.started_at <= self.ready_at < closes_at:
            raise StateError("Deferred SSH readiness falls outside its network transport")
        receiver = self.receiver_identity
        if receiver.hostname != self.target_hostname or receiver.started_at > self.ready_at:
            raise StateError("Deferred SSH receiver is incompatible with session readiness")

        receiver_hold = SshProcessHold(
            hostname=receiver.hostname,
            pid=receiver.pid,
            process_object_id=receiver.object_id,
            session_object_id=session_identity.object_id,
            principal=session_identity.principal,
            started_at=receiver.started_at,
            required_until=closes_at,
        )
        source_hold: SshProcessHold | None = None
        process_identities = [receiver]
        source = self.source_identity
        if source is not None:
            if source.started_at > transaction.started_at:
                raise StateError("Deferred SSH source process starts after TCP open")
            source_hold = SshProcessHold(
                hostname=source.hostname,
                pid=source.pid,
                process_object_id=source.object_id,
                session_object_id=self.source_session_object_id,
                principal=source.principal,
                started_at=source.started_at,
                required_until=closes_at,
            )
            process_identities.append(source)

        transport = SshTransportPlan(
            transport_id=transaction.stable_id,
            zeek_uid=transaction.zeek_uid,
            conn_id=transaction.conn_id,
            source_ip=transaction.src_ip,
            server_ip=transaction.dst_ip,
            source_port=transaction.src_port,
            server_port=transaction.dst_port,
            opened_at=transaction.started_at,
            closes_at=closes_at,
            source_process=source_hold,
            receiver_process=receiver_hold,
        )
        affinity = SshChannelAffinity(
            client_identity=self.client_identity,
            client_session_object_id=self.client_session_object_id,
            server_identity=self.target_hostname,
            server_session_object_id=session_identity.object_id,
            principal=session_identity.principal,
            auth_method=self.auth_method,
        )
        binding = SshSessionBinding(
            hostname=self.target_hostname,
            logon_id=session_identity.logon_id,
            session_object_id=session_identity.object_id,
            lifecycle_group_id=session_identity.lifecycle_group_id,
            principal=session_identity.principal,
            ready_at=self.ready_at,
        )
        token = self.manager.prepare_open_session_with_completed_operation(
            affinity,
            transport=transport,
            binding=binding,
            idle_timeout=closes_at - self.ready_at,
            initiator_budget=transaction.orig_bytes,
            responder_budget=transaction.resp_bytes,
            operation_budget=1,
            kind=self.operation_kind,
            semantic_operation_id=self.semantic_operation_id,
            started_at=self.ready_at,
            ended_at=closes_at,
            initiator_bytes=transaction.orig_bytes,
            responder_bytes=transaction.resp_bytes,
        )
        process_activity = tuple(
            ProcessActivityPatch(identity, closes_at) for identity in process_identities
        )
        session_activity = (SessionActivityPatch(self.receiver_state_session_identity, closes_at),)
        process_holds = tuple(
            LifecycleHold(
                hold_id=stable_uuid(
                    "deferred-ssh-process-hold",
                    transaction.stable_id,
                    identity.object_id,
                ),
                subject=LifecycleEntityRef("process", identity.object_id),
                acquired_at=transaction.started_at,
                hold_until=closes_at,
                action_id=stable_uuid(
                    "deferred-ssh-process-hold-action",
                    transaction.stable_id,
                    identity.object_id,
                ),
                reason="ssh_transport_close",
            )
            for identity in process_identities
        )
        return token, process_activity, session_activity, process_holds


@dataclass(frozen=True, slots=True)
class DeferredRdpApplicationIntent:
    """Typed RDP sidecar values resolved only after the network tuple is frozen."""

    manager: RdpReconnectStateManager = field(compare=False, repr=False)
    source_host: str
    target_host: str
    principal: str
    hard_deadline: datetime
    prior_session: RdpSessionSnapshot | None = field(default=None, compare=False, repr=False)
    expected_generation: int = 0
    max_logical_generations: int = 8

    def __post_init__(self) -> None:
        """Normalize immutable RDP preparation inputs and reject incomplete authority."""

        if type(self.manager) is not RdpReconnectStateManager:
            raise TypeError("Deferred RDP application intent requires its exact manager")
        if not all(value.strip() for value in (self.source_host, self.target_host, self.principal)):
            raise ValueError("Deferred RDP application intent requires complete affinity")
        object.__setattr__(self, "hard_deadline", ensure_utc(self.hard_deadline))
        if self.expected_generation < 0:
            raise ValueError("Deferred RDP generation must be non-negative")
        if self.max_logical_generations <= 0:
            raise ValueError("Deferred RDP logical generation budget must be positive")
        prior = self.prior_session
        if prior is None:
            if self.expected_generation != 0:
                raise ValueError("Deferred RDP open must create generation zero")
        else:
            if type(prior) is not RdpSessionSnapshot:
                raise TypeError("Deferred RDP reconnect requires an exact prior snapshot")
            if self.expected_generation != prior.generation.ordinal + 1:
                raise ValueError("Deferred RDP reconnect generation does not follow its snapshot")

    def prepare(
        self,
        session_identity: SessionIdentity,
        transaction: NetworkTransactionPlan,
    ) -> tuple[
        RdpSessionAdmissionToken,
        tuple[ProcessActivityPatch, ...],
        tuple[SessionActivityPatch, ...],
        tuple[LifecycleHold, ...],
    ]:
        """Reserve the exact RDP/common admission without publishing either registry."""

        if transaction.closed_at is None:
            raise StateError("Deferred RDP application intent requires a closed transport")
        if (
            session_identity.hostname.casefold().rstrip(".")
            != self.target_host.casefold().rstrip(".")
            or session_identity.principal.casefold() != self.principal.casefold()
            or session_identity.session_kind != "rdp"
        ):
            raise StateError("Deferred RDP application intent targets another State session")
        if self.hard_deadline <= transaction.closed_at:
            raise StateError("Deferred RDP transport must close before its logical deadline")

        channel_seed = _stable_seed(
            "rdp_transport_generation:"
            f"{session_identity.object_id}:{transaction.stable_id}:"
            f"{transaction.zeek_uid}:{self.expected_generation}"
        )
        transport_budget = ApplicationChannelBudget(
            initiator_bytes=transaction.orig_bytes,
            responder_bytes=transaction.resp_bytes,
            operations=1,
        )
        transport = RdpTransportPlan(
            channel_id=f"rdp-channel-{channel_seed:016x}",
            binding=ApplicationTransportBinding(
                transport_id=transaction.stable_id,
                opened_at=transaction.started_at,
                closes_at=transaction.closed_at,
            ),
            connected_at=transaction.started_at,
            budget=transport_budget,
        )
        prior = self.prior_session
        if prior is not None:
            affinity = prior.identity.affinity
            if (
                prior.identity.logical_session_id != session_identity.object_id
                or affinity.target_host != session_identity.hostname.casefold().rstrip(".")
                or affinity.principal != session_identity.principal.casefold()
                or affinity.logon_id != session_identity.logon_id.casefold()
                or affinity.session_id != session_identity.session_id
                or prior.identity.hard_deadline != self.hard_deadline
            ):
                raise StateError("Deferred RDP reconnect disagrees with its State identity")
            token = self.manager.prepare_reconnect(
                prior.identity.logical_session_id,
                affinity=affinity,
                transport=transport,
                expected_generation=self.expected_generation,
            )
        else:
            logical_span = self.hard_deadline - transaction.started_at
            identity = RdpLogicalSessionIdentity(
                logical_session_id=session_identity.object_id,
                affinity=RdpSessionAffinity(
                    source_host=self.source_host,
                    source_address=transaction.src_ip,
                    target_host=self.target_host,
                    target_address=transaction.dst_ip,
                    principal=self.principal,
                    logon_id=session_identity.logon_id,
                    session_id=session_identity.session_id,
                ),
                started_at=transaction.started_at,
                idle_timeout=transaction.closed_at - transaction.started_at,
                reconnect_timeout=logical_span,
                hard_deadline=self.hard_deadline,
                budget=ApplicationChannelBudget(
                    initiator_bytes=transaction.orig_bytes * self.max_logical_generations,
                    responder_bytes=transaction.resp_bytes * self.max_logical_generations,
                    operations=self.max_logical_generations,
                ),
            )
            token = self.manager.prepare_open_session(identity, transport)
        return token, (), (), ()


@dataclass(frozen=True, slots=True)
class DeferredSessionNetworkAuthority:
    """Exact session-owner handoff consumed with one deferred network root."""

    kind: DeferredSessionKind
    coordinator: DeferredSessionCompositionCoordinator = field(compare=False, repr=False)
    bound_at: datetime
    binding_disposition: DeferredSessionBindingDisposition | None = None
    strict_state_authority: DeferredSessionStateAuthority | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    session_object_id: str = ""
    state_intent: DeferredSessionStateIntent | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    state_batch: MaterializationBatchPlan | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    existing_state_intent: DeferredExistingSessionStateIntent | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    live_state_intent: DeferredLiveSessionStateIntent | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    existing_state_patch: ConnectionExistingSessionPatch | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    application_intent: DeferredSshApplicationIntent | DeferredRdpApplicationIntent | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    application_manager: SshApplicationChannelManager | RdpReconnectStateManager | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    application_token: DeferredSessionApplicationToken | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    application_process_activity: tuple[ProcessActivityPatch, ...] = field(
        default=(),
        compare=False,
        repr=False,
    )
    application_session_activity: tuple[SessionActivityPatch, ...] = field(
        default=(),
        compare=False,
        repr=False,
    )
    application_process_holds: tuple[LifecycleHold, ...] = field(
        default=(),
        compare=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        """Require one exact staged or already-live session authority."""

        if type(self.kind) is not DeferredSessionKind:
            raise TypeError("Deferred network authority requires an exact session kind")
        if type(self.coordinator) is not DeferredSessionCompositionCoordinator:
            raise TypeError("Deferred network authority requires its exact coordinator")
        if self.coordinator.kind is not self.kind:
            raise ValueError("Deferred network coordinator belongs to another protocol")
        session_object_id = self.session_object_id.strip()
        bound_at = ensure_utc(self.bound_at)
        strict_state_authority = self.strict_state_authority
        if strict_state_authority is not None:
            if type(strict_state_authority) is not DeferredSessionStateAuthority:
                raise TypeError("Deferred network strict State authority has an unsupported type")
            if self.binding_disposition is not strict_state_authority.binding_disposition:
                raise ValueError("Deferred network State disposition changed in transit")
            if self.kind.value != strict_state_authority.protocol.value:
                raise ValueError("Deferred network strict State authority belongs to another kind")
            if bound_at != strict_state_authority.bound_at:
                raise ValueError("Deferred network strict State binding time changed in transit")
            if any(
                value is not None
                for value in (
                    self.state_intent,
                    self.existing_state_intent,
                    self.live_state_intent,
                )
            ):
                raise ValueError("Strict deferred State authority cannot mix legacy State fields")
            if not strict_state_authority._owner.authenticates_deferred_session_state_authority(
                strict_state_authority
            ):
                raise ValueError("Deferred network strict State authority failed authentication")
            state_batch = strict_state_authority.batch
            existing_state_patch = strict_state_authority.existing_session_patch
            if self.state_batch is not None and self.state_batch is not state_batch:
                raise ValueError("Deferred network strict State batch was replaced")
            if self.existing_state_patch is not None and (
                self.existing_state_patch is not existing_state_patch
            ):
                raise ValueError("Deferred network strict State patch was replaced")
            session_plan = state_batch.session
            session_identity = (
                session_plan.identity
                if session_plan is not None
                else existing_state_patch.after.identity
                if existing_state_patch is not None
                else None
            )
            if session_identity is None:
                raise ValueError("Deferred network strict State authority has no target session")
            if session_object_id and session_object_id != session_identity.object_id:
                raise ValueError("Deferred network strict session identity was replaced")
            session_object_id = session_identity.object_id
            object.__setattr__(self, "state_batch", state_batch)
            object.__setattr__(self, "existing_state_patch", existing_state_patch)
        elif self.binding_disposition is not None:
            raise ValueError(
                "Legacy deferred State fields cannot claim an explicit binding disposition"
            )
        if self.state_intent is not None:
            if type(self.state_intent) is not DeferredSessionStateIntent:
                raise TypeError("Deferred network State intent has an unsupported type")
            if self.state_batch is not None or session_object_id:
                raise ValueError("Unresolved deferred State intent cannot carry a resolved batch")
            if self.state_intent.session_kind != self.kind.value:
                raise ValueError("Deferred State intent belongs to another protocol owner")
            if (self.state_intent.source_ready_time or self.state_intent.start_time) != bound_at:
                raise ValueError("Deferred network binding time differs from its session intent")
        if self.existing_state_intent is not None:
            if type(self.existing_state_intent) is not DeferredExistingSessionStateIntent:
                raise TypeError("Deferred existing-session intent has an unsupported type")
            if self.state_intent is not None or self.state_batch is not None or session_object_id:
                raise ValueError("Unresolved existing-session intent cannot carry another owner")
            if self.existing_state_patch is not None:
                raise ValueError("Unresolved existing-session intent cannot carry a State patch")
            if self.existing_state_intent.session_kind != self.kind.value:
                raise ValueError("Deferred existing intent belongs to another protocol owner")
            if (
                self.existing_state_intent.source_ready_time
                or self.existing_state_intent.start_time
            ) != bound_at:
                raise ValueError("Deferred network binding time differs from existing intent")
        if self.live_state_intent is not None:
            if type(self.live_state_intent) is not DeferredLiveSessionStateIntent:
                raise TypeError("Deferred live-session intent has an unsupported type")
            if (
                self.state_intent is not None
                or self.existing_state_intent is not None
                or self.state_batch is not None
                or self.existing_state_patch is not None
                or session_object_id
            ):
                raise ValueError("Unresolved live-session intent cannot carry another owner")
            if self.live_state_intent.source_ready_time != bound_at:
                raise ValueError("Deferred network binding time differs from live-session intent")
        if self.state_batch is not None:
            if type(self.state_batch) is not MaterializationBatchPlan:
                raise TypeError("Deferred network State authority must be an exact batch")
            session = self.state_batch.session
            if strict_state_authority is None:
                if session is None or session.identity.object_id != session_object_id:
                    raise ValueError("Deferred network State batch must own its named session")
            elif self.state_batch is not strict_state_authority.batch:
                raise ValueError("Deferred network strict State batch was replaced")
            elif session is not None and session.identity.object_id != session_object_id:
                raise ValueError("Deferred network strict State batch owns another session")
        if self.existing_state_patch is not None:
            if type(self.existing_state_patch) is not ConnectionExistingSessionPatch:
                raise TypeError("Deferred existing-session State patch has an unsupported type")
            if strict_state_authority is None and (
                self.state_batch is not None or self.state_intent is not None
            ):
                raise ValueError("Deferred existing-session patch cannot carry a new State batch")
            if strict_state_authority is not None and (
                self.existing_state_patch is not strict_state_authority.existing_session_patch
            ):
                raise ValueError("Deferred network strict State patch was replaced")
            if self.existing_state_intent is not None:
                raise ValueError("Resolved existing-session patch still carries its intent")
            if self.live_state_intent is not None:
                raise ValueError("Resolved existing-session patch still carries a live intent")
            if self.existing_state_patch.after.identity.object_id != session_object_id:
                raise ValueError("Deferred existing-session patch owns another session")
        if self.application_intent is not None:
            expected_intent_type = (
                DeferredSshApplicationIntent
                if self.kind is DeferredSessionKind.SSH
                else DeferredRdpApplicationIntent
            )
            if type(self.application_intent) is not expected_intent_type:
                raise TypeError("Deferred application intent belongs to another protocol owner")
            if self.application_manager is not None or self.application_token is not None:
                raise ValueError("Unresolved deferred application intent carries a result")
            if (
                self.application_process_activity
                or self.application_session_activity
                or self.application_process_holds
            ):
                raise ValueError("Unresolved deferred application intent carries State effects")
        if self.application_token is not None:
            expected_token_type = (
                SshChannelAdmissionToken
                if self.kind is DeferredSessionKind.SSH
                else RdpSessionAdmissionToken
            )
            expected_manager_type = (
                SshApplicationChannelManager
                if self.kind is DeferredSessionKind.SSH
                else RdpReconnectStateManager
            )
            if type(self.application_token) is not expected_token_type:
                raise TypeError("Deferred application token belongs to another owner")
            if type(self.application_manager) is not expected_manager_type:
                raise TypeError("Deferred application token requires its exact manager")
            if self.application_intent is not None:
                raise ValueError("Resolved deferred application token retains its intent")
            if not self.application_manager.authenticates_admission_token(self.application_token):
                raise ValueError("Deferred application token failed manager authentication")
        elif self.application_manager is not None:
            raise ValueError("Deferred application manager has no prepared token")
        if self.application_intent is None and self.application_token is None:
            raise ValueError(
                "Strict deferred SSH/RDP authority requires persistent manager admission"
            )
        for values, exact_type, label in (
            (self.application_process_activity, ProcessActivityPatch, "process activity"),
            (self.application_session_activity, SessionActivityPatch, "session activity"),
            (self.application_process_holds, LifecycleHold, "process hold"),
        ):
            if type(values) is not tuple or any(type(value) is not exact_type for value in values):
                raise TypeError(f"Deferred application {label} has an unsupported exact type")
        if (
            self.state_intent is None
            and self.existing_state_intent is None
            and self.live_state_intent is None
            and not session_object_id
        ):
            raise ValueError("Deferred network authority requires a staged or live session")
        object.__setattr__(self, "session_object_id", session_object_id)
        object.__setattr__(self, "bound_at", bound_at)

    @property
    def has_strict_state_authority(self) -> bool:
        """Return whether this handoff carries the new exact State authority payload."""

        return self.strict_state_authority is not None

    @property
    def strict_state_authority_bound(self) -> bool:
        """Return whether State bound the payload to this exact final wrapper."""

        payload = self.strict_state_authority
        return bool(payload is not None and payload._capability.outer_authority is self)

    def bind_strict_state_authority(self, state_manager: StateManager) -> None:
        """Bind a resolved strict payload to this exact outer network authority."""

        payload = self.strict_state_authority
        if payload is None:
            return
        if payload._owner is not state_manager:
            raise StateError("Deferred network strict State authority belongs to another owner")
        state_manager.bind_deferred_session_state_authority(payload, self)

    def prepare_state_authority(
        self,
        state_manager: StateManager,
        transaction: NetworkTransactionPlan,
    ) -> DeferredSessionNetworkAuthority:
        """Resolve the protocol intent against the final pre-network State fence."""

        strict = self.strict_state_authority
        if strict is not None:
            if strict._owner is not state_manager or (
                not state_manager.authenticates_deferred_session_state_authority(strict)
            ):
                raise StateError("Deferred strict State authority failed final authentication")
            return self

        intent = self.state_intent
        if intent is not None:
            state_batch, session_object_id, _logon_id = intent.prepare(
                state_manager,
                transaction,
            )
            return replace(
                self,
                session_object_id=session_object_id,
                state_intent=None,
                state_batch=state_batch,
            )
        existing_intent = self.existing_state_intent
        live_intent = self.live_state_intent
        if existing_intent is None and live_intent is None:
            raise StateError("Deferred session authority has no exact State expectation")
        selected_intent = existing_intent or live_intent
        assert selected_intent is not None
        patch = selected_intent.prepare(state_manager, transaction)
        return replace(
            self,
            session_object_id=patch.after.identity.object_id,
            existing_state_intent=None,
            live_state_intent=None,
            existing_state_patch=patch,
        )

    def prepare_application_authority(
        self,
        transaction: NetworkTransactionPlan,
    ) -> DeferredSessionNetworkAuthority:
        """Prepare one exact protocol sidecar against the resolved State identity."""

        intent = self.application_intent
        if intent is None:
            raise StateError("Deferred session authority has no persistent application owner")
        if self.application_token is not None or self.application_manager is not None:
            raise StateError("Deferred application authority is already resolved")
        session_plan = self.state_batch.session if self.state_batch is not None else None
        session_identity = (
            session_plan.identity
            if session_plan is not None
            else self.existing_state_patch.after.identity
            if self.existing_state_patch is not None
            else None
        )
        if session_identity is None:
            raise StateError("Deferred application authority has no exact State session")
        token, process_activity, session_activity, process_holds = intent.prepare(
            session_identity,
            transaction,
        )
        return replace(
            self,
            application_intent=None,
            application_manager=intent.manager,
            application_token=token,
            application_process_activity=process_activity,
            application_session_activity=session_activity,
            application_process_holds=process_holds,
        )


class NetworkConnectionPublicationOutcome(StrEnum):
    """Typed internal disposition of one committed canonical network root."""

    PUBLISHED = "published"
    COMMITTED_SUPPRESSED = "committed_suppressed"


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
    deferred_session_authority: DeferredSessionNetworkAuthority | None = field(
        default=None,
        compare=False,
        repr=False,
    )
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
        if self.deferred_session_authority is not None:
            if type(self.deferred_session_authority) is not DeferredSessionNetworkAuthority:
                raise TypeError("Network request deferred authority has an unsupported type")
            if self.transport_lifecycle_mode != "deferred_session":
                raise ValueError("Deferred session authority requires deferred_session mode")
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

        return _network_request_stable_id(self, NetworkConnectionRequest)


_register_network_request_type(NetworkConnectionRequest)


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
