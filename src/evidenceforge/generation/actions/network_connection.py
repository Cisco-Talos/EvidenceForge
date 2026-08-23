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
from datetime import datetime, timedelta
from enum import StrEnum
from math import isfinite
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
from evidenceforge.events.contracts import EventKind
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
from evidenceforge.generation.activity.timing_profiles import (
    SshAcceptedAuthenticationTiming,
    SshAuthenticationTimingPlan,
    plan_ssh_authentication_timing,
)
from evidenceforge.generation.deferred_session_composition import (
    DeferredSessionApplicationToken,
    DeferredSessionCompositionCoordinator,
    DeferredSessionKind,
)
from evidenceforge.generation.deferred_session_preseal import (
    DeferredSessionBindingDisposition,
    DeferredSessionDependentOccurrenceSpec,
)
from evidenceforge.generation.rdp_sessions import (
    RdpReconnectStateManager,
    RdpSessionAdmissionToken,
)
from evidenceforge.generation.source_timing import (
    SourceTimingPlanningRuntime,
    active_source_timing_planning_runtime,
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
from evidenceforge.generation.timing import TimingRuntime, TimingScope
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
    from evidenceforge.generation.network_observation import NetworkSensorObservation
    from evidenceforge.generation.network_runtime import PreparedNetworkTransactionRoot
    from evidenceforge.generation.source_timing import SourceTimingPreparation
    from evidenceforge.generation.state_manager import SmbConnectionPinInstallReceipt

TransportLifecycleRequestMode = Literal["network", "deferred_session"]
TransportLifecyclePlanMode = Literal["network", "deferred_session", "application_child"]


@dataclass(frozen=True, slots=True)
class PersistentSmbRootIntent:
    """State-owned Type-3 session values resolved against one TCP/445 root."""

    username: str
    system: str
    auth_time: datetime
    lifecycle_group_id: str
    auth_protocol: str
    smb_principal: str
    account_scope: str
    auth_session_ref: str
    effective_uid: int | None = None
    effective_gid: int | None = None

    def __post_init__(self) -> None:
        """Normalize the bounded immutable coordinator intent."""

        required = (
            self.username,
            self.system,
            self.lifecycle_group_id,
            self.auth_protocol,
            self.smb_principal,
            self.account_scope,
            self.auth_session_ref,
        )
        if any(type(value) is not str or not value.strip() for value in required):
            raise ValueError("Persistent SMB root intent requires complete exact identity")
        object.__setattr__(self, "auth_time", ensure_utc(self.auth_time))

    def prepare(
        self,
        state_manager: StateManager,
        transaction: NetworkTransactionPlan,
    ) -> MaterializationBatchPlan:
        """Prepare the sole Type-3 session admitted with the physical root."""

        if (
            transaction.protocol != "tcp"
            or transaction.dst_port != 445
            or transaction.service != "smb"
            or transaction.conn_state != "SF"
            or transaction.closed_at is None
        ):
            raise StateError("Persistent SMB root requires one successful closed TCP/445 plan")
        if not transaction.started_at <= self.auth_time < transaction.closed_at:
            raise StateError("Persistent SMB authentication must fall inside its transport")
        builder = state_manager.begin_materialization_batch()
        builder.plan_session(
            username=self.username,
            system=transaction.hostname,
            logon_type=3,
            source_ip=transaction.src_ip,
            source_port=transaction.src_port,
            session_kind="network",
            start_time=self.auth_time,
            logon_guid_required=True,
            lifecycle_group_id=self.lifecycle_group_id,
            auth_protocol=self.auth_protocol,
            smb_principal=self.smb_principal,
            account_scope=self.account_scope,
            auth_session_ref=self.auth_session_ref,
            effective_uid=self.effective_uid,
            effective_gid=self.effective_gid,
            network_close_time=transaction.closed_at,
            source_ready_time=self.auth_time,
            closure_owned_by_bundle=True,
            end_plan=SessionEndPlan(
                canonical_end=transaction.closed_at,
                authority="action_bundle",
            ),
        )
        return builder.seal()

    def identity_snapshot(self) -> tuple[object, ...]:
        """Return the exact scalar request identity carried through network planning."""

        return (
            self.username,
            self.system,
            self.auth_time,
            self.lifecycle_group_id,
            self.auth_protocol,
            self.smb_principal,
            self.account_scope,
            self.auth_session_ref,
            self.effective_uid,
            self.effective_gid,
        )

    @classmethod
    def from_identity_snapshot(cls, snapshot: object) -> PersistentSmbRootIntent:
        """Reconstruct one validated coordinator intent from its scalar identity."""

        if type(snapshot) is not tuple or len(snapshot) != 10:
            raise TypeError("Persistent SMB root snapshot requires ten exact scalar fields")
        (
            username,
            system,
            auth_time,
            lifecycle_group_id,
            auth_protocol,
            smb_principal,
            account_scope,
            auth_session_ref,
            effective_uid,
            effective_gid,
        ) = snapshot
        if type(auth_time) is not datetime:
            raise TypeError("Persistent SMB root snapshot requires an exact authentication time")
        for value, label in (
            (effective_uid, "effective UID"),
            (effective_gid, "effective GID"),
        ):
            if value is not None and type(value) is not int:
                raise TypeError(f"Persistent SMB root snapshot {label} has an invalid exact type")
        return cls(
            username=username,
            system=system,
            auth_time=auth_time,
            lifecycle_group_id=lifecycle_group_id,
            auth_protocol=auth_protocol,
            smb_principal=smb_principal,
            account_scope=account_scope,
            auth_session_ref=auth_session_ref,
            effective_uid=effective_uid,
            effective_gid=effective_gid,
        )


@dataclass(frozen=True, slots=True)
class PersistentSmbRootHandoff:
    """Exact retained owners needed to continue one committed SMB root."""

    prepared_dispatch: PreparedDispatch = field(compare=False, repr=False)
    observations: tuple[NetworkSensorObservation, ...]
    pin_install_receipt: SmbConnectionPinInstallReceipt


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
class DeferredSshTimingIntent:
    """Replay one previewed SSH authentication plan inside exact SourceTiming ownership."""

    auth_method: str
    public_key_type: str
    route_class: str
    scope: TimingScope
    expected_plan: SshAuthenticationTimingPlan
    transport_open_time: datetime
    ready_at: datetime
    receiver_bootstrap_headroom: timedelta = timedelta(seconds=2)

    def __post_init__(self) -> None:
        """Require bounded inert inputs and an internally consistent ready time."""

        if type(self.auth_method) is not str or not self.auth_method.strip():
            raise TypeError("Deferred SSH timing auth method requires an exact non-empty string")
        if len(self.auth_method) > 64:
            raise ValueError("Deferred SSH timing auth method exceeds its bounded length")
        if type(self.public_key_type) is not str:
            raise TypeError("Deferred SSH timing key type requires an exact string")
        if len(self.public_key_type) > 64:
            raise ValueError("Deferred SSH timing key type exceeds its bounded length")
        if type(self.route_class) is not str or self.route_class not in {"private", "public"}:
            raise ValueError("Deferred SSH timing route class must be private or public")
        if type(self.scope) is not TimingScope:
            raise TypeError("Deferred SSH timing scope requires its exact inert type")
        replace(self.scope)
        scope_strings = (
            self.scope.stable_id,
            self.scope.host,
            self.scope.source,
            self.scope.lifecycle_id,
        )
        if any(type(value) is not str or len(value) > 4_096 for value in scope_strings):
            raise ValueError("Deferred SSH timing scope contains malformed or oversized identity")
        if type(self.scope.ordinal) is not int or not 0 <= self.scope.ordinal <= 1_000_000:
            raise ValueError("Deferred SSH timing scope ordinal exceeds its bounded range")
        if type(self.expected_plan) is not SshAuthenticationTimingPlan or (
            type(self.expected_plan.accepted) is not SshAcceptedAuthenticationTiming
        ):
            raise TypeError("Deferred SSH timing preview has an unsupported exact type")
        numeric_values = (
            self.expected_plan.connection_gap_ms,
            self.expected_plan.accepted.phase_ms,
            self.expected_plan.accepted.cache_delay_ms,
            self.expected_plan.accepted.route_delay_ms,
            self.expected_plan.accepted.receiver_delay_ms,
            self.expected_plan.accepted.key_penalty_ms,
            self.expected_plan.pam_gap_ms,
            self.expected_plan.logind_gap_ms,
        )
        if any(
            type(value) is not float or not isfinite(value) or value < 0 for value in numeric_values
        ):
            raise ValueError("Deferred SSH timing preview contains an invalid numeric component")
        open_time = ensure_utc(self.transport_open_time)
        ready_at = ensure_utc(self.ready_at)
        receiver_bootstrap_headroom = self.receiver_bootstrap_headroom
        if type(
            receiver_bootstrap_headroom
        ) is not timedelta or receiver_bootstrap_headroom < timedelta(seconds=2):
            raise ValueError("Deferred SSH timing receiver bootstrap must be at least two seconds")
        accepted_at = (
            open_time
            + receiver_bootstrap_headroom
            + timedelta(milliseconds=max(1.0, self.expected_plan.connection_gap_ms))
            + timedelta(milliseconds=max(250.0, self.expected_plan.accepted_gap_ms))
        )
        pam_at = accepted_at + timedelta(milliseconds=max(1.0, self.expected_plan.pam_gap_ms))
        expected_ready = pam_at + timedelta(milliseconds=max(1.0, self.expected_plan.logind_gap_ms))
        if ready_at != expected_ready:
            raise ValueError("Deferred SSH timing preview changed its authentication ready time")
        object.__setattr__(self, "auth_method", self.auth_method.strip())
        object.__setattr__(self, "public_key_type", self.public_key_type.strip())
        object.__setattr__(self, "transport_open_time", open_time)
        object.__setattr__(self, "ready_at", ready_at)
        object.__setattr__(self, "receiver_bootstrap_headroom", receiver_bootstrap_headroom)

    def replay(
        self,
        runtime: SourceTimingPlanningRuntime,
        *,
        bound_at: datetime,
    ) -> None:
        """Stage the exact previewed audit draws or reject before canonical transfer."""

        # Reconstructing the frozen value catches ``object.__setattr__`` mutation
        # before its fields can influence the shared timing preparation.
        replace(self)
        if type(runtime) is not SourceTimingPlanningRuntime:
            raise TypeError("Deferred SSH timing replay requires exact SourceTiming ownership")
        if self.ready_at != ensure_utc(bound_at):
            raise StateError("Deferred SSH timing replay changed its State binding time")
        replayed = plan_ssh_authentication_timing(
            self.auth_method,
            public_key_type=self.public_key_type,
            route_class=self.route_class,
            timing_runtime=runtime,
            scope=self.scope,
        )
        if type(replayed) is not SshAuthenticationTimingPlan or replayed != self.expected_plan:
            raise StateError("Deferred SSH timing replay disagrees with its previewed plan")


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
    source_state_session_identity: SessionIdentity | None
    ready_at: datetime
    auth_method: str
    operation_kind: SshOperationKind
    semantic_operation_id: str
    allow_omitted_transport_actor: bool = False

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
        if type(self.allow_omitted_transport_actor) is not bool:
            raise TypeError("Deferred SSH transport-actor policy changed exact type")
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
        if (self.source_identity is None) != (self.source_state_session_identity is None):
            raise ValueError(
                "Deferred SSH source process and State session must be supplied together"
            )
        if self.source_state_session_identity is not None:
            source_session = self.source_state_session_identity
            source = self.source_identity
            assert source is not None
            if (
                type(source_session) is not SessionIdentity
                or source_session.object_id != self.source_session_object_id
                or source_session.logon_id != source.logon_id
                or source_session.hostname != source.hostname
            ):
                raise ValueError("Deferred SSH source process changed its State session identity")
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
            source_is_transport_actor = transaction.initiating_pid == source.pid
            if not source_is_transport_actor and not (
                self.allow_omitted_transport_actor and transaction.initiating_pid <= 0
            ):
                raise StateError("Deferred SSH transport changed its exact source process owner")
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
        session_activity = (
            SessionActivityPatch(self.receiver_state_session_identity, closes_at),
            *(
                (SessionActivityPatch(self.source_state_session_identity, closes_at),)
                if self.source_state_session_identity is not None
                else ()
            ),
        )
        process_holds = tuple(
            LifecycleHold(
                hold_id=stable_uuid(
                    "deferred-ssh-process-hold",
                    transaction.stable_id,
                    identity.object_id,
                ),
                subject=LifecycleEntityRef("process", identity.object_id),
                acquired_at=identity.started_at,
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
    user_sid: str = "S-1-0-0"
    elevated: bool = False
    privilege_list: str = ""
    allow_omitted_transport_actor: bool = False
    source_identity: ProcessIdentity | None = field(default=None, compare=False, repr=False)
    source_session_identity: SessionIdentity | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    prior_session: RdpSessionSnapshot | None = field(default=None, compare=False, repr=False)
    expected_generation: int = 0
    max_logical_generations: int = 8

    def __post_init__(self) -> None:
        """Normalize immutable RDP preparation inputs and reject incomplete authority."""

        if type(self.manager) is not RdpReconnectStateManager:
            raise TypeError("Deferred RDP application intent requires its exact manager")
        if not all(value.strip() for value in (self.source_host, self.target_host, self.principal)):
            raise ValueError("Deferred RDP application intent requires complete affinity")
        if type(self.user_sid) is not str or not self.user_sid.startswith("S-"):
            raise ValueError("Deferred RDP application intent requires a Windows SID")
        if type(self.elevated) is not bool or type(self.privilege_list) is not str:
            raise TypeError("Deferred RDP privilege facts changed exact type")
        if type(self.allow_omitted_transport_actor) is not bool:
            raise TypeError("Deferred RDP transport-actor policy changed exact type")
        if self.elevated != bool(self.privilege_list):
            raise ValueError("Deferred RDP elevated sessions require an exact privilege list")
        object.__setattr__(self, "hard_deadline", ensure_utc(self.hard_deadline))
        if self.expected_generation < 0:
            raise ValueError("Deferred RDP generation must be non-negative")
        if self.max_logical_generations <= 0:
            raise ValueError("Deferred RDP logical generation budget must be positive")
        source_identity = self.source_identity
        source_session = self.source_session_identity
        if (source_identity is None) != (source_session is None):
            raise ValueError("Deferred RDP source process and session must be supplied together")
        if source_identity is not None:
            if (
                type(source_identity) is not ProcessIdentity
                or type(source_session) is not SessionIdentity
            ):
                raise TypeError("Deferred RDP source ownership requires exact State identities")
            assert source_session is not None
            executable = source_identity.image.replace("/", "\\").rsplit("\\", 1)[-1]
            if (
                executable.casefold() != "mstsc.exe"
                or source_identity.hostname.casefold().rstrip(".")
                != self.source_host.casefold().rstrip(".")
                or source_identity.logon_id != source_session.logon_id
                or source_identity.hostname != source_session.hostname
            ):
                raise ValueError(
                    "Deferred RDP source ownership requires exact mstsc/session affinity"
                )
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
        source_identity = self.source_identity
        source_session = self.source_session_identity
        if source_identity is not None and (
            source_session is None
            or transaction.initiating_pid != source_identity.pid
            and not (self.allow_omitted_transport_actor and transaction.initiating_pid <= 0)
        ):
            raise StateError("Deferred RDP transport changed its exact source process owner")

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
        if source_identity is None or source_session is None:
            return token, (), (), ()
        process_activity = (ProcessActivityPatch(source_identity, transaction.closed_at),)
        session_activity = (SessionActivityPatch(source_session, transaction.closed_at),)
        process_holds = (
            LifecycleHold(
                hold_id=stable_uuid(
                    "deferred-rdp-process-hold",
                    transaction.stable_id,
                    source_identity.object_id,
                ),
                subject=LifecycleEntityRef("process", source_identity.object_id),
                acquired_at=source_identity.started_at,
                hold_until=transaction.closed_at,
                action_id=stable_uuid(
                    "deferred-rdp-process-hold-action",
                    transaction.stable_id,
                    source_identity.object_id,
                ),
                reason="rdp_transport_close",
            ),
        )
        return token, process_activity, session_activity, process_holds


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
    dependent_occurrences: tuple[DeferredSessionDependentOccurrenceSpec, ...] = field(
        default=(),
        compare=False,
        repr=False,
    )
    ssh_timing_intent: DeferredSshTimingIntent | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    ssh_timing_runtime: TimingRuntime | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    ssh_timing_replayed: bool = False

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
        if type(self.ssh_timing_replayed) is not bool:
            raise TypeError("Deferred SSH timing replay marker requires an exact boolean")
        if self.ssh_timing_intent is not None:
            if type(self.ssh_timing_intent) is not DeferredSshTimingIntent:
                raise TypeError("Deferred SSH timing intent has an unsupported exact type")
            if type(self.ssh_timing_runtime) is not TimingRuntime:
                raise TypeError("Deferred SSH timing intent requires its exact runtime owner")
            replace(self.ssh_timing_intent)
            if self.kind is not DeferredSessionKind.SSH or not self.dependent_occurrences:
                raise ValueError("Deferred SSH timing intent requires the exact SSH source cohort")
            if self.ssh_timing_replayed:
                raise ValueError("Deferred SSH timing intent cannot already be marked replayed")
            if self.ssh_timing_intent.ready_at != bound_at:
                raise ValueError("Deferred SSH timing intent changed the State binding time")
            session_plan = self.state_batch.session if self.state_batch is not None else None
            application_intent = self.application_intent
            if session_plan is None or type(application_intent) is not DeferredSshApplicationIntent:
                raise ValueError("Deferred SSH timing intent lost its State/application cohort")
            scope = self.ssh_timing_intent.scope
            if (
                scope.stable_id != session_plan.identity.lifecycle_group_id
                or scope.lifecycle_id != session_plan.identity.lifecycle_group_id
                or scope.host != session_plan.identity.hostname
                or scope.source != "ssh"
            ):
                raise ValueError("Deferred SSH timing scope changed its State identity")
            timing_auth_method = self.ssh_timing_intent.auth_method.casefold().replace("_", "-")
            timing_auth_method = {
                "keyboardinteractive": "keyboard-interactive",
                "gssapi": "gssapi-with-mic",
            }.get(timing_auth_method, timing_auth_method)
            if timing_auth_method != application_intent.auth_method:
                raise ValueError("Deferred SSH timing changed its application auth method")
            receiver_plan = self.state_batch.processes[0]
            if receiver_plan.identity.started_at != (
                self.ssh_timing_intent.transport_open_time
                + self.ssh_timing_intent.receiver_bootstrap_headroom
            ):
                raise ValueError("Deferred SSH timing changed its receiver process boundary")
        elif self.ssh_timing_runtime is not None:
            raise ValueError("Deferred SSH timing runtime cannot outlive its replay intent")
        elif (
            self.dependent_occurrences
            and self.kind is DeferredSessionKind.SSH
            and not (self.ssh_timing_replayed)
        ):
            raise ValueError("Deferred SSH source cohort requires exact timing replay authority")
        self.validate_dependent_occurrences()
        if (
            self.state_intent is None
            and self.existing_state_intent is None
            and self.live_state_intent is None
            and not session_object_id
        ):
            raise ValueError("Deferred network authority requires a staged or live session")
        object.__setattr__(self, "session_object_id", session_object_id)
        object.__setattr__(self, "bound_at", bound_at)

    def validate_dependent_occurrences(
        self,
    ) -> tuple[DeferredSessionDependentOccurrenceSpec, ...]:
        """Revalidate exact SSH source-start specifications immediately before use."""

        specs = self.dependent_occurrences
        if type(specs) is not tuple or any(
            type(spec) is not DeferredSessionDependentOccurrenceSpec for spec in specs
        ):
            raise TypeError(
                "Deferred session dependent occurrences require exact inert specifications"
            )
        if not specs:
            return ()
        if self.kind is DeferredSessionKind.RDP:
            return self._validate_rdp_dependent_occurrences(specs)
        if self.kind is not DeferredSessionKind.SSH:
            raise ValueError("Deferred dependent occurrence migration is currently scoped to SSH")
        if type(self.bound_at) is not datetime:
            raise TypeError("Deferred SSH dependent authority changed its binding-time type")
        if self.strict_state_authority is None or self.state_batch is None:
            raise ValueError("Deferred SSH dependent occurrences require strict State authority")
        state_members = (
            *((self.state_batch.session,) if self.state_batch.session is not None else ()),
            *self.state_batch.processes,
        )
        if self.state_batch.session is None or len(self.state_batch.processes) != 1:
            raise ValueError("Deferred SSH source cohort requires one session and one sshd process")
        if len(specs) != len(state_members):
            raise ValueError("Deferred SSH dependent occurrences must cover every State member")
        if any(
            type(spec.occurrence_id) is not str
            or not spec.occurrence_id.strip()
            or type(spec.event_type) is not EventKind
            or type(spec.canonical_time) is not datetime
            or type(spec.member_references) is not tuple
            or any(
                type(reference) is not str or not reference for reference in spec.member_references
            )
            or type(spec.publication_ordinal) is not int
            for spec in specs
        ):
            raise TypeError("Deferred SSH dependent occurrence fields changed exact type")
        if len({spec.occurrence_id for spec in specs}) != len(specs):
            raise ValueError("Deferred SSH dependent occurrence IDs must be unique")
        if tuple(spec.publication_ordinal for spec in specs) != tuple(
            range(1, len(state_members) + 1)
        ):
            raise ValueError("Deferred SSH dependent occurrence ordinals must be contiguous")
        members_by_object_id = {member.identity.object_id: member for member in state_members}
        if any(len(spec.member_references) != 1 for spec in specs):
            raise ValueError("Deferred SSH dependent occurrences require one exact State member")
        if {spec.member_references[0] for spec in specs} != set(members_by_object_id):
            raise ValueError("Deferred SSH dependent occurrences changed State membership")
        for spec in specs:
            member = members_by_object_id[spec.member_references[0]]
            identity = member.identity
            if member is self.state_batch.session:
                if spec.publication_ordinal != 2:
                    raise ValueError("Deferred SSH login dependent changed its publication ordinal")
                if spec.event_type is not EventKind.SSH_SESSION:
                    raise ValueError("Deferred SSH session dependent requires SSH login evidence")
                if spec.canonical_time != ensure_utc(self.bound_at):
                    raise ValueError("Deferred SSH login dependent changed its authentication time")
                if spec.occurrence_id != stable_uuid(
                    "ssh-deferred-login-occurrence",
                    identity.object_id,
                ):
                    raise ValueError("Deferred SSH login dependent changed semantic identity")
            elif spec.publication_ordinal != 1:
                raise ValueError("Deferred SSH process dependent changed its publication ordinal")
            elif spec.event_type is not EventKind.SYSTEM_PROCESS_CREATE:
                raise ValueError("Deferred SSH process dependent requires system-process evidence")
            elif spec.canonical_time != identity.started_at:
                raise ValueError("Deferred SSH process dependent changed its State start time")
            elif spec.occurrence_id != stable_uuid(
                "ssh-deferred-receiver-occurrence",
                identity.object_id,
            ):
                raise ValueError("Deferred SSH process dependent changed semantic identity")
        return specs

    def _validate_rdp_dependent_occurrences(
        self,
        specs: tuple[DeferredSessionDependentOccurrenceSpec, ...],
    ) -> tuple[DeferredSessionDependentOccurrenceSpec, ...]:
        """Require the bounded initial or ACTIVE RDP dependent cohort."""

        if type(self.bound_at) is not datetime:
            raise TypeError("Deferred RDP dependent authority changed its binding-time type")
        if self.strict_state_authority is None or self.state_batch is None:
            raise ValueError("Deferred RDP dependent occurrences require strict State authority")
        session = self.state_batch.session
        processes = self.state_batch.processes
        if self.binding_disposition is DeferredSessionBindingDisposition.ACTIVE_SESSION:
            patch = self.existing_state_patch
            if session is not None or patch is None or len(processes) != 1 or len(specs) != 2:
                raise ValueError(
                    "ACTIVE deferred RDP cohort requires one source process and live session"
                )
            source_plan = processes[0]
            session_identity = patch.after.identity
            source_identity = source_plan.identity
            process_spec, reconnect_spec = specs
            expected_generation = (
                self.application_intent.expected_generation
                if type(self.application_intent) is DeferredRdpApplicationIntent
                else self.application_token.expected_generation
                if type(self.application_token) is RdpSessionAdmissionToken
                else 0
            )
            if any(
                type(spec.occurrence_id) is not str
                or not spec.occurrence_id.strip()
                or type(spec.event_type) is not EventKind
                or type(spec.canonical_time) is not datetime
                or type(spec.member_references) is not tuple
                or len(spec.member_references) != 1
                or type(spec.member_references[0]) is not str
                or not spec.member_references[0]
                or type(spec.publication_ordinal) is not int
                for spec in specs
            ):
                raise TypeError("ACTIVE deferred RDP dependent fields changed exact type")
            if (
                process_spec.publication_ordinal != 1
                or process_spec.event_type is not EventKind.PROCESS_CREATE
                or process_spec.canonical_time != source_identity.started_at
                or process_spec.member_references != (source_identity.object_id,)
                or process_spec.occurrence_id
                != stable_uuid("rdp-deferred-process-occurrence", source_identity.object_id)
                or reconnect_spec.publication_ordinal != 2
                or reconnect_spec.event_type is not EventKind.RDP_RECONNECT
                or reconnect_spec.canonical_time != ensure_utc(self.bound_at)
                or reconnect_spec.member_references != (session_identity.object_id,)
                or reconnect_spec.occurrence_id
                != stable_uuid(
                    "rdp-deferred-reconnect-occurrence",
                    session_identity.object_id,
                    str(expected_generation),
                )
            ):
                raise ValueError("ACTIVE deferred RDP dependents changed exact semantics")
            return specs
        if session is None or len(processes) != 3:
            raise ValueError(
                "Initial deferred RDP source cohort requires one session and three processes"
            )
        state_members = (session, *processes)
        if len(specs) != len(state_members):
            raise ValueError("Deferred RDP dependent occurrences must cover every State member")
        if any(
            type(spec.occurrence_id) is not str
            or not spec.occurrence_id.strip()
            or type(spec.event_type) is not EventKind
            or type(spec.canonical_time) is not datetime
            or type(spec.member_references) is not tuple
            or len(spec.member_references) != 1
            or type(spec.member_references[0]) is not str
            or not spec.member_references[0]
            or type(spec.publication_ordinal) is not int
            for spec in specs
        ):
            raise TypeError("Deferred RDP dependent occurrence fields changed exact type")
        if len({spec.occurrence_id for spec in specs}) != len(specs):
            raise ValueError("Deferred RDP dependent occurrence IDs must be unique")
        if tuple(spec.publication_ordinal for spec in specs) != tuple(
            range(1, len(state_members) + 1)
        ):
            raise ValueError("Deferred RDP dependent occurrence ordinals must be contiguous")
        members_by_object_id = {member.identity.object_id: member for member in state_members}
        if {spec.member_references[0] for spec in specs} != set(members_by_object_id):
            raise ValueError("Deferred RDP dependent occurrences changed State membership")
        for spec in specs:
            member = members_by_object_id[spec.member_references[0]]
            identity = member.identity
            if member is session:
                if (
                    spec.publication_ordinal != 2
                    or spec.event_type is not EventKind.LOGON
                    or spec.canonical_time != ensure_utc(self.bound_at)
                    or spec.occurrence_id
                    != stable_uuid("rdp-deferred-login-occurrence", identity.object_id)
                ):
                    raise ValueError("Deferred RDP logon dependent changed exact semantics")
                continue
            expected_kind = (
                EventKind.SYSTEM_PROCESS_CREATE
                if identity.principal.casefold() == "system"
                else EventKind.PROCESS_CREATE
            )
            if (
                spec.event_type is not expected_kind
                or spec.canonical_time != identity.started_at
                or spec.occurrence_id
                != stable_uuid("rdp-deferred-process-occurrence", identity.object_id)
            ):
                raise ValueError("Deferred RDP process dependent changed exact semantics")
        return specs

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

    def prepare_timing_authority(
        self,
        runtime: SourceTimingPlanningRuntime,
    ) -> DeferredSessionNetworkAuthority:
        """Replay previewed SSH timing inside the network-owned exact preparation."""

        intent = self.ssh_timing_intent
        if intent is None:
            return self
        if self.kind is not DeferredSessionKind.SSH or not self.dependent_occurrences:
            raise StateError("Deferred SSH timing replay crossed its source cohort")
        strict = self.strict_state_authority
        if strict is None or not strict._owner.authenticates_deferred_session_state_authority(
            strict
        ):
            raise StateError("Deferred SSH timing replay lost its strict State authority")
        try:
            replace(self)
        except (TypeError, ValueError) as error:
            raise StateError("Deferred SSH authority changed before timing replay") from error
        owner_runtime = self.ssh_timing_runtime
        if (
            type(owner_runtime) is not TimingRuntime
            or active_source_timing_planning_runtime(owner_runtime) is not runtime
        ):
            raise StateError("Deferred SSH timing replay crossed its exact runtime owner")
        intent.replay(runtime, bound_at=self.bound_at)
        return replace(
            self,
            ssh_timing_intent=None,
            ssh_timing_runtime=None,
            ssh_timing_replayed=True,
        )

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
        prepared_dispatch: object | None = None,
        outcome: NetworkConnectionPublicationOutcome,
    ) -> None:
        """Publish one authenticated committed root and its internal disposition."""

        with self._lock:
            assert self._claim is claim and claim._capture is self and claim._active
            self._transaction = root.transaction
            self._lifecycle_mode = root.runtime_token.lifecycle_mode
            self._prepared_root = root
            self._prepared_dispatch = prepared_dispatch  # type: ignore[assignment]
            self._receipt = receipt
            self._application_receipt = application_receipt
            self._outcome = outcome
            claim._active = False
            self._claim = None

    def _authenticates_committed_claimed_publication(
        self,
        claim: _NetworkConnectionIdentityCaptureClaim,
        *,
        root: PreparedNetworkTransactionRoot,
        receipt: LifecyclePreparedNetworkReceipt,
        application_receipt: object | None,
        prepared_dispatch: object | None = None,
        outcome: NetworkConnectionPublicationOutcome,
    ) -> bool:
        """Authenticate the exact postcondition before its boundary drops the claim."""

        if type(claim) is not _NetworkConnectionIdentityCaptureClaim:
            return False
        with self._lock:
            return bool(
                self._claim is None
                and claim._capture is self
                and not claim._active
                and self._transaction is root.transaction
                and self._lifecycle_mode == root.runtime_token.lifecycle_mode
                and self._prepared_root is root
                and self._prepared_dispatch is prepared_dispatch
                and self._receipt is receipt
                and self._application_receipt is application_receipt
                and self._outcome is outcome
            )

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

    def require_persistent_smb_root_handoff(self) -> PersistentSmbRootHandoff:
        """Return the exact deferred-source owners for a persistent SMB root."""

        handoff = self.prepared_dispatch
        if type(handoff) is not PersistentSmbRootHandoff:
            raise ValueError("Network connection did not publish a persistent SMB root handoff")
        return handoff

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
    persistent_smb_root_intent: tuple[object, ...] | None = None
    defer_source_publication: bool = False
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
        if self.persistent_smb_root_intent is not None:
            PersistentSmbRootIntent.from_identity_snapshot(self.persistent_smb_root_intent)
            if (
                self.transport_lifecycle_mode != "network"
                or self.identity_capture is None
                or not self.defer_source_publication
                or self.proto != "tcp"
                or self.dst_port != 445
                or self.service != "smb"
            ):
                raise ValueError(
                    "Persistent SMB roots require captured deferred-source TCP/445 SMB mode"
                )
        elif self.defer_source_publication:
            raise ValueError("Deferred source publication is reserved for persistent SMB roots")
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
