# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Frozen owner-issued composition for deferred SSH and RDP sessions.

The types in this module are deliberately inert.  They bind already prepared
State, lifecycle, application, timing, and dispatch capabilities without
claiming, cancelling, committing, or publishing any of them.  The eventual
authority coordinator must still authenticate every nested capability with its
issuing owner immediately before entering the shared commit fence.

``PreparedDispatch`` is intentionally opaque here.  This leaf binds the exact
objects, their order, and their public occurrence IDs.  Its semantic intent,
lifecycle ticket, and source-timing ownership remain dispatcher precommit
obligations because those facts currently have no public projection.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from secrets import token_bytes, token_hex
from typing import TypeAlias

from evidenceforge.events.application import (
    ApplicationChannelIdentity,
    ApplicationOperationReservation,
    ApplicationTransportBinding,
)
from evidenceforge.events.dispatcher import PreparedDispatch
from evidenceforge.events.identity import SessionIdentity
from evidenceforge.events.lifecycle import (
    LifecycleHold,
    ProcessLifecycleIdentity,
    SessionLifecycleIdentity,
    TransportLifecycleIdentity,
    TransportSessionBindingIdentity,
)
from evidenceforge.events.network import NetworkTransactionPlan
from evidenceforge.events.rdp import RdpSessionSnapshot, RdpSessionState
from evidenceforge.generation.application_channels import ApplicationChannelAdmissionToken
from evidenceforge.generation.deferred_session_preseal import (
    DeferredSessionBindingDisposition,
)
from evidenceforge.generation.lifecycle_registry import (
    LifecycleClosedTransportAdmissionToken,
    LifecycleClosedTransportPublicationRequest,
    LifecycleClosedTransportStartMember,
    LifecycleProcessStartRequest,
    LifecycleSessionStartRequest,
)
from evidenceforge.generation.network_runtime import (
    NetworkConnectionCommitResult,
    NetworkTransactionPreparationToken,
    PreparedNetworkTransactionRoot,
)
from evidenceforge.generation.rdp_sessions import RdpSessionAdmissionToken
from evidenceforge.generation.source_timing import (
    SourceTimingPreparation,
    SourceTimingPreparationToken,
)
from evidenceforge.generation.ssh_channels import (
    SshChannelAdmissionToken,
    SshOperationLease,
    SshProcessHold,
    SshSessionBinding,
    SshSessionView,
    SshTransportPlan,
)
from evidenceforge.generation.state_manager import (
    ConnectionCompositeMaterializationPlan,
    ConnectionExistingSessionLifecycleDisposition,
    ConnectionExistingSessionPatch,
    ConnectionMaterializationMode,
    DeferredSessionStateAuthority,
    MaterializationBatchPlan,
    ProcessActivityPatch,
    ProcessMaterializationPlan,
    SessionActivityPatch,
    SessionMaterializationPlan,
)
from evidenceforge.models.exceptions import StateError


class DeferredSessionKind(StrEnum):
    """Protocol owner for one deferred-session composition."""

    SSH = "ssh"
    RDP = "rdp"


DeferredSessionApplicationToken: TypeAlias = SshChannelAdmissionToken | RdpSessionAdmissionToken
DeferredSessionStatePlan: TypeAlias = SessionMaterializationPlan | ProcessMaterializationPlan


@dataclass(frozen=True, slots=True)
class DeferredSessionStateMemberBinding:
    """Pair one exact State start plan with its lifecycle start member."""

    state_member: DeferredSessionStatePlan
    lifecycle_member: LifecycleClosedTransportStartMember

    def __post_init__(self) -> None:
        """Reject type, token, or canonical-identity drift at the leaf boundary."""

        state_member = self.state_member
        lifecycle_member = self.lifecycle_member
        if type(state_member) not in {SessionMaterializationPlan, ProcessMaterializationPlan}:
            raise TypeError("Deferred session State member has an unsupported exact type")
        if type(lifecycle_member) is not LifecycleClosedTransportStartMember:
            raise TypeError("Deferred session lifecycle member has an unsupported exact type")
        if state_member.publication_token != lifecycle_member.publication_token:
            raise ValueError("Deferred session State and lifecycle member tokens disagree")

        request = lifecycle_member.request
        if type(state_member) is SessionMaterializationPlan:
            if type(request) is not LifecycleSessionStartRequest:
                raise ValueError("Deferred State session must bind a lifecycle session start")
            _validate_session_member_identity(state_member, request.identity)
            return
        if type(request) is not LifecycleProcessStartRequest:
            raise ValueError("Deferred State process must bind a lifecycle process start")
        _validate_process_member_identity(state_member, request)


@dataclass(frozen=True, slots=True)
class DeferredSessionExistingStateBinding:
    """Pair one exact live-session State patch with its lifecycle start."""

    state_patch: ConnectionExistingSessionPatch
    lifecycle_member: LifecycleClosedTransportStartMember | None

    def __post_init__(self) -> None:
        """Reject replaced patch/member objects or mismatched after-identities."""

        if type(self.state_patch) is not ConnectionExistingSessionPatch:
            raise TypeError("Deferred existing State binding requires an exact session patch")
        disposition = self.state_patch.lifecycle_disposition
        if disposition is ConnectionExistingSessionLifecycleDisposition.START:
            if type(self.lifecycle_member) is not LifecycleClosedTransportStartMember:
                raise TypeError("Deferred session start binding requires an exact lifecycle member")
            request = self.lifecycle_member.request
            if type(request) is not LifecycleSessionStartRequest:
                raise ValueError("Deferred session start binding requires a session start")
            _validate_session_identity(self.state_patch.after.identity, request.identity)
        elif disposition is ConnectionExistingSessionLifecycleDisposition.EXISTING:
            if self.lifecycle_member is not None:
                raise ValueError("Existing lifecycle session cannot carry another start member")
        else:
            raise ValueError("Deferred existing State binding has an unsupported disposition")


@dataclass(frozen=True, slots=True)
class DeferredSessionComposition:
    """One signed inert carrier for a complete deferred SSH/RDP publication."""

    kind: DeferredSessionKind
    prepared_root: PreparedNetworkTransactionRoot
    source_timing_preparation: SourceTimingPreparation
    lifecycle_token: LifecycleClosedTransportAdmissionToken
    state_members: tuple[DeferredSessionStateMemberBinding, ...]
    application_token: DeferredSessionApplicationToken | None
    transport_dispatch: PreparedDispatch
    dependent_dispatches: tuple[PreparedDispatch, ...]
    existing_state_session: DeferredSessionExistingStateBinding | None
    binding_disposition: DeferredSessionBindingDisposition | None
    state_authority: DeferredSessionStateAuthority | None
    coordinator_id: str
    _integrity: str = field(repr=False)

    def __post_init__(self) -> None:
        """Keep direct construction exact and allocation-free after normalization."""

        if type(self.kind) is not DeferredSessionKind:
            raise TypeError("Deferred session composition requires an exact protocol kind")
        if type(self.state_members) is not tuple:
            raise TypeError("Deferred session State member bindings must be an exact tuple")
        if type(self.dependent_dispatches) is not tuple:
            raise TypeError("Deferred session dependent dispatches must be an exact tuple")
        if (
            self.existing_state_session is not None
            and type(self.existing_state_session) is not DeferredSessionExistingStateBinding
        ):
            raise TypeError("Deferred session existing State binding has an unsupported type")
        if self.binding_disposition is not None and (
            type(self.binding_disposition) is not DeferredSessionBindingDisposition
        ):
            raise TypeError("Deferred session binding disposition has an unsupported type")
        if self.state_authority is not None and (
            type(self.state_authority) is not DeferredSessionStateAuthority
        ):
            raise TypeError("Deferred session State authority has an unsupported type")
        if type(self.coordinator_id) is not str or not self.coordinator_id:
            raise ValueError("Deferred session composition requires a coordinator identity")
        if type(self._integrity) is not str or not self._integrity:
            raise ValueError("Deferred session composition requires an integrity token")

    @property
    def publication_token(self) -> str:
        """Return the owner-issued keyed proof over the exact nested objects."""

        return self._integrity

    @property
    def physical_transport_id(self) -> str:
        """Return the sole State-authenticated physical transport identity."""

        return self.prepared_root.state_plan.physical_transport_id

    @property
    def expected_state_version(self) -> int:
        """Return the single State version fenced by the prepared root."""

        return self.prepared_root.state_plan.expected_version

    @property
    def publication_order(self) -> tuple[PreparedDispatch, ...]:
        """Return transport-first canonical publication order."""

        return (self.transport_dispatch, *self.dependent_dispatches)


class DeferredSessionCompositionCoordinator:
    """Issue and authenticate inert protocol-scoped deferred compositions.

    The coordinator retains only its protocol, owner identity, and secret.  It
    never retains caller capabilities, including after a failed issue or
    authentication attempt.
    """

    __slots__ = ("_coordinator_id", "_kind", "_secret")

    def __init__(self, kind: DeferredSessionKind) -> None:
        if type(kind) is not DeferredSessionKind:
            raise TypeError("Deferred session coordinator requires an exact protocol kind")
        self._kind = kind
        self._coordinator_id = f"deferred-session-{kind.value}-{token_hex(16)}"
        self._secret = token_bytes(32)

    @property
    def kind(self) -> DeferredSessionKind:
        """Return the sole protocol this owner may compose."""

        return self._kind

    @property
    def coordinator_id(self) -> str:
        """Return the stable identity bound into every issued proof."""

        return self._coordinator_id

    def issue(
        self,
        *,
        prepared_root: PreparedNetworkTransactionRoot,
        source_timing_preparation: SourceTimingPreparation,
        lifecycle_token: LifecycleClosedTransportAdmissionToken,
        state_members: tuple[DeferredSessionStateMemberBinding, ...],
        application_token: DeferredSessionApplicationToken | None,
        transport_dispatch: PreparedDispatch,
        dependent_dispatches: tuple[PreparedDispatch, ...] = (),
        existing_state_session: DeferredSessionExistingStateBinding | None = None,
        binding_disposition: DeferredSessionBindingDisposition | None = None,
        state_authority: DeferredSessionStateAuthority | None = None,
    ) -> DeferredSessionComposition:
        """Validate and sign one exact carrier without retaining or consuming it."""

        values = _DeferredSessionCompositionValues(
            kind=self._kind,
            prepared_root=prepared_root,
            source_timing_preparation=source_timing_preparation,
            lifecycle_token=lifecycle_token,
            state_members=state_members,
            application_token=application_token,
            transport_dispatch=transport_dispatch,
            dependent_dispatches=dependent_dispatches,
            existing_state_session=existing_state_session,
            binding_disposition=binding_disposition,
            state_authority=state_authority,
        )
        _validate_composition_values(
            values,
            coordinator_id=self._coordinator_id,
            require_outer_bound=False,
        )
        integrity = self._integrity(values)
        return DeferredSessionComposition(
            kind=values.kind,
            prepared_root=values.prepared_root,
            source_timing_preparation=values.source_timing_preparation,
            lifecycle_token=values.lifecycle_token,
            state_members=values.state_members,
            application_token=values.application_token,
            transport_dispatch=values.transport_dispatch,
            dependent_dispatches=values.dependent_dispatches,
            existing_state_session=values.existing_state_session,
            binding_disposition=values.binding_disposition,
            state_authority=values.state_authority,
            coordinator_id=self._coordinator_id,
            _integrity=integrity,
        )

    def authenticates(self, composition: object) -> bool:
        """Return whether this owner issued the intact exact-object composition."""

        if type(composition) is not DeferredSessionComposition:
            return False
        if composition.kind is not self._kind:
            return False
        if composition.coordinator_id != self._coordinator_id:
            return False
        if type(composition.publication_token) is not str:
            return False
        values = _DeferredSessionCompositionValues(
            kind=composition.kind,
            prepared_root=composition.prepared_root,
            source_timing_preparation=composition.source_timing_preparation,
            lifecycle_token=composition.lifecycle_token,
            state_members=composition.state_members,
            application_token=composition.application_token,
            transport_dispatch=composition.transport_dispatch,
            dependent_dispatches=composition.dependent_dispatches,
            existing_state_session=composition.existing_state_session,
            binding_disposition=composition.binding_disposition,
            state_authority=composition.state_authority,
        )
        try:
            _validate_composition_values(
                values,
                coordinator_id=self._coordinator_id,
                require_outer_bound=True,
            )
            expected = self._integrity(values)
        except (AttributeError, StateError, TypeError, ValueError):
            return False
        return hmac.compare_digest(composition.publication_token, expected)

    def _integrity(self, values: _DeferredSessionCompositionValues) -> str:
        preimage = _composition_integrity_preimage(
            self._coordinator_id,
            values,
        )
        return hmac.new(self._secret, repr(preimage).encode(), hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class _DeferredSessionCompositionValues:
    """Internal parameter bundle shared by issue and authentication."""

    kind: DeferredSessionKind
    prepared_root: PreparedNetworkTransactionRoot
    source_timing_preparation: SourceTimingPreparation
    lifecycle_token: LifecycleClosedTransportAdmissionToken
    state_members: tuple[DeferredSessionStateMemberBinding, ...]
    application_token: DeferredSessionApplicationToken | None
    transport_dispatch: PreparedDispatch
    dependent_dispatches: tuple[PreparedDispatch, ...]
    existing_state_session: DeferredSessionExistingStateBinding | None
    binding_disposition: DeferredSessionBindingDisposition | None
    state_authority: DeferredSessionStateAuthority | None


def _validate_session_member_identity(
    state_member: SessionMaterializationPlan,
    lifecycle_identity: SessionLifecycleIdentity,
) -> None:
    _validate_session_identity(state_member.identity, lifecycle_identity)


def _validate_session_identity(
    identity: SessionIdentity,
    lifecycle_identity: SessionLifecycleIdentity,
) -> None:
    """Require exact shared identity across State and lifecycle projections."""

    if type(identity) is not SessionIdentity:
        raise ValueError("Deferred State session identity has an unsupported exact type")
    if type(lifecycle_identity) is not SessionLifecycleIdentity:
        raise ValueError("Deferred session lifecycle identity has an unsupported exact type")
    shared = (
        identity.hostname,
        identity.object_id,
        identity.logon_id,
        identity.principal,
        identity.session_kind,
        identity.started_at,
        identity.session_id,
        identity.logon_guid,
    )
    lifecycle_shared = (
        lifecycle_identity.hostname,
        lifecycle_identity.object_id,
        lifecycle_identity.logon_id,
        lifecycle_identity.principal,
        lifecycle_identity.session_kind,
        lifecycle_identity.started_at,
        lifecycle_identity.session_id,
        lifecycle_identity.logon_guid,
    )
    if shared != lifecycle_shared:
        raise ValueError("Deferred State and lifecycle session identities disagree")


def _validate_process_member_identity(
    state_member: ProcessMaterializationPlan,
    request: LifecycleProcessStartRequest,
) -> None:
    lifecycle_identity = request.identity
    if type(lifecycle_identity) is not ProcessLifecycleIdentity:
        raise ValueError("Deferred process lifecycle identity has an unsupported exact type")
    identity = state_member.identity
    shared = (
        identity.hostname,
        identity.object_id,
        identity.pid,
        identity.started_at,
        identity.image,
    )
    lifecycle_shared = (
        lifecycle_identity.hostname,
        lifecycle_identity.object_id,
        lifecycle_identity.pid,
        lifecycle_identity.started_at,
        lifecycle_identity.image,
    )
    if shared != lifecycle_shared:
        raise ValueError("Deferred State and lifecycle process identities disagree")
    if (
        request.token.principal != identity.principal
        or request.token.logon_id != identity.logon_id
        or request.token.integrity_level != state_member.integrity_level
    ):
        raise ValueError("Deferred process lifecycle token disagrees with State identity")
    if (
        state_member.auth_session_id is not None
        and request.token.session_id != state_member.auth_session_id
    ):
        raise ValueError("Deferred process lifecycle session ID disagrees with State")
    if (
        state_member.auth_logon_type is not None
        and request.token.logon_type != state_member.auth_logon_type
    ):
        raise ValueError("Deferred process lifecycle logon type disagrees with State")


def _validate_composition_values(
    values: _DeferredSessionCompositionValues,
    *,
    coordinator_id: str,
    require_outer_bound: bool,
) -> None:
    if type(values.kind) is not DeferredSessionKind:
        raise TypeError("Deferred session composition kind must be exact")
    _validate_prepared_root(values.kind, values.prepared_root)
    _validate_source_timing(values.source_timing_preparation)
    _validate_state_and_lifecycle(
        values.prepared_root.state_plan,
        values.lifecycle_token,
        values.state_members,
        values.existing_state_session,
    )
    _validate_binding_disposition(
        values.kind,
        values.binding_disposition,
        values.state_authority,
        values.prepared_root.state_plan,
        coordinator_id=coordinator_id,
        application_token=values.application_token,
        require_outer_bound=require_outer_bound,
    )
    if values.state_authority is not None:
        lifecycle_binding = values.lifecycle_token.request.binding_identity
        if (
            lifecycle_binding is None
            or lifecycle_binding.bound_at != values.state_authority.bound_at
        ):
            raise StateError("Strict deferred State and lifecycle binding times disagree")
    _validate_application_token(
        values.kind,
        values.prepared_root,
        values.lifecycle_token,
        values.application_token,
    )
    _validate_dispatches(values.transport_dispatch, values.dependent_dispatches)


def _validate_binding_disposition(
    kind: DeferredSessionKind,
    disposition: DeferredSessionBindingDisposition | None,
    state_authority: DeferredSessionStateAuthority | None,
    state_plan: ConnectionCompositeMaterializationPlan,
    *,
    coordinator_id: str,
    application_token: DeferredSessionApplicationToken | None,
    require_outer_bound: bool,
) -> None:
    """Bind the strict semantic disposition to the exact State plan shape."""

    if disposition is None:
        if state_authority is not None:
            raise StateError("Legacy deferred composition cannot carry strict State authority")
        return
    if type(disposition) is not DeferredSessionBindingDisposition:
        raise TypeError("Deferred session binding disposition must be exact")
    if type(state_authority) is not DeferredSessionStateAuthority:
        raise StateError("Strict deferred composition requires exact State authority")
    if not state_authority._owner.authenticates_deferred_session_state_payload(state_authority):
        raise StateError("Strict deferred composition State authority failed authentication")
    if require_outer_bound and not state_authority.outer_bound:
        raise StateError("Strict deferred composition State authority lacks its outer binding")
    if require_outer_bound:
        outer = state_authority._capability.outer_authority
        assert outer is not None
        if (
            getattr(getattr(outer, "coordinator", None), "coordinator_id", "") != coordinator_id
            or getattr(outer, "kind", None) is not kind
            or getattr(outer, "binding_disposition", None) is not disposition
            or getattr(outer, "strict_state_authority", None) is not state_authority
            or getattr(outer, "application_token", None) is not application_token
        ):
            raise StateError("Strict deferred composition owns another outer network authority")
    if (
        state_authority.binding_disposition is not disposition
        or state_authority.protocol.value != kind.value
        or state_authority.batch is not state_plan.batch
        or state_authority.existing_session_patch is not state_plan.existing_session_patch
        or state_authority.existing_session_process_roles_patch
        is not state_plan.existing_session_process_roles_patch
    ):
        raise StateError("Strict deferred composition replaced its exact State authority")
    batch = state_plan.batch
    patch = state_plan.existing_session_patch
    roles = state_plan.existing_session_process_roles_patch
    if batch is None or not batch.processes:
        raise StateError("Strict deferred session composition requires process members")
    if disposition is DeferredSessionBindingDisposition.NEW_SESSION:
        if batch.session is None or patch is not None or roles is not None:
            raise StateError("NEW deferred composition changed its exact State shape")
        return
    if batch.session is not None or patch is None:
        raise StateError("Existing deferred composition changed its exact State shape")
    expected = (
        ConnectionExistingSessionLifecycleDisposition.START
        if disposition is DeferredSessionBindingDisposition.PREALLOCATED_SESSION_START
        else ConnectionExistingSessionLifecycleDisposition.EXISTING
    )
    if patch.lifecycle_disposition is not expected:
        raise StateError("Deferred composition disposition disagrees with its session patch")
    target_processes = tuple(
        process
        for process in batch.processes
        if process.identity.hostname == patch.after.identity.hostname
    )
    if target_processes and roles is None:
        raise StateError("Deferred target process composition lost its exact role patch")
    if not target_processes and roles is not None:
        raise StateError("Deferred source-only composition gained a target role patch")


def _validate_prepared_root(
    kind: DeferredSessionKind,
    root: PreparedNetworkTransactionRoot,
) -> None:
    if type(root) is not PreparedNetworkTransactionRoot:
        raise TypeError("Deferred session requires an exact prepared network root")
    if type(root.transaction) is not NetworkTransactionPlan:
        raise StateError("Deferred session root has an unsupported transaction type")
    if type(root.state_plan) is not ConnectionCompositeMaterializationPlan:
        raise StateError("Deferred session root has an unsupported State plan type")
    if type(root.runtime_token) is not NetworkTransactionPreparationToken:
        raise StateError("Deferred session root has an unsupported runtime token type")
    if type(root.result) is not NetworkConnectionCommitResult:
        raise StateError("Deferred session root has an unsupported result type")

    transaction = root.transaction
    state_plan = root.state_plan
    runtime_token = root.runtime_token
    result = root.result
    if runtime_token.lifecycle_mode != "deferred_session":
        raise StateError("Deferred session root requires deferred_session lifecycle mode")
    if runtime_token.materialization_mode is not ConnectionMaterializationMode.PHYSICAL:
        raise StateError("Deferred session root must reserve a physical State transport")
    if state_plan.mode is not ConnectionMaterializationMode.PHYSICAL:
        raise StateError("Deferred session State plan must be physical")
    if not state_plan.materializes_connection:
        raise StateError("Deferred session State plan must materialize its physical transport")
    if result.lifecycle_mode != "deferred_session":
        raise StateError("Deferred session result changed lifecycle mode")
    if result.transaction is not transaction:
        raise StateError("Deferred session result must retain the exact root transaction")
    if state_plan.transaction != transaction:
        raise StateError("Deferred session State plan disagrees with the root transaction")
    if runtime_token.transaction_id != transaction.stable_id:
        raise StateError("Deferred session runtime token targets another transaction")
    if runtime_token.state_publication_token != state_plan.publication_token:
        raise StateError("Deferred session runtime token targets another State plan")

    expected_port = 22 if kind is DeferredSessionKind.SSH else 3389
    if transaction.protocol.casefold() != "tcp" or transaction.dst_port != expected_port:
        raise StateError(
            f"Deferred {kind.value.upper()} requires an exact TCP/{expected_port} transport"
        )
    if transaction.outcome != "success" or transaction.conn_state.upper() != "SF":
        raise StateError("Deferred session requires a successful established transport")
    if transaction.closed_at is None:
        raise StateError("Deferred session requires a closed physical transport")
    if transaction.application_layer_only:
        raise StateError("Deferred session cannot use an application-layer-only transaction")
    if transaction.service and transaction.service.casefold() != kind.value:
        raise StateError("Deferred session transport service disagrees with its protocol owner")

    fingerprint = state_plan.physical_transport_fingerprint
    expected_fingerprint = (
        transaction.stable_id,
        transaction.conn_id,
        transaction.zeek_uid,
        (
            transaction.src_ip,
            transaction.src_port,
            transaction.dst_ip,
            transaction.dst_port,
            transaction.protocol.casefold(),
        ),
        transaction.started_at,
        transaction.closed_at,
    )
    actual_fingerprint = (
        fingerprint.transport_id,
        fingerprint.conn_id,
        fingerprint.zeek_uid,
        fingerprint.tuple_key,
        fingerprint.started_at,
        fingerprint.closed_at,
    )
    if actual_fingerprint != expected_fingerprint:
        raise StateError("Deferred session physical transport fingerprint drifted")


def _validate_source_timing(preparation: SourceTimingPreparation) -> None:
    if type(preparation) is not SourceTimingPreparation:
        raise TypeError("Deferred session requires an exact source timing preparation")
    if preparation.census().state != "sealed":
        raise StateError("Deferred session source timing preparation must be sealed and owned")
    if not preparation.sealed or preparation.committed or preparation.receipt is not None:
        raise StateError("Deferred session source timing preparation is no longer caller-owned")
    if type(preparation.binding_token) is not SourceTimingPreparationToken:
        raise StateError("Deferred session source timing binding token has an unsupported type")


def _validate_state_and_lifecycle(
    state_plan: ConnectionCompositeMaterializationPlan,
    lifecycle_token: LifecycleClosedTransportAdmissionToken,
    bindings: tuple[DeferredSessionStateMemberBinding, ...],
    existing_binding: DeferredSessionExistingStateBinding | None,
) -> None:
    if type(lifecycle_token) is not LifecycleClosedTransportAdmissionToken:
        raise TypeError("Deferred session requires an exact lifecycle admission token")
    if type(bindings) is not tuple:
        raise TypeError("Deferred session State member bindings must be an exact tuple")
    if any(type(binding) is not DeferredSessionStateMemberBinding for binding in bindings):
        raise TypeError("Deferred session State member binding has an unsupported exact type")
    if (
        existing_binding is not None
        and type(existing_binding) is not DeferredSessionExistingStateBinding
    ):
        raise TypeError("Deferred existing State binding has an unsupported exact type")
    request = lifecycle_token.request
    if type(request) is not LifecycleClosedTransportPublicationRequest:
        raise StateError("Deferred session lifecycle token has an unsupported request type")
    if type(request.identity) is not TransportLifecycleIdentity:
        raise StateError("Deferred session lifecycle token has an unsupported transport type")
    if type(request.start_members) is not tuple or type(request.process_holds) is not tuple:
        raise StateError("Deferred session lifecycle members and holds must be exact tuples")
    fingerprint = state_plan.physical_transport_fingerprint
    identity = request.identity
    if (
        identity.transport_id,
        identity.conn_id,
        identity.zeek_uid,
        identity.tuple_key,
        identity.opened_at,
        identity.close_deadline,
    ) != (
        fingerprint.transport_id,
        fingerprint.conn_id,
        fingerprint.zeek_uid,
        fingerprint.tuple_key,
        fingerprint.started_at,
        fingerprint.closed_at,
    ):
        raise StateError("Deferred lifecycle admission targets another transport")

    batch = state_plan.batch
    if batch is not None and type(batch) is not MaterializationBatchPlan:
        raise StateError("Deferred session State batch has an unsupported exact type")
    if batch is not None and (
        type(batch.processes) is not tuple or batch.expected_version != state_plan.expected_version
    ):
        raise StateError("Deferred session State batch changed its single version or ordering")
    expected_state_members: tuple[DeferredSessionStatePlan, ...] = (
        ()
        if batch is None
        else (
            *((batch.session,) if batch.session is not None else ()),
            *batch.processes,
        )
    )
    lifecycle_members = request.start_members
    existing_patch = state_plan.existing_session_patch
    existing_start_required = (
        existing_patch is not None
        and existing_patch.lifecycle_disposition
        is ConnectionExistingSessionLifecycleDisposition.START
    )
    expected_lifecycle_count = len(expected_state_members) + (1 if existing_start_required else 0)
    if len(bindings) != len(expected_state_members) or len(lifecycle_members) != (
        expected_lifecycle_count
    ):
        raise StateError("Deferred State and lifecycle start member counts disagree")
    for binding, state_member, lifecycle_member in zip(
        bindings,
        expected_state_members,
        lifecycle_members[: len(expected_state_members)],
        strict=True,
    ):
        if binding.state_member is not state_member:
            raise StateError("Deferred State member binding replaced an exact plan object")
        if binding.lifecycle_member is not lifecycle_member:
            raise StateError("Deferred lifecycle member binding replaced an exact request object")
    if existing_patch is None:
        if existing_binding is not None:
            raise StateError("Deferred composition carries an unexpected existing State binding")
    else:
        if existing_binding is None or existing_binding.state_patch is not existing_patch:
            raise StateError("Deferred existing State binding replaced its exact authority")
        if existing_start_required:
            if (
                existing_binding.lifecycle_member is not lifecycle_members[-1]
                or existing_binding.lifecycle_member.publication_token
                != state_plan.publication_token
            ):
                raise StateError("Deferred session start binding replaced its exact authority")
        elif existing_binding.lifecycle_member is not None:
            raise StateError("Existing lifecycle session unexpectedly carries a start member")
    expected_start_tokens = (
        *(member.publication_token for member in expected_state_members),
        *((state_plan.publication_token,) if existing_start_required else ()),
    )
    if request.start_plan_tokens != expected_start_tokens:
        raise StateError("Deferred lifecycle member tokens disagree with the State batch")
    _validate_parent_order(batch, bindings)
    _validate_transport_session_binding(
        batch,
        existing_patch,
        request.binding_identity,
    )
    _validate_connection_holds(
        state_plan.process_activity,
        state_plan.session_activity,
        request.process_holds,
        fingerprint.closed_at,
    )


def _validate_parent_order(
    batch: MaterializationBatchPlan | None,
    bindings: tuple[DeferredSessionStateMemberBinding, ...],
) -> None:
    if batch is None:
        return
    staged_by_pid: dict[tuple[str, int], str] = {}
    process_bindings = bindings[1:] if batch.session is not None else bindings
    for process_plan, binding in zip(batch.processes, process_bindings, strict=True):
        identity = process_plan.identity
        request = binding.lifecycle_member.request
        assert type(request) is LifecycleProcessStartRequest
        staged_parent_id = staged_by_pid.get((identity.hostname, identity.parent_pid))
        if staged_parent_id is not None and request.identity.parent_object_id != staged_parent_id:
            raise StateError("Deferred lifecycle process parent order disagrees with State")
        staged_by_pid[(identity.hostname, identity.pid)] = identity.object_id

        session_plan = batch.session
        if session_plan is None or identity.logon_id != session_plan.identity.logon_id:
            continue
        session_object_id = session_plan.identity.object_id
        if request.membership.session_object_id != session_object_id:
            raise StateError("Deferred lifecycle process uses another staged session")


def _validate_transport_session_binding(
    batch: MaterializationBatchPlan | None,
    existing_patch: ConnectionExistingSessionPatch | None,
    binding: TransportSessionBindingIdentity | None,
) -> None:
    if binding is not None and type(binding) is not TransportSessionBindingIdentity:
        raise StateError("Deferred transport/session binding has an unsupported exact type")
    session_plan = batch.session if batch is not None else None
    if session_plan is not None:
        if binding is None or binding.session_object_id != session_plan.identity.object_id:
            raise StateError("Deferred transport binding does not target the staged session")
    if existing_patch is not None:
        if binding is None or binding.session_object_id != existing_patch.after.identity.object_id:
            raise StateError("Deferred transport binding does not target the patched session")


def _validate_connection_holds(
    process_activity: tuple[ProcessActivityPatch, ...],
    session_activity: tuple[SessionActivityPatch, ...],
    holds: tuple[LifecycleHold, ...],
    closed_at: datetime | None,
) -> None:
    if type(process_activity) is not tuple or type(session_activity) is not tuple:
        raise StateError("Deferred State activity patches must be exact tuples")
    if type(holds) is not tuple:
        raise StateError("Deferred lifecycle holds must be an exact tuple")
    if any(type(patch) is not ProcessActivityPatch for patch in process_activity):
        raise StateError("Deferred process activity contains an unsupported exact type")
    if any(type(patch) is not SessionActivityPatch for patch in session_activity):
        raise StateError("Deferred session activity contains an unsupported exact type")
    if any(type(hold) is not LifecycleHold for hold in holds):
        raise StateError("Deferred lifecycle holds contain an unsupported exact type")
    process_patches = {patch.identity.object_id: patch for patch in process_activity}
    if len(process_patches) != len(process_activity):
        raise StateError("Deferred session repeats a process activity owner")
    hold_subjects = [hold.subject.object_id for hold in holds]
    if len(set(hold_subjects)) != len(hold_subjects):
        raise StateError("Deferred session repeats a lifecycle hold subject")
    if set(hold_subjects) != set(process_patches):
        raise StateError("Deferred process activity and lifecycle holds disagree")
    session_patches = {patch.identity.logon_id: patch for patch in session_activity}
    if len(session_patches) != len(session_activity):
        raise StateError("Deferred session repeats a session activity owner")
    expected_logon_ids = {
        patch.identity.logon_id for patch in process_activity if patch.identity.logon_id
    }
    if set(session_patches) != expected_logon_ids:
        raise StateError("Deferred session activity and lifecycle holds disagree")
    for hold in holds:
        if hold.subject.kind != "process":
            raise StateError("Deferred session holds must target process lifecycles")
        if closed_at is None or hold.hold_until < closed_at:
            raise StateError("Deferred session process hold ends before transport close")
        patch = process_patches[hold.subject.object_id]
        if patch.activity_time != hold.hold_until:
            raise StateError("Deferred process hold and State activity deadline disagree")
        if not patch.identity.logon_id:
            continue
        session_patch = session_patches[patch.identity.logon_id]
        if session_patch.activity_time != hold.hold_until:
            raise StateError("Deferred owning-session activity deadline disagrees with hold")


def _validate_application_token(
    kind: DeferredSessionKind,
    root: PreparedNetworkTransactionRoot,
    lifecycle_token: LifecycleClosedTransportAdmissionToken,
    token: DeferredSessionApplicationToken | None,
) -> None:
    if token is None:
        raise StateError(
            "Strict deferred SSH/RDP composition requires its persistent manager admission"
        )
    expected_type = (
        SshChannelAdmissionToken if kind is DeferredSessionKind.SSH else RdpSessionAdmissionToken
    )
    if type(token) is not expected_type:
        raise StateError("Deferred session application token belongs to another protocol owner")
    common = token.application_token
    if type(common) is not ApplicationChannelAdmissionToken:
        raise StateError("Deferred session application token lacks an exact common admission")
    identity = common.identity
    if type(identity) is not ApplicationChannelIdentity:
        raise StateError("Deferred session application admission must open a typed channel")
    if common.kind != "open_completed":
        raise StateError("Deferred session requires a completed application open admission")
    if type(common.reservation) is not ApplicationOperationReservation:
        raise StateError("Deferred session common reservation has an unsupported exact type")
    if type(identity.binding) is not ApplicationTransportBinding:
        raise StateError("Deferred session common transport binding has an unsupported type")
    fingerprint = root.state_plan.physical_transport_fingerprint
    if identity.protocol != kind.value:
        raise StateError("Deferred common application protocol disagrees with its owner")
    if (
        identity.binding.transport_id,
        identity.binding.opened_at,
        identity.binding.closes_at,
    ) != (
        fingerprint.transport_id,
        fingerprint.started_at,
        fingerprint.closed_at,
    ):
        raise StateError("Deferred common application admission targets another transport")

    if kind is DeferredSessionKind.SSH:
        assert type(token) is SshChannelAdmissionToken
        _validate_ssh_token(root, lifecycle_token, token)
    else:
        assert type(token) is RdpSessionAdmissionToken
        _validate_rdp_token(root, lifecycle_token, token)


def _validate_ssh_token(
    root: PreparedNetworkTransactionRoot,
    lifecycle_token: LifecycleClosedTransportAdmissionToken,
    token: SshChannelAdmissionToken,
) -> None:
    if token.kind != "open_completed":
        raise StateError("Deferred SSH requires an open_completed manager admission")
    if type(token.session) is not SshSessionView:
        raise StateError("Deferred SSH manager token has an unsupported session view")
    if type(token.session.transport) is not SshTransportPlan:
        raise StateError("Deferred SSH manager token has an unsupported transport plan")
    if type(token.session.binding) is not SshSessionBinding:
        raise StateError("Deferred SSH manager token has an unsupported session binding")
    if (
        type(token.operation) is not SshOperationLease
        or token.operation.session is not token.session
    ):
        raise StateError("Deferred SSH operation replaced its exact session view")

    transaction = root.transaction
    transport = token.session.transport
    if (
        transport.transport_id,
        transport.zeek_uid,
        transport.conn_id,
        transport.source_ip,
        transport.source_port,
        transport.server_ip,
        transport.server_port,
        transport.opened_at,
        transport.closes_at,
    ) != (
        transaction.stable_id,
        transaction.zeek_uid,
        transaction.conn_id,
        transaction.src_ip,
        transaction.src_port,
        transaction.dst_ip,
        transaction.dst_port,
        transaction.started_at,
        transaction.closed_at,
    ):
        raise StateError("Deferred SSH manager admission targets another network transport")
    common = token.application_token
    common_identity = common.identity
    assert common_identity is not None
    if (
        common_identity.channel_id != token.session.channel_id
        or common_identity.owner_id != token.session.owner_id
        or common_identity.opened_at != token.session.binding.ready_at
        or common.reservation.operation_id != token.operation.operation_id
        or common.reservation.channel_id != token.operation.channel_id
        or common.reservation.started_at != token.operation.started_at
        or common.reservation.ended_at != token.operation.ended_at
    ):
        raise StateError("Deferred SSH common and manager admissions disagree")

    batch = root.state_plan.batch
    session_plan = batch.session if batch is not None else None
    binding = token.session.binding
    if session_plan is not None:
        identity = session_plan.identity
        if (
            binding.hostname,
            binding.logon_id,
            binding.session_object_id,
            binding.lifecycle_group_id,
            binding.principal,
        ) != (
            identity.hostname.casefold(),
            identity.logon_id,
            identity.object_id,
            identity.lifecycle_group_id,
            identity.principal.casefold(),
        ):
            raise StateError("Deferred SSH manager session disagrees with staged State identity")
        if token.session.affinity.server_session_object_id != identity.object_id:
            raise StateError("Deferred SSH affinity targets another staged session")
    lifecycle_binding = lifecycle_token.request.binding_identity
    if (
        lifecycle_binding is None
        or lifecycle_binding.session_object_id != binding.session_object_id
    ):
        raise StateError("Deferred SSH lifecycle and manager session bindings disagree")
    if not transport.opened_at <= binding.ready_at < transport.closes_at:
        raise StateError("Deferred SSH readiness must lie inside the transport")
    _validate_ssh_process_holds(root.state_plan.process_activity, transport)


def _validate_ssh_process_holds(
    process_activity: tuple[ProcessActivityPatch, ...],
    transport: SshTransportPlan,
) -> None:
    manager_holds = tuple(
        hold for hold in (transport.source_process, transport.receiver_process) if hold is not None
    )
    patches = {patch.identity.object_id: patch for patch in process_activity}
    if {hold.process_object_id for hold in manager_holds} != set(patches):
        raise StateError("Deferred SSH process holds disagree with State activity owners")
    for hold in manager_holds:
        if type(hold) is not SshProcessHold:
            raise StateError("Deferred SSH transport has an unsupported process hold")
        patch = patches[hold.process_object_id]
        identity = patch.identity
        if (
            identity.hostname.casefold(),
            identity.pid,
            identity.object_id,
            identity.started_at,
            patch.activity_time,
        ) != (
            hold.hostname,
            hold.pid,
            hold.process_object_id,
            hold.started_at,
            hold.required_until,
        ):
            raise StateError("Deferred SSH process hold disagrees with State identity")


def _validate_rdp_token(
    root: PreparedNetworkTransactionRoot,
    lifecycle_token: LifecycleClosedTransportAdmissionToken,
    token: RdpSessionAdmissionToken,
) -> None:
    if token.kind not in {"open", "reconnect"}:
        raise StateError("Deferred RDP manager admission has an unsupported kind")
    if type(token.session) is not RdpSessionSnapshot:
        raise StateError("Deferred RDP manager token has an unsupported snapshot")
    if token.session.state is not RdpSessionState.CONNECTED:
        raise StateError("Deferred RDP admission must publish a connected snapshot")
    if type(token.transport_ids) is not tuple or not token.transport_ids:
        raise StateError("Deferred RDP manager token requires ordered transport identities")
    if len(set(token.transport_ids)) != len(token.transport_ids):
        raise StateError("Deferred RDP manager token repeats a transport identity")
    if token.transport_ids[-1] != root.state_plan.physical_transport_id:
        raise StateError("Deferred RDP manager admission targets another current transport")
    if token.kind == "open" and len(token.transport_ids) != 1:
        raise StateError("Deferred RDP open must own exactly one transport")
    if token.kind == "reconnect" and len(token.transport_ids) != 2:
        raise StateError("Deferred RDP reconnect must bind prior and current transports")

    generation = token.session.generation
    fingerprint = root.state_plan.physical_transport_fingerprint
    if (
        generation.binding.transport_id,
        generation.binding.opened_at,
        generation.binding.closes_at,
        generation.connected_at,
    ) != (
        fingerprint.transport_id,
        fingerprint.started_at,
        fingerprint.closed_at,
        fingerprint.started_at,
    ):
        raise StateError("Deferred RDP generation disagrees with the current transport")
    if generation.ordinal != token.expected_generation:
        raise StateError("Deferred RDP expected generation disagrees with its snapshot")
    if token.kind == "open" and token.expected_generation != 0:
        raise StateError("Deferred RDP open must create generation zero")
    if token.kind == "reconnect" and token.expected_generation <= 0:
        raise StateError("Deferred RDP reconnect must advance a prior generation")

    common = token.application_token
    common_identity = common.identity
    assert common_identity is not None
    if (
        common_identity.channel_id != generation.channel_id
        or common_identity.owner_id != token.session.identity.owner_id
        or common.reservation.operation_id != token.operation_id
        or common.reservation.channel_id != generation.channel_id
    ):
        raise StateError("Deferred RDP common and manager admissions disagree")
    affinity = token.session.identity.affinity
    transaction = root.transaction
    if affinity.source_address != transaction.src_ip.casefold() or (
        affinity.target_address != transaction.dst_ip.casefold()
    ):
        raise StateError("Deferred RDP affinity disagrees with the network endpoints")

    batch = root.state_plan.batch
    session_plan = batch.session if batch is not None else None
    existing_patch = root.state_plan.existing_session_patch
    identity = (
        session_plan.identity
        if session_plan is not None
        else existing_patch.after.identity
        if existing_patch is not None
        else None
    )
    logon_type = (
        session_plan.logon_type
        if session_plan is not None
        else existing_patch.after.logon_type
        if existing_patch is not None
        else None
    )
    if identity is None or logon_type != 10 or identity.session_kind.casefold() != "rdp":
        raise StateError("Deferred RDP admission requires an exact Type 10 State session")
    if (
        token.session.identity.logical_session_id,
        affinity.target_host,
        affinity.principal,
        affinity.logon_id,
        affinity.session_id,
    ) != (
        identity.object_id,
        identity.hostname.casefold().rstrip("."),
        identity.principal.casefold(),
        identity.logon_id.casefold(),
        identity.session_id,
    ):
        raise StateError("Deferred RDP manager session disagrees with its State identity")
    end_plan = (
        session_plan.end_plan
        if session_plan is not None
        else existing_patch.after.end_plan
        if existing_patch is not None
        else None
    )
    if end_plan is not None and end_plan.canonical_end != token.session.identity.hard_deadline:
        raise StateError("Deferred RDP manager deadline disagrees with its State end plan")
    if token.kind == "reconnect":
        if session_plan is not None:
            raise StateError("Deferred RDP reconnect cannot stage a second session identity")
        if (
            existing_patch is None
            or existing_patch.lifecycle_disposition
            is not ConnectionExistingSessionLifecycleDisposition.EXISTING
        ):
            raise StateError("Deferred RDP reconnect requires an existing live State session")

    lifecycle_binding = lifecycle_token.request.binding_identity
    if lifecycle_binding is None or (
        lifecycle_binding.session_object_id != token.session.identity.logical_session_id
    ):
        raise StateError("Deferred RDP lifecycle and manager session bindings disagree")


def _validate_dispatches(
    transport: PreparedDispatch,
    dependents: tuple[PreparedDispatch, ...],
) -> None:
    if type(transport) is not PreparedDispatch:
        raise TypeError("Deferred session transport dispatch must be exact")
    if type(dependents) is not tuple:
        raise TypeError("Deferred session dependent dispatches must be an exact tuple")
    if any(type(dispatch) is not PreparedDispatch for dispatch in dependents):
        raise TypeError("Deferred session dependent dispatch has an unsupported exact type")
    ordered = (transport, *dependents)
    if len({id(dispatch) for dispatch in ordered}) != len(ordered):
        raise StateError("Deferred session repeats an exact dispatch object")
    occurrence_ids = tuple(dispatch.occurrence_id for dispatch in ordered)
    if any(type(occurrence_id) is not str or not occurrence_id for occurrence_id in occurrence_ids):
        raise StateError("Deferred session dispatch requires a stable occurrence identity")
    if len(set(occurrence_ids)) != len(occurrence_ids):
        raise StateError("Deferred session repeats a dispatch occurrence identity")


def _composition_integrity_preimage(
    coordinator_id: str,
    values: _DeferredSessionCompositionValues,
) -> tuple[object, ...]:
    root = values.prepared_root
    state_plan = root.state_plan
    fingerprint = state_plan.physical_transport_fingerprint
    timing_token = values.source_timing_preparation.binding_token
    lifecycle_token = values.lifecycle_token
    request = lifecycle_token.request
    application = values.application_token
    application_preimage: tuple[object, ...]
    if application is None:
        application_preimage = ()
    else:
        application_preimage = (
            id(application),
            application.publication_token,
            id(application.application_token),
            application.application_token.publication_token,
            repr(application),
        )
    member_preimage = tuple(
        (
            id(binding),
            id(binding.state_member),
            binding.state_member.publication_token,
            id(binding.lifecycle_member),
            binding.lifecycle_member.publication_token,
            binding.lifecycle_member.request.identity.object_id,
        )
        for binding in values.state_members
    )
    existing_binding = values.existing_state_session
    existing_preimage = (
        ()
        if existing_binding is None
        else (
            id(existing_binding),
            id(existing_binding.state_patch),
            existing_binding.state_patch,
            (
                ()
                if existing_binding.lifecycle_member is None
                else (
                    id(existing_binding.lifecycle_member),
                    existing_binding.lifecycle_member.publication_token,
                    existing_binding.lifecycle_member.request.identity.object_id,
                )
            ),
        )
    )
    dispatch_preimage = tuple(
        (id(dispatch), dispatch.occurrence_id)
        for dispatch in (values.transport_dispatch, *values.dependent_dispatches)
    )
    state_authority = values.state_authority
    state_authority_preimage = (
        ()
        if state_authority is None
        else (
            id(state_authority),
            state_authority.publication_token,
            state_authority.protocol,
            state_authority.binding_disposition,
            state_authority.bound_at,
            id(state_authority.batch),
            state_authority.batch.publication_token,
            id(state_authority.existing_session_patch),
            id(state_authority.existing_session_process_roles_patch),
        )
    )
    return (
        "deferred-session-composition-v3",
        coordinator_id,
        values.kind.value,
        values.binding_disposition,
        state_authority_preimage,
        id(root),
        id(root.transaction),
        id(state_plan),
        id(root.runtime_token),
        id(root.result),
        root.runtime_token.publication_token,
        state_plan.publication_token,
        repr(root.result),
        root.transaction.stable_id,
        root.transaction.conn_id,
        root.transaction.zeek_uid,
        fingerprint,
        state_plan.expected_version,
        state_plan.final_state_time,
        id(values.source_timing_preparation),
        id(timing_token),
        timing_token.preparation_id,
        timing_token.base_state_digest,
        values.source_timing_preparation.overlay_digest,
        id(lifecycle_token),
        lifecycle_token.publication_token,
        id(request),
        request.start_plan_tokens,
        request.identity,
        request.binding_identity,
        request.process_holds,
        member_preimage,
        existing_preimage,
        application_preimage,
        dispatch_preimage,
    )


__all__ = [
    "DeferredSessionApplicationToken",
    "DeferredSessionComposition",
    "DeferredSessionCompositionCoordinator",
    "DeferredSessionExistingStateBinding",
    "DeferredSessionKind",
    "DeferredSessionStateMemberBinding",
]
