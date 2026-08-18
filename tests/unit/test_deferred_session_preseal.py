# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Pure structural contracts for deferred SSH/RDP pre-seal handoff values."""

import random
from collections.abc import Callable
from copy import copy
from dataclasses import FrozenInstanceError, dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from evidenceforge.events.contracts import EventKind
from evidenceforge.events.dispatcher import PreparedDispatch
from evidenceforge.events.identity import ProcessIdentity, SessionIdentity, ThreadIdentity
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.generation.deferred_session_preseal import (
    DeferredSessionActivitySpec,
    DeferredSessionBindingDisposition,
    DeferredSessionBoundSessionSpec,
    DeferredSessionDependentOccurrenceSpec,
    DeferredSessionEndpoint,
    DeferredSessionEntityKind,
    DeferredSessionIdentitySpec,
    DeferredSessionOsFamily,
    DeferredSessionPresealPayload,
    DeferredSessionPrincipal,
    DeferredSessionProcessHoldSpec,
    DeferredSessionProcessMemberSpec,
    DeferredSessionProcessRole,
    DeferredSessionProtocol,
    DeferredSessionSessionMemberSpec,
    DeferredSessionStateStartOccurrenceSpec,
    DeferredSessionTransportPolicy,
    DeferredSessionTransportSpec,
    RdpDeferredAdmissionSpec,
    RdpDeferredSessionIntent,
    RdpDeferredSessionMode,
    RdpOpenAdmissionSpec,
    RdpReconnectAdmissionSpec,
    SshDeferredAdmissionSpec,
    SshDeferredAuthenticationMethod,
    SshDeferredOperationKind,
    SshDeferredSessionIntent,
)
from evidenceforge.generation.network_runtime import (
    NetworkTransactionPreparation,
    NetworkTransactionPreparationToken,
)
from evidenceforge.generation.rdp_sessions import RdpSessionAdmissionToken
from evidenceforge.generation.source_timing import (
    SourceTimingPreparation,
    SourceTimingPreparationToken,
)
from evidenceforge.generation.ssh_channels import SshChannelAdmissionToken
from evidenceforge.generation.state_manager import (
    ConnectionPlanningCursor,
    MaterializationBatchBuilder,
)

_OPEN = datetime(2026, 8, 17, 13, 0, tzinfo=UTC)
_AUTH = _OPEN + timedelta(milliseconds=100)
_READY = _OPEN + timedelta(milliseconds=200)
_CLOSE = _OPEN + timedelta(seconds=30)
_HARD_DEADLINE = _OPEN + timedelta(hours=1)


@dataclass(frozen=True, slots=True)
class _EndpointLookalike:
    """Structurally similar data must not pass an exact public-type boundary."""

    address: str
    hostname: str
    os_family: DeferredSessionOsFamily


class _TupleSubclass(tuple[object, ...]):
    """Tuple subclasses are not exact immutable public-contract containers."""


def _tamper(value: object, field_name: str, replacement: object) -> object:
    """Return a shallow copy with one frozen slot changed without revalidation."""

    result = copy(value)
    object.__setattr__(result, field_name, replacement)
    return result


def _session_identity(protocol: DeferredSessionProtocol) -> SessionIdentity:
    """Return a positive, immutable protocol-appropriate session identity."""

    is_ssh = protocol is DeferredSessionProtocol.SSH
    return SessionIdentity(
        hostname="db-01.example.test" if is_ssh else "rdp-01.example.test",
        object_id="ssh-session-1" if is_ssh else "rdp-session-1",
        logon_id="0x1001" if is_ssh else "0x2001",
        session_id=42 if is_ssh else 7,
        principal="analyst" if is_ssh else "EXAMPLE\\analyst",
        session_kind="ssh" if is_ssh else "rdp",
        started_at=_AUTH,
        lifecycle_group_id="ssh-lifecycle-1" if is_ssh else "rdp-lifecycle-1",
        logon_guid="{11111111-1111-1111-1111-111111111111}" if not is_ssh else "",
    )


def _identity_spec(protocol: DeferredSessionProtocol) -> DeferredSessionIdentitySpec:
    return DeferredSessionIdentitySpec(identity=_session_identity(protocol), logon_type=10)


def _transport_policy() -> DeferredSessionTransportPolicy:
    return DeferredSessionTransportPolicy(
        requested_source_port=50_001,
        duration_min=timedelta(seconds=10),
        duration_max=timedelta(seconds=60),
        initiator_bytes_min=100,
        initiator_bytes_max=10_000,
        responder_bytes_min=100,
        responder_bytes_max=20_000,
    )


def _transport(protocol: DeferredSessionProtocol) -> DeferredSessionTransportSpec:
    is_ssh = protocol is DeferredSessionProtocol.SSH
    return DeferredSessionTransportSpec(
        transaction_id="ssh-transport-1" if is_ssh else "rdp-transport-1",
        conn_id="C000000000000001" if is_ssh else "C000000000000002",
        zeek_uid="C1ssh" if is_ssh else "C1rdp",
        source_address="10.0.0.10",
        source_port=50_001,
        target_address="10.0.0.20",
        target_port=22 if is_ssh else 3389,
        opened_at=_OPEN,
        closes_at=_CLOSE,
        initiator_bytes=4_000,
        responder_bytes=8_000,
        conn_state="SF",
    )


def _ssh_intent() -> SshDeferredSessionIntent:
    return SshDeferredSessionIntent(
        source=DeferredSessionEndpoint(
            address="10.0.0.10",
            hostname="ws-01.example.test",
            os_family=DeferredSessionOsFamily.LINUX,
        ),
        target=DeferredSessionEndpoint(
            address="10.0.0.20",
            hostname="db-01.example.test",
            os_family=DeferredSessionOsFamily.LINUX,
        ),
        principal=DeferredSessionPrincipal(
            username="analyst",
            principal="analyst",
            uid=1001,
        ),
        identity=_identity_spec(DeferredSessionProtocol.SSH),
        transport_policy=_transport_policy(),
        authentication_method=SshDeferredAuthenticationMethod.PASSWORD,
        operation_kind=SshDeferredOperationKind.EXEC,
        operation_semantic_id="ssh-command-1",
        authentication_time=_AUTH,
        ready_time=_READY,
        end_plan=SessionEndPlan(_CLOSE, "action_bundle"),
    )


def _rdp_intent(
    mode: RdpDeferredSessionMode = RdpDeferredSessionMode.OPEN,
) -> RdpDeferredSessionIntent:
    generation = None if mode is RdpDeferredSessionMode.OPEN else 1
    identity = _session_identity(DeferredSessionProtocol.RDP)
    if mode is RdpDeferredSessionMode.RECONNECT:
        identity = replace(identity, started_at=_OPEN - timedelta(minutes=10))
    return RdpDeferredSessionIntent(
        source=DeferredSessionEndpoint(
            address="10.0.0.10",
            hostname="ws-01.example.test",
            os_family=DeferredSessionOsFamily.WINDOWS,
        ),
        target=DeferredSessionEndpoint(
            address="10.0.0.20",
            hostname="rdp-01.example.test",
            os_family=DeferredSessionOsFamily.WINDOWS,
        ),
        principal=DeferredSessionPrincipal(
            username="analyst",
            principal="EXAMPLE\\analyst",
            sid="S-1-5-21-1000-1000-1000-1105",
        ),
        identity=DeferredSessionIdentitySpec(identity=identity, logon_type=10),
        transport_policy=_transport_policy(),
        mode=mode,
        authentication_time=_AUTH,
        hard_deadline=_HARD_DEADLINE,
        logical_session_id="rdp-logical-session-1",
        expected_generation=generation,
        end_plan=SessionEndPlan(_HARD_DEADLINE, "action_bundle"),
    )


def _ssh_process_identity(*, shell: bool) -> ProcessIdentity:
    return ProcessIdentity(
        hostname="db-01.example.test",
        object_id="ssh-shell-1" if shell else "ssh-responder-1",
        pid=4_202 if shell else 4_201,
        parent_pid=4_201 if shell else 1,
        image="/bin/bash" if shell else "/usr/sbin/sshd",
        command_line="/bin/bash" if shell else "sshd: analyst@pts/0",
        principal="analyst" if shell else "root",
        logon_id="0x1001",
        started_at=_READY + timedelta(milliseconds=10)
        if shell
        else _AUTH + timedelta(milliseconds=10),
        lifecycle_group_id="ssh-shell-lifecycle-1" if shell else "ssh-responder-lifecycle-1",
        parent_lifecycle_group_id="ssh-responder-lifecycle-1" if shell else "",
    )


def _rdp_source_process_identity() -> ProcessIdentity:
    return ProcessIdentity(
        hostname="ws-01.example.test",
        object_id="rdp-source-client-1",
        pid=3_389,
        parent_pid=2_000,
        image=r"C:\Windows\System32\mstsc.exe",
        command_line="mstsc.exe /v:rdp-01.example.test",
        principal="EXAMPLE\\analyst",
        logon_id="0x3001",
        started_at=_OPEN + timedelta(milliseconds=10),
        lifecycle_group_id="rdp-source-client-lifecycle-1",
    )


def _ssh_payload() -> DeferredSessionPresealPayload:
    intent = _ssh_intent()
    session_identity = intent.identity.identity
    session_member = DeferredSessionSessionMemberSpec(
        member_id="session",
        identity=session_identity,
        logon_type=10,
        source_address=intent.source.address,
        source_port=50_001,
        auth_protocol="ssh",
    )
    responder = DeferredSessionProcessMemberSpec(
        member_id="responder",
        identity=_ssh_process_identity(shell=False),
        role=DeferredSessionProcessRole.SSH_RECEIVER,
        session_member_id="session",
    )
    shell = DeferredSessionProcessMemberSpec(
        member_id="shell",
        identity=_ssh_process_identity(shell=True),
        role=DeferredSessionProcessRole.SSH_SHELL,
        parent_member_id="responder",
        session_member_id="session",
    )
    state_members = (session_member, responder, shell)
    state_starts = (
        DeferredSessionStateStartOccurrenceSpec(
            occurrence_id="ssh-logon-1",
            event_type=EventKind.LOGON,
            canonical_time=_AUTH,
            member_id="session",
            publication_ordinal=1,
        ),
        DeferredSessionStateStartOccurrenceSpec(
            occurrence_id="ssh-responder-create-1",
            event_type=EventKind.PROCESS_CREATE,
            canonical_time=responder.identity.started_at,
            member_id="responder",
            publication_ordinal=2,
        ),
        DeferredSessionStateStartOccurrenceSpec(
            occurrence_id="ssh-shell-create-1",
            event_type=EventKind.PROCESS_CREATE,
            canonical_time=shell.identity.started_at,
            member_id="shell",
            publication_ordinal=3,
        ),
    )
    dependents = (
        DeferredSessionDependentOccurrenceSpec(
            occurrence_id="ssh-accepted-1",
            event_type=EventKind.SYSLOG,
            canonical_time=_READY + timedelta(milliseconds=20),
            member_references=("session", "responder"),
            publication_ordinal=4,
        ),
        DeferredSessionDependentOccurrenceSpec(
            occurrence_id="ssh-session-observation-1",
            event_type=EventKind.SSH_SESSION,
            canonical_time=_READY + timedelta(milliseconds=30),
            member_references=("session", "shell"),
            publication_ordinal=5,
        ),
    )
    return DeferredSessionPresealPayload(
        protocol=DeferredSessionProtocol.SSH,
        intent=intent,
        transport=_transport(DeferredSessionProtocol.SSH),
        state_members=state_members,
        activity=(
            DeferredSessionActivitySpec(
                entity_kind=DeferredSessionEntityKind.SESSION,
                object_id=session_identity.object_id,
                activity_time=_CLOSE,
            ),
            DeferredSessionActivitySpec(
                entity_kind=DeferredSessionEntityKind.PROCESS,
                object_id=responder.identity.object_id,
                activity_time=_CLOSE,
            ),
        ),
        process_holds=(
            DeferredSessionProcessHoldSpec(
                hold_id="ssh-receiver-transport-hold",
                process_object_id=responder.identity.object_id,
                acquired_at=responder.identity.started_at,
                hold_until=_CLOSE,
                action_id="ssh-transport-1",
                reason="canonical_transport_close",
            ),
        ),
        bound_session=DeferredSessionBoundSessionSpec(
            reference_id="session",
            binding_disposition=DeferredSessionBindingDisposition.NEW_SESSION,
            identity=session_identity,
            source_address=intent.source.address,
            source_port=50_001,
            transport_process_object_id=responder.identity.object_id,
            network_close_time=_CLOSE,
            source_ready_time=_READY,
            closure_owned_by_bundle=True,
            end_plan=intent.end_plan,
        ),
        application_admission=SshDeferredAdmissionSpec(
            channel_id="ssh-channel-1",
            operation_id="ssh-operation-1",
            semantic_operation_id=intent.operation_semantic_id,
            authentication_method=intent.authentication_method,
            operation_kind=intent.operation_kind,
            started_at=_READY,
            ended_at=_CLOSE,
            initiator_bytes=4_000,
            responder_bytes=8_000,
        ),
        state_starts=state_starts,
        dependents=dependents,
    )


def _rdp_admission(mode: RdpDeferredSessionMode) -> RdpDeferredAdmissionSpec:
    common: dict[str, object] = {
        "logical_session_id": "rdp-logical-session-1",
        "operation_id": "rdp-operation-1",
        "connected_at": _OPEN,
        "hard_deadline": _HARD_DEADLINE,
        "initiator_bytes": 4_000,
        "responder_bytes": 8_000,
    }
    if mode is RdpDeferredSessionMode.OPEN:
        return RdpOpenAdmissionSpec(**common)
    return RdpReconnectAdmissionSpec(
        **common,
        expected_generation=1,
        prior_transport_id="rdp-transport-0",
        current_transport_id="rdp-transport-1",
    )


def _rdp_payload(
    mode: RdpDeferredSessionMode = RdpDeferredSessionMode.OPEN,
) -> DeferredSessionPresealPayload:
    intent = _rdp_intent(mode)
    identity = intent.identity.identity
    is_open = mode is RdpDeferredSessionMode.OPEN
    bound_session_reference = "session" if is_open else "existing-rdp-session"
    state_members = (
        (
            DeferredSessionSessionMemberSpec(
                member_id="session",
                identity=identity,
                logon_type=10,
                source_address=intent.source.address,
                source_port=50_001,
                auth_protocol="rdp",
            ),
        )
        if is_open
        else ()
    )
    state_starts = (
        (
            DeferredSessionStateStartOccurrenceSpec(
                occurrence_id="rdp-logon-1",
                event_type=EventKind.LOGON,
                canonical_time=_AUTH,
                member_id="session",
                publication_ordinal=1,
            ),
        )
        if is_open
        else ()
    )
    dependent_ordinal = 2 if is_open else 1
    return DeferredSessionPresealPayload(
        protocol=DeferredSessionProtocol.RDP,
        intent=intent,
        transport=_transport(DeferredSessionProtocol.RDP),
        state_members=state_members,
        activity=(
            DeferredSessionActivitySpec(
                entity_kind=DeferredSessionEntityKind.SESSION,
                object_id=identity.object_id,
                activity_time=_CLOSE,
            ),
        ),
        process_holds=(),
        bound_session=DeferredSessionBoundSessionSpec(
            reference_id=bound_session_reference,
            binding_disposition=(
                DeferredSessionBindingDisposition.NEW_SESSION
                if is_open
                else DeferredSessionBindingDisposition.ACTIVE_SESSION
            ),
            identity=identity,
            source_address=intent.source.address,
            source_port=50_001,
            transport_process_object_id="",
            network_close_time=_CLOSE,
            source_ready_time=_READY,
            closure_owned_by_bundle=is_open,
            end_plan=intent.end_plan,
        ),
        application_admission=_rdp_admission(mode),
        state_starts=state_starts,
        dependents=(
            DeferredSessionDependentOccurrenceSpec(
                occurrence_id="rdp-auth-observation-1",
                event_type=EventKind.WFP_CONNECTION,
                canonical_time=_READY,
                member_references=(bound_session_reference,),
                publication_ordinal=dependent_ordinal,
            ),
        ),
    )


@pytest.mark.parametrize(
    "payload_factory",
    (
        pytest.param(_ssh_payload, id="ssh-initial"),
        pytest.param(_rdp_payload, id="rdp-open"),
        pytest.param(
            lambda: _rdp_payload(RdpDeferredSessionMode.RECONNECT),
            id="rdp-reconnect",
        ),
    ),
)
def test_valid_preseal_payloads_are_frozen_inert_and_transport_first(
    payload_factory: Callable[[], DeferredSessionPresealPayload],
) -> None:
    payload = payload_factory()

    assert payload.transport_ordinal == 0
    assert tuple(
        occurrence.publication_ordinal
        for occurrence in (*payload.state_starts, *payload.dependents)
    ) == tuple(range(1, 1 + len(payload.state_starts) + len(payload.dependents)))
    assert type(payload.state_members) is tuple
    assert type(payload.activity) is tuple
    assert type(payload.process_holds) is tuple
    assert type(payload.state_starts) is tuple
    assert type(payload.dependents) is tuple
    assert not hasattr(payload, "__dict__")
    with pytest.raises((FrozenInstanceError, AttributeError)):
        payload.protocol = DeferredSessionProtocol.RDP


@pytest.mark.parametrize(
    "disposition",
    (
        DeferredSessionBindingDisposition.PREALLOCATED_SESSION_START,
        DeferredSessionBindingDisposition.ACTIVE_SESSION,
    ),
)
def test_ssh_existing_binding_reuses_exact_bound_session_without_second_start(
    disposition: DeferredSessionBindingDisposition,
) -> None:
    payload = _ssh_payload()
    session, responder, shell = payload.state_members
    assert isinstance(session, DeferredSessionSessionMemberSpec)
    assert isinstance(responder, DeferredSessionProcessMemberSpec)
    assert isinstance(shell, DeferredSessionProcessMemberSpec)
    reference_id = "existing-ssh-session"
    responder = replace(responder, session_member_id=reference_id)
    shell = replace(shell, session_member_id=reference_id)
    starts = tuple(
        replace(start, publication_ordinal=ordinal)
        for ordinal, start in enumerate(payload.state_starts[1:], start=1)
    )
    dependents = tuple(
        replace(
            dependent,
            member_references=tuple(
                reference_id if reference == "session" else reference
                for reference in dependent.member_references
            ),
            publication_ordinal=len(starts) + ordinal,
        )
        for ordinal, dependent in enumerate(payload.dependents, start=1)
    )

    existing = replace(
        payload,
        state_members=(responder, shell),
        bound_session=replace(
            payload.bound_session,
            reference_id=reference_id,
            binding_disposition=disposition,
        ),
        state_starts=starts,
        dependents=dependents,
    )

    assert existing.bound_session.binding_disposition is disposition
    assert all(
        not isinstance(member, DeferredSessionSessionMemberSpec)
        for member in existing.state_members
    )


@pytest.mark.parametrize(
    ("mode", "disposition", "message"),
    (
        (
            RdpDeferredSessionMode.OPEN,
            DeferredSessionBindingDisposition.ACTIVE_SESSION,
            "RDP open",
        ),
        (
            RdpDeferredSessionMode.RECONNECT,
            DeferredSessionBindingDisposition.NEW_SESSION,
            "RDP reconnect",
        ),
        (
            RdpDeferredSessionMode.RECONNECT,
            DeferredSessionBindingDisposition.PREALLOCATED_SESSION_START,
            "RDP reconnect",
        ),
    ),
)
def test_rdp_protocol_mode_rejects_wrong_binding_disposition(
    mode: RdpDeferredSessionMode,
    disposition: DeferredSessionBindingDisposition,
    message: str,
) -> None:
    payload = _rdp_payload(mode)

    with pytest.raises(ValueError, match=message):
        replace(
            payload,
            bound_session=replace(
                payload.bound_session,
                binding_disposition=disposition,
            ),
        )


def test_binding_disposition_rejects_wrong_state_session_cardinality() -> None:
    new_payload = _ssh_payload()
    with pytest.raises(ValueError, match="session"):
        replace(new_payload, state_members=new_payload.state_members[1:])

    with pytest.raises(ValueError, match="cannot start another State session"):
        replace(
            new_payload,
            bound_session=replace(
                new_payload.bound_session,
                binding_disposition=(DeferredSessionBindingDisposition.PREALLOCATED_SESSION_START),
            ),
        )


def test_bound_session_requires_exact_binding_disposition_type() -> None:
    payload = _ssh_payload()

    with pytest.raises(TypeError, match="binding disposition|exact type"):
        replace(
            payload.bound_session,
            binding_disposition=DeferredSessionBindingDisposition.NEW_SESSION.value,
        )


def _forged_instance(type_: type[object]) -> object:
    return object.__new__(type_)


_FORBIDDEN_VALUES: tuple[object, ...] = (
    pytest.param(lambda: None, id="callback"),
    pytest.param(random.Random(17), id="rng"),
    pytest.param(_forged_instance(ConnectionPlanningCursor), id="state-cursor"),
    pytest.param(_forged_instance(MaterializationBatchBuilder), id="state-builder"),
    pytest.param(_forged_instance(NetworkTransactionPreparation), id="network-preparation"),
    pytest.param(_forged_instance(SourceTimingPreparation), id="timing-preparation"),
    pytest.param(
        _forged_instance(NetworkTransactionPreparationToken),
        id="network-preparation-token",
    ),
    pytest.param(
        _forged_instance(SourceTimingPreparationToken),
        id="timing-preparation-token",
    ),
    pytest.param(_forged_instance(SshChannelAdmissionToken), id="ssh-manager-token"),
    pytest.param(_forged_instance(RdpSessionAdmissionToken), id="rdp-manager-token"),
    pytest.param(_forged_instance(PreparedDispatch), id="prepared-dispatch"),
)


@pytest.mark.parametrize("forbidden", _FORBIDDEN_VALUES)
def test_intent_recursively_rejects_active_capabilities(forbidden: object) -> None:
    intent = _ssh_intent()
    tainted_source = _tamper(intent.source, "hostname", forbidden)

    with pytest.raises((TypeError, ValueError), match="inert|type|hostname|capability"):
        replace(intent, source=tainted_source)


@pytest.mark.parametrize("forbidden", _FORBIDDEN_VALUES)
def test_payload_recursively_rejects_active_capabilities(forbidden: object) -> None:
    payload = _ssh_payload()
    tainted_transport = _tamper(payload.transport, "conn_id", forbidden)

    with pytest.raises((TypeError, ValueError), match="inert|type|conn_id|capability"):
        replace(payload, transport=tainted_transport)


def test_payload_recursively_validates_primary_thread_identity_and_ownership() -> None:
    payload = _ssh_payload()
    receiver = payload.state_members[1]
    assert isinstance(receiver, DeferredSessionProcessMemberSpec)
    thread = ThreadIdentity(
        hostname=receiver.identity.hostname,
        process_object_id=receiver.identity.object_id,
        pid=receiver.identity.pid,
        tid=receiver.identity.pid,
        object_id="ssh-responder-thread-1",
        started_at=receiver.identity.started_at,
        kind="main",
    )
    receiver_with_thread = replace(
        receiver,
        identity=replace(receiver.identity, primary_thread=thread),
    )
    with_thread = replace(
        payload,
        state_members=(payload.state_members[0], receiver_with_thread, payload.state_members[2]),
    )

    assert receiver_with_thread.identity.primary_thread == thread
    tainted_thread = _tamper(thread, "object_id", random.Random(23))
    tainted_receiver = _tamper(receiver_with_thread.identity, "primary_thread", tainted_thread)
    with pytest.raises((TypeError, ValueError), match="thread|object|inert|type"):
        replace(
            with_thread,
            state_members=(
                with_thread.state_members[0],
                _tamper(receiver_with_thread, "identity", tainted_receiver),
                with_thread.state_members[2],
            ),
        )
    mismatched_thread = _tamper(thread, "process_object_id", "different-process")
    mismatched_receiver = _tamper(
        receiver_with_thread.identity, "primary_thread", mismatched_thread
    )
    with pytest.raises((TypeError, ValueError), match="thread|owning|process|reference"):
        replace(
            with_thread,
            state_members=(
                with_thread.state_members[0],
                _tamper(receiver_with_thread, "identity", mismatched_receiver),
                with_thread.state_members[2],
            ),
        )


@pytest.mark.parametrize(
    "mutable",
    (
        pytest.param([], id="list"),
        pytest.param({}, id="dict"),
        pytest.param(set(), id="set"),
        pytest.param(bytearray(b"mutable"), id="bytearray"),
    ),
)
def test_public_contracts_recursively_reject_mutable_containers(mutable: object) -> None:
    intent = _ssh_intent()
    payload = _ssh_payload()
    tainted_principal = _tamper(intent.principal, "principal", mutable)
    tainted_dependent = _tamper(payload.dependents[0], "member_references", mutable)

    with pytest.raises((TypeError, ValueError), match="inert|type|principal|mutable"):
        replace(intent, principal=tainted_principal)
    with pytest.raises((TypeError, ValueError), match="inert|tuple|references|mutable"):
        replace(payload, dependents=(tainted_dependent, *payload.dependents[1:]))


def test_public_contracts_require_exact_enum_and_dataclass_types() -> None:
    endpoint = _ssh_intent().source
    intent = _ssh_intent()
    payload = _ssh_payload()
    bad_occurrence = _tamper(payload.state_starts[0], "event_type", EventKind.LOGON.value)
    endpoint_lookalike = _EndpointLookalike(
        address=endpoint.address,
        hostname=endpoint.hostname,
        os_family=endpoint.os_family,
    )

    with pytest.raises((TypeError, ValueError), match="OS|family|exact|type"):
        replace(endpoint, os_family=DeferredSessionOsFamily.LINUX.value)
    with pytest.raises((TypeError, ValueError), match="endpoint|exact|type"):
        replace(intent, source=endpoint_lookalike)
    with pytest.raises((TypeError, ValueError), match="protocol|exact|type"):
        replace(payload, protocol=DeferredSessionProtocol.SSH.value)
    with pytest.raises((TypeError, ValueError), match="event|kind|exact|type"):
        replace(payload, state_starts=(bad_occurrence, *payload.state_starts[1:]))
    with pytest.raises((TypeError, ValueError), match="hostname|empty|normalize"):
        replace(endpoint, hostname=".")


@pytest.mark.parametrize(
    "field_name",
    ("state_members", "activity", "process_holds", "state_starts", "dependents"),
)
def test_payload_rejects_nonexact_tuple_sequence_types(field_name: str) -> None:
    payload = _ssh_payload()
    nonexact = _TupleSubclass(getattr(payload, field_name))

    with pytest.raises((TypeError, ValueError), match="tuple|exact|type"):
        replace(payload, **{field_name: nonexact})

    dependent = payload.dependents[0]
    with pytest.raises((TypeError, ValueError), match="tuple|exact|reference|type"):
        replace(dependent, member_references=_TupleSubclass(dependent.member_references))


@pytest.mark.parametrize(
    ("protocol", "intent", "admission"),
    (
        (
            DeferredSessionProtocol.SSH,
            _rdp_intent(),
            _rdp_admission(RdpDeferredSessionMode.OPEN),
        ),
        (
            DeferredSessionProtocol.RDP,
            _ssh_intent(),
            _ssh_payload().application_admission,
        ),
        (
            DeferredSessionProtocol.RDP,
            _rdp_intent(RdpDeferredSessionMode.OPEN),
            _rdp_admission(RdpDeferredSessionMode.RECONNECT),
        ),
        (
            DeferredSessionProtocol.RDP,
            _rdp_intent(RdpDeferredSessionMode.RECONNECT),
            _rdp_admission(RdpDeferredSessionMode.OPEN),
        ),
    ),
)
def test_payload_rejects_wrong_protocol_intent_or_admission_pairing(
    protocol: DeferredSessionProtocol,
    intent: SshDeferredSessionIntent | RdpDeferredSessionIntent,
    admission: object,
) -> None:
    rdp_mode = (
        intent.mode if type(intent) is RdpDeferredSessionIntent else RdpDeferredSessionMode.OPEN
    )
    base = _ssh_payload() if protocol is DeferredSessionProtocol.SSH else _rdp_payload(rdp_mode)

    with pytest.raises((TypeError, ValueError), match="protocol|intent|admission|mode|pair"):
        replace(base, protocol=protocol, intent=intent, application_admission=admission)


@pytest.mark.parametrize(
    "mutate",
    (
        pytest.param(
            lambda payload: replace(
                payload,
                state_starts=(
                    replace(payload.state_starts[0], publication_ordinal=0),
                    *payload.state_starts[1:],
                ),
            ),
            id="ordinal-zero-reserved-for-transport",
        ),
        pytest.param(
            lambda payload: replace(
                payload,
                state_starts=(
                    payload.state_starts[0],
                    replace(payload.state_starts[1], publication_ordinal=1),
                    *payload.state_starts[2:],
                ),
            ),
            id="duplicate-ordinal",
        ),
        pytest.param(
            lambda payload: replace(
                payload,
                dependents=(
                    replace(payload.dependents[0], publication_ordinal=6),
                    payload.dependents[1],
                ),
            ),
            id="ordinal-gap",
        ),
        pytest.param(
            lambda payload: replace(payload, dependents=tuple(reversed(payload.dependents))),
            id="tuple-order-disagrees-with-ordinals",
        ),
        pytest.param(
            lambda payload: replace(
                payload,
                dependents=(
                    payload.dependents[0],
                    replace(
                        payload.dependents[1],
                        occurrence_id=payload.dependents[0].occurrence_id,
                    ),
                ),
            ),
            id="duplicate-occurrence-id",
        ),
    ),
)
def test_payload_rejects_noncanonical_publication_order(
    mutate: Callable[[DeferredSessionPresealPayload], Any],
) -> None:
    with pytest.raises((TypeError, ValueError), match="ordinal|order|duplicate|occurrence"):
        mutate(_ssh_payload())


def test_payload_rejects_reordered_starts_and_dependents_before_referenced_members() -> None:
    payload = _ssh_payload()
    session_start, receiver_start, shell_start = payload.state_starts

    with pytest.raises((TypeError, ValueError), match="parent|child|member|order"):
        replace(
            payload,
            state_starts=(
                replace(receiver_start, publication_ordinal=1),
                replace(session_start, publication_ordinal=2),
                shell_start,
            ),
        )
    with pytest.raises((TypeError, ValueError), match="dependent|precede|member|start"):
        replace(
            payload,
            dependents=(
                replace(
                    payload.dependents[0],
                    canonical_time=_AUTH + timedelta(milliseconds=5),
                ),
                payload.dependents[1],
            ),
        )
    with pytest.raises((TypeError, ValueError), match="dependent|session|interval"):
        replace(
            payload,
            dependents=(
                payload.dependents[0],
                replace(
                    payload.dependents[1],
                    canonical_time=_CLOSE + timedelta(microseconds=1),
                ),
            ),
        )


@pytest.mark.parametrize(
    "mutate",
    (
        pytest.param(
            lambda payload: replace(payload, state_starts=payload.state_starts[:-1]),
            id="missing-state-start",
        ),
        pytest.param(
            lambda payload: replace(
                payload,
                state_starts=(
                    *payload.state_starts,
                    replace(
                        payload.state_starts[-1],
                        occurrence_id="extra-shell-start",
                        publication_ordinal=4,
                    ),
                ),
                dependents=tuple(
                    replace(item, publication_ordinal=item.publication_ordinal + 1)
                    for item in payload.dependents
                ),
            ),
            id="duplicate-state-start",
        ),
        pytest.param(
            lambda payload: replace(
                payload,
                state_members=(
                    payload.state_members[0],
                    payload.state_members[1],
                    replace(payload.state_members[2], member_id="responder"),
                ),
            ),
            id="duplicate-member-id",
        ),
        pytest.param(
            lambda payload: replace(
                payload,
                state_members=(
                    payload.state_members[0],
                    replace(payload.state_members[1], parent_member_id="shell"),
                    payload.state_members[2],
                ),
            ),
            id="forward-parent-reference",
        ),
        pytest.param(
            lambda payload: replace(
                payload,
                dependents=(
                    replace(payload.dependents[0], member_references=("missing",)),
                    payload.dependents[1],
                ),
            ),
            id="unknown-member-reference",
        ),
        pytest.param(
            lambda payload: replace(
                payload,
                dependents=(
                    replace(payload.dependents[0], member_references=("session", "session")),
                    payload.dependents[1],
                ),
            ),
            id="duplicate-member-reference",
        ),
    ),
)
def test_payload_rejects_member_duplicates_bad_order_and_nonexact_start_coverage(
    mutate: Callable[[DeferredSessionPresealPayload], Any],
) -> None:
    with pytest.raises(
        (TypeError, ValueError), match="member|start|parent|reference|duplicate|order"
    ):
        mutate(_ssh_payload())


def test_payload_rejects_cross_host_process_parent_reference() -> None:
    payload = _ssh_payload()
    session, receiver, shell = payload.state_members
    assert isinstance(receiver, DeferredSessionProcessMemberSpec)
    source_identity = _rdp_source_process_identity()
    source_member = DeferredSessionProcessMemberSpec(
        member_id="source-client",
        identity=source_identity,
        role=DeferredSessionProcessRole.SOURCE_CLIENT,
    )
    cross_host_receiver = replace(
        receiver,
        identity=replace(
            receiver.identity,
            parent_pid=source_identity.pid,
            parent_lifecycle_group_id=source_identity.lifecycle_group_id,
        ),
        parent_member_id=source_member.member_id,
    )

    with pytest.raises((TypeError, ValueError), match="parent|host|same"):
        replace(
            payload,
            state_members=(session, source_member, cross_host_receiver, shell),
        )


@pytest.mark.parametrize(
    ("field_name", "invalid"),
    (
        ("logon_id", ""),
        ("session_id", 0),
        ("principal", "other-user"),
        ("session_kind", "rdp"),
        ("hostname", "other-host.example.test"),
    ),
)
def test_ssh_intent_rejects_invalid_or_inconsistent_logon_identity(
    field_name: str,
    invalid: object,
) -> None:
    intent = _ssh_intent()
    bad_identity = _tamper(intent.identity.identity, field_name, invalid)
    bad_spec = _tamper(intent.identity, "identity", bad_identity)

    with pytest.raises((TypeError, ValueError), match="identity|logon|session|principal|host|SSH"):
        replace(intent, identity=bad_spec)


@pytest.mark.parametrize(
    ("field_name", "invalid"),
    (
        ("logon_id", ""),
        ("session_id", 0),
        ("principal", "other-user"),
        ("session_kind", "ssh"),
        ("hostname", "other-host.example.test"),
    ),
)
def test_rdp_intent_rejects_invalid_or_inconsistent_logon_identity(
    field_name: str,
    invalid: object,
) -> None:
    intent = _rdp_intent()
    bad_identity = _tamper(intent.identity.identity, field_name, invalid)
    bad_spec = _tamper(intent.identity, "identity", bad_identity)

    with pytest.raises((TypeError, ValueError), match="identity|logon|session|principal|host|RDP"):
        replace(intent, identity=bad_spec)


@pytest.mark.parametrize("protocol", (DeferredSessionProtocol.SSH, DeferredSessionProtocol.RDP))
def test_identity_spec_requires_remote_interactive_logon_type_10(
    protocol: DeferredSessionProtocol,
) -> None:
    intent = _ssh_intent() if protocol is DeferredSessionProtocol.SSH else _rdp_intent()
    bad_spec = _tamper(intent.identity, "logon_type", 3)

    with pytest.raises((TypeError, ValueError), match="logon.type|10|remote"):
        replace(intent, identity=bad_spec)


def test_ssh_is_initial_only_and_rdp_mode_generation_shape_is_exact() -> None:
    ssh = _ssh_payload()
    open_intent = _rdp_intent(RdpDeferredSessionMode.OPEN)
    reconnect_intent = _rdp_intent(RdpDeferredSessionMode.RECONNECT)

    assert not hasattr(ssh.intent, "mode")
    with pytest.raises((TypeError, ValueError), match="mode|exact|enum"):
        replace(open_intent, mode=RdpDeferredSessionMode.OPEN.value)
    with pytest.raises((TypeError, ValueError), match="generation|open|reconnect"):
        replace(open_intent, expected_generation=1)
    with pytest.raises((TypeError, ValueError), match="generation|reconnect"):
        replace(reconnect_intent, expected_generation=0)
    with pytest.raises((TypeError, ValueError), match="logical|reconnect|session"):
        replace(reconnect_intent, logical_session_id="")


@pytest.mark.parametrize(
    "changes",
    (
        {"requested_source_port": 0},
        {"requested_source_port": 65_536},
        {"requested_source_port": True},
        {"duration_min": timedelta(0)},
        {"duration_min": timedelta(seconds=61)},
        {"initiator_bytes_min": -1},
        {"initiator_bytes_min": 10_001},
        {"responder_bytes_min": -1},
        {"responder_bytes_min": 20_001},
    ),
)
def test_transport_policy_rejects_invalid_ports_duration_and_budget_bounds(
    changes: dict[str, object],
) -> None:
    with pytest.raises((TypeError, ValueError), match="port|duration|byte|bound|range"):
        replace(_transport_policy(), **changes)


@pytest.mark.parametrize(
    ("field_name", "invalid"),
    (
        ("source_port", 0),
        ("source_port", 65_536),
        ("source_port", True),
        ("target_port", 443),
        ("closes_at", _OPEN),
        ("initiator_bytes", -1),
        ("responder_bytes", -1),
        ("conn_state", "S0"),
    ),
)
def test_resolved_transport_rejects_invalid_ports_interval_budget_and_state(
    field_name: str,
    invalid: object,
) -> None:
    transport = _transport(DeferredSessionProtocol.SSH)

    with pytest.raises((TypeError, ValueError), match="port|close|byte|state|SF|bound"):
        replace(transport, **{field_name: invalid})


@pytest.mark.parametrize(
    "mutate",
    (
        pytest.param(
            lambda payload: replace(
                payload,
                transport=replace(payload.transport, closes_at=_OPEN + timedelta(seconds=61)),
            ),
            id="duration-above-policy",
        ),
        pytest.param(
            lambda payload: replace(
                payload,
                transport=replace(payload.transport, initiator_bytes=10_001),
            ),
            id="initiator-bytes-above-policy",
        ),
        pytest.param(
            lambda payload: replace(
                payload,
                transport=replace(payload.transport, responder_bytes=20_001),
            ),
            id="responder-bytes-above-policy",
        ),
        pytest.param(
            lambda payload: replace(
                payload,
                intent=replace(payload.intent, authentication_time=_OPEN),
            ),
            id="authentication-not-inside-transport",
        ),
        pytest.param(
            lambda payload: replace(
                payload,
                intent=replace(payload.intent, ready_time=_AUTH - timedelta(microseconds=1)),
            ),
            id="ready-before-authentication",
        ),
        pytest.param(
            lambda payload: replace(
                payload,
                bound_session=replace(payload.bound_session, source_ready_time=_CLOSE),
            ),
            id="readiness-not-inside-transport",
        ),
        pytest.param(
            lambda payload: replace(
                payload,
                bound_session=replace(
                    payload.bound_session,
                    network_close_time=_CLOSE - timedelta(microseconds=1),
                ),
            ),
            id="bound-close-differs-from-transport",
        ),
        pytest.param(
            lambda payload: replace(
                payload,
                bound_session=replace(
                    payload.bound_session,
                    end_plan=SessionEndPlan(_CLOSE - timedelta(microseconds=1), "action_bundle"),
                ),
            ),
            id="session-end-before-transport-close",
        ),
        pytest.param(
            lambda payload: replace(
                payload,
                activity=(
                    replace(payload.activity[0], activity_time=_CLOSE + timedelta(microseconds=1)),
                    *payload.activity[1:],
                ),
            ),
            id="activity-after-session-end",
        ),
    ),
)
def test_payload_rejects_values_outside_transport_policy_and_lifecycle_bounds(
    mutate: Callable[[DeferredSessionPresealPayload], Any],
) -> None:
    with pytest.raises(
        (TypeError, ValueError), match="transport|policy|byte|time|ready|readiness|end|activity"
    ):
        mutate(_ssh_payload())


def test_payload_pairs_readiness_and_end_plan_with_the_protocol_intent() -> None:
    ssh = _ssh_payload()
    with pytest.raises((TypeError, ValueError), match="SSH|readiness|intent"):
        replace(
            ssh,
            bound_session=replace(
                ssh.bound_session,
                source_ready_time=_READY + timedelta(microseconds=1),
            ),
        )
    with pytest.raises((TypeError, ValueError), match="end|plan|intent"):
        replace(
            ssh,
            bound_session=replace(
                ssh.bound_session,
                end_plan=SessionEndPlan(_CLOSE + timedelta(seconds=1), "action_bundle"),
            ),
        )

    rdp = _rdp_payload()
    with pytest.raises((TypeError, ValueError), match="end|plan|intent"):
        replace(
            rdp,
            bound_session=replace(
                rdp.bound_session,
                end_plan=SessionEndPlan(
                    _HARD_DEADLINE - timedelta(seconds=1),
                    "action_bundle",
                ),
            ),
        )


def test_payload_rejects_process_hold_outside_exact_transport_and_process_lifetime() -> None:
    payload = _ssh_payload()
    hold = payload.process_holds[0]

    with pytest.raises((TypeError, ValueError), match="hold|process|transport|time"):
        replace(
            payload,
            process_holds=(replace(hold, hold_until=_CLOSE - timedelta(microseconds=1)),),
        )
    with pytest.raises((TypeError, ValueError), match="hold|process|acquired|time"):
        replace(
            payload,
            process_holds=(replace(hold, acquired_at=_OPEN),),
        )


def test_payload_rejects_protocol_port_os_and_auth_protocol_drift() -> None:
    ssh = _ssh_payload()
    rdp = _rdp_payload()

    with pytest.raises((TypeError, ValueError), match="SSH|port|22"):
        replace(ssh, transport=replace(ssh.transport, target_port=3389))
    with pytest.raises((TypeError, ValueError), match="RDP|port|3389"):
        replace(rdp, transport=replace(rdp.transport, target_port=22))
    with pytest.raises((TypeError, ValueError), match="SSH|Linux|OS"):
        replace(
            ssh,
            intent=replace(
                ssh.intent,
                target=replace(ssh.intent.target, os_family=DeferredSessionOsFamily.WINDOWS),
            ),
        )
    with pytest.raises((TypeError, ValueError), match="RDP|Windows|OS"):
        replace(
            rdp,
            intent=replace(
                rdp.intent,
                target=replace(rdp.intent.target, os_family=DeferredSessionOsFamily.LINUX),
            ),
        )
    with pytest.raises((TypeError, ValueError), match="auth|protocol|SSH"):
        replace(
            ssh,
            state_members=(
                replace(ssh.state_members[0], auth_protocol="rdp"),
                *ssh.state_members[1:],
            ),
        )


def test_payload_rejects_protocol_process_role_and_containment_drift() -> None:
    ssh = _ssh_payload()
    session, receiver, shell = ssh.state_members
    assert isinstance(receiver, DeferredSessionProcessMemberSpec)
    assert isinstance(shell, DeferredSessionProcessMemberSpec)

    with pytest.raises((TypeError, ValueError), match="SSH|RDP|role|unsupported"):
        replace(
            ssh,
            state_members=(
                session,
                replace(receiver, role=DeferredSessionProcessRole.RDP_WINLOGON),
                shell,
            ),
        )
    with pytest.raises((TypeError, ValueError), match="SSH|receiver|target|host"):
        replace(
            ssh,
            state_members=(
                session,
                replace(
                    receiver,
                    identity=replace(
                        receiver.identity,
                        hostname="other-target.example.test",
                    ),
                ),
                shell,
            ),
        )
    with pytest.raises((TypeError, ValueError), match="SSH|receiver|session|bind"):
        replace(
            ssh,
            state_members=(session, replace(receiver, session_member_id=""), shell),
        )
    with pytest.raises((TypeError, ValueError), match="SSH|shell|parent|receiver"):
        replace(
            ssh,
            state_members=(session, receiver, replace(shell, parent_member_id="")),
        )

    rdp = _rdp_payload()
    foreign_identity = replace(
        receiver.identity,
        hostname=rdp.intent.target.hostname,
        logon_id=rdp.bound_session.identity.logon_id,
    )
    foreign_process = replace(
        receiver,
        member_id="rdp-foreign-process",
        identity=foreign_identity,
        session_member_id=rdp.bound_session.reference_id,
    )
    with pytest.raises((TypeError, ValueError), match="RDP|SSH|role|unsupported"):
        replace(rdp, state_members=(*rdp.state_members, foreign_process))


def test_rdp_source_client_role_owns_the_optional_transport_process() -> None:
    payload = _rdp_payload()
    source_identity = _rdp_source_process_identity()
    source_member = DeferredSessionProcessMemberSpec(
        member_id="source-client",
        identity=source_identity,
        role=DeferredSessionProcessRole.SOURCE_CLIENT,
    )
    source_start = DeferredSessionStateStartOccurrenceSpec(
        occurrence_id="rdp-source-client-create-1",
        event_type=EventKind.PROCESS_CREATE,
        canonical_time=source_identity.started_at,
        member_id=source_member.member_id,
        publication_ordinal=2,
    )
    source_hold = DeferredSessionProcessHoldSpec(
        hold_id="rdp-source-client-transport-hold",
        process_object_id=source_identity.object_id,
        acquired_at=source_identity.started_at,
        hold_until=_CLOSE,
        action_id=payload.transport.transaction_id,
        reason="canonical_transport_close",
    )
    with_source = replace(
        payload,
        state_members=(*payload.state_members, source_member),
        activity=(
            *payload.activity,
            DeferredSessionActivitySpec(
                entity_kind=DeferredSessionEntityKind.PROCESS,
                object_id=source_identity.object_id,
                activity_time=_CLOSE,
            ),
        ),
        process_holds=(source_hold,),
        bound_session=replace(
            payload.bound_session,
            transport_process_object_id=source_identity.object_id,
        ),
        state_starts=(*payload.state_starts, source_start),
        dependents=(replace(payload.dependents[0], publication_ordinal=3),),
    )

    assert with_source.bound_session.transport_process_object_id == source_identity.object_id
    with pytest.raises((TypeError, ValueError), match="RDP|transport|mstsc|source"):
        replace(
            with_source,
            bound_session=replace(
                with_source.bound_session,
                transport_process_object_id="different-process",
            ),
        )


def test_rdp_reconnect_has_no_new_state_start_and_binds_ordered_transport_history() -> None:
    payload = _rdp_payload(RdpDeferredSessionMode.RECONNECT)

    assert payload.state_members == ()
    assert payload.state_starts == ()
    assert payload.bound_session.reference_id == "existing-rdp-session"
    assert payload.dependents[0].member_references == ("existing-rdp-session",)
    assert isinstance(payload.application_admission, RdpReconnectAdmissionSpec)
    assert payload.application_admission.prior_transport_id == "rdp-transport-0"
    assert payload.application_admission.current_transport_id == payload.transport.transaction_id
    assert payload.application_admission.transport_ids == (
        "rdp-transport-0",
        "rdp-transport-1",
    )


def test_rdp_reconnect_requires_its_explicit_bound_session_reference() -> None:
    payload = _rdp_payload(RdpDeferredSessionMode.RECONNECT)

    with pytest.raises((TypeError, ValueError), match="unknown|member|reference"):
        replace(
            payload,
            dependents=(replace(payload.dependents[0], member_references=("session",)),),
        )


def test_rdp_reconnect_rejects_duplicate_or_reversed_transport_history() -> None:
    payload = _rdp_payload(RdpDeferredSessionMode.RECONNECT)
    admission = payload.application_admission
    assert isinstance(admission, RdpReconnectAdmissionSpec)

    with pytest.raises((TypeError, ValueError), match="prior|current|transport|order|duplicate"):
        replace(
            payload, application_admission=replace(admission, prior_transport_id="rdp-transport-1")
        )
    with pytest.raises((TypeError, ValueError), match="prior|current|transport|order"):
        replace(payload, transport=replace(payload.transport, transaction_id="rdp-transport-0"))
    blank_current = _tamper(admission, "current_transport_id", "")
    with pytest.raises((TypeError, ValueError), match="current|transport|empty"):
        replace(payload, application_admission=blank_current)
