"""Explicit bounded-live checkpoint head for the lifecycle registry.

This participant deliberately understands lifecycle value objects one field at a time. It does
not traverse arbitrary Python objects and rejects owner families that do not yet have a lossless
hydration path.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from evidenceforge.events.content_identity import (
    CompiledServiceDeploymentIdentity,
    RuntimeServiceDeploymentIdentity,
)
from evidenceforge.events.lifecycle import (
    LifecycleCloseBarrier,
    LifecycleClosureTicket,
    LifecycleEntityRef,
    LifecycleHold,
    LifecycleMembership,
    LifecycleTransition,
    LogicalServiceIdentity,
    ProcessLifecycleIdentity,
    ProcessLifecycleSnapshot,
    ProcessTokenIdentity,
    ServiceInstanceLifecycleIdentity,
    ServiceInstanceLifecycleSnapshot,
    ServiceProcessBindingIdentity,
    ServiceProcessBindingSnapshot,
    SessionLifecycleIdentity,
    SessionLifecycleSnapshot,
    TransportLifecycleIdentity,
    TransportLifecycleSnapshot,
    TransportSessionBindingIdentity,
    TransportSessionBindingSnapshot,
)
from evidenceforge.events.network import NetworkTuple
from evidenceforge.generation.lifecycle_registry import (
    LifecycleRegistry,
    _LifecycleState,
    _ProcessEntry,
)
from evidenceforge.models.exceptions import StateError

from .errors import CheckpointCorruptionError, CheckpointError
from .owner_inventory import (
    LIFECYCLE_PARTITION_CHECKPOINT_FIELDS,
    LIFECYCLE_REGISTRY_CHECKPOINT_FIELDS,
    assert_transient_owner_state_empty,
)
from .packed import dumps, loads
from .participants import OwnerStateField, ParticipantSeal
from .store import HeadDraft

_SCHEMA_VERSION = "3"


def _time(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _decode_time(value: object, *, optional: bool = False) -> datetime | None:
    if value is None and optional:
        return None
    if type(value) is not str:
        raise CheckpointCorruptionError("lifecycle checkpoint time is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise CheckpointCorruptionError("lifecycle checkpoint time is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CheckpointCorruptionError("lifecycle checkpoint time lacks a UTC offset")
    return parsed


def _record(value: object, length: int, label: str) -> list[object]:
    if type(value) is not list or len(value) != length:
        raise CheckpointCorruptionError(f"lifecycle checkpoint {label} record is invalid")
    return value


def _ref(value: LifecycleEntityRef) -> list[object]:
    return [value.kind, value.object_id]


def _decode_ref(value: object) -> LifecycleEntityRef:
    kind, object_id = _record(value, 2, "entity reference")
    if type(kind) is not str or type(object_id) is not str:
        raise CheckpointCorruptionError("lifecycle checkpoint entity reference is invalid")
    try:
        return LifecycleEntityRef(kind, object_id)  # type: ignore[arg-type]
    except ValueError as error:
        raise CheckpointCorruptionError(
            "lifecycle checkpoint entity reference is invalid"
        ) from error


def _transition(value: LifecycleTransition) -> list[object]:
    return [
        value.transition_id,
        _ref(value.subject),
        value.kind,
        _time(value.canonical_time),
        value.action_id,
        value.reason,
        value.transition_ordinal,
    ]


def _decode_transition(value: object) -> LifecycleTransition:
    transition_id, subject, kind, canonical_time, action_id, reason, ordinal = _record(
        value, 7, "transition"
    )
    try:
        return LifecycleTransition(
            transition_id=transition_id,  # type: ignore[arg-type]
            subject=_decode_ref(subject),
            kind=kind,  # type: ignore[arg-type]
            canonical_time=_decode_time(canonical_time),  # type: ignore[arg-type]
            action_id=action_id,  # type: ignore[arg-type]
            reason=reason,  # type: ignore[arg-type]
            transition_ordinal=ordinal,  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError("lifecycle checkpoint transition is invalid") from error


def _hold(value: LifecycleHold) -> list[object]:
    return [
        value.hold_id,
        _ref(value.subject),
        _time(value.acquired_at),
        _time(value.hold_until),
        value.action_id,
        value.reason,
        value.transition_ordinal,
    ]


def _decode_hold(value: object) -> LifecycleHold:
    hold_id, subject, acquired_at, hold_until, action_id, reason, ordinal = _record(
        value, 7, "hold"
    )
    try:
        return LifecycleHold(
            hold_id=hold_id,  # type: ignore[arg-type]
            subject=_decode_ref(subject),
            acquired_at=_decode_time(acquired_at),  # type: ignore[arg-type]
            hold_until=_decode_time(hold_until),  # type: ignore[arg-type]
            action_id=action_id,  # type: ignore[arg-type]
            reason=reason,  # type: ignore[arg-type]
            transition_ordinal=ordinal,  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError("lifecycle checkpoint hold is invalid") from error


def _barrier(value: LifecycleCloseBarrier | None) -> list[object] | None:
    if value is None:
        return None
    return [
        value.barrier_id,
        _ref(value.subject),
        _time(value.requested_at),
        value.authority,
        value.action_id,
    ]


def _decode_barrier(value: object) -> LifecycleCloseBarrier | None:
    if value is None:
        return None
    barrier_id, subject, requested_at, authority, action_id = _record(value, 5, "barrier")
    try:
        return LifecycleCloseBarrier(
            barrier_id=barrier_id,  # type: ignore[arg-type]
            subject=_decode_ref(subject),
            requested_at=_decode_time(requested_at),  # type: ignore[arg-type]
            authority=authority,  # type: ignore[arg-type]
            action_id=action_id,  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError("lifecycle checkpoint barrier is invalid") from error


def _ticket(value: LifecycleClosureTicket | None) -> list[object] | None:
    if value is None:
        return None
    return [
        value.ticket_id,
        value.barrier_id,
        _ref(value.subject),
        _time(value.requested_at),
        _time(value.effective_at),
        value.authority,
        value.action_id,
    ]


def _decode_ticket(value: object) -> LifecycleClosureTicket | None:
    if value is None:
        return None
    ticket_id, barrier_id, subject, requested_at, effective_at, authority, action_id = _record(
        value, 7, "ticket"
    )
    try:
        return LifecycleClosureTicket(
            ticket_id=ticket_id,  # type: ignore[arg-type]
            barrier_id=barrier_id,  # type: ignore[arg-type]
            subject=_decode_ref(subject),
            requested_at=_decode_time(requested_at),  # type: ignore[arg-type]
            effective_at=_decode_time(effective_at),  # type: ignore[arg-type]
            authority=authority,  # type: ignore[arg-type]
            action_id=action_id,  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError("lifecycle checkpoint ticket is invalid") from error


def _state(value: object, authority: object) -> list[object]:
    commits = authority.commits
    commit_rows = (
        []
        if commits is None
        else [
            [action_id, ordinal, transition_id]
            for (action_id, ordinal), transition_id in sorted(commits.items())
        ]
    )
    durable_ids = authority.durable_transition_ids
    durable_rows = (
        []
        if durable_ids is None
        else [durable_ids]
        if isinstance(durable_ids, str)
        else list(durable_ids)
    )
    return [
        [_transition(item) for item in value.transitions],
        [_hold(item) for item in value.holds],
        _barrier(value.close_barrier),
        _ticket(value.closure_ticket),
        _time(value.closed_at),
        value.transition_count,
        value.compacted_transition_count,
        value.transition_ledger_digest,
        value.hold_count,
        value.compacted_hold_count,
        value.hold_ledger_digest,
        _time(value.latest_dependent_at),
        _time(value.latest_hold_until),
        commit_rows,
        durable_rows,
    ]


@dataclass(frozen=True)
class _DecodedState:
    snapshot_fields: dict[str, object]
    commits: tuple[tuple[str, int, str], ...]
    durable_transition_ids: tuple[str, ...]


def _decode_state(value: object) -> _DecodedState:
    (
        transitions,
        holds,
        barrier,
        ticket,
        closed_at,
        transition_count,
        compacted_transition_count,
        transition_digest,
        hold_count,
        compacted_hold_count,
        hold_digest,
        latest_dependent_at,
        latest_hold_until,
        commits,
        durable_transition_ids,
    ) = _record(value, 15, "entity state")
    if type(transitions) is not list or type(holds) is not list:
        raise CheckpointCorruptionError("lifecycle checkpoint entity ledger is invalid")
    if (
        type(transition_count) is not int
        or type(compacted_transition_count) is not int
        or type(transition_digest) is not str
        or type(hold_count) is not int
        or type(compacted_hold_count) is not int
        or type(hold_digest) is not str
    ):
        raise CheckpointCorruptionError("lifecycle checkpoint entity aggregates are invalid")
    if type(commits) is not list or type(durable_transition_ids) is not list:
        raise CheckpointCorruptionError("lifecycle checkpoint durable authority is invalid")
    decoded_commits: list[tuple[str, int, str]] = []
    for item in commits:
        action_id, ordinal, transition_id = _record(item, 3, "durable commit")
        if type(action_id) is not str or type(ordinal) is not int or type(transition_id) is not str:
            raise CheckpointCorruptionError("lifecycle checkpoint durable commit is invalid")
        decoded_commits.append((action_id, ordinal, transition_id))
    if any(type(item) is not str for item in durable_transition_ids):
        raise CheckpointCorruptionError("lifecycle checkpoint durable transition ID is invalid")
    decoded_transitions = tuple(_decode_transition(item) for item in transitions)
    decoded_holds = tuple(_decode_hold(item) for item in holds)
    if transition_count < len(decoded_transitions) or hold_count < len(decoded_holds):
        raise CheckpointCorruptionError(
            "lifecycle checkpoint entity aggregate is smaller than its detail ledger"
        )
    if compacted_transition_count != transition_count - len(
        decoded_transitions
    ) or compacted_hold_count != hold_count - len(decoded_holds):
        raise CheckpointCorruptionError(
            "lifecycle checkpoint compacted counts do not match retained detail"
        )
    return _DecodedState(
        snapshot_fields={
            "transitions": decoded_transitions,
            "holds": decoded_holds,
            "close_barrier": _decode_barrier(barrier),
            "closure_ticket": _decode_ticket(ticket),
            "closed_at": _decode_time(closed_at, optional=True),
            "transition_count": transition_count,
            "compacted_transition_count": compacted_transition_count,
            "transition_ledger_digest": transition_digest,
            "hold_count": hold_count,
            "compacted_hold_count": compacted_hold_count,
            "hold_ledger_digest": hold_digest,
            "latest_dependent_at": _decode_time(latest_dependent_at, optional=True),
            "latest_hold_until": _decode_time(latest_hold_until, optional=True),
        },
        commits=tuple(decoded_commits),
        durable_transition_ids=tuple(durable_transition_ids),
    )


def _process_identity(value: ProcessLifecycleIdentity) -> list[object]:
    return [
        value.hostname,
        value.object_id,
        value.pid,
        _time(value.started_at),
        value.image,
        value.parent_object_id,
        value.role,
    ]


def _decode_process_identity(value: object) -> ProcessLifecycleIdentity:
    hostname, object_id, pid, started_at, image, parent_object_id, role = _record(
        value, 7, "process identity"
    )
    try:
        return ProcessLifecycleIdentity(
            hostname=hostname,  # type: ignore[arg-type]
            object_id=object_id,  # type: ignore[arg-type]
            pid=pid,  # type: ignore[arg-type]
            started_at=_decode_time(started_at),  # type: ignore[arg-type]
            image=image,  # type: ignore[arg-type]
            parent_object_id=parent_object_id,  # type: ignore[arg-type]
            role=role,  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError(
            "lifecycle checkpoint process identity is invalid"
        ) from error


def _token(value: ProcessTokenIdentity) -> list[object]:
    return [
        value.principal,
        value.logon_id,
        value.session_id,
        value.logon_type,
        value.integrity_level,
    ]


def _decode_token(value: object) -> ProcessTokenIdentity:
    principal, logon_id, session_id, logon_type, integrity_level = _record(value, 5, "token")
    try:
        return ProcessTokenIdentity(
            principal=principal,  # type: ignore[arg-type]
            logon_id=logon_id,  # type: ignore[arg-type]
            session_id=session_id,  # type: ignore[arg-type]
            logon_type=logon_type,  # type: ignore[arg-type]
            integrity_level=integrity_level,  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError("lifecycle checkpoint process token is invalid") from error


def _membership(value: LifecycleMembership) -> list[object]:
    return [value.owner_kind, value.owner_object_id, value.session_object_id]


def _decode_membership(value: object) -> LifecycleMembership:
    owner_kind, owner_object_id, session_object_id = _record(value, 3, "membership")
    try:
        return LifecycleMembership(
            owner_kind=owner_kind,  # type: ignore[arg-type]
            owner_object_id=owner_object_id,  # type: ignore[arg-type]
            session_object_id=session_object_id,  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError("lifecycle checkpoint membership is invalid") from error


def _session_identity(value: SessionLifecycleIdentity) -> list[object]:
    return [
        value.hostname,
        value.object_id,
        value.logon_id,
        value.principal,
        value.session_kind,
        _time(value.started_at),
        value.session_id,
        value.logon_guid,
    ]


def _decode_session_identity(value: object) -> SessionLifecycleIdentity:
    hostname, object_id, logon_id, principal, kind, started_at, session_id, guid = _record(
        value, 8, "session identity"
    )
    try:
        return SessionLifecycleIdentity(
            hostname=hostname,  # type: ignore[arg-type]
            object_id=object_id,  # type: ignore[arg-type]
            logon_id=logon_id,  # type: ignore[arg-type]
            principal=principal,  # type: ignore[arg-type]
            session_kind=kind,  # type: ignore[arg-type]
            started_at=_decode_time(started_at),  # type: ignore[arg-type]
            session_id=session_id,  # type: ignore[arg-type]
            logon_guid=guid,  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError(
            "lifecycle checkpoint session identity is invalid"
        ) from error


def _deployment(
    value: CompiledServiceDeploymentIdentity | RuntimeServiceDeploymentIdentity | None,
) -> list[object] | None:
    if value is None:
        return None
    if type(value) is CompiledServiceDeploymentIdentity:
        return ["compiled", value.hostname, value.service_id]
    if type(value) is RuntimeServiceDeploymentIdentity:
        return ["runtime", value.hostname, value.canonical_name, value.action_id]
    raise CheckpointError("lifecycle checkpoint encountered an unsupported deployment identity")


def _decode_deployment(
    value: object,
) -> CompiledServiceDeploymentIdentity | RuntimeServiceDeploymentIdentity | None:
    if value is None:
        return None
    if type(value) is not list or not value:
        raise CheckpointCorruptionError("lifecycle checkpoint deployment identity is invalid")
    try:
        if value[0] == "compiled" and len(value) == 3:
            return CompiledServiceDeploymentIdentity(value[1], value[2])
        if value[0] == "runtime" and len(value) == 4:
            return RuntimeServiceDeploymentIdentity(value[1], value[2], value[3])
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError(
            "lifecycle checkpoint deployment identity is invalid"
        ) from error
    raise CheckpointCorruptionError("lifecycle checkpoint deployment identity is invalid")


def _logical_service(value: LogicalServiceIdentity) -> list[object]:
    return [
        value.hostname,
        value.logical_service_id,
        value.canonical_name,
        value.service_kind,
        value.deployment_service_id,
        _deployment(value.deployment_identity),
    ]


def _decode_logical_service(value: object) -> LogicalServiceIdentity:
    hostname, logical_id, name, kind, deployment_id, deployment = _record(
        value, 6, "logical service"
    )
    try:
        return LogicalServiceIdentity(
            hostname=hostname,  # type: ignore[arg-type]
            logical_service_id=logical_id,  # type: ignore[arg-type]
            canonical_name=name,  # type: ignore[arg-type]
            service_kind=kind,  # type: ignore[arg-type]
            deployment_service_id=deployment_id,  # type: ignore[arg-type]
            deployment_identity=_decode_deployment(deployment),
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError(
            "lifecycle checkpoint logical service is invalid"
        ) from error


def _service_identity(value: ServiceInstanceLifecycleIdentity) -> list[object]:
    return [
        value.hostname,
        value.object_id,
        value.logical_service_id,
        value.boot_id,
        value.instance_id,
        _time(value.started_at),
        value.parent_service_object_id,
    ]


def _decode_service_identity(value: object) -> ServiceInstanceLifecycleIdentity:
    hostname, object_id, logical_id, boot_id, instance_id, started_at, parent_id = _record(
        value, 7, "service identity"
    )
    try:
        return ServiceInstanceLifecycleIdentity(
            hostname=hostname,  # type: ignore[arg-type]
            object_id=object_id,  # type: ignore[arg-type]
            logical_service_id=logical_id,  # type: ignore[arg-type]
            boot_id=boot_id,  # type: ignore[arg-type]
            instance_id=instance_id,  # type: ignore[arg-type]
            started_at=_decode_time(started_at),  # type: ignore[arg-type]
            parent_service_object_id=parent_id,  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError(
            "lifecycle checkpoint service identity is invalid"
        ) from error


def _transport_identity(value: TransportLifecycleIdentity) -> list[object]:
    network = value.network_tuple
    return [
        value.hostname,
        value.object_id,
        value.transport_id,
        value.src_hostname,
        value.dst_hostname,
        [network.src_ip, network.src_port, network.dst_ip, network.dst_port, network.protocol],
        _time(value.opened_at),
        _time(value.close_deadline),
        value.zeek_uid,
        value.conn_id,
    ]


def _decode_transport_identity(value: object) -> TransportLifecycleIdentity:
    hostname, object_id, transport_id, src_host, dst_host, network, opened, deadline, uid, conn = (
        _record(value, 10, "transport identity")
    )
    src_ip, src_port, dst_ip, dst_port, protocol = _record(network, 5, "network tuple")
    try:
        return TransportLifecycleIdentity(
            hostname=hostname,  # type: ignore[arg-type]
            object_id=object_id,  # type: ignore[arg-type]
            transport_id=transport_id,  # type: ignore[arg-type]
            src_hostname=src_host,  # type: ignore[arg-type]
            dst_hostname=dst_host,  # type: ignore[arg-type]
            network_tuple=NetworkTuple(src_ip, src_port, dst_ip, dst_port, protocol),  # type: ignore[arg-type]
            opened_at=_decode_time(opened),  # type: ignore[arg-type]
            close_deadline=_decode_time(deadline),  # type: ignore[arg-type]
            zeek_uid=uid,  # type: ignore[arg-type]
            conn_id=conn,  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError(
            "lifecycle checkpoint transport identity is invalid"
        ) from error


def _service_binding(value: ServiceProcessBindingSnapshot) -> list[object]:
    identity = value.identity
    return [
        identity.binding_id,
        identity.service_object_id,
        identity.process_object_id,
        _time(identity.bound_at),
        identity.role,
        identity.action_id,
        identity.transition_ordinal,
        _time(value.closed_at),
        value.close_action_id,
        value.close_transition_ordinal,
    ]


def _decode_service_binding(value: object) -> ServiceProcessBindingSnapshot:
    (
        binding_id,
        service_id,
        process_id,
        bound_at,
        role,
        action_id,
        ordinal,
        closed_at,
        close_action_id,
        close_ordinal,
    ) = _record(value, 10, "service/process binding")
    try:
        return ServiceProcessBindingSnapshot(
            identity=ServiceProcessBindingIdentity(
                binding_id=binding_id,  # type: ignore[arg-type]
                service_object_id=service_id,  # type: ignore[arg-type]
                process_object_id=process_id,  # type: ignore[arg-type]
                bound_at=_decode_time(bound_at),  # type: ignore[arg-type]
                role=role,  # type: ignore[arg-type]
                action_id=action_id,  # type: ignore[arg-type]
                transition_ordinal=ordinal,  # type: ignore[arg-type]
            ),
            closed_at=_decode_time(closed_at, optional=True),
            close_action_id=close_action_id,  # type: ignore[arg-type]
            close_transition_ordinal=close_ordinal,  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError(
            "lifecycle checkpoint service/process binding is invalid"
        ) from error


def _transport_binding(value: TransportSessionBindingSnapshot) -> list[object]:
    identity = value.identity
    return [
        identity.binding_id,
        identity.transport_object_id,
        identity.session_object_id,
        _time(identity.bound_at),
        identity.role,
        identity.action_id,
        identity.transition_ordinal,
        _time(value.closed_at),
        value.close_action_id,
        value.close_transition_ordinal,
    ]


def _decode_transport_binding(value: object) -> TransportSessionBindingSnapshot:
    (
        binding_id,
        transport_id,
        session_id,
        bound_at,
        role,
        action_id,
        ordinal,
        closed_at,
        close_action_id,
        close_ordinal,
    ) = _record(value, 10, "transport/session binding")
    try:
        return TransportSessionBindingSnapshot(
            identity=TransportSessionBindingIdentity(
                binding_id=binding_id,  # type: ignore[arg-type]
                transport_object_id=transport_id,  # type: ignore[arg-type]
                session_object_id=session_id,  # type: ignore[arg-type]
                bound_at=_decode_time(bound_at),  # type: ignore[arg-type]
                role=role,  # type: ignore[arg-type]
                action_id=action_id,  # type: ignore[arg-type]
                transition_ordinal=ordinal,  # type: ignore[arg-type]
            ),
            closed_at=_decode_time(closed_at, optional=True),
            close_action_id=close_action_id,  # type: ignore[arg-type]
            close_transition_ordinal=close_ordinal,  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError(
            "lifecycle checkpoint transport/session binding is invalid"
        ) from error


def _start(snapshot: object, state: _DecodedState) -> LifecycleTransition:
    starts = [item for item in snapshot.transitions if item.kind == "started"]
    if len(starts) == 1:
        return starts[0]
    if starts:
        raise CheckpointCorruptionError("lifecycle checkpoint entity has duplicate starts")
    if not state.durable_transition_ids:
        raise CheckpointCorruptionError("lifecycle checkpoint entity lacks a durable start")
    transition_id = state.durable_transition_ids[0]
    commit = next((item for item in state.commits if item[2] == transition_id), None)
    if commit is None:
        raise CheckpointCorruptionError("lifecycle checkpoint start commit is missing")
    identity = snapshot.identity
    started_at = identity.started_at
    return LifecycleTransition(
        transition_id=transition_id,
        subject=identity.ref,
        kind="started",
        canonical_time=started_at,
        action_id=commit[0],
        transition_ordinal=commit[1],
    )


def _unsupported_partition_state(registry: LifecycleRegistry) -> list[str]:
    unsupported: list[str] = []
    names = (
        "_leases",
        "_foreground_leases",
        "_singleton_leases",
    )
    for partition_id, partition in enumerate(registry._partitions):
        for name in names:
            if len(getattr(partition, name)):
                unsupported.append(f"partition[{partition_id}].{name}")
    return unsupported


def _capture(registry: LifecycleRegistry) -> bytes:
    assert_transient_owner_state_empty(
        registry,
        LIFECYCLE_REGISTRY_CHECKPOINT_FIELDS,
        owner_name="lifecycle-registry",
    )
    unsupported = _unsupported_partition_state(registry)
    if unsupported:
        raise CheckpointError(
            "lifecycle checkpoint has no hydration adapter for: " + ", ".join(unsupported)
        )
    partitions: list[list[object]] = []
    with registry._gate.watermark():
        for partition_id, partition in enumerate(registry._partitions):
            assert_transient_owner_state_empty(
                partition,
                LIFECYCLE_PARTITION_CHECKPOINT_FIELDS,
                owner_name=f"lifecycle-partition-{partition_id}",
            )
            with partition._catalog_lock, partition._index_lock:
                processes = [
                    [
                        _process_identity(item.identity),
                        _token(item.token),
                        _membership(item.membership),
                        _state(partition._process_snapshot(item), item.state),
                    ]
                    for item in partition._processes.iter_entries()
                ]
                sessions = [
                    [
                        _session_identity(item.identity),
                        _state(partition._session_snapshot(item), item.state),
                    ]
                    for item in partition._sessions.iter_entries()
                ]
                services = [
                    [
                        _logical_service(item.logical_identity),
                        _service_identity(item.identity),
                        _state(partition._service_snapshot(item), item.state),
                    ]
                    for item in partition._services.iter_entries()
                ]
                transports = [
                    [
                        _transport_identity(item.identity),
                        _state(partition._transport_snapshot(item), item.state),
                        item.active_binding_count,
                    ]
                    for item in partition._transports.iter_entries()
                ]
                service_bindings = [
                    _service_binding(ServiceProcessBindingSnapshot(item.identity))
                    for item in partition._service_process_bindings.iter_values_by_handle()
                ]
                service_bindings.extend(
                    _service_binding(item)
                    for item in partition._service_process_tombstones.iter_values_by_handle()
                )
                transport_bindings = [
                    _transport_binding(TransportSessionBindingSnapshot(item.identity))
                    for item in partition._transport_session_bindings.iter_values_by_handle()
                ]
                transport_bindings.extend(
                    _transport_binding(item)
                    for item in partition._transport_session_tombstones.iter_values_by_handle()
                )
                partitions.append(
                    [
                        processes,
                        sessions,
                        services,
                        transports,
                        service_bindings,
                        transport_bindings,
                    ]
                )
    return dumps(
        {
            "closed_retention_us": int(registry.closed_retention.total_seconds() * 1_000_000),
            "ledger_detail_retention_us": int(
                registry.ledger_detail_retention.total_seconds() * 1_000_000
            ),
            "partitions": partitions,
            "schema_version": _SCHEMA_VERSION,
            "shard_count": registry.shard_count,
            "snapshot_history_limit": registry.snapshot_history_limit,
            "watermark": _time(registry._watermark),
        }
    )


def _decode_snapshot_rows(
    document: dict[str, object],
) -> tuple[
    list[ProcessLifecycleSnapshot],
    list[SessionLifecycleSnapshot],
    list[ServiceInstanceLifecycleSnapshot],
    list[TransportLifecycleSnapshot],
    list[ServiceProcessBindingSnapshot],
    list[TransportSessionBindingSnapshot],
    dict[str, _DecodedState],
]:
    partitions = document.get("partitions")
    if type(partitions) is not list:
        raise CheckpointCorruptionError("lifecycle checkpoint partition table is invalid")
    processes: list[ProcessLifecycleSnapshot] = []
    sessions: list[SessionLifecycleSnapshot] = []
    services: list[ServiceInstanceLifecycleSnapshot] = []
    transports: list[TransportLifecycleSnapshot] = []
    service_bindings: list[ServiceProcessBindingSnapshot] = []
    transport_bindings: list[TransportSessionBindingSnapshot] = []
    states: dict[str, _DecodedState] = {}
    for partition in partitions:
        (
            process_rows,
            session_rows,
            service_rows,
            transport_rows,
            service_binding_rows,
            transport_binding_rows,
        ) = _record(partition, 6, "partition")
        if not all(type(rows) is list for rows in partition):
            raise CheckpointCorruptionError("lifecycle checkpoint entity table is invalid")
        for row in process_rows:  # type: ignore[union-attr]
            identity, token, membership, state = _record(row, 4, "process")
            decoded = _decode_state(state)
            snapshot = ProcessLifecycleSnapshot(
                identity=_decode_process_identity(identity),
                token=_decode_token(token),
                membership=_decode_membership(membership),
                **decoded.snapshot_fields,  # type: ignore[arg-type]
            )
            processes.append(snapshot)
            states[snapshot.identity.object_id] = decoded
        for row in session_rows:  # type: ignore[union-attr]
            identity, state = _record(row, 2, "session")
            decoded = _decode_state(state)
            snapshot = SessionLifecycleSnapshot(
                identity=_decode_session_identity(identity),
                **decoded.snapshot_fields,  # type: ignore[arg-type]
            )
            sessions.append(snapshot)
            states[snapshot.identity.object_id] = decoded
        for row in service_rows:  # type: ignore[union-attr]
            logical, identity, state = _record(row, 3, "service")
            decoded = _decode_state(state)
            snapshot = ServiceInstanceLifecycleSnapshot(
                logical_identity=_decode_logical_service(logical),
                identity=_decode_service_identity(identity),
                **decoded.snapshot_fields,  # type: ignore[arg-type]
            )
            services.append(snapshot)
            states[snapshot.identity.object_id] = decoded
        for row in transport_rows:  # type: ignore[union-attr]
            identity, state, active_binding_count = _record(row, 3, "transport")
            if type(active_binding_count) is not int or active_binding_count < 0:
                raise CheckpointCorruptionError(
                    "lifecycle checkpoint transport binding count is invalid"
                )
            decoded = _decode_state(state)
            snapshot = TransportLifecycleSnapshot(
                identity=_decode_transport_identity(identity),
                active_binding_count=active_binding_count,
                **decoded.snapshot_fields,  # type: ignore[arg-type]
            )
            transports.append(snapshot)
            states[snapshot.identity.object_id] = decoded
        service_bindings.extend(
            _decode_service_binding(row)
            for row in service_binding_rows  # type: ignore[union-attr]
        )
        transport_bindings.extend(
            _decode_transport_binding(row)
            for row in transport_binding_rows  # type: ignore[union-attr]
        )
    return (
        processes,
        sessions,
        services,
        transports,
        service_bindings,
        transport_bindings,
        states,
    )


def _register_parent_ordered(
    snapshots: list[object],
    *,
    parent_id: Callable[[object], str],
    register: Callable[[object], object],
) -> None:
    pending = list(snapshots)
    registered: set[str] = set()
    while pending:
        ready = [item for item in pending if not parent_id(item) or parent_id(item) in registered]
        if not ready:
            raise CheckpointCorruptionError("lifecycle checkpoint contains a parent cycle")
        for item in sorted(ready, key=lambda value: value.identity.object_id):
            register(item)
            registered.add(item.identity.object_id)
            pending.remove(item)


def _install_authority_states(
    registry: LifecycleRegistry,
    snapshots: list[object],
    states: dict[str, _DecodedState],
) -> None:
    """Replace replay scaffolding with the exact retained authority summaries."""

    for snapshot in snapshots:
        object_id = snapshot.identity.object_id
        decoded = states[object_id]
        fields = decoded.snapshot_fields
        transitions = fields["transitions"]
        holds = fields["holds"]
        assert isinstance(transitions, tuple)
        assert isinstance(holds, tuple)
        transition_details: LifecycleTransition | list[LifecycleTransition] | None = (
            None
            if not transitions
            else transitions[0]
            if len(transitions) == 1
            else list(transitions)
        )
        hold_details: LifecycleHold | list[LifecycleHold] | None = (
            None if not holds else holds[0] if len(holds) == 1 else list(holds)
        )
        durable_ids: str | tuple[str, ...] | None = (
            None
            if not decoded.durable_transition_ids
            else decoded.durable_transition_ids[0]
            if len(decoded.durable_transition_ids) == 1
            else decoded.durable_transition_ids
        )
        try:
            transition_digest = int(fields["transition_ledger_digest"], 16)
            hold_digest = int(fields["hold_ledger_digest"], 16)
        except (TypeError, ValueError) as error:
            raise CheckpointCorruptionError(
                "lifecycle checkpoint ledger digest is invalid"
            ) from error
        authority = _LifecycleState(
            transitions=transition_details,
            holds=hold_details,
            close_barrier=fields["close_barrier"],  # type: ignore[arg-type]
            closure_ticket=fields["closure_ticket"],  # type: ignore[arg-type]
            closed_at=fields["closed_at"],  # type: ignore[arg-type]
            transition_count=fields["transition_count"],  # type: ignore[arg-type]
            hold_count=fields["hold_count"],  # type: ignore[arg-type]
            transition_digest=transition_digest,
            hold_digest=hold_digest,
            latest_dependent_at=fields["latest_dependent_at"],  # type: ignore[arg-type]
            latest_hold_until=fields["latest_hold_until"],  # type: ignore[arg-type]
            commits=(
                None
                if not decoded.commits
                else {
                    (action, ordinal): transition for action, ordinal, transition in decoded.commits
                }
            ),
            durable_transition_ids=durable_ids,
        )
        partition_id = registry._partition_id(snapshot.identity.hostname)
        partition = registry._partitions[partition_id]
        entry = partition._entry(snapshot.identity.ref)
        if entry is None:
            raise CheckpointCorruptionError("lifecycle checkpoint entity route was not rebuilt")
        if isinstance(snapshot, ProcessLifecycleSnapshot):
            partition._processes._store[object_id] = _ProcessEntry(
                identity=entry.identity,
                token=entry.token,
                membership=entry.membership,
                state=authority,
            )
        elif isinstance(snapshot, SessionLifecycleSnapshot):
            partition._sessions._states[entry.handle] = authority
        elif isinstance(snapshot, ServiceInstanceLifecycleSnapshot):
            partition._services._states[entry.handle] = authority
        else:
            partition._transports._states[entry.handle] = authority
        if isinstance(snapshot, (ServiceInstanceLifecycleSnapshot, TransportLifecycleSnapshot)):
            kind = (
                "service" if isinstance(snapshot, ServiceInstanceLifecycleSnapshot) else "transport"
            )
            with registry._routes.locked(((kind, object_id),)):
                registry._routes.invalidate_snapshot_locked(kind, object_id)


def _restore(registry: LifecycleRegistry, head: bytes) -> None:
    document = loads(head)
    if type(document) is not dict or document.get("schema_version") != _SCHEMA_VERSION:
        raise CheckpointCorruptionError("lifecycle checkpoint head schema is invalid")
    integer_fields = (
        "closed_retention_us",
        "ledger_detail_retention_us",
        "shard_count",
        "snapshot_history_limit",
    )
    if any(type(document.get(name)) is not int for name in integer_fields):
        raise CheckpointCorruptionError("lifecycle checkpoint configuration is invalid")
    fresh = LifecycleRegistry(
        closed_retention=timedelta(microseconds=document["closed_retention_us"]),  # type: ignore[arg-type]
        ledger_detail_retention=timedelta(
            microseconds=document["ledger_detail_retention_us"]  # type: ignore[arg-type]
        ),
        shard_count=document["shard_count"],  # type: ignore[arg-type]
        snapshot_history_limit=document["snapshot_history_limit"],  # type: ignore[arg-type]
    )
    (
        processes,
        sessions,
        services,
        transports,
        service_bindings,
        transport_bindings,
        states,
    ) = _decode_snapshot_rows(document)
    for snapshot in sorted(
        sessions, key=lambda item: (item.identity.started_at, item.identity.object_id)
    ):
        start = _start(snapshot, states[snapshot.identity.object_id])
        fresh.register_session(
            snapshot.identity,
            action_id=start.action_id,
            transition_id=start.transition_id,
            transition_ordinal=start.transition_ordinal,
        )
    _register_parent_ordered(
        services,
        parent_id=lambda item: item.identity.parent_service_object_id,
        register=lambda item: fresh.register_service_instance(
            item.logical_identity,
            item.identity,
            action_id=_start(item, states[item.identity.object_id]).action_id,
            transition_id=_start(item, states[item.identity.object_id]).transition_id,
            transition_ordinal=_start(item, states[item.identity.object_id]).transition_ordinal,
        ),
    )
    for snapshot in sorted(
        transports, key=lambda item: (item.identity.opened_at, item.identity.object_id)
    ):
        start = _start(snapshot, states[snapshot.identity.object_id])
        fresh.register_transport(
            snapshot.identity,
            action_id=start.action_id,
            transition_id=start.transition_id,
            transition_ordinal=start.transition_ordinal,
        )
    _register_parent_ordered(
        processes,
        parent_id=lambda item: item.identity.parent_object_id,
        register=lambda item: fresh.register_process(
            item.identity,
            token=item.token,
            membership=item.membership,
            action_id=_start(item, states[item.identity.object_id]).action_id,
            transition_id=_start(item, states[item.identity.object_id]).transition_id,
            transition_ordinal=_start(item, states[item.identity.object_id]).transition_ordinal,
        ),
    )
    for binding in sorted(service_bindings, key=lambda item: item.identity.binding_id):
        fresh.bind_service_process(binding.identity)
        if binding.closed_at is not None:
            fresh.close_service_process_binding(
                binding.identity.binding_id,
                expected_identity=binding.identity,
                closed_at=binding.closed_at,
                action_id=binding.close_action_id,
                transition_ordinal=binding.close_transition_ordinal,
            )
    for binding in sorted(transport_bindings, key=lambda item: item.identity.binding_id):
        fresh.bind_transport_session(binding.identity)
        if binding.closed_at is not None:
            fresh.close_transport_session_binding(
                binding.identity.binding_id,
                expected_identity=binding.identity,
                closed_at=binding.closed_at,
                action_id=binding.close_action_id,
                transition_ordinal=binding.close_transition_ordinal,
            )
    snapshots = [*sessions, *services, *transports, *processes]
    for snapshot in snapshots:
        for hold in snapshot.holds:
            fresh.add_hold(hold)
        for transition in snapshot.transitions:
            if transition.kind == "dependent":
                fresh.record_dependent(
                    transition.subject,
                    transition_id=transition.transition_id,
                    canonical_time=transition.canonical_time,
                    action_id=transition.action_id,
                    reason=transition.reason,
                    transition_ordinal=transition.transition_ordinal,
                )
    closing = [item for item in snapshots if item.close_barrier is not None]
    for snapshot in sorted(
        closing,
        key=lambda item: (item.close_barrier.requested_at, item.identity.object_id),
    ):
        assert snapshot.close_barrier is not None
        assert snapshot.closure_ticket is not None
        ticket = fresh.request_close(
            snapshot.close_barrier,
            ticket_id=snapshot.closure_ticket.ticket_id,
        )
        if ticket != snapshot.closure_ticket:
            raise CheckpointCorruptionError("lifecycle checkpoint closure ticket changed")
    pending_close = [item for item in closing if item.closed_at is not None]
    while pending_close:
        progressed = False
        for snapshot in sorted(
            pending_close,
            key=lambda item: (item.closed_at, item.identity.object_id),
        ):
            assert snapshot.closure_ticket is not None
            try:
                fresh.close(snapshot.closure_ticket.ticket_id)
            except StateError:
                continue
            pending_close.remove(snapshot)
            progressed = True
        if not progressed:
            raise CheckpointCorruptionError("lifecycle checkpoint closure graph cannot hydrate")
    _install_authority_states(fresh, snapshots, states)
    watermark = _decode_time(document.get("watermark"), optional=True)
    if watermark is not None:
        fresh.advance_watermark(watermark)
    registry.__dict__.clear()
    registry.__dict__.update(fresh.__dict__)


class LifecycleRegistryParticipant:
    """Persist the registry's bounded retained head without arbitrary graph traversal."""

    checkpoint_owner = "lifecycle-registry"
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = (
        OwnerStateField("retained_entities", "bounded-live-head"),
        OwnerStateField("immutable_history", "immutable-incremental-segments"),
        OwnerStateField("indexes_routes_locks", "deterministically-rebuilt"),
        OwnerStateField("publication_capabilities", "transient-empty-at-barrier"),
    )

    def __init__(self, registry: LifecycleRegistry) -> None:
        self.registry = registry
        self._prepared_sequence: int | None = None
        self._prepared_seal: ParticipantSeal | None = None

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture one stable partition/handle ordered bounded live head."""

        if self._prepared_sequence is not None:
            if self._prepared_sequence != sequence or self._prepared_seal is None:
                raise RuntimeError("lifecycle participant already prepared another sequence")
            return self._prepared_seal
        seal = ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=_capture(self.registry),
            )
        )
        self._prepared_sequence = sequence
        self._prepared_seal = seal
        return seal

    def checkpoint_committed(self, sequence: int) -> None:
        """Release a published immutable head."""

        if self._prepared_sequence != sequence:
            raise RuntimeError("lifecycle commit does not match its prepared sequence")
        self._prepared_sequence = None
        self._prepared_seal = None

    def checkpoint_aborted(self, sequence: int) -> None:
        """Release a failed immutable head without changing registry state."""

        if self._prepared_sequence != sequence:
            raise RuntimeError("lifecycle abort does not match its prepared sequence")
        self._prepared_sequence = None
        self._prepared_seal = None

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Hydrate into the existing registry identity and rebuild derived indexes."""

        if segments:
            raise CheckpointCorruptionError("lifecycle bounded head cannot own history segments")
        _restore(self.registry, head)
        self._prepared_sequence = None
        self._prepared_seal = None
