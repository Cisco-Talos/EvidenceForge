# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed lifecycle metadata for correlated action groups."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from evidenceforge.events.content_identity import ServiceDeploymentIdentity
from evidenceforge.events.network import NetworkTuple
from evidenceforge.utils.time import ensure_utc

LifecyclePhase = Literal["start", "dependent", "closure"]
SessionEndAuthority = Literal["explicit_storyline", "action_bundle", "generated"]
LifecycleEntityKind = Literal["process", "session", "service", "transport"]
LifecycleOwnerKind = Literal["boot", "service", "session", "transport", "detached"]
LifecycleCloseAuthority = Literal["authoritative", "generated"]
LifecycleServiceKind = Literal["builtin", "installed"]
TransportSessionBindingRole = Literal[
    "authentication",
    "session",
    "control",
    "application",
    "scanner",
]
LifecycleTransitionKind = Literal[
    "started",
    "dependent",
    "hold_acquired",
    "close_requested",
    "close_scheduled",
    "closed",
]
LifecycleForegroundLeaseKey = tuple[str, str, str, str]
LifecycleSingletonLeaseKey = tuple[str, str, str, str, str]
_LIFECYCLE_ENTITY_KINDS = frozenset({"process", "session", "service", "transport"})
_LIFECYCLE_OWNER_KINDS = frozenset({"boot", "service", "session", "transport", "detached"})
_LIFECYCLE_CLOSE_AUTHORITIES = frozenset({"authoritative", "generated"})
_LIFECYCLE_TRANSITION_KINDS = frozenset(
    {
        "started",
        "dependent",
        "hold_acquired",
        "close_requested",
        "close_scheduled",
        "closed",
    }
)
_LIFECYCLE_SERVICE_KINDS = frozenset({"builtin", "installed"})
_TRANSPORT_SESSION_BINDING_ROLES = frozenset(
    {"authentication", "session", "control", "application", "scanner"}
)


@dataclass(frozen=True, slots=True)
class LifecycleEntityRef:
    """Stable reference to one lifecycle-managed process or session."""

    kind: LifecycleEntityKind
    object_id: str

    def __post_init__(self) -> None:
        """Reject references that cannot resolve through an exact identity index."""

        if self.kind not in _LIFECYCLE_ENTITY_KINDS:
            raise ValueError(f"Unsupported lifecycle entity kind {self.kind!r}")
        if not self.object_id:
            raise ValueError("Lifecycle entity references require a non-empty object_id")


@dataclass(frozen=True, slots=True)
class ProcessTokenIdentity:
    """Immutable credential identity rendered for one process lifecycle.

    Token identity deliberately does not express which session, service, or
    transport owns the process lifecycle. That relationship belongs to
    :class:`LifecycleMembership`.
    """

    principal: str
    logon_id: str = ""
    session_id: int | None = None
    logon_type: int | None = None
    integrity_level: str = ""

    def __post_init__(self) -> None:
        """Reject incomplete or invalid immutable token fields."""

        if not self.principal:
            raise ValueError("Process token identity requires a principal")
        if self.session_id is not None and self.session_id < 0:
            raise ValueError("Process token session_id must be non-negative")
        if self.logon_type is not None and self.logon_type < 0:
            raise ValueError("Process token logon_type must be non-negative")


@dataclass(frozen=True, slots=True)
class LifecycleMembership:
    """Immutable lifecycle ownership independent of process credentials."""

    owner_kind: LifecycleOwnerKind
    owner_object_id: str
    session_object_id: str = ""

    def __post_init__(self) -> None:
        """Require an exact owner and internally consistent session ownership."""

        if self.owner_kind not in _LIFECYCLE_OWNER_KINDS:
            raise ValueError(f"Unsupported lifecycle owner kind {self.owner_kind!r}")
        if not self.owner_object_id:
            raise ValueError("Lifecycle membership requires an owner_object_id")
        if self.owner_kind == "session" and self.session_object_id != self.owner_object_id:
            raise ValueError(
                "Session-owned lifecycle membership must reference the same session object"
            )


@dataclass(frozen=True, slots=True)
class ProcessLifecycleIdentity:
    """Immutable host- and start-scoped identity for a canonical process."""

    hostname: str
    object_id: str
    pid: int
    started_at: datetime
    image: str
    parent_object_id: str = ""
    role: str = "application"

    def __post_init__(self) -> None:
        """Normalize canonical time and reject incomplete process identity."""

        if not self.hostname or not self.object_id or not self.image:
            raise ValueError("Process lifecycle identity requires host, object, and image")
        if self.pid < 0:
            raise ValueError("Process lifecycle PID must be non-negative")
        if self.parent_object_id == self.object_id:
            raise ValueError("A process lifecycle cannot parent itself")
        if not self.role:
            raise ValueError("Process lifecycle identity requires a role")
        object.__setattr__(self, "started_at", ensure_utc(self.started_at))

    @property
    def ref(self) -> LifecycleEntityRef:
        """Return the exact registry reference for this process."""

        return LifecycleEntityRef("process", self.object_id)


@dataclass(frozen=True, slots=True)
class SessionLifecycleIdentity:
    """Immutable identity for one canonical authentication/session lifecycle."""

    hostname: str
    object_id: str
    logon_id: str
    principal: str
    session_kind: str
    started_at: datetime
    session_id: int = 0
    logon_guid: str = ""

    def __post_init__(self) -> None:
        """Normalize canonical time and reject incomplete session identity."""

        if not self.hostname or not self.object_id or not self.logon_id:
            raise ValueError("Session lifecycle identity requires host, object, and LogonID")
        if not self.principal or not self.session_kind:
            raise ValueError("Session lifecycle identity requires principal and kind")
        if self.session_id < 0:
            raise ValueError("Session lifecycle session_id must be non-negative")
        object.__setattr__(self, "started_at", ensure_utc(self.started_at))

    @property
    def ref(self) -> LifecycleEntityRef:
        """Return the exact registry reference for this session."""

        return LifecycleEntityRef("session", self.object_id)


@dataclass(frozen=True, slots=True)
class LogicalServiceIdentity:
    """Immutable semantic identity for one service deployed on one host.

    Logical identity is deliberately separate from runtime instances. A
    built-in Windows service may keep this identity across boots, while every
    boot receives a distinct :class:`ServiceInstanceLifecycleIdentity`.
    """

    hostname: str
    logical_service_id: str
    canonical_name: str
    service_kind: LifecycleServiceKind
    deployment_service_id: str = ""
    deployment_identity: ServiceDeploymentIdentity | None = None

    def __post_init__(self) -> None:
        """Reject anonymous or deployment-inconsistent logical services."""

        if not self.hostname or not self.logical_service_id or not self.canonical_name:
            raise ValueError(
                "Logical service identity requires host, logical ID, and canonical name"
            )
        if self.service_kind not in _LIFECYCLE_SERVICE_KINDS:
            raise ValueError(f"Unsupported lifecycle service kind {self.service_kind!r}")
        if self.service_kind == "installed" and not self.deployment_service_id:
            raise ValueError("Installed logical services require a deployment service identity")
        deployment_identity = self.deployment_identity
        if deployment_identity is None:
            return
        if deployment_identity.hostname != self.hostname.strip().casefold():
            raise ValueError("Service deployment identity host must match lifecycle host")
        if deployment_identity.deployment_service_id != self.deployment_service_id:
            raise ValueError(
                "Typed service deployment identity must match the compatibility service ID"
            )

    @property
    def host_logical_key(self) -> tuple[str, str]:
        """Return the normalized exact host/logical-service key."""

        return (self.hostname.strip().casefold(), self.logical_service_id.strip().casefold())


@dataclass(frozen=True, slots=True)
class ServiceInstanceLifecycleIdentity:
    """Immutable boot-scoped runtime identity for one logical service."""

    hostname: str
    object_id: str
    logical_service_id: str
    boot_id: str
    instance_id: str
    started_at: datetime
    parent_service_object_id: str = ""

    def __post_init__(self) -> None:
        """Normalize start time and require a complete boot-scoped identity."""

        if not all(
            (
                self.hostname,
                self.object_id,
                self.logical_service_id,
                self.boot_id,
                self.instance_id,
            )
        ):
            raise ValueError(
                "Service instances require host, object, logical service, boot, and instance IDs"
            )
        if self.parent_service_object_id == self.object_id:
            raise ValueError("A service instance cannot parent itself")
        object.__setattr__(self, "started_at", ensure_utc(self.started_at))

    @property
    def ref(self) -> LifecycleEntityRef:
        """Return the exact registry reference for this service instance."""

        return LifecycleEntityRef("service", self.object_id)

    @property
    def host_instance_key(self) -> tuple[str, str, str, str]:
        """Return the exact built-in/installed runtime uniqueness key."""

        return (
            self.hostname.strip().casefold(),
            self.boot_id,
            self.logical_service_id.strip().casefold(),
            self.instance_id,
        )


@dataclass(frozen=True, slots=True)
class TransportLifecycleIdentity:
    """Immutable canonical transport identity consumed from a network plan.

    The registry never allocates tuple, UID, or connection identity. Those
    values must already be frozen by the canonical network transaction.
    ``hostname`` names the lifecycle authority partition; explicit source and
    destination hosts retain cross-host semantics for SSH/RDP and remote admin.
    """

    hostname: str
    object_id: str
    transport_id: str
    src_hostname: str
    dst_hostname: str
    network_tuple: NetworkTuple
    opened_at: datetime
    close_deadline: datetime
    zeek_uid: str = ""
    conn_id: str = ""

    def __post_init__(self) -> None:
        """Normalize the interval and reject invented or ambiguous identity."""

        if not all(
            (
                self.hostname,
                self.object_id,
                self.transport_id,
                self.src_hostname,
                self.dst_hostname,
                self.zeek_uid,
            )
        ):
            raise ValueError(
                "Transport lifecycle identity requires authority, object, transport, "
                "source-host, destination-host, and canonical UID identities"
            )
        opened_at = ensure_utc(self.opened_at)
        close_deadline = ensure_utc(self.close_deadline)
        if not 0 <= self.network_tuple.src_port <= 65_535 or not (
            0 <= self.network_tuple.dst_port <= 65_535
        ):
            raise ValueError("Transport lifecycle ports must be between 0 and 65,535")
        if close_deadline < opened_at:
            raise ValueError("Transport close deadline cannot precede transport open")
        object.__setattr__(self, "opened_at", opened_at)
        object.__setattr__(self, "close_deadline", close_deadline)

    @property
    def ref(self) -> LifecycleEntityRef:
        """Return the exact registry reference for this transport."""

        return LifecycleEntityRef("transport", self.object_id)

    @property
    def started_at(self) -> datetime:
        """Expose the canonical open as the generic lifecycle start."""

        return self.opened_at

    @property
    def tuple_key(self) -> tuple[str, int, str, int, str]:
        """Return the exact canonical five-tuple key."""

        return (
            self.network_tuple.src_ip,
            self.network_tuple.src_port,
            self.network_tuple.dst_ip,
            self.network_tuple.dst_port,
            self.network_tuple.protocol.casefold(),
        )


@dataclass(frozen=True, slots=True)
class TransportSessionBindingIdentity:
    """Immutable relation between one canonical transport and one session."""

    binding_id: str
    transport_object_id: str
    session_object_id: str
    bound_at: datetime
    role: TransportSessionBindingRole
    action_id: str
    transition_ordinal: int = 0

    def __post_init__(self) -> None:
        """Normalize binding time and require exact relation identity."""

        if not all(
            (
                self.binding_id,
                self.transport_object_id,
                self.session_object_id,
                self.action_id,
            )
        ):
            raise ValueError(
                "Transport/session bindings require binding, transport, session, and action IDs"
            )
        if self.role not in _TRANSPORT_SESSION_BINDING_ROLES:
            raise ValueError(f"Unsupported transport/session binding role {self.role!r}")
        if self.transition_ordinal < 0:
            raise ValueError("Transport/session binding ordinal must be non-negative")
        object.__setattr__(self, "bound_at", ensure_utc(self.bound_at))

    @property
    def order_key(self) -> tuple[datetime, str, int]:
        """Return deterministic binding commit order."""

        return (self.bound_at, self.action_id, self.transition_ordinal)


@dataclass(frozen=True, slots=True)
class ServiceProcessBindingIdentity:
    """Immutable ownership relation between a service and one process.

    The relation permits one shared host process, such as ``svchost.exe``, to
    serve multiple logical service instances without aliasing their identities.
    """

    binding_id: str
    service_object_id: str
    process_object_id: str
    bound_at: datetime
    role: str
    action_id: str
    transition_ordinal: int = 0

    def __post_init__(self) -> None:
        """Normalize binding time and reject anonymous ownership relations."""

        if not all(
            (
                self.binding_id,
                self.service_object_id,
                self.process_object_id,
                self.role,
                self.action_id,
            )
        ):
            raise ValueError(
                "Service/process bindings require binding, service, process, role, and action IDs"
            )
        if self.transition_ordinal < 0:
            raise ValueError("Service/process binding ordinal must be non-negative")
        object.__setattr__(self, "bound_at", ensure_utc(self.bound_at))

    @property
    def order_key(self) -> tuple[datetime, str, int]:
        """Return deterministic binding commit order."""

        return (self.bound_at, self.action_id, self.transition_ordinal)


@dataclass(frozen=True, slots=True)
class LifecycleActionCommit:
    """Stable action-relative identity for deterministic transition ordering."""

    action_id: str
    transition_ordinal: int

    def __post_init__(self) -> None:
        """Require a named action and non-negative semantic ordinal."""

        if not self.action_id:
            raise ValueError("Lifecycle action commits require an action_id")
        if self.transition_ordinal < 0:
            raise ValueError("Lifecycle transition_ordinal must be non-negative")


@dataclass(frozen=True, slots=True)
class LifecycleTransition:
    """One append-only canonical transition for a lifecycle entity."""

    transition_id: str
    subject: LifecycleEntityRef
    kind: LifecycleTransitionKind
    canonical_time: datetime
    action_id: str
    reason: str = ""
    transition_ordinal: int = 0

    def __post_init__(self) -> None:
        """Normalize transition time and require stable action-relative identity."""

        if self.kind not in _LIFECYCLE_TRANSITION_KINDS:
            raise ValueError(f"Unsupported lifecycle transition kind {self.kind!r}")
        if not self.transition_id or not self.action_id:
            raise ValueError("Lifecycle transitions require transition_id and action_id")
        if self.transition_ordinal < 0:
            raise ValueError("Lifecycle transition_ordinal must be non-negative")
        object.__setattr__(self, "canonical_time", ensure_utc(self.canonical_time))

    @property
    def commit_identity(self) -> LifecycleActionCommit:
        """Return the stable action-relative transition identity."""

        return LifecycleActionCommit(self.action_id, self.transition_ordinal)

    @property
    def order_key(self) -> tuple[datetime, str, int]:
        """Return the deterministic per-entity ledger ordering key."""

        return (self.canonical_time, self.action_id, self.transition_ordinal)


@dataclass(frozen=True, slots=True)
class LifecycleHold:
    """Typed dependent interval that prevents premature lifecycle closure."""

    hold_id: str
    subject: LifecycleEntityRef
    acquired_at: datetime
    hold_until: datetime
    action_id: str
    reason: str
    transition_ordinal: int = 0

    def __post_init__(self) -> None:
        """Normalize the interval and reject backward or anonymous holds."""

        if not self.hold_id or not self.action_id or not self.reason:
            raise ValueError("Lifecycle holds require hold_id, action_id, and reason")
        if self.transition_ordinal < 0:
            raise ValueError("Lifecycle hold transition_ordinal must be non-negative")
        acquired_at = ensure_utc(self.acquired_at)
        hold_until = ensure_utc(self.hold_until)
        if hold_until < acquired_at:
            raise ValueError("Lifecycle hold_until cannot precede acquired_at")
        object.__setattr__(self, "acquired_at", acquired_at)
        object.__setattr__(self, "hold_until", hold_until)


@dataclass(frozen=True, slots=True)
class LifecycleCloseBarrier:
    """Immutable point after which an entity accepts no new dependents."""

    barrier_id: str
    subject: LifecycleEntityRef
    requested_at: datetime
    authority: LifecycleCloseAuthority
    action_id: str

    def __post_init__(self) -> None:
        """Normalize close time and require stable barrier ownership."""

        if self.authority not in _LIFECYCLE_CLOSE_AUTHORITIES:
            raise ValueError(f"Unsupported lifecycle close authority {self.authority!r}")
        if not self.barrier_id or not self.action_id:
            raise ValueError("Lifecycle close barriers require barrier_id and action_id")
        object.__setattr__(self, "requested_at", ensure_utc(self.requested_at))


@dataclass(frozen=True, slots=True)
class LifecycleClosureTicket:
    """Resolved canonical close time for one accepted close barrier."""

    ticket_id: str
    barrier_id: str
    subject: LifecycleEntityRef
    requested_at: datetime
    effective_at: datetime
    authority: LifecycleCloseAuthority
    action_id: str

    def __post_init__(self) -> None:
        """Normalize close times and reject a ticket that moves before intent."""

        if self.authority not in _LIFECYCLE_CLOSE_AUTHORITIES:
            raise ValueError(f"Unsupported lifecycle close authority {self.authority!r}")
        if not self.ticket_id or not self.barrier_id or not self.action_id:
            raise ValueError("Lifecycle closure tickets require stable IDs and action ownership")
        requested_at = ensure_utc(self.requested_at)
        effective_at = ensure_utc(self.effective_at)
        if effective_at < requested_at:
            raise ValueError("Lifecycle effective close cannot precede the requested close")
        object.__setattr__(self, "requested_at", requested_at)
        object.__setattr__(self, "effective_at", effective_at)


@dataclass(frozen=True, slots=True)
class LifecycleRetentionLease:
    """Bounded reference that retains one closed identity through a deadline."""

    lease_id: str
    subject: LifecycleEntityRef
    retain_until: datetime
    reason: str

    def __post_init__(self) -> None:
        """Normalize the retention deadline and reject anonymous leases."""

        if not self.lease_id or not self.reason:
            raise ValueError("Lifecycle retention leases require lease_id and reason")
        object.__setattr__(self, "retain_until", ensure_utc(self.retain_until))


def _normalized_lease_text(value: str) -> str:
    """Return one case-insensitive exact-key component."""

    return value.strip().casefold()


def _normalized_lease_image(value: str) -> str:
    """Return one platform-neutral canonical image-key component."""

    return value.strip().replace("\\", "/").casefold()


@dataclass(frozen=True, slots=True)
class LifecycleForegroundLease:
    """Exclusive ownership of one interactive shell foreground lane.

    One lease represents an entire concurrency group.  Pipeline stages share
    the exact lease identity and shell-process holder; they do not acquire
    overlapping per-stage leases.  ``concurrency_group_id`` is immutable for
    the lifetime of the lease, so a different group must wait for release or
    expiry before acquiring the resource.
    """

    lease_id: str
    hostname: str
    principal: str
    session_object_id: str
    process_object_id: str
    acquired_at: datetime
    lease_until: datetime
    action_id: str
    concurrency_group_id: str = ""
    transition_ordinal: int = 0

    def __post_init__(self) -> None:
        """Normalize the interval and require exact lifecycle ownership."""

        if not all(
            (
                self.lease_id,
                self.hostname,
                self.principal,
                self.session_object_id,
                self.process_object_id,
                self.action_id,
            )
        ):
            raise ValueError(
                "Lifecycle foreground leases require lease, host, principal, session, "
                "process, and action identities"
            )
        if self.transition_ordinal < 0:
            raise ValueError("Lifecycle foreground lease ordinal must be non-negative")
        acquired_at = ensure_utc(self.acquired_at)
        lease_until = ensure_utc(self.lease_until)
        if lease_until < acquired_at:
            raise ValueError("Lifecycle foreground lease cannot end before acquisition")
        object.__setattr__(self, "acquired_at", acquired_at)
        object.__setattr__(self, "lease_until", lease_until)

    @property
    def resource_key(self) -> LifecycleForegroundLeaseKey:
        """Return the normalized exact exclusive-resource identity."""

        return (
            _normalized_lease_text(self.hostname),
            _normalized_lease_text(self.principal),
            self.session_object_id,
            self.process_object_id,
        )

    @property
    def order_key(self) -> tuple[datetime, str, int]:
        """Return deterministic acquisition commit order."""

        return (self.acquired_at, self.action_id, self.transition_ordinal)


@dataclass(frozen=True, slots=True)
class LifecycleSingletonLease:
    """Exclusive interval for one session-scoped singleton application."""

    lease_id: str
    hostname: str
    principal: str
    session_object_id: str
    logon_id: str
    canonical_image: str
    process_object_id: str
    acquired_at: datetime
    lease_until: datetime
    action_id: str
    transition_ordinal: int = 0

    def __post_init__(self) -> None:
        """Normalize the interval and require an exact session resource key.

        ``process_object_id`` may be empty only while generation owns a
        pre-allocation claim. The registry requires an exact live process when
        the claim is bound after publication.
        """

        if not all(
            (
                self.lease_id,
                self.hostname,
                self.principal,
                self.session_object_id,
                self.logon_id,
                self.canonical_image,
                self.action_id,
            )
        ):
            raise ValueError(
                "Lifecycle singleton leases require lease, host, principal, session, "
                "LogonID, image, and action identities"
            )
        if self.transition_ordinal < 0:
            raise ValueError("Lifecycle singleton lease ordinal must be non-negative")
        acquired_at = ensure_utc(self.acquired_at)
        lease_until = ensure_utc(self.lease_until)
        if lease_until < acquired_at:
            raise ValueError("Lifecycle singleton lease cannot end before acquisition")
        object.__setattr__(self, "acquired_at", acquired_at)
        object.__setattr__(self, "lease_until", lease_until)

    @property
    def resource_key(self) -> LifecycleSingletonLeaseKey:
        """Return the normalized exact exclusive-resource identity."""

        return (
            _normalized_lease_text(self.hostname),
            _normalized_lease_text(self.principal),
            self.session_object_id,
            _normalized_lease_text(self.logon_id),
            _normalized_lease_image(self.canonical_image),
        )

    @property
    def is_bound(self) -> bool:
        """Return whether the pre-allocation claim names its realized process."""

        return bool(self.process_object_id)

    @property
    def order_key(self) -> tuple[datetime, str, int]:
        """Return deterministic acquisition commit order."""

        return (self.acquired_at, self.action_id, self.transition_ordinal)


@dataclass(frozen=True, slots=True)
class ProcessLifecycleSnapshot:
    """Frozen public view of one process lifecycle registry entry."""

    identity: ProcessLifecycleIdentity
    token: ProcessTokenIdentity
    membership: LifecycleMembership
    transitions: tuple[LifecycleTransition, ...]
    holds: tuple[LifecycleHold, ...]
    close_barrier: LifecycleCloseBarrier | None = None
    closure_ticket: LifecycleClosureTicket | None = None
    closed_at: datetime | None = None
    transition_count: int = 0
    compacted_transition_count: int = 0
    transition_ledger_digest: str = ""
    hold_count: int = 0
    compacted_hold_count: int = 0
    hold_ledger_digest: str = ""
    latest_dependent_at: datetime | None = None
    latest_hold_until: datetime | None = None


@dataclass(frozen=True, slots=True)
class SessionLifecycleSnapshot:
    """Frozen public view of one session lifecycle registry entry."""

    identity: SessionLifecycleIdentity
    transitions: tuple[LifecycleTransition, ...]
    holds: tuple[LifecycleHold, ...]
    close_barrier: LifecycleCloseBarrier | None = None
    closure_ticket: LifecycleClosureTicket | None = None
    closed_at: datetime | None = None
    transition_count: int = 0
    compacted_transition_count: int = 0
    transition_ledger_digest: str = ""
    hold_count: int = 0
    compacted_hold_count: int = 0
    hold_ledger_digest: str = ""
    latest_dependent_at: datetime | None = None
    latest_hold_until: datetime | None = None


@dataclass(frozen=True, slots=True)
class ServiceInstanceLifecycleSnapshot:
    """Frozen public view of one logical service runtime instance."""

    logical_identity: LogicalServiceIdentity
    identity: ServiceInstanceLifecycleIdentity
    transitions: tuple[LifecycleTransition, ...]
    holds: tuple[LifecycleHold, ...]
    close_barrier: LifecycleCloseBarrier | None = None
    closure_ticket: LifecycleClosureTicket | None = None
    closed_at: datetime | None = None
    transition_count: int = 0
    compacted_transition_count: int = 0
    transition_ledger_digest: str = ""
    hold_count: int = 0
    compacted_hold_count: int = 0
    hold_ledger_digest: str = ""
    latest_dependent_at: datetime | None = None
    latest_hold_until: datetime | None = None


@dataclass(frozen=True, slots=True)
class TransportLifecycleSnapshot:
    """Frozen public view of one canonical transport lifecycle."""

    identity: TransportLifecycleIdentity
    transitions: tuple[LifecycleTransition, ...]
    holds: tuple[LifecycleHold, ...]
    close_barrier: LifecycleCloseBarrier | None = None
    closure_ticket: LifecycleClosureTicket | None = None
    closed_at: datetime | None = None
    active_binding_count: int = 0
    transition_count: int = 0
    compacted_transition_count: int = 0
    transition_ledger_digest: str = ""
    hold_count: int = 0
    compacted_hold_count: int = 0
    hold_ledger_digest: str = ""
    latest_dependent_at: datetime | None = None
    latest_hold_until: datetime | None = None


@dataclass(frozen=True, slots=True)
class TransportSessionBindingSnapshot:
    """Frozen state of one exact transport/session membership relation."""

    identity: TransportSessionBindingIdentity
    closed_at: datetime | None = None
    close_action_id: str = ""
    close_transition_ordinal: int = 0


@dataclass(frozen=True, slots=True)
class ServiceProcessBindingSnapshot:
    """Frozen state of one exact service/process ownership relation."""

    identity: ServiceProcessBindingIdentity
    closed_at: datetime | None = None
    close_action_id: str = ""
    close_transition_ordinal: int = 0


class SessionLifecycleSnapshotView(Protocol):
    """Read-only public shape shared by materialized and packed session snapshots."""

    @property
    def identity(self) -> SessionLifecycleIdentity: ...

    @property
    def transitions(self) -> tuple[LifecycleTransition, ...]: ...

    @property
    def holds(self) -> tuple[LifecycleHold, ...]: ...

    @property
    def close_barrier(self) -> LifecycleCloseBarrier | None: ...

    @property
    def closure_ticket(self) -> LifecycleClosureTicket | None: ...

    @property
    def closed_at(self) -> datetime | None: ...

    @property
    def transition_count(self) -> int: ...

    @property
    def compacted_transition_count(self) -> int: ...

    @property
    def transition_ledger_digest(self) -> str: ...

    @property
    def hold_count(self) -> int: ...

    @property
    def compacted_hold_count(self) -> int: ...

    @property
    def hold_ledger_digest(self) -> str: ...

    @property
    def latest_dependent_at(self) -> datetime | None: ...

    @property
    def latest_hold_until(self) -> datetime | None: ...


@dataclass(frozen=True, slots=True)
class LifecycleRegistryStats:
    """Constant-time census of lifecycle registry live and retained state.

    ``estimated_bytes`` is a low-cost structural estimate for capacity alarms;
    it deliberately excludes shared strings and Python allocator overhead.
    ``candidates_inspected`` is cumulative and makes accidental history scans
    visible to duration-stability probes.
    """

    process_entries: int
    session_entries: int
    live_processes: int
    live_sessions: int
    retained_processes: int
    retained_sessions: int
    transitions: int
    holds: int
    close_barriers: int
    closure_tickets: int
    retention_leases: int
    evicted_processes: int
    evicted_sessions: int
    high_water_processes: int
    high_water_sessions: int
    watermark: datetime | None
    process_index_backing_entries: int = 0
    session_index_backing_entries: int = 0
    process_temporal_live_entries: int = 0
    process_temporal_backing_entries: int = 0
    process_temporal_groups: int = 0
    session_temporal_live_entries: int = 0
    session_temporal_backing_entries: int = 0
    session_temporal_groups: int = 0
    temporal_stale_entries: int = 0
    retention_deadline_entries: int = 0
    retention_deadline_backing_entries: int = 0
    lease_deadline_backing_entries: int = 0
    lookup_candidates_inspected: int = 0
    estimated_bytes: int = 0
    estimated_index_bytes: int = 0
    detailed_transition_entries: int = 0
    detailed_hold_entries: int = 0
    compacted_transition_entries: int = 0
    compacted_hold_entries: int = 0
    ledger_floor: datetime | None = None
    ledger_temporal_backing_entries: int = 0
    ledger_compaction_pending: bool = False
    ledger_commit_map_entries: int = 0
    ledger_commit_map_backing_bytes: int = 0
    lifecycle_shards_allocated: int = 1
    lifecycle_shard_count: int = 1
    maximum_shard_entries: int = 0
    primary_map_backing_bytes: int = 0
    primary_compaction_pending: bool = False
    primary_compaction_work: int = 0
    route_entries: int = 0
    route_map_backing_bytes: int = 0
    route_compaction_pending: bool = False
    route_compaction_work: int = 0
    foreground_leases: int = 0
    singleton_leases: int = 0
    resource_lease_deadline_entries: int = 0
    resource_lease_deadline_backing_entries: int = 0
    resource_lease_subjects: int = 0
    resource_lease_subject_bindings: int = 0
    resource_lease_deadline_candidates_inspected: int = 0
    resource_lease_max_subject_bindings: int = 0
    retention_lease_subjects: int = 0
    retention_lease_subject_bindings: int = 0
    retention_lease_deadline_candidates_inspected: int = 0
    retention_lease_max_subject_bindings: int = 0
    singleton_lease_temporal_live_entries: int = 0
    singleton_lease_temporal_backing_entries: int = 0
    singleton_lease_temporal_groups: int = 0
    logical_service_entries: int = 0
    service_instance_entries: int = 0
    live_service_instances: int = 0
    retained_service_instances: int = 0
    transport_entries: int = 0
    live_transports: int = 0
    retained_transports: int = 0
    transport_session_bindings: int = 0
    active_transport_session_bindings: int = 0
    service_process_bindings: int = 0
    active_service_process_bindings: int = 0
    service_index_backing_entries: int = 0
    transport_index_backing_entries: int = 0
    binding_index_backing_entries: int = 0
    service_temporal_live_entries: int = 0
    service_temporal_backing_entries: int = 0
    service_temporal_groups: int = 0
    transport_temporal_live_entries: int = 0
    transport_temporal_backing_entries: int = 0
    transport_temporal_groups: int = 0
    service_retention_deadline_entries: int = 0
    transport_retention_deadline_entries: int = 0
    service_evictions: int = 0
    transport_evictions: int = 0
    binding_evictions: int = 0
    decoded_snapshot_cache_entries: int = 0
    decoded_snapshot_cache_capacity: int = 0
    decoded_snapshot_cache_estimated_bytes: int = 0

    @property
    def candidates_inspected(self) -> int:
        """Return the cumulative indexed lookup-candidate count."""

        return self.lookup_candidates_inspected


@dataclass(frozen=True, slots=True)
class SessionEndPlan:
    """Canonical intent for one durable session end.

    Explicit storyline plans are exact authoritative ends. Action bundles may
    publish an immutable hard deadline before allocating dependent state while
    retaining freedom to choose an earlier terminal time. Generated plans may
    still be moved after later activity by the owning session bundle.
    """

    canonical_end: datetime
    authority: SessionEndAuthority
    storyline_event_id: str = ""

    @property
    def is_authoritative(self) -> bool:
        """Return whether the canonical end must be preserved exactly."""

        return self.authority == "explicit_storyline"

    @property
    def is_hard_deadline(self) -> bool:
        """Return whether new dependents must fit before this immutable fence."""

        return self.authority in {"explicit_storyline", "action_bundle"}

    def __post_init__(self) -> None:
        """Require explicit plans to retain their storyline owner."""

        if self.authority == "explicit_storyline" and not self.storyline_event_id:
            raise ValueError("Explicit session end plans require a storyline_event_id")


@dataclass(frozen=True, slots=True)
class ActionLifecycleContext:
    """Source-independent lifecycle identity used by final window admission."""

    group_id: str
    canonical_start: datetime
    phase: LifecyclePhase
    parent_group_id: str | None = None

    def __post_init__(self) -> None:
        """Reject incomplete group metadata before dispatch."""

        if not self.group_id:
            raise ValueError("Action lifecycle group_id cannot be empty")
        if self.parent_group_id == self.group_id:
            raise ValueError("An action lifecycle group cannot parent itself")
