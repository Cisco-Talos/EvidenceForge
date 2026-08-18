# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Pure semantic contracts for deferred SSH and RDP pre-seal work.

This module is intentionally capability-free.  Its frozen values describe the
semantic work that a later owner will resolve into State, lifecycle,
application-manager, source-timing, and dispatcher capabilities.  They never
carry callbacks, random-number generators, planning cursors, mutable event
builders, preparation objects, admission tokens, or prepared dispatches.

The physical transport is publication ordinal zero.  State-start and dependent
occurrence specifications use one contiguous, transport-relative sequence
starting at one.  That convention lets the later owner prove transport-first
publication without exposing any live publication capability here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from ipaddress import ip_address
from typing import TypeAlias

from evidenceforge.events.contracts import EventKind
from evidenceforge.events.identity import ProcessIdentity, SessionIdentity, ThreadIdentity
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.utils.time import ensure_utc


class DeferredSessionProtocol(StrEnum):
    """Protocol owner of one deferred-session semantic payload."""

    SSH = "ssh"
    RDP = "rdp"


class DeferredSessionBindingDisposition(StrEnum):
    """State/lifecycle treatment of the target protocol session.

    Protocol open/reconnect semantics remain a separate concern.  This value
    describes whether the final connection composite creates the State session,
    starts lifecycle ownership for an exact preallocated State session, or binds
    another transport to an already-live State/lifecycle session.
    """

    NEW_SESSION = "new_session"
    PREALLOCATED_SESSION_START = "preallocated_session_start"
    ACTIVE_SESSION = "active_session"


class DeferredSessionOsFamily(StrEnum):
    """Normalized endpoint operating-system family used by protocol admission."""

    UNKNOWN = "unknown"
    LINUX = "linux"
    WINDOWS = "windows"


class DeferredSessionEntityKind(StrEnum):
    """Canonical State entity family referenced by one activity specification."""

    SESSION = "session"
    PROCESS = "process"


class DeferredSessionProcessRole(StrEnum):
    """Bounded process roles that a deferred session may start."""

    SOURCE_CLIENT = "source_client"
    SSH_RECEIVER = "ssh_receiver"
    SSH_SHELL = "ssh_shell"
    RDP_USER_MANAGER = "rdp_user_manager"
    RDP_WINLOGON = "rdp_winlogon"
    RDP_USERINIT = "rdp_userinit"
    RDP_EXPLORER = "rdp_explorer"
    PROCESS_TREE_ROOT = "process_tree_root"


class SshDeferredAuthenticationMethod(StrEnum):
    """Supported SSH authentication methods at the pure semantic boundary."""

    PASSWORD = "password"
    PUBLIC_KEY = "publickey"
    KEYBOARD_INTERACTIVE = "keyboard-interactive"
    GSSAPI_WITH_MIC = "gssapi-with-mic"


class SshDeferredOperationKind(StrEnum):
    """Supported synchronous first SSH operation families."""

    SHELL = "shell"
    EXEC = "exec"
    SFTP = "sftp"
    SCP = "scp"


class RdpDeferredSessionMode(StrEnum):
    """Whether an RDP transport opens or reconnects a logical session."""

    OPEN = "open"
    RECONNECT = "reconnect"


def _required_text(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{field_name} requires an exact inert string type")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized


def _optional_text(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{field_name} requires an exact inert string type")
    return value.strip()


def _utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise TypeError(f"{field_name} requires an exact datetime type")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return ensure_utc(value)


def _timedelta(value: object, field_name: str, *, positive: bool = False) -> timedelta:
    if type(value) is not timedelta:
        raise TypeError(f"{field_name} requires an exact timedelta type")
    if positive and value <= timedelta(0):
        raise ValueError(f"{field_name} must be positive")
    return value


def _integer(
    value: object,
    field_name: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if type(value) is not int:
        raise TypeError(f"{field_name} requires an exact integer type")
    if value < minimum or (maximum is not None and value > maximum):
        limit = f"{minimum}..{maximum}" if maximum is not None else f">= {minimum}"
        raise ValueError(f"{field_name} must be in range {limit}")
    return value


def _port(value: object, field_name: str) -> int:
    return _integer(value, field_name, minimum=1, maximum=65_535)


def _address(value: object, field_name: str) -> str:
    normalized = _required_text(value, field_name)
    try:
        return ip_address(normalized).compressed.casefold()
    except ValueError as error:
        raise ValueError(f"{field_name} must be a valid IP address") from error


def _exact(value: object, expected: type[object], field_name: str) -> None:
    if type(value) is not expected:
        raise TypeError(f"{field_name} requires exact type {expected.__name__}")


def _revalidate(value: object, expected: type[object], field_name: str) -> None:
    """Re-run a frozen owned value's constructor validation without retaining it."""

    _exact(value, expected, field_name)
    replace(value)


def _validate_session_identity(identity: object, field_name: str) -> SessionIdentity:
    _exact(identity, SessionIdentity, field_name)
    assert isinstance(identity, SessionIdentity)
    _required_text(identity.hostname, f"{field_name}.hostname")
    _required_text(identity.object_id, f"{field_name}.object_id")
    _required_text(identity.logon_id, f"{field_name}.logon_id")
    _integer(identity.session_id, f"{field_name}.session_id", minimum=1)
    _required_text(identity.principal, f"{field_name}.principal")
    session_kind = _required_text(identity.session_kind, f"{field_name}.session_kind").casefold()
    if session_kind not in {protocol.value for protocol in DeferredSessionProtocol}:
        raise ValueError(f"{field_name}.session_kind must be ssh or rdp")
    _utc(identity.started_at, f"{field_name}.started_at")
    _required_text(identity.lifecycle_group_id, f"{field_name}.lifecycle_group_id")
    _optional_text(identity.logon_guid, f"{field_name}.logon_guid")
    _optional_text(
        identity.parent_lifecycle_group_id,
        f"{field_name}.parent_lifecycle_group_id",
    )
    return identity


def _validate_process_identity(identity: object, field_name: str) -> ProcessIdentity:
    _exact(identity, ProcessIdentity, field_name)
    assert isinstance(identity, ProcessIdentity)
    _required_text(identity.hostname, f"{field_name}.hostname")
    _required_text(identity.object_id, f"{field_name}.object_id")
    _integer(identity.pid, f"{field_name}.pid", minimum=1)
    _integer(identity.parent_pid, f"{field_name}.parent_pid")
    _required_text(identity.image, f"{field_name}.image")
    _required_text(identity.command_line, f"{field_name}.command_line")
    _required_text(identity.principal, f"{field_name}.principal")
    _required_text(identity.logon_id, f"{field_name}.logon_id")
    _utc(identity.started_at, f"{field_name}.started_at")
    _required_text(identity.lifecycle_group_id, f"{field_name}.lifecycle_group_id")
    _optional_text(
        identity.parent_lifecycle_group_id,
        f"{field_name}.parent_lifecycle_group_id",
    )
    if identity.primary_thread is not None:
        _exact(identity.primary_thread, ThreadIdentity, f"{field_name}.primary_thread")
        thread = identity.primary_thread
        thread_host = (
            _required_text(
                thread.hostname,
                f"{field_name}.primary_thread.hostname",
            )
            .casefold()
            .rstrip(".")
        )
        process_object_id = _required_text(
            thread.process_object_id,
            f"{field_name}.primary_thread.process_object_id",
        )
        thread_pid = _integer(thread.pid, f"{field_name}.primary_thread.pid", minimum=1)
        _integer(thread.tid, f"{field_name}.primary_thread.tid", minimum=1)
        _required_text(thread.object_id, f"{field_name}.primary_thread.object_id")
        thread_started_at = _utc(
            thread.started_at,
            f"{field_name}.primary_thread.started_at",
        )
        _required_text(thread.kind, f"{field_name}.primary_thread.kind")
        if thread_host != identity.hostname.casefold().rstrip("."):
            raise ValueError(f"{field_name}.primary_thread must share its process host")
        if process_object_id != identity.object_id or thread_pid != identity.pid:
            raise ValueError(f"{field_name}.primary_thread must reference its owning process")
        if thread_started_at < _utc(identity.started_at, f"{field_name}.started_at"):
            raise ValueError(f"{field_name}.primary_thread cannot predate its process")
    return identity


def _validate_end_plan(value: object, field_name: str) -> SessionEndPlan:
    _exact(value, SessionEndPlan, field_name)
    assert isinstance(value, SessionEndPlan)
    _utc(value.canonical_end, f"{field_name}.canonical_end")
    authority = _required_text(value.authority, f"{field_name}.authority")
    if authority not in {"explicit_storyline", "action_bundle", "generated"}:
        raise ValueError(f"{field_name}.authority is unsupported")
    storyline_id = _optional_text(value.storyline_event_id, f"{field_name}.storyline_event_id")
    if authority == "explicit_storyline" and not storyline_id:
        raise ValueError(f"{field_name} explicit authority requires a storyline identity")
    return value


@dataclass(frozen=True, slots=True)
class DeferredSessionEndpoint:
    """Immutable source or target endpoint projection."""

    address: str
    hostname: str
    os_family: DeferredSessionOsFamily

    def __post_init__(self) -> None:
        """Normalize inert endpoint values and reject active substitutions."""

        address = _address(self.address, "Deferred session endpoint address")
        hostname = (
            _required_text(
                self.hostname,
                "Deferred session endpoint hostname",
            )
            .casefold()
            .rstrip(".")
        )
        if not hostname:
            raise ValueError("Deferred session endpoint hostname must not normalize to empty")
        _exact(self.os_family, DeferredSessionOsFamily, "Deferred session endpoint OS family")
        object.__setattr__(self, "address", address)
        object.__setattr__(self, "hostname", hostname)


@dataclass(frozen=True, slots=True)
class DeferredSessionPrincipal:
    """Immutable cross-platform account identity needed by a session owner."""

    username: str
    principal: str
    uid: int | None = None
    sid: str = ""

    def __post_init__(self) -> None:
        """Normalize the account without retaining a mutable scenario model."""

        username = _required_text(self.username, "Deferred session username")
        principal = _required_text(self.principal, "Deferred session principal")
        if self.uid is not None:
            _integer(self.uid, "Deferred session UID")
        sid = _optional_text(self.sid, "Deferred session SID")
        object.__setattr__(self, "username", username.casefold())
        object.__setattr__(self, "principal", principal.casefold())
        object.__setattr__(self, "sid", sid)


@dataclass(frozen=True, slots=True)
class DeferredSessionTransportPolicy:
    """Unsampled bounds owned by the later revocable network preparation."""

    requested_source_port: int | None
    duration_min: timedelta
    duration_max: timedelta
    initiator_bytes_min: int
    initiator_bytes_max: int
    responder_bytes_min: int
    responder_bytes_max: int

    def __post_init__(self) -> None:
        """Reject invalid ports, durations, or directional byte ranges."""

        if self.requested_source_port is not None:
            _port(self.requested_source_port, "Deferred transport requested source port")
        duration_min = _timedelta(
            self.duration_min,
            "Deferred transport minimum duration",
            positive=True,
        )
        duration_max = _timedelta(
            self.duration_max,
            "Deferred transport maximum duration",
            positive=True,
        )
        if duration_max < duration_min:
            raise ValueError("Deferred transport duration bounds are reversed")
        initiator_min = _integer(
            self.initiator_bytes_min,
            "Deferred transport initiator minimum bytes",
        )
        initiator_max = _integer(
            self.initiator_bytes_max,
            "Deferred transport initiator maximum bytes",
        )
        responder_min = _integer(
            self.responder_bytes_min,
            "Deferred transport responder minimum bytes",
        )
        responder_max = _integer(
            self.responder_bytes_max,
            "Deferred transport responder maximum bytes",
        )
        if initiator_max < initiator_min or responder_max < responder_min:
            raise ValueError("Deferred transport byte bounds are reversed")


@dataclass(frozen=True, slots=True)
class DeferredSessionIdentitySpec:
    """Pure positive remote-interactive session identity."""

    identity: SessionIdentity
    logon_type: int = 10

    def __post_init__(self) -> None:
        """Forbid placeholder session zero and non-Type-10 identity drift."""

        _validate_session_identity(self.identity, "Deferred session identity")
        if type(self.logon_type) is not int or self.logon_type != 10:
            raise ValueError("Deferred sessions require remote-interactive logon type 10")

    @property
    def protocol(self) -> DeferredSessionProtocol:
        """Return the protocol encoded by the canonical session kind."""

        return DeferredSessionProtocol(self.identity.session_kind.casefold())


def _validate_intent_common(
    *,
    protocol: DeferredSessionProtocol,
    source: object,
    target: object,
    principal: object,
    identity: object,
    transport_policy: object,
) -> None:
    _revalidate(source, DeferredSessionEndpoint, "Deferred session source endpoint")
    _revalidate(target, DeferredSessionEndpoint, "Deferred session target endpoint")
    _revalidate(principal, DeferredSessionPrincipal, "Deferred session principal")
    _revalidate(identity, DeferredSessionIdentitySpec, "Deferred session identity spec")
    _revalidate(
        transport_policy,
        DeferredSessionTransportPolicy,
        "Deferred session transport policy",
    )
    assert isinstance(source, DeferredSessionEndpoint)
    assert isinstance(target, DeferredSessionEndpoint)
    assert isinstance(principal, DeferredSessionPrincipal)
    assert isinstance(identity, DeferredSessionIdentitySpec)
    if source.address == target.address:
        raise ValueError("Deferred sessions require distinct remote source and target addresses")
    expected_os = (
        DeferredSessionOsFamily.LINUX
        if protocol is DeferredSessionProtocol.SSH
        else DeferredSessionOsFamily.WINDOWS
    )
    if target.os_family is not expected_os:
        name = "SSH/Linux" if protocol is DeferredSessionProtocol.SSH else "RDP/Windows"
        raise ValueError(f"{name} target OS family does not match the deferred protocol")
    if identity.protocol is not protocol:
        raise ValueError(f"Deferred {protocol.value.upper()} identity has the wrong session kind")
    canonical_host = identity.identity.hostname.casefold().rstrip(".")
    if canonical_host != target.hostname:
        raise ValueError(f"Deferred {protocol.value.upper()} identity targets a different host")
    identity_principal = identity.identity.principal.casefold()
    if identity_principal not in {principal.username, principal.principal}:
        raise ValueError(f"Deferred {protocol.value.upper()} identity has a different principal")


@dataclass(frozen=True, slots=True)
class SshDeferredSessionIntent:
    """Pure SSH semantic intent after exact identity selection."""

    source: DeferredSessionEndpoint
    target: DeferredSessionEndpoint
    principal: DeferredSessionPrincipal
    identity: DeferredSessionIdentitySpec
    transport_policy: DeferredSessionTransportPolicy
    authentication_method: SshDeferredAuthenticationMethod
    operation_kind: SshDeferredOperationKind
    operation_semantic_id: str
    authentication_time: datetime
    ready_time: datetime
    end_plan: SessionEndPlan | None = None

    def __post_init__(self) -> None:
        """Validate initial-only SSH identity, timing, and operation shape."""

        _validate_intent_common(
            protocol=DeferredSessionProtocol.SSH,
            source=self.source,
            target=self.target,
            principal=self.principal,
            identity=self.identity,
            transport_policy=self.transport_policy,
        )
        _exact(
            self.authentication_method,
            SshDeferredAuthenticationMethod,
            "SSH authentication method",
        )
        _exact(self.operation_kind, SshDeferredOperationKind, "SSH operation kind")
        operation_id = _required_text(
            self.operation_semantic_id,
            "SSH semantic operation identity",
        )
        authentication_time = _utc(self.authentication_time, "SSH authentication time")
        ready_time = _utc(self.ready_time, "SSH ready time")
        if ready_time <= authentication_time:
            raise ValueError("SSH ready time must follow authentication time")
        if self.end_plan is not None:
            _validate_end_plan(self.end_plan, "SSH session end plan")
            end_time = _utc(self.end_plan.canonical_end, "SSH session end time")
            if end_time < ready_time:
                raise ValueError("SSH session end cannot precede readiness")
        object.__setattr__(self, "operation_semantic_id", operation_id)
        object.__setattr__(self, "authentication_time", authentication_time)
        object.__setattr__(self, "ready_time", ready_time)


@dataclass(frozen=True, slots=True)
class RdpDeferredSessionIntent:
    """Pure initial or reconnect RDP semantic intent."""

    source: DeferredSessionEndpoint
    target: DeferredSessionEndpoint
    principal: DeferredSessionPrincipal
    identity: DeferredSessionIdentitySpec
    transport_policy: DeferredSessionTransportPolicy
    mode: RdpDeferredSessionMode
    authentication_time: datetime
    hard_deadline: datetime
    logical_session_id: str
    expected_generation: int | None
    end_plan: SessionEndPlan | None = None

    def __post_init__(self) -> None:
        """Validate exact RDP mode, identity, generation, and deadline shape."""

        _validate_intent_common(
            protocol=DeferredSessionProtocol.RDP,
            source=self.source,
            target=self.target,
            principal=self.principal,
            identity=self.identity,
            transport_policy=self.transport_policy,
        )
        _exact(self.mode, RdpDeferredSessionMode, "RDP deferred session mode")
        authentication_time = _utc(self.authentication_time, "RDP authentication time")
        hard_deadline = _utc(self.hard_deadline, "RDP hard deadline")
        if hard_deadline <= authentication_time:
            raise ValueError("RDP hard deadline must follow authentication")
        logical_id = _required_text(self.logical_session_id, "RDP logical session identity")
        if self.mode is RdpDeferredSessionMode.OPEN:
            if self.expected_generation is not None:
                raise ValueError("RDP open rejects reconnect generation identity")
        elif self.expected_generation is None:
            raise ValueError("RDP reconnect requires an expected generation")
        else:
            _integer(self.expected_generation, "RDP reconnect generation", minimum=1)
        if self.end_plan is not None:
            _validate_end_plan(self.end_plan, "RDP session end plan")
            end_time = _utc(self.end_plan.canonical_end, "RDP session end time")
            if end_time < authentication_time or end_time > hard_deadline:
                raise ValueError("RDP session end lies outside its hard deadline")
        object.__setattr__(self, "authentication_time", authentication_time)
        object.__setattr__(self, "hard_deadline", hard_deadline)
        object.__setattr__(self, "logical_session_id", logical_id)


DeferredSessionPresealIntent: TypeAlias = SshDeferredSessionIntent | RdpDeferredSessionIntent


@dataclass(frozen=True, slots=True)
class DeferredSessionTransportSpec:
    """Resolved successful physical transport facts without owner capabilities."""

    transaction_id: str
    conn_id: str
    zeek_uid: str
    source_address: str
    source_port: int
    target_address: str
    target_port: int
    opened_at: datetime
    closes_at: datetime
    initiator_bytes: int
    responder_bytes: int
    conn_state: str = "SF"

    def __post_init__(self) -> None:
        """Normalize the exact successful transport interval and accounting."""

        transaction_id = _required_text(self.transaction_id, "Deferred transport transaction_id")
        conn_id = _required_text(self.conn_id, "Deferred transport conn_id")
        zeek_uid = _required_text(self.zeek_uid, "Deferred transport Zeek UID")
        source_address = _address(self.source_address, "Deferred transport source address")
        target_address = _address(self.target_address, "Deferred transport target address")
        source_port = _port(self.source_port, "Deferred transport source port")
        target_port = _port(self.target_port, "Deferred transport target port")
        if target_port not in {22, 3389}:
            raise ValueError("Deferred session target port must be SSH/22 or RDP/3389")
        opened_at = _utc(self.opened_at, "Deferred transport open time")
        closes_at = _utc(self.closes_at, "Deferred transport close time")
        if closes_at <= opened_at:
            raise ValueError("Deferred transport close must follow transport open")
        _integer(self.initiator_bytes, "Deferred transport initiator bytes")
        _integer(self.responder_bytes, "Deferred transport responder bytes")
        state = _required_text(self.conn_state, "Deferred transport connection state").upper()
        if state != "SF":
            raise ValueError("Deferred successful sessions require an SF transport state")
        object.__setattr__(self, "transaction_id", transaction_id)
        object.__setattr__(self, "conn_id", conn_id)
        object.__setattr__(self, "zeek_uid", zeek_uid)
        object.__setattr__(self, "source_address", source_address)
        object.__setattr__(self, "target_address", target_address)
        object.__setattr__(self, "source_port", source_port)
        object.__setattr__(self, "target_port", target_port)
        object.__setattr__(self, "opened_at", opened_at)
        object.__setattr__(self, "closes_at", closes_at)
        object.__setattr__(self, "conn_state", state)


@dataclass(frozen=True, slots=True)
class DeferredSessionSessionMemberSpec:
    """Pure State session-start member referenced by stable member identity."""

    member_id: str
    identity: SessionIdentity
    logon_type: int
    source_address: str
    source_port: int
    auth_protocol: str

    def __post_init__(self) -> None:
        """Require a positive remote-interactive session member."""

        member_id = _required_text(self.member_id, "Deferred session member identity")
        _validate_session_identity(self.identity, "Deferred session member canonical identity")
        if type(self.logon_type) is not int or self.logon_type != 10:
            raise ValueError("Deferred session members require logon type 10")
        source_address = _address(self.source_address, "Deferred session member source address")
        source_port = _port(self.source_port, "Deferred session member source port")
        auth_protocol = _required_text(
            self.auth_protocol,
            "Deferred session member auth protocol",
        ).casefold()
        if auth_protocol not in {protocol.value for protocol in DeferredSessionProtocol}:
            raise ValueError("Deferred session member auth protocol must be ssh or rdp")
        object.__setattr__(self, "member_id", member_id)
        object.__setattr__(self, "source_address", source_address)
        object.__setattr__(self, "source_port", source_port)
        object.__setattr__(self, "auth_protocol", auth_protocol)


@dataclass(frozen=True, slots=True)
class DeferredSessionProcessMemberSpec:
    """Pure parent-ordered State process-start member."""

    member_id: str
    identity: ProcessIdentity
    role: DeferredSessionProcessRole
    parent_member_id: str = ""
    session_member_id: str = ""

    def __post_init__(self) -> None:
        """Normalize stable references without resolving any State capability."""

        member_id = _required_text(self.member_id, "Deferred process member identity")
        _validate_process_identity(self.identity, "Deferred process member canonical identity")
        _exact(self.role, DeferredSessionProcessRole, "Deferred process member role")
        parent_member_id = _optional_text(
            self.parent_member_id,
            "Deferred process parent member identity",
        )
        session_member_id = _optional_text(
            self.session_member_id,
            "Deferred process session member identity",
        )
        if parent_member_id == member_id or session_member_id == member_id:
            raise ValueError("Deferred process member cannot reference itself")
        object.__setattr__(self, "member_id", member_id)
        object.__setattr__(self, "parent_member_id", parent_member_id)
        object.__setattr__(self, "session_member_id", session_member_id)


DeferredSessionStateMemberSpec: TypeAlias = (
    DeferredSessionSessionMemberSpec | DeferredSessionProcessMemberSpec
)


@dataclass(frozen=True, slots=True)
class DeferredSessionActivitySpec:
    """Pure activity-frontier update for one exact entity object."""

    entity_kind: DeferredSessionEntityKind
    object_id: str
    activity_time: datetime

    def __post_init__(self) -> None:
        """Normalize the reference and canonical activity time."""

        _exact(self.entity_kind, DeferredSessionEntityKind, "Deferred activity entity kind")
        object_id = _required_text(self.object_id, "Deferred activity object identity")
        activity_time = _utc(self.activity_time, "Deferred activity time")
        object.__setattr__(self, "object_id", object_id)
        object.__setattr__(self, "activity_time", activity_time)


@dataclass(frozen=True, slots=True)
class DeferredSessionProcessHoldSpec:
    """Pure lifecycle hold bound to one process object."""

    hold_id: str
    process_object_id: str
    acquired_at: datetime
    hold_until: datetime
    action_id: str
    reason: str

    def __post_init__(self) -> None:
        """Require an ordered, auditable hold interval."""

        hold_id = _required_text(self.hold_id, "Deferred process hold identity")
        process_object_id = _required_text(
            self.process_object_id,
            "Deferred process hold object identity",
        )
        acquired_at = _utc(self.acquired_at, "Deferred process hold acquired time")
        hold_until = _utc(self.hold_until, "Deferred process hold end time")
        if hold_until < acquired_at:
            raise ValueError("Deferred process hold end cannot precede acquisition")
        action_id = _required_text(self.action_id, "Deferred process hold action identity")
        reason = _required_text(self.reason, "Deferred process hold reason")
        object.__setattr__(self, "hold_id", hold_id)
        object.__setattr__(self, "process_object_id", process_object_id)
        object.__setattr__(self, "acquired_at", acquired_at)
        object.__setattr__(self, "hold_until", hold_until)
        object.__setattr__(self, "action_id", action_id)
        object.__setattr__(self, "reason", reason)


@dataclass(frozen=True, slots=True)
class DeferredSessionBoundSessionSpec:
    """Authenticated-later metadata intent for the exact target session."""

    reference_id: str
    binding_disposition: DeferredSessionBindingDisposition
    identity: SessionIdentity
    source_address: str
    source_port: int
    transport_process_object_id: str
    network_close_time: datetime
    source_ready_time: datetime
    closure_owned_by_bundle: bool
    end_plan: SessionEndPlan | None = None

    def __post_init__(self) -> None:
        """Normalize session metadata without applying it to State."""

        reference_id = _required_text(
            self.reference_id,
            "Deferred bound session semantic reference",
        )
        identity = _validate_session_identity(
            self.identity,
            "Deferred bound session identity",
        )
        _exact(
            self.binding_disposition,
            DeferredSessionBindingDisposition,
            "Deferred bound session binding disposition",
        )
        source_address = _address(self.source_address, "Deferred bound session source address")
        source_port = _port(self.source_port, "Deferred bound session source port")
        transport_object_id = _optional_text(
            self.transport_process_object_id,
            "Deferred bound session transport process identity",
        )
        close_time = _utc(self.network_close_time, "Deferred bound session network close")
        ready_time = _utc(self.source_ready_time, "Deferred bound session source readiness")
        if ready_time < _utc(identity.started_at, "Deferred bound session start time"):
            raise ValueError("Deferred session readiness cannot precede session start")
        if close_time < ready_time:
            raise ValueError("Deferred session network close cannot precede readiness")
        if type(self.closure_owned_by_bundle) is not bool:
            raise TypeError("Deferred session closure ownership requires an exact bool")
        if self.end_plan is not None:
            _validate_end_plan(self.end_plan, "Deferred bound session end plan")
            end_time = _utc(self.end_plan.canonical_end, "Deferred bound session end time")
            if end_time < close_time:
                raise ValueError("Deferred session end cannot precede network close")
        object.__setattr__(self, "reference_id", reference_id)
        object.__setattr__(self, "source_address", source_address)
        object.__setattr__(self, "source_port", source_port)
        object.__setattr__(self, "transport_process_object_id", transport_object_id)
        object.__setattr__(self, "network_close_time", close_time)
        object.__setattr__(self, "source_ready_time", ready_time)


@dataclass(frozen=True, slots=True)
class SshDeferredAdmissionSpec:
    """Pure values consumed later by the SSH staged manager API."""

    channel_id: str
    operation_id: str
    semantic_operation_id: str
    authentication_method: SshDeferredAuthenticationMethod
    operation_kind: SshDeferredOperationKind
    started_at: datetime
    ended_at: datetime
    initiator_bytes: int
    responder_bytes: int

    def __post_init__(self) -> None:
        """Validate exact SSH identifiers, operation span, and accounting."""

        channel_id = _required_text(self.channel_id, "SSH admission channel identity")
        operation_id = _required_text(self.operation_id, "SSH admission operation identity")
        semantic_id = _required_text(
            self.semantic_operation_id,
            "SSH admission semantic operation identity",
        )
        _exact(
            self.authentication_method,
            SshDeferredAuthenticationMethod,
            "SSH admission authentication method",
        )
        _exact(self.operation_kind, SshDeferredOperationKind, "SSH admission operation kind")
        started_at = _utc(self.started_at, "SSH admission operation start")
        ended_at = _utc(self.ended_at, "SSH admission operation end")
        if ended_at < started_at:
            raise ValueError("SSH admission operation end cannot precede its start")
        _integer(self.initiator_bytes, "SSH admission initiator bytes")
        _integer(self.responder_bytes, "SSH admission responder bytes")
        object.__setattr__(self, "channel_id", channel_id)
        object.__setattr__(self, "operation_id", operation_id)
        object.__setattr__(self, "semantic_operation_id", semantic_id)
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "ended_at", ended_at)


@dataclass(frozen=True, slots=True)
class RdpOpenAdmissionSpec:
    """Pure initial values consumed later by the RDP staged manager."""

    logical_session_id: str
    operation_id: str
    connected_at: datetime
    hard_deadline: datetime
    initiator_bytes: int
    responder_bytes: int

    def __post_init__(self) -> None:
        """Require one exact initial RDP generation."""

        logical_id = _required_text(self.logical_session_id, "RDP logical session identity")
        operation_id = _required_text(self.operation_id, "RDP admission operation identity")
        connected_at = _utc(self.connected_at, "RDP admission connection time")
        hard_deadline = _utc(self.hard_deadline, "RDP admission hard deadline")
        if hard_deadline <= connected_at:
            raise ValueError("RDP admission hard deadline must follow connection")
        _integer(self.initiator_bytes, "RDP admission initiator bytes")
        _integer(self.responder_bytes, "RDP admission responder bytes")
        object.__setattr__(self, "logical_session_id", logical_id)
        object.__setattr__(self, "operation_id", operation_id)
        object.__setattr__(self, "connected_at", connected_at)
        object.__setattr__(self, "hard_deadline", hard_deadline)


@dataclass(frozen=True, slots=True)
class RdpReconnectAdmissionSpec:
    """Pure ordered prior/current RDP reconnect admission values."""

    logical_session_id: str
    operation_id: str
    connected_at: datetime
    hard_deadline: datetime
    expected_generation: int
    initiator_bytes: int
    responder_bytes: int
    prior_transport_id: str
    current_transport_id: str

    def __post_init__(self) -> None:
        """Require a later generation and distinct ordered transport identities."""

        logical_id = _required_text(self.logical_session_id, "RDP logical session identity")
        operation_id = _required_text(self.operation_id, "RDP admission operation identity")
        connected_at = _utc(self.connected_at, "RDP reconnect connection time")
        hard_deadline = _utc(self.hard_deadline, "RDP reconnect hard deadline")
        if hard_deadline <= connected_at:
            raise ValueError("RDP reconnect hard deadline must follow connection")
        _integer(self.expected_generation, "RDP reconnect generation", minimum=1)
        prior_transport_id = _required_text(
            self.prior_transport_id,
            "RDP reconnect prior transport identity",
        )
        current_transport_id = _required_text(
            self.current_transport_id,
            "RDP reconnect current transport identity",
        )
        if current_transport_id == prior_transport_id:
            raise ValueError("RDP reconnect prior and current transports must be distinct")
        _integer(self.initiator_bytes, "RDP reconnect initiator bytes")
        _integer(self.responder_bytes, "RDP reconnect responder bytes")
        object.__setattr__(self, "logical_session_id", logical_id)
        object.__setattr__(self, "operation_id", operation_id)
        object.__setattr__(self, "connected_at", connected_at)
        object.__setattr__(self, "hard_deadline", hard_deadline)
        object.__setattr__(self, "prior_transport_id", prior_transport_id)
        object.__setattr__(self, "current_transport_id", current_transport_id)

    @property
    def transport_ids(self) -> tuple[str, str]:
        """Return the manager-required ordered prior/current transport pair."""

        return (self.prior_transport_id, self.current_transport_id)


RdpDeferredAdmissionSpec: TypeAlias = RdpOpenAdmissionSpec | RdpReconnectAdmissionSpec
DeferredSessionAdmissionSpec: TypeAlias = SshDeferredAdmissionSpec | RdpDeferredAdmissionSpec


@dataclass(frozen=True, slots=True)
class DeferredSessionStateStartOccurrenceSpec:
    """Semantic start occurrence for one exact State member reference."""

    occurrence_id: str
    event_type: EventKind
    canonical_time: datetime
    member_id: str
    publication_ordinal: int

    def __post_init__(self) -> None:
        """Normalize one positive transport-relative start ordinal."""

        occurrence_id = _required_text(self.occurrence_id, "Deferred start occurrence identity")
        _exact(self.event_type, EventKind, "Deferred start occurrence event kind")
        canonical_time = _utc(self.canonical_time, "Deferred start occurrence time")
        member_id = _required_text(self.member_id, "Deferred start occurrence member identity")
        _integer(
            self.publication_ordinal,
            "Deferred start publication ordinal",
            minimum=1,
        )
        object.__setattr__(self, "occurrence_id", occurrence_id)
        object.__setattr__(self, "canonical_time", canonical_time)
        object.__setattr__(self, "member_id", member_id)


@dataclass(frozen=True, slots=True)
class DeferredSessionDependentOccurrenceSpec:
    """Semantic non-State occurrence with stable State-member references."""

    occurrence_id: str
    event_type: EventKind
    canonical_time: datetime
    member_references: tuple[str, ...]
    publication_ordinal: int

    def __post_init__(self) -> None:
        """Require exact immutable references and a positive publication ordinal."""

        occurrence_id = _required_text(
            self.occurrence_id,
            "Deferred dependent occurrence identity",
        )
        _exact(self.event_type, EventKind, "Deferred dependent occurrence event kind")
        canonical_time = _utc(self.canonical_time, "Deferred dependent occurrence time")
        if type(self.member_references) is not tuple:
            raise TypeError("Deferred dependent member references require an exact inert tuple")
        references = tuple(
            _required_text(reference, "Deferred dependent member reference")
            for reference in self.member_references
        )
        if len(set(references)) != len(references):
            raise ValueError("Deferred dependent occurrence repeats a member reference")
        _integer(
            self.publication_ordinal,
            "Deferred dependent publication ordinal",
            minimum=1,
        )
        object.__setattr__(self, "occurrence_id", occurrence_id)
        object.__setattr__(self, "canonical_time", canonical_time)
        object.__setattr__(self, "member_references", references)


@dataclass(frozen=True, slots=True)
class DeferredSessionPresealPayload:
    """Complete inert semantic payload for one later owner resolution."""

    protocol: DeferredSessionProtocol
    intent: DeferredSessionPresealIntent
    transport: DeferredSessionTransportSpec
    state_members: tuple[DeferredSessionStateMemberSpec, ...]
    activity: tuple[DeferredSessionActivitySpec, ...]
    process_holds: tuple[DeferredSessionProcessHoldSpec, ...]
    bound_session: DeferredSessionBoundSessionSpec
    application_admission: DeferredSessionAdmissionSpec
    state_starts: tuple[DeferredSessionStateStartOccurrenceSpec, ...]
    dependents: tuple[DeferredSessionDependentOccurrenceSpec, ...]

    def __post_init__(self) -> None:
        """Validate exact pairing, references, order, timing, and containment."""

        _exact(self.protocol, DeferredSessionProtocol, "Deferred payload protocol")
        _revalidate(self.transport, DeferredSessionTransportSpec, "Deferred payload transport")
        _revalidate(
            self.bound_session,
            DeferredSessionBoundSessionSpec,
            "Deferred payload bound session",
        )
        for value, field_name in (
            (self.state_members, "state_members"),
            (self.activity, "activity"),
            (self.process_holds, "process_holds"),
            (self.state_starts, "state_starts"),
            (self.dependents, "dependents"),
        ):
            if type(value) is not tuple:
                raise TypeError(f"Deferred payload {field_name} requires an exact inert tuple")
        _validate_payload_pairing(self)
        _validate_payload_transport(self)
        members = _validate_payload_members(self)
        _validate_protocol_process_roles(self, members)
        _validate_payload_activity_and_holds(self, members)
        _validate_payload_occurrences(self, members)

    @property
    def transport_ordinal(self) -> int:
        """Return the reserved transport-first publication ordinal."""

        return 0


def _validate_payload_pairing(payload: DeferredSessionPresealPayload) -> None:
    disposition = payload.bound_session.binding_disposition
    if payload.protocol is DeferredSessionProtocol.SSH:
        _revalidate(payload.intent, SshDeferredSessionIntent, "SSH deferred payload intent")
        _revalidate(
            payload.application_admission,
            SshDeferredAdmissionSpec,
            "SSH deferred payload admission",
        )
        assert isinstance(payload.intent, SshDeferredSessionIntent)
        if payload.bound_session.identity.session_kind.casefold() != "ssh":
            raise ValueError("SSH payload bound session has the wrong session kind")
        return
    _revalidate(payload.intent, RdpDeferredSessionIntent, "RDP deferred payload intent")
    assert isinstance(payload.intent, RdpDeferredSessionIntent)
    if payload.intent.mode is RdpDeferredSessionMode.OPEN:
        if disposition not in {
            DeferredSessionBindingDisposition.NEW_SESSION,
            DeferredSessionBindingDisposition.PREALLOCATED_SESSION_START,
        }:
            raise ValueError("RDP open requires a new or preallocated session binding")
        _revalidate(
            payload.application_admission,
            RdpOpenAdmissionSpec,
            "RDP open payload admission",
        )
    else:
        if disposition is not DeferredSessionBindingDisposition.ACTIVE_SESSION:
            raise ValueError("RDP reconnect requires an active-session binding")
        _revalidate(
            payload.application_admission,
            RdpReconnectAdmissionSpec,
            "RDP reconnect payload admission",
        )
    if payload.bound_session.identity.session_kind.casefold() != "rdp":
        raise ValueError("RDP payload bound session has the wrong session kind")


def _validate_payload_transport(payload: DeferredSessionPresealPayload) -> None:
    transport = payload.transport
    intent = payload.intent
    policy = intent.transport_policy
    expected_port = 22 if payload.protocol is DeferredSessionProtocol.SSH else 3389
    if transport.target_port != expected_port:
        raise ValueError(
            f"Deferred {payload.protocol.value.upper()} transport requires port {expected_port}"
        )
    if transport.source_address != intent.source.address:
        raise ValueError("Deferred transport source address differs from the protocol intent")
    if transport.target_address != intent.target.address:
        raise ValueError("Deferred transport target address differs from the protocol intent")
    if (
        policy.requested_source_port is not None
        and transport.source_port != policy.requested_source_port
    ):
        raise ValueError("Deferred transport source port differs from the requested port")
    duration = transport.closes_at - transport.opened_at
    if not policy.duration_min <= duration <= policy.duration_max:
        raise ValueError("Deferred transport duration lies outside its policy bounds")
    if not policy.initiator_bytes_min <= transport.initiator_bytes <= policy.initiator_bytes_max:
        raise ValueError("Deferred transport initiator bytes lie outside policy bounds")
    if not policy.responder_bytes_min <= transport.responder_bytes <= policy.responder_bytes_max:
        raise ValueError("Deferred transport responder bytes lie outside policy bounds")
    authentication_time = intent.authentication_time
    if not transport.opened_at < authentication_time < transport.closes_at:
        raise ValueError("Deferred authentication time must be inside the transport")
    bound = payload.bound_session
    if bound.identity != intent.identity.identity:
        raise ValueError("Deferred bound session differs from the intent identity")
    if bound.end_plan != intent.end_plan:
        raise ValueError("Deferred bound session end plan differs from the protocol intent")
    if isinstance(intent, SshDeferredSessionIntent):
        if bound.source_ready_time != intent.ready_time:
            raise ValueError("SSH bound session readiness differs from the protocol intent")
    if (
        bound.source_address != transport.source_address
        or bound.source_port != transport.source_port
    ):
        raise ValueError("Deferred bound session source tuple differs from the transport")
    if bound.network_close_time != transport.closes_at:
        raise ValueError("Deferred bound session close differs from the transport close")
    if not transport.opened_at < bound.source_ready_time < transport.closes_at:
        raise ValueError("Deferred session readiness must be inside the transport")
    if bound.source_ready_time < authentication_time:
        raise ValueError("Deferred session readiness cannot precede authentication")
    if bound.end_plan is not None:
        end_time = _utc(bound.end_plan.canonical_end, "Deferred bound session end time")
        if end_time < transport.closes_at:
            raise ValueError("Deferred session end cannot precede transport close")
    admission = payload.application_admission
    if admission.initiator_bytes != transport.initiator_bytes:
        raise ValueError("Deferred application initiator bytes differ from transport accounting")
    if admission.responder_bytes != transport.responder_bytes:
        raise ValueError("Deferred application responder bytes differ from transport accounting")
    if isinstance(admission, SshDeferredAdmissionSpec):
        if admission.semantic_operation_id != intent.operation_semantic_id:
            raise ValueError("SSH admission semantic operation identity differs from its intent")
        if admission.authentication_method is not intent.authentication_method:
            raise ValueError("SSH admission authentication method differs from its intent")
        if admission.operation_kind is not intent.operation_kind:
            raise ValueError("SSH admission operation kind differs from its intent")
        if admission.started_at < bound.source_ready_time:
            raise ValueError("SSH admission operation starts before session readiness")
        if admission.ended_at > transport.closes_at:
            raise ValueError("SSH admission operation ends after transport close")
    elif isinstance(admission, (RdpOpenAdmissionSpec, RdpReconnectAdmissionSpec)):
        assert isinstance(intent, RdpDeferredSessionIntent)
        if admission.logical_session_id != intent.logical_session_id:
            raise ValueError("RDP admission logical session differs from its intent")
        if not transport.opened_at <= admission.connected_at < transport.closes_at:
            raise ValueError("RDP admission connection must lie inside the transport")
        if admission.hard_deadline != intent.hard_deadline:
            raise ValueError("RDP admission hard deadline differs from its intent")
        if transport.closes_at > admission.hard_deadline:
            raise ValueError("RDP transport closes after its hard deadline")
        if isinstance(admission, RdpReconnectAdmissionSpec):
            if admission.expected_generation != intent.expected_generation:
                raise ValueError("RDP reconnect generation differs from its intent")
            current = admission.current_transport_id
            if current != transport.transaction_id:
                raise ValueError("RDP reconnect current transport differs from the payload")
            if admission.prior_transport_id == current:
                raise ValueError("RDP reconnect prior and current transports must be distinct")


def _validate_payload_members(
    payload: DeferredSessionPresealPayload,
) -> dict[str, DeferredSessionStateMemberSpec]:
    members: dict[str, DeferredSessionStateMemberSpec] = {}
    disposition = payload.bound_session.binding_disposition
    bound_reference = payload.bound_session.reference_id
    session_members = 0
    process_object_ids: set[str] = set()
    session_object_ids: set[str] = set()
    for index, member in enumerate(payload.state_members):
        if type(member) not in {
            DeferredSessionSessionMemberSpec,
            DeferredSessionProcessMemberSpec,
        }:
            raise TypeError("Deferred State member has an unsupported exact type")
        replace(member)
        if member.member_id in members:
            raise ValueError("Deferred payload repeats a State member identity")
        if isinstance(member, DeferredSessionSessionMemberSpec):
            session_members += 1
            if index != 0:
                raise ValueError("Deferred session member must precede process members")
            if member.identity.object_id in session_object_ids:
                raise ValueError("Deferred payload repeats a session object identity")
            if member.identity.session_kind.casefold() != payload.protocol.value:
                raise ValueError("Deferred State session kind differs from payload protocol")
            if member.auth_protocol != payload.protocol.value:
                raise ValueError(
                    f"Deferred {payload.protocol.value.upper()} State member auth protocol drift"
                )
            if member.identity != payload.bound_session.identity:
                raise ValueError("Deferred State session differs from the bound target session")
            if member.source_address != payload.transport.source_address:
                raise ValueError("Deferred State session source address differs from transport")
            if member.source_port != payload.transport.source_port:
                raise ValueError("Deferred State session source port differs from transport")
            session_object_ids.add(member.identity.object_id)
        else:
            if member.identity.object_id in process_object_ids:
                raise ValueError("Deferred payload repeats a process object identity")
            if member.parent_member_id:
                parent = members.get(member.parent_member_id)
                if type(parent) is not DeferredSessionProcessMemberSpec:
                    raise ValueError("Deferred process parent must be an earlier process member")
                assert isinstance(parent, DeferredSessionProcessMemberSpec)
                if member.identity.hostname.casefold().rstrip(
                    "."
                ) != parent.identity.hostname.casefold().rstrip("."):
                    raise ValueError("Deferred process parent must run on the same host")
                if member.identity.parent_pid != parent.identity.pid:
                    raise ValueError(
                        "Deferred process parent PID differs from its member reference"
                    )
                if member.identity.parent_lifecycle_group_id != parent.identity.lifecycle_group_id:
                    raise ValueError(
                        "Deferred process lifecycle parent differs from its member reference"
                    )
            if member.session_member_id:
                session = members.get(member.session_member_id)
                if session is None and (
                    disposition
                    in {
                        DeferredSessionBindingDisposition.PREALLOCATED_SESSION_START,
                        DeferredSessionBindingDisposition.ACTIVE_SESSION,
                    }
                    and member.session_member_id == bound_reference
                ):
                    if member.identity.logon_id != payload.bound_session.identity.logon_id:
                        raise ValueError(
                            "Deferred process LogonID differs from its bound existing session"
                        )
                else:
                    if type(session) is not DeferredSessionSessionMemberSpec:
                        raise ValueError(
                            "Deferred process session must be an earlier or bound session"
                        )
                    assert isinstance(session, DeferredSessionSessionMemberSpec)
                    if member.identity.logon_id != session.identity.logon_id:
                        raise ValueError("Deferred process LogonID differs from its session member")
            process_object_ids.add(member.identity.object_id)
        members[member.member_id] = member
    if session_members > 1:
        raise ValueError("Deferred payload may start at most one session member")
    if disposition is DeferredSessionBindingDisposition.NEW_SESSION:
        if session_members != 1:
            raise ValueError("New deferred session binding requires exactly one State session")
    elif session_members != 0:
        raise ValueError("Existing deferred session binding cannot start another State session")
    referenced_member = members.get(bound_reference)
    if disposition is DeferredSessionBindingDisposition.NEW_SESSION:
        if referenced_member is None:
            raise ValueError("New deferred session binding must reference its State member")
        if type(referenced_member) is not DeferredSessionSessionMemberSpec:
            raise ValueError("Deferred bound-session reference collides with a process member")
        assert isinstance(referenced_member, DeferredSessionSessionMemberSpec)
        if referenced_member.identity != payload.bound_session.identity:
            raise ValueError("Deferred bound-session reference identifies a different session")
    elif referenced_member is not None:
        raise ValueError("Existing deferred session binding must use an external reference")
    return members


def _validate_protocol_process_roles(
    payload: DeferredSessionPresealPayload,
    members: dict[str, DeferredSessionStateMemberSpec],
) -> None:
    """Require protocol-specific process shape and endpoint/session containment."""

    processes = tuple(
        member
        for member in members.values()
        if isinstance(member, DeferredSessionProcessMemberSpec)
    )
    roles: dict[DeferredSessionProcessRole, DeferredSessionProcessMemberSpec] = {}
    for process in processes:
        if process.role in roles:
            raise ValueError("Deferred payload repeats a protocol process role")
        roles[process.role] = process
        if (
            _utc(process.identity.started_at, "Deferred process start")
            >= payload.transport.closes_at
        ):
            raise ValueError("Deferred process starts at or after transport close")

    source_host = payload.intent.source.hostname
    target_host = payload.intent.target.hostname
    bound_reference = payload.bound_session.reference_id
    if payload.protocol is DeferredSessionProtocol.SSH:
        allowed = {
            DeferredSessionProcessRole.SOURCE_CLIENT,
            DeferredSessionProcessRole.SSH_RECEIVER,
            DeferredSessionProcessRole.SSH_SHELL,
        }
        if any(role not in allowed for role in roles):
            raise ValueError("SSH payload contains an RDP or unsupported process role")
        receiver = roles.get(DeferredSessionProcessRole.SSH_RECEIVER)
        if receiver is None:
            raise ValueError("SSH payload requires exactly one receiver process")
        if receiver.identity.hostname.casefold().rstrip(".") != target_host:
            raise ValueError("SSH receiver process must run on the target host")
        if receiver.identity.principal.casefold() != "root":
            raise ValueError("SSH receiver process must retain privileged root ownership")
        if receiver.session_member_id != bound_reference:
            raise ValueError("SSH receiver process must bind the target session")
        if payload.bound_session.transport_process_object_id != receiver.identity.object_id:
            raise ValueError("SSH bound session transport process differs from the receiver")
        shell = roles.get(DeferredSessionProcessRole.SSH_SHELL)
        if shell is not None:
            if shell.identity.hostname.casefold().rstrip(".") != target_host:
                raise ValueError("SSH shell process must run on the target host")
            if (
                shell.identity.principal.casefold()
                != payload.bound_session.identity.principal.casefold()
            ):
                raise ValueError("SSH shell principal differs from the target session")
            if shell.session_member_id != bound_reference:
                raise ValueError("SSH shell process must bind the target session")
            if shell.parent_member_id != receiver.member_id:
                raise ValueError("SSH shell process must be parented by the receiver")
        source = roles.get(DeferredSessionProcessRole.SOURCE_CLIENT)
        if source is not None:
            if source.identity.hostname.casefold().rstrip(".") != source_host:
                raise ValueError("SSH source client process must run on the source host")
            if source.session_member_id:
                raise ValueError("SSH source client cannot bind the target session member")
        return

    allowed = {
        DeferredSessionProcessRole.SOURCE_CLIENT,
        DeferredSessionProcessRole.RDP_USER_MANAGER,
        DeferredSessionProcessRole.RDP_WINLOGON,
        DeferredSessionProcessRole.RDP_USERINIT,
        DeferredSessionProcessRole.RDP_EXPLORER,
        DeferredSessionProcessRole.PROCESS_TREE_ROOT,
    }
    if any(role not in allowed for role in roles):
        raise ValueError("RDP payload contains an SSH or unsupported process role")
    source = roles.get(DeferredSessionProcessRole.SOURCE_CLIENT)
    if source is not None:
        if source.identity.hostname.casefold().rstrip(".") != source_host:
            raise ValueError("RDP source client process must run on the source host")
        if source.session_member_id:
            raise ValueError("RDP source client cannot bind the target session member")
    target_roles = tuple(
        role for role in roles if role is not DeferredSessionProcessRole.SOURCE_CLIENT
    )
    assert isinstance(payload.intent, RdpDeferredSessionIntent)
    if payload.intent.mode is RdpDeferredSessionMode.RECONNECT and target_roles:
        raise ValueError("RDP reconnect cannot start a second target-session process tree")
    for role in target_roles:
        process = roles[role]
        if process.identity.hostname.casefold().rstrip(".") != target_host:
            raise ValueError("RDP target-session process must run on the target host")
        if process.session_member_id != bound_reference:
            raise ValueError("RDP target-session process must bind the target session")
    transport_process_id = payload.bound_session.transport_process_object_id
    if transport_process_id:
        if source is None or transport_process_id != source.identity.object_id:
            raise ValueError("RDP bound transport process must be the source mstsc process")


def _validate_payload_activity_and_holds(
    payload: DeferredSessionPresealPayload,
    members: dict[str, DeferredSessionStateMemberSpec],
) -> None:
    object_kinds: dict[str, DeferredSessionEntityKind] = {
        payload.bound_session.identity.object_id: DeferredSessionEntityKind.SESSION,
    }
    process_members: dict[str, DeferredSessionProcessMemberSpec] = {}
    for member in members.values():
        if isinstance(member, DeferredSessionSessionMemberSpec):
            object_kinds[member.identity.object_id] = DeferredSessionEntityKind.SESSION
        else:
            object_kinds[member.identity.object_id] = DeferredSessionEntityKind.PROCESS
            process_members[member.identity.object_id] = member
    activity_keys: set[tuple[DeferredSessionEntityKind, str]] = set()
    end_time = (
        payload.bound_session.end_plan.canonical_end
        if payload.bound_session.end_plan is not None
        else payload.transport.closes_at
    )
    end_time = _utc(end_time, "Deferred payload activity end bound")
    for activity in payload.activity:
        _revalidate(activity, DeferredSessionActivitySpec, "Deferred payload activity spec")
        expected_kind = object_kinds.get(activity.object_id)
        if expected_kind is None or expected_kind is not activity.entity_kind:
            raise ValueError("Deferred activity references an unknown or wrong-kind entity")
        key = (activity.entity_kind, activity.object_id)
        if key in activity_keys:
            raise ValueError("Deferred payload repeats an activity entity")
        if activity.activity_time > end_time:
            raise ValueError("Deferred activity time exceeds the session end bound")
        activity_keys.add(key)
    hold_ids: set[str] = set()
    held_processes: set[str] = set()
    for hold in payload.process_holds:
        _revalidate(hold, DeferredSessionProcessHoldSpec, "Deferred payload process hold")
        if hold.hold_id in hold_ids or hold.process_object_id in held_processes:
            raise ValueError("Deferred payload repeats a process hold")
        member = process_members.get(hold.process_object_id)
        if member is None:
            raise ValueError("Deferred process hold references an unknown process member")
        if hold.acquired_at != _utc(member.identity.started_at, "Deferred held process start"):
            raise ValueError("Deferred process hold acquisition differs from process start")
        if hold.hold_until < payload.transport.closes_at:
            raise ValueError("Deferred process hold ends before the transport close")
        hold_ids.add(hold.hold_id)
        held_processes.add(hold.process_object_id)
    transport_object_id = payload.bound_session.transport_process_object_id
    if transport_object_id:
        if transport_object_id not in process_members:
            raise ValueError("Deferred bound session transport process is not a State member")
        if transport_object_id not in held_processes:
            raise ValueError("Deferred bound session transport process lacks a lifecycle hold")


def _validate_payload_occurrences(
    payload: DeferredSessionPresealPayload,
    members: dict[str, DeferredSessionStateMemberSpec],
) -> None:
    starts_by_member: dict[str, DeferredSessionStateStartOccurrenceSpec] = {}
    occurrence_ids: set[str] = set()
    ordered_occurrences = (*payload.state_starts, *payload.dependents)
    expected_ordinals = tuple(range(1, len(ordered_occurrences) + 1))
    actual_ordinals = tuple(item.publication_ordinal for item in ordered_occurrences)
    if actual_ordinals != expected_ordinals:
        raise ValueError("Deferred occurrence publication ordinal order is not contiguous")
    for start in payload.state_starts:
        _revalidate(
            start,
            DeferredSessionStateStartOccurrenceSpec,
            "Deferred State start occurrence",
        )
        if start.occurrence_id in occurrence_ids:
            raise ValueError("Deferred payload repeats an occurrence identity")
        member = members.get(start.member_id)
        if member is None:
            raise ValueError("Deferred State start references an unknown member")
        if start.member_id in starts_by_member:
            raise ValueError("Deferred payload repeats a State member start")
        if isinstance(member, DeferredSessionSessionMemberSpec):
            if start.event_type is not EventKind.LOGON:
                raise ValueError("Deferred session member start requires a logon occurrence")
        elif start.event_type not in {EventKind.PROCESS_CREATE, EventKind.SYSTEM_PROCESS_CREATE}:
            raise ValueError("Deferred process member start requires a process-create occurrence")
        if start.canonical_time != _utc(member.identity.started_at, "Deferred member start time"):
            raise ValueError("Deferred State start time differs from the member identity")
        starts_by_member[start.member_id] = start
        occurrence_ids.add(start.occurrence_id)
    if set(starts_by_member) != set(members):
        raise ValueError("Deferred State starts do not cover all and only State members")
    if tuple(starts_by_member) != tuple(members):
        raise ValueError("Deferred State starts must preserve parent-before-child member order")
    valid_references = set(members)
    valid_references.add(payload.bound_session.reference_id)
    reference_start_times = {
        member_id: _utc(member.identity.started_at, "Deferred member reference start")
        for member_id, member in members.items()
    }
    reference_start_times[payload.bound_session.reference_id] = _utc(
        payload.bound_session.identity.started_at,
        "Deferred bound-session reference start",
    )
    session_end = (
        payload.bound_session.end_plan.canonical_end
        if payload.bound_session.end_plan is not None
        else payload.transport.closes_at
    )
    session_end = _utc(session_end, "Deferred dependent session end bound")
    for dependent in payload.dependents:
        _revalidate(
            dependent,
            DeferredSessionDependentOccurrenceSpec,
            "Deferred dependent occurrence",
        )
        if dependent.occurrence_id in occurrence_ids:
            raise ValueError("Deferred payload repeats an occurrence identity")
        if any(reference not in valid_references for reference in dependent.member_references):
            raise ValueError("Deferred dependent occurrence has an unknown member reference")
        if not payload.transport.opened_at <= dependent.canonical_time <= session_end:
            raise ValueError("Deferred dependent occurrence lies outside its session interval")
        if any(
            dependent.canonical_time < reference_start_times[reference]
            for reference in dependent.member_references
        ):
            raise ValueError("Deferred dependent occurrence precedes a referenced member start")
        occurrence_ids.add(dependent.occurrence_id)
