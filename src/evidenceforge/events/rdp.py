# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical identities and snapshots for reconnectable RDP sessions.

An RDP logon is one logical Windows session that may outlive several network
transports.  These frozen values keep that logical identity distinct from each
immutable transport generation.  They intentionally carry counters rather
than completed operation or transport histories.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationChannelCensus,
    ApplicationOperationReservation,
    ApplicationTransportBinding,
)
from evidenceforge.utils.time import ensure_utc


def _required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized


def _normalized_host(value: str, field_name: str) -> str:
    normalized = _required_text(value, field_name).casefold().rstrip(".")
    if not normalized:
        raise ValueError(f"{field_name} must not contain only dots")
    return normalized


def _semantic_digest(namespace: str, values: tuple[object, ...]) -> str:
    encoded = json.dumps(
        (namespace, *values),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class RdpSessionState(StrEnum):
    """Lifecycle state of one logical RDP session."""

    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    LOGGED_OUT = "logged_out"


@dataclass(frozen=True, slots=True)
class RdpSessionAffinity:
    """Exact logical-session affinity, excluding replaceable transport facts."""

    source_host: str
    source_address: str
    target_host: str
    target_address: str
    principal: str
    logon_id: str
    session_id: int
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        """Normalize Windows identity fields and compute one exact digest."""

        source_host = _normalized_host(self.source_host, "source_host")
        source_address = _required_text(self.source_address, "source_address").casefold()
        target_host = _normalized_host(self.target_host, "target_host")
        target_address = _required_text(self.target_address, "target_address").casefold()
        principal = _required_text(self.principal, "principal").casefold()
        logon_id = _required_text(self.logon_id, "logon_id").casefold()
        if self.session_id < 0:
            raise ValueError("RDP session_id must be non-negative")
        object.__setattr__(self, "source_host", source_host)
        object.__setattr__(self, "source_address", source_address)
        object.__setattr__(self, "target_host", target_host)
        object.__setattr__(self, "target_address", target_address)
        object.__setattr__(self, "principal", principal)
        object.__setattr__(self, "logon_id", logon_id)
        object.__setattr__(
            self,
            "digest",
            _semantic_digest(
                "rdp-logical-affinity-v1",
                (
                    source_host,
                    source_address,
                    target_host,
                    target_address,
                    principal,
                    logon_id,
                    self.session_id,
                ),
            ),
        )


@dataclass(frozen=True, slots=True)
class RdpLogicalSessionIdentity:
    """Immutable identity, fences, and aggregate budget for one RDP logon."""

    logical_session_id: str
    affinity: RdpSessionAffinity
    started_at: datetime
    idle_timeout: timedelta
    reconnect_timeout: timedelta
    hard_deadline: datetime
    budget: ApplicationChannelBudget

    def __post_init__(self) -> None:
        """Normalize the interval and reject non-progressing timeout fences."""

        object.__setattr__(
            self,
            "logical_session_id",
            _required_text(self.logical_session_id, "logical_session_id"),
        )
        started_at = ensure_utc(self.started_at)
        hard_deadline = ensure_utc(self.hard_deadline)
        if self.idle_timeout <= timedelta(0):
            raise ValueError("RDP idle_timeout must be positive")
        if self.reconnect_timeout <= timedelta(0):
            raise ValueError("RDP reconnect_timeout must be positive")
        if hard_deadline <= started_at:
            raise ValueError("RDP hard_deadline must follow started_at")
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "hard_deadline", hard_deadline)

    @property
    def owner_id(self) -> str:
        """Return the stable application-channel owner for every generation."""

        return f"rdp-logical-session:{self.logical_session_id}"


@dataclass(frozen=True, slots=True)
class RdpTransportPlan:
    """One requested immutable channel/transport generation."""

    channel_id: str
    binding: ApplicationTransportBinding
    connected_at: datetime
    budget: ApplicationChannelBudget

    def __post_init__(self) -> None:
        """Normalize connection time and require transport containment."""

        object.__setattr__(self, "channel_id", _required_text(self.channel_id, "channel_id"))
        connected_at = ensure_utc(self.connected_at)
        if connected_at < self.binding.opened_at or connected_at >= self.binding.closes_at:
            raise ValueError("RDP connected_at must be inside its transport binding")
        object.__setattr__(self, "connected_at", connected_at)


@dataclass(frozen=True, slots=True)
class RdpTransportGeneration:
    """Current or most-recent immutable transport generation of a session."""

    ordinal: int
    channel_id: str
    binding: ApplicationTransportBinding
    connected_at: datetime
    idle_deadline: datetime
    disconnected_at: datetime | None = None

    def __post_init__(self) -> None:
        """Normalize times without weakening the immutable binding."""

        if self.ordinal < 0:
            raise ValueError("RDP transport generation ordinal must be non-negative")
        object.__setattr__(self, "channel_id", _required_text(self.channel_id, "channel_id"))
        connected_at = ensure_utc(self.connected_at)
        idle_deadline = ensure_utc(self.idle_deadline)
        disconnected_at = (
            ensure_utc(self.disconnected_at) if self.disconnected_at is not None else None
        )
        if connected_at < self.binding.opened_at or connected_at >= self.binding.closes_at:
            raise ValueError("RDP generation connection must be inside its transport")
        if idle_deadline < connected_at:
            raise ValueError("RDP generation idle deadline cannot precede connection")
        if disconnected_at is not None and disconnected_at < connected_at:
            raise ValueError("RDP generation disconnect cannot precede connection")
        object.__setattr__(self, "connected_at", connected_at)
        object.__setattr__(self, "idle_deadline", idle_deadline)
        object.__setattr__(self, "disconnected_at", disconnected_at)


@dataclass(frozen=True, slots=True)
class RdpRetentionLease:
    """Explicit bounded retention authority for one logical-session tombstone."""

    lease_id: str
    logical_session_id: str
    acquired_at: datetime
    retain_until: datetime
    reason: str

    def __post_init__(self) -> None:
        """Normalize the lease interval and require an auditable reason."""

        object.__setattr__(self, "lease_id", _required_text(self.lease_id, "lease_id"))
        object.__setattr__(
            self,
            "logical_session_id",
            _required_text(self.logical_session_id, "logical_session_id"),
        )
        object.__setattr__(self, "reason", _required_text(self.reason, "reason"))
        acquired_at = ensure_utc(self.acquired_at)
        retain_until = ensure_utc(self.retain_until)
        if retain_until < acquired_at:
            raise ValueError("RDP lease retain_until cannot precede acquired_at")
        object.__setattr__(self, "acquired_at", acquired_at)
        object.__setattr__(self, "retain_until", retain_until)


@dataclass(frozen=True, slots=True)
class RdpSessionSnapshot:
    """Frozen current logical state with counters instead of completed history."""

    identity: RdpLogicalSessionIdentity
    state: RdpSessionState
    generation: RdpTransportGeneration
    last_transition_at: datetime
    reconnect_deadline: datetime | None = None
    logged_out_at: datetime | None = None
    retention_deadline: datetime | None = None
    reserved_initiator_bytes: int = 0
    reserved_responder_bytes: int = 0
    reserved_operations: int = 0
    completed_operations: int = 0
    active_operations: int = 0
    member_admissions: int = 0
    dependent_admissions: int = 0
    active_leases: int = 0

    def __post_init__(self) -> None:
        """Normalize timestamps and validate the compact state-machine summary."""

        last_transition_at = ensure_utc(self.last_transition_at)
        reconnect_deadline = (
            ensure_utc(self.reconnect_deadline) if self.reconnect_deadline is not None else None
        )
        logged_out_at = ensure_utc(self.logged_out_at) if self.logged_out_at else None
        retention_deadline = (
            ensure_utc(self.retention_deadline) if self.retention_deadline else None
        )
        counters = (
            self.reserved_initiator_bytes,
            self.reserved_responder_bytes,
            self.reserved_operations,
            self.completed_operations,
            self.active_operations,
            self.member_admissions,
            self.dependent_admissions,
            self.active_leases,
        )
        if any(counter < 0 for counter in counters):
            raise ValueError("RDP session counters must be non-negative")
        if self.completed_operations + self.active_operations != self.reserved_operations:
            raise ValueError("RDP operation counters are inconsistent")
        if self.reserved_initiator_bytes > self.identity.budget.initiator_bytes:
            raise ValueError("RDP initiator reservations exceed the logical budget")
        if self.reserved_responder_bytes > self.identity.budget.responder_bytes:
            raise ValueError("RDP responder reservations exceed the logical budget")
        if self.reserved_operations > self.identity.budget.operations:
            raise ValueError("RDP operation reservations exceed the logical budget")
        if last_transition_at < self.identity.started_at:
            raise ValueError("RDP transition cannot precede logical-session start")
        if self.state is RdpSessionState.CONNECTED:
            if self.generation.disconnected_at is not None:
                raise ValueError("Connected RDP generation cannot have a disconnect time")
            if reconnect_deadline is not None or logged_out_at is not None:
                raise ValueError("Connected RDP session cannot carry close deadlines")
        elif self.state is RdpSessionState.DISCONNECTED:
            if self.generation.disconnected_at is None or reconnect_deadline is None:
                raise ValueError("Disconnected RDP session requires disconnect/reconnect times")
            if logged_out_at is not None:
                raise ValueError("Disconnected RDP session cannot have logged_out_at")
        else:
            if logged_out_at is None or retention_deadline is None:
                raise ValueError("Logged-out RDP session requires logout retention times")
            if self.active_operations:
                raise ValueError("Logged-out RDP session cannot retain active operations")
        object.__setattr__(self, "last_transition_at", last_transition_at)
        object.__setattr__(self, "reconnect_deadline", reconnect_deadline)
        object.__setattr__(self, "logged_out_at", logged_out_at)
        object.__setattr__(self, "retention_deadline", retention_deadline)

    @property
    def logical_session_id(self) -> str:
        """Return the immutable logical-session identity."""

        return self.identity.logical_session_id

    @property
    def token_active(self) -> bool:
        """Return whether the Windows token remains valid."""

        return self.state is not RdpSessionState.LOGGED_OUT

    @property
    def session_active(self) -> bool:
        """Return whether members may still belong to this logical session."""

        return self.state is not RdpSessionState.LOGGED_OUT


@dataclass(frozen=True, slots=True)
class RdpOperationAdmission:
    """One accepted contained operation and resulting logical snapshot."""

    reservation: ApplicationOperationReservation
    session: RdpSessionSnapshot


@dataclass(frozen=True, slots=True)
class RdpReconnectCensus:
    """Bounded structural census for the RDP logical-session manager."""

    retained_sessions: int
    connected_sessions: int
    disconnected_sessions: int
    logged_out_sessions: int
    active_operations: int
    active_leases: int
    sidecar_shard_count: int
    affinity_partition_count: int
    max_shard_load: int
    maximum_lease_bucket: int
    generation_high_water_mark: int
    lookup_candidates_inspected: int
    logical_lookup_candidates_inspected: int
    affinity_lookup_candidates_inspected: int
    session_expiry_entries: int
    stale_session_expiry_entries: int
    lease_expiry_entries: int
    stale_lease_expiry_entries: int
    blocker_expiry_entries: int
    stale_blocker_expiry_entries: int
    compaction_pending: int
    compaction_rotations: int
    compaction_work: int
    compaction_seconds: float
    decoded_cache_entries: int
    decoded_cache_capacity: int
    decoded_cache_estimated_bytes: int
    estimated_bytes: int
    estimated_index_bytes: int
    primary_map_bytes: int
    watermark: datetime
    application: ApplicationChannelCensus


@dataclass(frozen=True, slots=True)
class RdpSessionClosure:
    """Lock-free terminal close intent for one exact logical RDP session."""

    logical_session_id: str
    target_hostname: str
    principal: str
    logon_id: str
    session_id: int
    channel_id: str
    transport_id: str
    generation_ordinal: int
    closed_at: datetime
    reason: str

    def __post_init__(self) -> None:
        """Normalize the terminal time and reject incomplete frozen authority."""

        for field_name in (
            "logical_session_id",
            "target_hostname",
            "principal",
            "logon_id",
            "channel_id",
            "transport_id",
            "reason",
        ):
            object.__setattr__(
                self,
                field_name,
                _required_text(str(getattr(self, field_name)), field_name),
            )
        if self.session_id < 0:
            raise ValueError("RDP closure session_id must be non-negative")
        if self.generation_ordinal < 0:
            raise ValueError("RDP closure generation ordinal must be non-negative")
        object.__setattr__(self, "closed_at", ensure_utc(self.closed_at))


@dataclass(frozen=True, slots=True)
class RdpWatermarkResult:
    """One bounded RDP watermark page and its terminal lifecycle intents."""

    census: RdpReconnectCensus
    closures: tuple[RdpSessionClosure, ...]
    has_more: bool = False
