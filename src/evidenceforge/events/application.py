# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Protocol-neutral identities for persistent application channels.

The value objects in this module describe canonical application state without
carrying rendered records or payload bytes. Protocol managers may layer HTTP,
SMB, SSH, or RDP semantics on top while sharing the same immutable transport,
budget, ownership, and operation-span contracts.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from evidenceforge.utils.time import ensure_utc


def _required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized


@dataclass(frozen=True, slots=True)
class ApplicationChannelBudget:
    """Immutable directional capacity assigned to one application channel."""

    initiator_bytes: int
    responder_bytes: int
    operations: int

    def __post_init__(self) -> None:
        """Reject negative byte capacity and channels that cannot do work."""

        if self.initiator_bytes < 0 or self.responder_bytes < 0:
            raise ValueError("Application channel byte budgets must be non-negative")
        if self.operations <= 0:
            raise ValueError("Application channel operation budget must be positive")


@dataclass(frozen=True, slots=True)
class ApplicationTransportBinding:
    """Immutable binding to one canonical transport interval."""

    transport_id: str
    opened_at: datetime
    closes_at: datetime

    def __post_init__(self) -> None:
        """Normalize the transport interval and reject backward bindings."""

        object.__setattr__(self, "transport_id", _required_text(self.transport_id, "transport_id"))
        opened_at = ensure_utc(self.opened_at)
        closes_at = ensure_utc(self.closes_at)
        if closes_at < opened_at:
            raise ValueError("Application transport closes_at cannot precede opened_at")
        object.__setattr__(self, "opened_at", opened_at)
        object.__setattr__(self, "closes_at", closes_at)


@dataclass(frozen=True, slots=True)
class ApplicationChannelIdentity:
    """Immutable canonical identity and limits for one reusable channel."""

    channel_id: str
    protocol: str
    owner_id: str
    affinity_digest: str
    binding: ApplicationTransportBinding
    opened_at: datetime
    idle_timeout: timedelta
    hard_deadline: datetime
    budget: ApplicationChannelBudget

    def __post_init__(self) -> None:
        """Normalize identity fields and enforce transport containment."""

        object.__setattr__(self, "channel_id", _required_text(self.channel_id, "channel_id"))
        object.__setattr__(self, "protocol", _required_text(self.protocol, "protocol").casefold())
        object.__setattr__(self, "owner_id", _required_text(self.owner_id, "owner_id"))
        object.__setattr__(
            self,
            "affinity_digest",
            _required_text(self.affinity_digest, "affinity_digest").casefold(),
        )
        opened_at = ensure_utc(self.opened_at)
        hard_deadline = ensure_utc(self.hard_deadline)
        if self.idle_timeout <= timedelta(0):
            raise ValueError("Application channel idle_timeout must be positive")
        if opened_at < self.binding.opened_at:
            raise ValueError("Application channel cannot open before its transport")
        if hard_deadline < opened_at:
            raise ValueError("Application channel hard_deadline cannot precede opened_at")
        if hard_deadline > self.binding.closes_at:
            raise ValueError("Application channel hard_deadline must be inside its transport")
        object.__setattr__(self, "opened_at", opened_at)
        object.__setattr__(self, "hard_deadline", hard_deadline)


@dataclass(frozen=True, slots=True)
class ApplicationOperationReservation:
    """One active application operation with a reserved immutable span."""

    operation_id: str
    channel_id: str
    ordinal: int
    started_at: datetime
    ended_at: datetime
    initiator_bytes: int = 0
    responder_bytes: int = 0
    parent_operation_id: str = ""

    def __post_init__(self) -> None:
        """Normalize the span and reject invalid sizes or self-parenting."""

        object.__setattr__(self, "operation_id", _required_text(self.operation_id, "operation_id"))
        object.__setattr__(self, "channel_id", _required_text(self.channel_id, "channel_id"))
        object.__setattr__(self, "parent_operation_id", self.parent_operation_id.strip())
        if self.ordinal < 0:
            raise ValueError("Application operation ordinal must be non-negative")
        if self.initiator_bytes < 0 or self.responder_bytes < 0:
            raise ValueError("Application operation byte reservations must be non-negative")
        if self.parent_operation_id == self.operation_id:
            raise ValueError("Application operation cannot parent itself")
        started_at = ensure_utc(self.started_at)
        ended_at = ensure_utc(self.ended_at)
        if ended_at < started_at:
            raise ValueError("Application operation ended_at cannot precede started_at")
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "ended_at", ended_at)


@dataclass(frozen=True, slots=True)
class ApplicationChannelSnapshot:
    """Frozen current state for one channel, excluding operation history."""

    identity: ApplicationChannelIdentity
    last_activity_at: datetime
    idle_deadline: datetime
    reserved_initiator_bytes: int = 0
    reserved_responder_bytes: int = 0
    reserved_operations: int = 0
    completed_operations: int = 0
    active_operations: int = 0
    closed_at: datetime | None = None
    close_reason: str = ""

    def __post_init__(self) -> None:
        """Normalize snapshot timestamps and validate compact counters."""

        last_activity_at = ensure_utc(self.last_activity_at)
        idle_deadline = ensure_utc(self.idle_deadline)
        closed_at = ensure_utc(self.closed_at) if self.closed_at is not None else None
        counters = (
            self.reserved_initiator_bytes,
            self.reserved_responder_bytes,
            self.reserved_operations,
            self.completed_operations,
            self.active_operations,
        )
        if any(counter < 0 for counter in counters):
            raise ValueError("Application channel counters must be non-negative")
        if self.completed_operations + self.active_operations != self.reserved_operations:
            raise ValueError("Application channel operation counters are inconsistent")
        budget = self.identity.budget
        if self.reserved_initiator_bytes > budget.initiator_bytes:
            raise ValueError("Application channel initiator reservations exceed the budget")
        if self.reserved_responder_bytes > budget.responder_bytes:
            raise ValueError("Application channel responder reservations exceed the budget")
        if self.reserved_operations > budget.operations:
            raise ValueError("Application channel operation reservations exceed the budget")
        if last_activity_at < self.identity.opened_at:
            raise ValueError("Application channel activity cannot precede channel open")
        if idle_deadline < self.identity.opened_at or idle_deadline > self.identity.hard_deadline:
            raise ValueError("Application channel idle deadline must remain inside the channel")
        if closed_at is not None and self.active_operations:
            raise ValueError("A closed application channel cannot retain active operations")
        if closed_at is None and self.close_reason:
            raise ValueError("An open application channel cannot have a close reason")
        if closed_at is not None and not self.close_reason.strip():
            raise ValueError("A closed application channel requires a close reason")
        object.__setattr__(self, "last_activity_at", last_activity_at)
        object.__setattr__(self, "idle_deadline", idle_deadline)
        object.__setattr__(self, "closed_at", closed_at)

    @property
    def channel_id(self) -> str:
        """Return the stable semantic channel identity."""

        return self.identity.channel_id

    @property
    def is_open(self) -> bool:
        """Return whether the channel has not been finalized."""

        return self.closed_at is None


@dataclass(frozen=True, slots=True)
class ApplicationChannelCensus:
    """Constant-time cardinality and lookup-work snapshot for one registry."""

    retained_channels: int
    open_channels: int
    retained_closed_channels: int
    active_operations: int
    used_operation_ids: int
    prepared_admissions: int
    claimed_admissions: int
    reserved_channel_ids: int
    reserved_transport_ids: int
    reserved_operation_ids: int
    shard_count: int
    max_shard_load: int
    decoded_cache_entries: int
    decoded_cache_capacity: int
    decoded_cache_estimated_bytes: int
    estimated_prepared_bytes: int
    estimated_bytes: int
    estimated_index_bytes: int
    estimated_store_index_bytes: int
    estimated_route_index_bytes: int
    estimated_expiry_index_bytes: int
    expiry_entries: int
    stale_expiry_entries: int
    expiry_compaction_pending: int
    expiry_compaction_work: int
    expiry_compaction_seconds: float
    maximum_affinity_bucket: int
    lookup_candidates_inspected: int
    high_water_mark: int
    route_entries: int
    route_map_bytes: int
    route_map_amplification: float
    route_compaction_pending: int
    route_compaction_rotations: int
    route_compaction_work: int
    route_compaction_seconds: float
    store_primary_map_bytes: int
    store_primary_compaction_pending: int
    store_primary_compaction_rotations: int
    store_primary_compaction_work: int
    store_primary_compaction_seconds: float
    watermark: datetime
    recoverable_admission_slots: int
    recoverable_admission_results: int
    recoverable_admission_capacity: int
    prepared_admission_tokens: int
    prepared_admission_capabilities: int
    prepared_close_tokens: int
    prepared_close_capabilities: int
    prepared_close_projections: int
    prepared_commit_journals: int
    prepared_close_commit_journals: int
    releasing_admissions: int
    acknowledging_admission_results: int
    acknowledging_close_results: int
    recoverable_admission_receipts: int
    recoverable_close_results: int
    recoverable_close_receipts: int
