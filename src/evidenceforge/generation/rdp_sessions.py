# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Compact logical-session state for reconnectable RDP activity.

The shared application-channel registry owns immutable transport bindings,
directional capacity, and active operation spans.  This layer owns the RDP
fact that one Windows logon may disconnect and later reconnect over a new
transport.  Only current state, aggregate counters, active operations, active
leases, and bounded tombstones are retained.
"""

from __future__ import annotations

import hashlib
import json
import sys
import zlib
from array import array
from collections import OrderedDict
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from struct import Struct
from threading import Condition, Lock, RLock

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationChannelIdentity,
    ApplicationOperationReservation,
    ApplicationTransportBinding,
)
from evidenceforge.events.rdp import (
    RdpLogicalSessionIdentity,
    RdpOperationAdmission,
    RdpReconnectCensus,
    RdpRetentionLease,
    RdpSessionAffinity,
    RdpSessionClosure,
    RdpSessionSnapshot,
    RdpSessionState,
    RdpTransportGeneration,
    RdpTransportPlan,
    RdpWatermarkResult,
)
from evidenceforge.generation.application_channels import (
    ApplicationChannelCloseToken,
    ApplicationChannelRegistry,
)
from evidenceforge.generation.indexes import (
    CompactHandleStore,
    IncrementalExactMap,
    IndexMetrics,
    PackedHandleExpiryIndex,
    PackedUniqueDigestMap,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.time import ensure_utc

_DEFAULT_POST_LOGOUT_GRACE = timedelta(seconds=30)
_DEFAULT_MAX_RETENTION_EXTENSION = timedelta(hours=1)
_DEFAULT_MAX_LEASES_PER_SESSION = 16
_PRIMARY_COMPACTION_WORK_PER_WATERMARK = 4_096
_EXPIRY_COMPACTION_WORK_PER_WATERMARK = 4_096
_SNAPSHOT_CACHE_ENTRIES_PER_SHARD = 256
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MAX_TIME = datetime.max.replace(tzinfo=UTC)
_MISSING_TIME = -(1 << 63)
_IDENTITY_TEXT_FIELDS = 7
_GENERATION_TEXT_FIELDS = 2
_IDENTITY_HEADER = Struct(">qqqqQQQQ7H")
_GENERATION_HEADER = Struct(">Iqqqqq2H")


class RdpSessionAdmissionError(StateError):
    """An RDP action cannot fit before its immutable lifecycle/window fence."""


def _compress_row(row: bytes) -> bytes:
    """Return one independently decodable low-latency packed row."""

    return zlib.compress(row, 1, -15)


def _decompress_row(row: bytes) -> bytes:
    """Decode one raw-DEFLATE packed row."""

    return zlib.decompress(row, -15)


def _stable_digest(namespace: str, value: str) -> int:
    digest = hashlib.blake2b(
        f"{namespace}\0{value}".encode(),
        digest_size=8,
    ).digest()
    return int.from_bytes(digest, "big")


def _stable_partition(namespace: str, value: str, shard_count: int) -> int:
    return _stable_digest(namespace, value) % shard_count


def _semantic_token(namespace: str, value: str) -> int:
    """Return a stable compact token whose collisions are verified on lookup."""

    return int.from_bytes(
        hashlib.blake2b(f"{namespace}\0{value}".encode(), digest_size=8).digest(),
        "big",
    )


def _logical_affinity_digest(values: tuple[object, ...]) -> str:
    encoded = json.dumps(
        ("rdp-logical-affinity-v1", *values),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _datetime_to_microseconds(value: datetime) -> int:
    delta = ensure_utc(value) - _EPOCH
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


def _datetime_from_microseconds(value: int) -> datetime:
    return datetime.fromtimestamp(value / 1_000_000, tz=UTC)


def _optional_time_to_microseconds(value: datetime | None) -> int:
    return _MISSING_TIME if value is None else _datetime_to_microseconds(value)


def _optional_time_from_microseconds(value: int) -> datetime | None:
    return None if value == _MISSING_TIME else _datetime_from_microseconds(value)


def _operation_id(logical_session_id: str, generation: int, ordinal: int) -> str:
    digest = hashlib.sha256(
        f"rdp-operation-v1\0{logical_session_id}\0{generation}\0{ordinal}".encode()
    ).hexdigest()
    return f"rdp-operation-{digest[:32]}"


def _transport_affinity_digest(logical_affinity_digest: str, channel_id: str) -> str:
    """Return a generation-specific channel key under one logical affinity."""

    return hashlib.sha256(
        f"rdp-transport-affinity-v1\0{logical_affinity_digest}\0{channel_id}".encode()
    ).hexdigest()


def _lease_estimated_bytes(lease: RdpRetentionLease) -> int:
    return sum(
        sys.getsizeof(value)
        for value in (
            lease,
            lease.lease_id,
            lease.logical_session_id,
            lease.acquired_at,
            lease.retain_until,
            lease.reason,
        )
    )


def _decoded_row_cache_value_bytes(value: tuple[bytes, bytes, str]) -> int:
    """Estimate one bounded decoded row/digest cache entry."""

    return sum(sys.getsizeof(item) for item in (value, *value))


class _MutationGate:
    """Admit disjoint mutations concurrently while fencing watermarks."""

    def __init__(self) -> None:
        self._condition = Condition(Lock())
        self._readers = 0
        self._writer = False
        self._waiting_writers = 0

    @contextmanager
    def mutation(self) -> Iterator[None]:
        """Enter one shared mutation admission lane."""

        with self._condition:
            while self._writer or self._waiting_writers:
                self._condition.wait()
            self._readers += 1
        try:
            yield
        finally:
            with self._condition:
                self._readers -= 1
                if self._readers == 0:
                    self._condition.notify_all()

    @contextmanager
    def watermark(self) -> Iterator[None]:
        """Fence mutations while one canonical cutoff commits."""

        with self._condition:
            self._waiting_writers += 1
            try:
                while self._writer or self._readers:
                    self._condition.wait()
                self._writer = True
            finally:
                self._waiting_writers -= 1
        try:
            yield
        finally:
            with self._condition:
                self._writer = False
                self._condition.notify_all()


class _PackedRdpSessionStore:
    """Primitive-column logical sessions with on-demand frozen reconstruction."""

    _STATE_CODES = {
        RdpSessionState.CONNECTED: 1,
        RdpSessionState.DISCONNECTED: 2,
        RdpSessionState.LOGGED_OUT: 3,
    }
    _STATES = {
        1: RdpSessionState.CONNECTED,
        2: RdpSessionState.DISCONNECTED,
        3: RdpSessionState.LOGGED_OUT,
    }

    def __init__(self) -> None:
        self._identity_arenas = [bytearray(), bytearray()]
        self._identity_arena_ids = bytearray()
        self._identity_offsets = array("I")
        self._identity_lengths = array("I")
        self._identity_active_arena = 0
        self._identity_live_bytes = 0
        self._identity_compacting = False
        self._identity_compaction_cursor = 0
        self._identity_compaction_work = 0
        self._generation_arenas = [bytearray(), bytearray()]
        self._generation_arena_ids = bytearray()
        self._generation_offsets = array("I")
        self._generation_lengths = array("I")
        self._generation_active_arena = 0
        self._generation_live_bytes = 0
        self._generation_compacting = False
        self._generation_compaction_cursor = 0
        self._generation_compaction_work = 0
        self._active = bytearray()
        self._states = bytearray()
        self._last_transition = array("q")
        self._state_deadline = array("q")
        self._reserved_initiator = array("Q")
        self._reserved_responder = array("Q")
        self._reserved_operations = array("I")
        self._completed_operations = array("I")
        self._active_operations = array("I")
        self._member_admissions = array("I")
        self._dependent_admissions = array("I")
        self._active_leases = array("I")
        self._close_locators = array("I")
        self._close_generations = array("I")
        self._logical_route_keys = array("Q")
        self._affinity_route_keys = array("Q")
        self._affinity_partition_ids = array("I")
        self._free_handles: list[int] = []
        self._live_count = 0
        self._high_water_mark = 0

    def __len__(self) -> int:
        return self._live_count

    @staticmethod
    def _encode_texts(values: tuple[str, ...], expected: int) -> tuple[tuple[int, ...], bytes]:
        if len(values) != expected:
            raise AssertionError("RDP packed text field count changed")
        encoded = tuple(value.encode("utf-8") for value in values)
        lengths = tuple(len(value) for value in encoded)
        if any(length >= 1 << 16 for length in lengths):
            raise ValueError("RDP packed text fields must be shorter than 65,536 bytes")
        return lengths, b"".join(encoded)

    @classmethod
    def _pack_identity(cls, identity: RdpLogicalSessionIdentity) -> bytes:
        affinity = identity.affinity
        lengths, text = cls._encode_texts(
            (
                identity.logical_session_id,
                affinity.source_host,
                affinity.source_address,
                affinity.target_host,
                affinity.target_address,
                affinity.principal,
                affinity.logon_id,
            ),
            _IDENTITY_TEXT_FIELDS,
        )
        header = _IDENTITY_HEADER.pack(
            _datetime_to_microseconds(identity.started_at),
            round(identity.idle_timeout.total_seconds() * 1_000_000),
            round(identity.reconnect_timeout.total_seconds() * 1_000_000),
            _datetime_to_microseconds(identity.hard_deadline),
            identity.budget.initiator_bytes,
            identity.budget.responder_bytes,
            identity.budget.operations,
            affinity.session_id,
            *lengths,
        )
        return _compress_row(header + text)

    @classmethod
    def _unpack_identity(
        cls,
        row: bytes,
        *,
        affinity_digest: str | None = None,
    ) -> RdpLogicalSessionIdentity:
        values = _IDENTITY_HEADER.unpack_from(row)
        (
            started_us,
            idle_us,
            reconnect_us,
            hard_us,
            initiator_budget,
            responder_budget,
            operation_budget,
            session_id,
        ) = values[:8]
        (
            logical_length,
            source_host_length,
            source_address_length,
            target_host_length,
            (target_address_length),
            principal_length,
            logon_length,
        ) = values[8 : 8 + _IDENTITY_TEXT_FIELDS]
        logical_end = _IDENTITY_HEADER.size + logical_length
        source_host_end = logical_end + source_host_length
        source_address_end = source_host_end + source_address_length
        target_host_end = source_address_end + target_host_length
        target_address_end = target_host_end + target_address_length
        principal_end = target_address_end + principal_length
        logon_end = principal_end + logon_length
        logical_id = row[_IDENTITY_HEADER.size : logical_end].decode("utf-8")
        source_host = row[logical_end:source_host_end].decode("utf-8")
        source_address = row[source_host_end:source_address_end].decode("utf-8")
        target_host = row[source_address_end:target_host_end].decode("utf-8")
        target_address = row[target_host_end:target_address_end].decode("utf-8")
        principal = row[target_address_end:principal_end].decode("utf-8")
        logon_id = row[principal_end:logon_end].decode("utf-8")
        set_frozen = object.__setattr__
        affinity = object.__new__(RdpSessionAffinity)
        set_frozen(affinity, "source_host", source_host)
        set_frozen(affinity, "source_address", source_address)
        set_frozen(affinity, "target_host", target_host)
        set_frozen(affinity, "target_address", target_address)
        set_frozen(affinity, "principal", principal)
        set_frozen(affinity, "logon_id", logon_id)
        set_frozen(affinity, "session_id", session_id)
        set_frozen(
            affinity,
            "digest",
            affinity_digest
            or _logical_affinity_digest(
                (
                    source_host,
                    source_address,
                    target_host,
                    target_address,
                    principal,
                    logon_id,
                    session_id,
                )
            ),
        )
        budget = object.__new__(ApplicationChannelBudget)
        set_frozen(budget, "initiator_bytes", initiator_budget)
        set_frozen(budget, "responder_bytes", responder_budget)
        set_frozen(budget, "operations", operation_budget)
        identity = object.__new__(RdpLogicalSessionIdentity)
        set_frozen(identity, "logical_session_id", logical_id)
        set_frozen(identity, "affinity", affinity)
        set_frozen(identity, "started_at", _datetime_from_microseconds(started_us))
        set_frozen(identity, "idle_timeout", timedelta(microseconds=idle_us))
        set_frozen(identity, "reconnect_timeout", timedelta(microseconds=reconnect_us))
        set_frozen(identity, "hard_deadline", _datetime_from_microseconds(hard_us))
        set_frozen(identity, "budget", budget)
        return identity

    @classmethod
    def _pack_generation(cls, generation: RdpTransportGeneration) -> bytes:
        lengths, text = cls._encode_texts(
            (generation.channel_id, generation.binding.transport_id),
            _GENERATION_TEXT_FIELDS,
        )
        header = _GENERATION_HEADER.pack(
            generation.ordinal,
            _datetime_to_microseconds(generation.binding.opened_at),
            _datetime_to_microseconds(generation.binding.closes_at),
            _datetime_to_microseconds(generation.connected_at),
            _datetime_to_microseconds(generation.idle_deadline),
            _optional_time_to_microseconds(generation.disconnected_at),
            *lengths,
        )
        return _compress_row(header + text)

    @classmethod
    def _unpack_generation(cls, row: bytes) -> RdpTransportGeneration:
        values = _GENERATION_HEADER.unpack_from(row)
        ordinal, opened_us, closes_us, connected_us, idle_us, disconnected_us = values[:6]
        lengths = tuple(values[6 : 6 + _GENERATION_TEXT_FIELDS])
        offset = _GENERATION_HEADER.size
        channel_end = offset + lengths[0]
        channel_id = row[offset:channel_end].decode("utf-8")
        transport_id = row[channel_end : channel_end + lengths[1]].decode("utf-8")
        set_frozen = object.__setattr__
        binding = object.__new__(ApplicationTransportBinding)
        set_frozen(binding, "transport_id", transport_id)
        set_frozen(binding, "opened_at", _datetime_from_microseconds(opened_us))
        set_frozen(binding, "closes_at", _datetime_from_microseconds(closes_us))
        generation = object.__new__(RdpTransportGeneration)
        set_frozen(generation, "ordinal", ordinal)
        set_frozen(generation, "channel_id", channel_id)
        set_frozen(generation, "binding", binding)
        set_frozen(generation, "connected_at", _datetime_from_microseconds(connected_us))
        set_frozen(generation, "idle_deadline", _datetime_from_microseconds(idle_us))
        set_frozen(
            generation,
            "disconnected_at",
            _optional_time_from_microseconds(disconnected_us),
        )
        return generation

    def _write_mutable(self, handle: int, snapshot: RdpSessionSnapshot) -> None:
        self._states[handle] = self._STATE_CODES[snapshot.state]
        self._last_transition[handle] = _datetime_to_microseconds(snapshot.last_transition_at)
        if snapshot.state is RdpSessionState.DISCONNECTED:
            self._state_deadline[handle] = _optional_time_to_microseconds(
                snapshot.reconnect_deadline
            )
        elif snapshot.state is RdpSessionState.LOGGED_OUT:
            if snapshot.logged_out_at != snapshot.last_transition_at:
                raise StateError("RDP logout must be the session's latest transition")
            self._state_deadline[handle] = _optional_time_to_microseconds(
                snapshot.retention_deadline
            )
        else:
            self._state_deadline[handle] = _MISSING_TIME
        for column, value in (
            (self._reserved_initiator, snapshot.reserved_initiator_bytes),
            (self._reserved_responder, snapshot.reserved_responder_bytes),
            (self._reserved_operations, snapshot.reserved_operations),
            (self._completed_operations, snapshot.completed_operations),
            (self._active_operations, snapshot.active_operations),
            (self._member_admissions, snapshot.member_admissions),
            (self._dependent_admissions, snapshot.dependent_admissions),
            (self._active_leases, snapshot.active_leases),
        ):
            if value and not column:
                column.extend(array(column.typecode, [0]) * len(self._active))
            if column:
                column[handle] = value

    def _append_mutable(self) -> None:
        self._active.append(1)
        self._states.append(0)
        for column in (self._last_transition, self._state_deadline):
            column.append(_MISSING_TIME)
        for column in (
            self._reserved_initiator,
            self._reserved_responder,
            self._reserved_operations,
            self._completed_operations,
            self._active_operations,
            self._member_admissions,
            self._dependent_admissions,
            self._active_leases,
        ):
            if column:
                column.append(0)
        self._close_locators.append(0)
        self._close_generations.append(0)
        self._logical_route_keys.append(0)
        self._affinity_route_keys.append(0)
        self._affinity_partition_ids.append(0)

    def _append_identity_row(self, row: bytes) -> tuple[int, int]:
        arena = self._identity_arenas[self._identity_active_arena]
        offset = len(arena)
        if offset >= 1 << 32 and self._identity_offsets.typecode == "I":
            self._identity_offsets = array("Q", self._identity_offsets)
        arena.extend(row)
        return offset, len(row)

    def _write_identity_row(self, handle: int, row: bytes, *, new_slot: bool) -> None:
        offset, length = self._append_identity_row(row)
        if new_slot:
            self._identity_arena_ids.append(self._identity_active_arena)
            self._identity_offsets.append(offset)
            self._identity_lengths.append(length)
        else:
            self._identity_arena_ids[handle] = self._identity_active_arena
            self._identity_offsets[handle] = offset
            self._identity_lengths[handle] = length
        self._identity_live_bytes += length

    def _identity_row(self, handle: int) -> bytes:
        length = self._identity_lengths[handle]
        if not length:
            raise KeyError(handle)
        arena = self._identity_arenas[self._identity_arena_ids[handle]]
        offset = self._identity_offsets[handle]
        return bytes(arena[offset : offset + length])

    def _reset_identity_arenas(self) -> None:
        self._identity_arenas = [bytearray(), bytearray()]
        self._identity_active_arena = 0
        self._identity_compacting = False
        self._identity_compaction_cursor = 0

    def _append_generation_row(self, row: bytes) -> tuple[int, int]:
        arena = self._generation_arenas[self._generation_active_arena]
        offset = len(arena)
        if offset >= 1 << 32 and self._generation_offsets.typecode == "I":
            self._generation_offsets = array("Q", self._generation_offsets)
        arena.extend(row)
        return offset, len(row)

    def _write_generation_row(self, handle: int, row: bytes, *, new_slot: bool) -> None:
        if not new_slot:
            self._generation_live_bytes -= self._generation_lengths[handle]
        offset, length = self._append_generation_row(row)
        if new_slot:
            self._generation_arena_ids.append(self._generation_active_arena)
            self._generation_offsets.append(offset)
            self._generation_lengths.append(length)
        else:
            self._generation_arena_ids[handle] = self._generation_active_arena
            self._generation_offsets[handle] = offset
            self._generation_lengths[handle] = length
        self._generation_live_bytes += length

    def _generation_row(self, handle: int) -> bytes:
        length = self._generation_lengths[handle]
        if not length:
            raise KeyError(handle)
        arena = self._generation_arenas[self._generation_arena_ids[handle]]
        offset = self._generation_offsets[handle]
        return bytes(arena[offset : offset + length])

    def _reset_generation_arenas(self) -> None:
        self._generation_arenas = [bytearray(), bytearray()]
        self._generation_active_arena = 0
        self._generation_compacting = False
        self._generation_compaction_cursor = 0

    def compact(self, *, max_slots: int = 4_096) -> int:
        """Incrementally reclaim packed identity/generation holes within one budget."""

        if max_slots < 0:
            raise ValueError("RDP packed session compaction budget cannot be negative")
        if not self._live_count:
            self._reset_identity_arenas()
            self._reset_generation_arenas()
            return 0
        backing_bytes = sum(len(arena) for arena in self._identity_arenas)
        if not self._identity_compacting:
            if backing_bytes > self._identity_live_bytes * 2:
                target = 1 - self._identity_active_arena
                self._identity_arenas[target] = bytearray()
                self._identity_active_arena = target
                self._identity_compacting = True
                self._identity_compaction_cursor = 0
        inspected = 0
        if self._identity_compacting:
            old_arena_id = 1 - self._identity_active_arena
            while self._identity_compaction_cursor < len(self._active) and inspected < max_slots:
                handle = self._identity_compaction_cursor
                self._identity_compaction_cursor += 1
                inspected += 1
                if not self._active[handle] or self._identity_arena_ids[handle] != old_arena_id:
                    continue
                row = self._identity_row(handle)
                offset, length = self._append_identity_row(row)
                self._identity_arena_ids[handle] = self._identity_active_arena
                self._identity_offsets[handle] = offset
                self._identity_lengths[handle] = length
            self._identity_compaction_work += inspected
            if self._identity_compaction_cursor >= len(self._active):
                self._identity_arenas[old_arena_id] = bytearray()
                self._identity_compacting = False
                self._identity_compaction_cursor = 0

        remaining = max_slots - inspected
        generation_backing = sum(len(arena) for arena in self._generation_arenas)
        if not self._generation_compacting and generation_backing > self._generation_live_bytes * 2:
            target = 1 - self._generation_active_arena
            self._generation_arenas[target] = bytearray()
            self._generation_active_arena = target
            self._generation_compacting = True
            self._generation_compaction_cursor = 0
        generation_inspected = 0
        if self._generation_compacting and remaining:
            old_arena_id = 1 - self._generation_active_arena
            while (
                self._generation_compaction_cursor < len(self._active)
                and generation_inspected < remaining
            ):
                handle = self._generation_compaction_cursor
                self._generation_compaction_cursor += 1
                generation_inspected += 1
                if not self._active[handle] or self._generation_arena_ids[handle] != old_arena_id:
                    continue
                row = self._generation_row(handle)
                offset, length = self._append_generation_row(row)
                self._generation_arena_ids[handle] = self._generation_active_arena
                self._generation_offsets[handle] = offset
                self._generation_lengths[handle] = length
            self._generation_compaction_work += generation_inspected
            if self._generation_compaction_cursor >= len(self._active):
                self._generation_arenas[old_arena_id] = bytearray()
                self._generation_compacting = False
                self._generation_compaction_cursor = 0
        return inspected + generation_inspected

    def insert(self, snapshot: RdpSessionSnapshot) -> int:
        """Insert one packed snapshot and return a reusable compact handle."""

        identity_row = self._pack_identity(snapshot.identity)
        generation_row = self._pack_generation(snapshot.generation)
        if self._free_handles:
            handle = self._free_handles.pop()
            self._write_identity_row(handle, identity_row, new_slot=False)
            self._write_generation_row(handle, generation_row, new_slot=False)
            self._active[handle] = 1
            self._close_locators[handle] = 0
            self._close_generations[handle] = 0
        else:
            handle = len(self._active)
            self._write_identity_row(handle, identity_row, new_slot=True)
            self._write_generation_row(handle, generation_row, new_slot=True)
            self._append_mutable()
        self._write_mutable(handle, snapshot)
        self._live_count += 1
        self._high_water_mark = max(self._high_water_mark, self._live_count)
        return handle

    def set_close_token(self, handle: int, token: ApplicationChannelCloseToken) -> None:
        """Bind the current immutable transport to one ABA-safe close token."""

        self._require_live(handle)
        self._close_locators[handle] = token.locator
        self._close_generations[handle] = token.generation

    def set_route_metadata(
        self,
        handle: int,
        *,
        logical_route_key: int,
        affinity_route_key: int,
        affinity_partition_id: int,
    ) -> None:
        """Bind packed exact-route metadata for reconstruction-free eviction."""

        self._require_live(handle)
        self._logical_route_keys[handle] = logical_route_key
        self._affinity_route_keys[handle] = affinity_route_key
        self._affinity_partition_ids[handle] = affinity_partition_id

    def route_metadata(self, handle: int) -> tuple[int, int, int]:
        """Return logical key, affinity key, and affinity partition for one live handle."""

        self._require_live(handle)
        return (
            self._logical_route_keys[handle],
            self._affinity_route_keys[handle],
            self._affinity_partition_ids[handle],
        )

    def logged_out_reference_counts(self, handle: int) -> tuple[int, int] | None:
        """Return active operation/lease counts for a logged-out handle, else ``None``."""

        self._require_live(handle)
        if self._states[handle] != self._STATE_CODES[RdpSessionState.LOGGED_OUT]:
            return None
        return (
            self._active_operations[handle] if self._active_operations else 0,
            self._active_leases[handle] if self._active_leases else 0,
        )

    def close_token(self, handle: int) -> ApplicationChannelCloseToken:
        """Return the current generation's packed application close token."""

        self._require_live(handle)
        generation = self._close_generations[handle]
        if generation <= 0:
            raise StateError(f"RDP session handle {handle} has no application close token")
        return ApplicationChannelCloseToken(
            locator=self._close_locators[handle],
            generation=generation,
        )

    def replace(self, handle: int, snapshot: RdpSessionSnapshot) -> None:
        """Replace mutable columns and current generation for a live handle."""

        self._require_live(handle)
        generation_row = self._pack_generation(snapshot.generation)
        self._write_generation_row(handle, generation_row, new_slot=False)
        self._write_mutable(handle, snapshot)

    def _require_live(self, handle: int) -> None:
        if handle < 0 or handle >= len(self._active) or not self._active[handle]:
            raise KeyError(handle)

    def get_by_handle(
        self,
        handle: int,
        *,
        affinity_digest: str | None = None,
        decoded_identity_row: bytes | None = None,
        decoded_generation_row: bytes | None = None,
    ) -> RdpSessionSnapshot:
        """Reconstruct one frozen snapshot from compact primitive columns."""

        self._require_live(handle)
        identity_row = decoded_identity_row or _decompress_row(self._identity_row(handle))
        generation_row = decoded_generation_row or _decompress_row(self._generation_row(handle))
        set_frozen = object.__setattr__
        snapshot = object.__new__(RdpSessionSnapshot)
        set_frozen(
            snapshot,
            "identity",
            self._unpack_identity(identity_row, affinity_digest=affinity_digest),
        )
        state = self._STATES[self._states[handle]]
        last_transition_at = _datetime_from_microseconds(self._last_transition[handle])
        state_deadline = _optional_time_from_microseconds(self._state_deadline[handle])
        set_frozen(snapshot, "state", state)
        set_frozen(snapshot, "generation", self._unpack_generation(generation_row))
        set_frozen(snapshot, "last_transition_at", last_transition_at)
        set_frozen(
            snapshot,
            "reconnect_deadline",
            state_deadline if state is RdpSessionState.DISCONNECTED else None,
        )
        set_frozen(
            snapshot,
            "logged_out_at",
            last_transition_at if state is RdpSessionState.LOGGED_OUT else None,
        )
        set_frozen(
            snapshot,
            "retention_deadline",
            state_deadline if state is RdpSessionState.LOGGED_OUT else None,
        )
        set_frozen(
            snapshot,
            "reserved_initiator_bytes",
            self._reserved_initiator[handle] if self._reserved_initiator else 0,
        )
        set_frozen(
            snapshot,
            "reserved_responder_bytes",
            self._reserved_responder[handle] if self._reserved_responder else 0,
        )
        set_frozen(
            snapshot,
            "reserved_operations",
            self._reserved_operations[handle] if self._reserved_operations else 0,
        )
        set_frozen(
            snapshot,
            "completed_operations",
            self._completed_operations[handle] if self._completed_operations else 0,
        )
        set_frozen(
            snapshot,
            "active_operations",
            self._active_operations[handle] if self._active_operations else 0,
        )
        set_frozen(
            snapshot,
            "member_admissions",
            self._member_admissions[handle] if self._member_admissions else 0,
        )
        set_frozen(
            snapshot,
            "dependent_admissions",
            self._dependent_admissions[handle] if self._dependent_admissions else 0,
        )
        set_frozen(
            snapshot,
            "active_leases",
            self._active_leases[handle] if self._active_leases else 0,
        )
        return snapshot

    def decoded_rows(self, handle: int) -> tuple[bytes, bytes]:
        """Decode the immutable identity and current generation for bounded caching."""

        self._require_live(handle)
        return (
            _decompress_row(self._identity_row(handle)),
            _decompress_row(self._generation_row(handle)),
        )

    def _delete_handle(self, handle: int) -> None:
        """Delete one live primitive handle without reconstructing its frozen value."""

        self._identity_live_bytes -= self._identity_lengths[handle]
        self._identity_lengths[handle] = 0
        self._generation_live_bytes -= self._generation_lengths[handle]
        self._generation_lengths[handle] = 0
        self._active[handle] = 0
        self._states[handle] = 0
        self._close_locators[handle] = 0
        self._close_generations[handle] = 0
        self._logical_route_keys[handle] = 0
        self._affinity_route_keys[handle] = 0
        self._affinity_partition_ids[handle] = 0
        self._free_handles.append(handle)
        self._live_count -= 1
        if not self._live_count:
            self._reset_identity_arenas()
            self._reset_generation_arenas()

    def delete_handle(self, handle: int) -> None:
        """Delete one live handle without materializing its frozen snapshot."""

        self._require_live(handle)
        self._delete_handle(handle)

    def delete(
        self,
        handle: int,
        *,
        decoded: RdpSessionSnapshot | None = None,
    ) -> RdpSessionSnapshot:
        """Delete one live handle without reconstructing an already-decoded row."""

        self._require_live(handle)
        snapshot = decoded if decoded is not None else self.get_by_handle(handle)
        self._delete_handle(handle)
        return snapshot

    @property
    def estimated_value_bytes(self) -> int:
        """Return exact packed-row backing bytes without scanning values."""

        return sum(sys.getsizeof(arena) for arena in self._identity_arenas) + sum(
            sys.getsizeof(arena) for arena in self._generation_arenas
        )

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return primitive structural metrics without reconstructing snapshots."""

        columns: tuple[object, ...] = (
            self,
            self._identity_arena_ids,
            self._identity_offsets,
            self._identity_lengths,
            self._generation_arena_ids,
            self._generation_offsets,
            self._generation_lengths,
            self._active,
            self._states,
            self._last_transition,
            self._state_deadline,
            self._reserved_initiator,
            self._reserved_responder,
            self._reserved_operations,
            self._completed_operations,
            self._active_operations,
            self._member_admissions,
            self._dependent_admissions,
            self._active_leases,
            self._close_locators,
            self._close_generations,
            self._logical_route_keys,
            self._affinity_route_keys,
            self._affinity_partition_ids,
            self._free_handles,
        )
        return IndexMetrics(
            live_entries=self._live_count,
            backing_entries=len(self._active),
            stale_entries=len(self._free_handles),
            allocated_slots=len(self._active),
            high_water_mark=self._high_water_mark,
            compaction_work=(self._identity_compaction_work + self._generation_compaction_work),
            compaction_pending=(self._identity_compacting or self._generation_compacting),
            estimated_bytes=sum(sys.getsizeof(column) for column in columns)
            if estimate_bytes
            else 0,
        )


@dataclass(slots=True)
class _AffinityPartition:
    partition_id: int
    lock: RLock = field(default_factory=RLock)
    routes: PackedUniqueDigestMap = field(
        default_factory=lambda: PackedUniqueDigestMap(b"ef-rdp-affinity")
    )
    deletions: int = 0
    lookup_candidates_inspected: int = 0


@dataclass(slots=True)
class _RdpSessionShard:
    shard_id: int
    lock: RLock = field(default_factory=RLock)
    sessions: _PackedRdpSessionStore = field(default_factory=_PackedRdpSessionStore)
    session_routes: PackedUniqueDigestMap = field(
        default_factory=lambda: PackedUniqueDigestMap(b"ef-rdp-logical")
    )
    operations: IncrementalExactMap[str, int] = field(default_factory=IncrementalExactMap)
    leases: CompactHandleStore[RdpRetentionLease] = field(
        default_factory=lambda: CompactHandleStore(
            logical_session=lambda item: item.logical_session_id,
        )
    )
    lease_routes: IncrementalExactMap[tuple[str, str], int] = field(
        default_factory=IncrementalExactMap
    )
    session_expiry: PackedHandleExpiryIndex = field(default_factory=PackedHandleExpiryIndex)
    lease_expiry: PackedHandleExpiryIndex = field(default_factory=PackedHandleExpiryIndex)
    blocker_expiry: PackedHandleExpiryIndex = field(default_factory=PackedHandleExpiryIndex)
    connected_sessions: int = 0
    disconnected_sessions: int = 0
    logged_out_sessions: int = 0
    active_operations: int = 0
    active_leases: int = 0
    maximum_lease_bucket: int = 0
    logical_lookup_candidates_inspected: int = 0
    generation_high_water_mark: int = 0
    estimated_value_bytes: int = 0
    session_route_deletions: int = 0
    operation_deletions: int = 0
    lease_route_deletions: int = 0
    compaction_cursor: int = 0
    expiry_compaction_cursor: int = 0
    snapshot_cache: OrderedDict[int, tuple[bytes, bytes, str]] = field(default_factory=OrderedDict)
    snapshot_cache_value_bytes: int = 0

    def map_metrics(self) -> tuple[IndexMetrics, ...]:
        """Return structural metrics for exact semantic routes."""

        return tuple(
            route.metrics(estimate_bytes=True)
            for route in (self.session_routes, self.operations, self.lease_routes)
        )

    def public_snapshot(self, route_key: int, handle: int) -> RdpSessionSnapshot:
        """Reconstruct one row using a fixed-size decoded-affinity cache."""

        decoded = self.snapshot_cache.get(route_key)
        if decoded is not None:
            self.snapshot_cache.move_to_end(route_key)
            identity_row, generation_row, affinity_digest = decoded
            return self.sessions.get_by_handle(
                handle,
                affinity_digest=affinity_digest,
                decoded_identity_row=identity_row,
                decoded_generation_row=generation_row,
            )
        identity_row, generation_row = self.sessions.decoded_rows(handle)
        snapshot = self.sessions.get_by_handle(
            handle,
            decoded_identity_row=identity_row,
            decoded_generation_row=generation_row,
        )
        if len(self.snapshot_cache) >= _SNAPSHOT_CACHE_ENTRIES_PER_SHARD:
            _evicted_handle, evicted = self.snapshot_cache.popitem(last=False)
            self.snapshot_cache_value_bytes -= _decoded_row_cache_value_bytes(evicted)
        cached = (identity_row, generation_row, snapshot.identity.affinity.digest)
        self.snapshot_cache[route_key] = cached
        self.snapshot_cache_value_bytes += _decoded_row_cache_value_bytes(cached)
        return snapshot

    def invalidate_snapshot(self, route_key: int) -> None:
        """Invalidate one decoded snapshot after a packed-row mutation."""

        cached = self.snapshot_cache.pop(route_key, None)
        if cached is not None:
            self.snapshot_cache_value_bytes -= _decoded_row_cache_value_bytes(cached)


@contextmanager
def _acquire_stable_locks(
    entries: list[tuple[tuple[int, int], RLock]],
) -> Iterator[None]:
    """Acquire distinct affinity-route then owner-shard locks stably."""

    unique: dict[int, tuple[tuple[int, int], RLock]] = {}
    for token, lock in entries:
        unique.setdefault(id(lock), (token, lock))
    ordered = sorted(unique.values(), key=lambda item: item[0])
    for _token, lock in ordered:
        lock.acquire()
    try:
        yield
    finally:
        for _token, lock in reversed(ordered):
            lock.release()


class RdpReconnectStateManager:
    """Own reconnectable RDP logical sessions above immutable app channels.

    The injected application registry is shared infrastructure.  Callers must
    route channels created here back through this manager; direct mutation can
    violate the manager/application commit ordering.  Canonical watermark
    integration advances this manager before advancing the shared registry.
    Member/dependent counters are lifetime admission telemetry only; active
    child close authority remains exclusively in :class:`LifecycleRegistry`.
    """

    def __init__(
        self,
        *,
        application_registry: ApplicationChannelRegistry,
        window_start: datetime,
        window_end: datetime,
        post_logout_grace: timedelta = _DEFAULT_POST_LOGOUT_GRACE,
        max_retention_extension: timedelta = _DEFAULT_MAX_RETENTION_EXTENSION,
        max_leases_per_session: int = _DEFAULT_MAX_LEASES_PER_SESSION,
    ) -> None:
        """Create an empty manager for one canonical generation window."""

        self._window_start = ensure_utc(window_start)
        self._window_end = ensure_utc(window_end)
        if self._window_end <= self._window_start:
            raise ValueError("RDP window_end must follow window_start")
        if (
            application_registry.window_start != self._window_start
            or application_registry.window_end != self._window_end
        ):
            raise ValueError(
                "RDP and application-channel registries must use the exact same window"
            )
        if post_logout_grace < timedelta(0):
            raise ValueError("RDP post_logout_grace must be non-negative")
        if max_retention_extension < post_logout_grace:
            raise ValueError("RDP max_retention_extension cannot be shorter than post_logout_grace")
        if max_leases_per_session <= 0:
            raise ValueError("RDP max_leases_per_session must be positive")
        self._application = application_registry
        self._post_logout_grace = post_logout_grace
        remaining_retention = _MAX_TIME - self._window_end
        self._retention_horizon = self._window_end + min(
            max_retention_extension,
            remaining_retention,
        )
        self._max_leases_per_session = max_leases_per_session
        self._shard_count = application_registry.shard_count
        self._shards: dict[int, _RdpSessionShard] = {}
        self._affinity_partitions: list[_AffinityPartition | None] = [None] * self._shard_count
        self._directory_lock = RLock()
        self._gate = _MutationGate()
        self._watermark_lane = Lock()
        self._watermark = self._window_start
        self._route_compaction_cursor = 0
        self._shard_compaction_cursor = 0
        self._expiry_compaction_cursor = 0

    @property
    def application_registry(self) -> ApplicationChannelRegistry:
        """Return the injected shared application-channel registry."""

        return self._application

    def _owner_id(self, logical_session_id: str) -> str:
        return f"rdp-logical-session:{logical_session_id.strip()}"

    def partition_id(self, logical_session_id: str) -> int:
        """Return the aligned application owner partition for one logical ID."""

        if not logical_session_id.strip():
            raise ValueError("logical_session_id must not be empty")
        return self._logical_route_key(logical_session_id) % self._shard_count

    def affinity_partition_id(self, affinity: RdpSessionAffinity) -> int:
        """Return the fixed exact-affinity route partition."""

        return _stable_partition("rdp-affinity", affinity.digest, self._shard_count)

    @staticmethod
    def _logical_route_key(logical_session_id: str) -> int:
        owner_id = f"rdp-logical-session:{logical_session_id.strip()}"
        return _stable_digest("owner", owner_id)

    @staticmethod
    def _affinity_route_key(affinity: RdpSessionAffinity) -> int:
        return _semantic_token("rdp-affinity-route", affinity.digest)

    def _shard(self, logical_session_id: str, *, create: bool) -> _RdpSessionShard | None:
        shard_id = self.partition_id(logical_session_id)
        shard = self._shards.get(shard_id)
        if shard is not None or not create:
            return shard
        with self._directory_lock:
            shard = self._shards.get(shard_id)
            if shard is None:
                shard = _RdpSessionShard(shard_id=shard_id)
                self._shards[shard_id] = shard
            return shard

    def _affinity_partition(
        self,
        affinity: RdpSessionAffinity,
        *,
        create: bool,
    ) -> _AffinityPartition | None:
        partition_id = self.affinity_partition_id(affinity)
        partition = self._affinity_partitions[partition_id]
        if partition is not None or not create:
            return partition
        with self._directory_lock:
            partition = self._affinity_partitions[partition_id]
            if partition is None:
                partition = _AffinityPartition(partition_id=partition_id)
                self._affinity_partitions[partition_id] = partition
            return partition

    @staticmethod
    def _route_lock_entry(partition: _AffinityPartition) -> tuple[tuple[int, int], RLock]:
        return (0, partition.partition_id), partition.lock

    @staticmethod
    def _shard_lock_entry(shard: _RdpSessionShard) -> tuple[tuple[int, int], RLock]:
        return (1, shard.shard_id), shard.lock

    def _pack_locator(self, shard_id: int, handle: int) -> int:
        return handle * self._shard_count + shard_id

    def _unpack_locator(self, locator: int) -> tuple[int, int]:
        handle, shard_id = divmod(locator, self._shard_count)
        return shard_id, handle

    def _require_window_time(
        self,
        value: datetime,
        field_name: str,
        *,
        allow_end_boundary: bool = False,
    ) -> datetime:
        canonical_time = ensure_utc(value)
        after_window = canonical_time > self._window_end or (
            canonical_time == self._window_end and not allow_end_boundary
        )
        if canonical_time < self._window_start or after_window:
            raise StateError(
                f"{field_name} {canonical_time.isoformat()} is outside the RDP window "
                f"[{self._window_start.isoformat()}, {self._window_end.isoformat()})"
            )
        return canonical_time

    def _require_retention_time(self, value: datetime, field_name: str) -> datetime:
        canonical_time = ensure_utc(value)
        if canonical_time < self._window_start or canonical_time > self._retention_horizon:
            raise StateError(
                f"{field_name} {canonical_time.isoformat()} is outside the bounded RDP "
                f"retention horizon ending {self._retention_horizon.isoformat()}"
            )
        return canonical_time

    def _reject_behind_watermark(self, value: datetime, operation: str) -> None:
        if value < self._watermark:
            raise StateError(
                f"RDP {operation} at {value.isoformat()} is behind watermark "
                f"{self._watermark.isoformat()}"
            )

    @staticmethod
    def _lookup_locked(
        shard: _RdpSessionShard,
        logical_session_id: str,
    ) -> tuple[int, RdpSessionSnapshot] | None:
        handle = shard.session_routes.get_digest(
            RdpReconnectStateManager._logical_route_key(logical_session_id)
        )
        if handle is None:
            return None
        shard.logical_lookup_candidates_inspected += 1
        try:
            snapshot = shard.sessions.get_by_handle(handle)
        except KeyError:
            return None
        if snapshot.logical_session_id != logical_session_id:
            return None
        return handle, snapshot

    def _replace_snapshot_locked(
        self,
        shard: _RdpSessionShard,
        handle: int,
        _prior: RdpSessionSnapshot,
        updated: RdpSessionSnapshot,
    ) -> None:
        shard.invalidate_snapshot(self._logical_route_key(_prior.logical_session_id))
        shard.sessions.replace(handle, updated)

    def _channel_identity(
        self,
        identity: RdpLogicalSessionIdentity,
        plan: RdpTransportPlan,
    ) -> ApplicationChannelIdentity:
        hard_deadline = min(identity.hard_deadline, plan.binding.closes_at, self._window_end)
        if hard_deadline <= plan.connected_at:
            raise StateError("RDP transport closes before its channel can connect")
        budget = plan.budget
        logical_budget = identity.budget
        if (
            budget.initiator_bytes > logical_budget.initiator_bytes
            or budget.responder_bytes > logical_budget.responder_bytes
            or budget.operations > logical_budget.operations
        ):
            raise StateError("RDP transport budget cannot exceed its logical-session budget")
        return ApplicationChannelIdentity(
            channel_id=plan.channel_id,
            protocol="rdp",
            owner_id=identity.owner_id,
            affinity_digest=_transport_affinity_digest(
                identity.affinity.digest,
                plan.channel_id,
            ),
            binding=plan.binding,
            opened_at=plan.connected_at,
            idle_timeout=identity.idle_timeout,
            hard_deadline=hard_deadline,
            budget=budget,
        )

    def _effective_generation_deadline(self, snapshot: RdpSessionSnapshot) -> datetime:
        generation = snapshot.generation
        return min(
            generation.idle_deadline,
            generation.binding.closes_at,
            snapshot.identity.hard_deadline,
            self._window_end,
        )

    def _same_transport_plan(
        self,
        generation: RdpTransportGeneration,
        plan: RdpTransportPlan,
    ) -> bool:
        if not (
            generation.channel_id == plan.channel_id
            and generation.binding == plan.binding
            and generation.connected_at == plan.connected_at
        ):
            return False
        channel = self._application.get(generation.channel_id)
        return channel is not None and channel.identity.budget == plan.budget

    def open_session(
        self,
        identity: RdpLogicalSessionIdentity,
        transport: RdpTransportPlan,
    ) -> RdpSessionSnapshot:
        """Create one logical session and its immutable generation zero."""

        with self._gate.mutation():
            started_at = self._require_window_time(identity.started_at, "RDP started_at")
            self._reject_behind_watermark(started_at, "session open")
            if identity.hard_deadline > self._window_end:
                raise StateError("RDP hard_deadline must be inside the generation window")
            if transport.connected_at != started_at:
                raise StateError("Initial RDP transport must connect at logical-session start")
            shard = self._shard(identity.logical_session_id, create=True)
            affinity_route = self._affinity_partition(identity.affinity, create=True)
            assert shard is not None and affinity_route is not None
            with _acquire_stable_locks(
                [self._route_lock_entry(affinity_route), self._shard_lock_entry(shard)]
            ):
                existing = self._lookup_locked(shard, identity.logical_session_id)
                logical_route_key = self._logical_route_key(identity.logical_session_id)
                if (
                    existing is None
                    and shard.session_routes.get_digest(logical_route_key) is not None
                ):
                    raise StateError("RDP logical-session route token collision")
                if existing is not None:
                    _handle, snapshot = existing
                    if (
                        snapshot.identity == identity
                        and snapshot.state is RdpSessionState.CONNECTED
                        and snapshot.generation.ordinal == 0
                        and self._same_transport_plan(snapshot.generation, transport)
                    ):
                        return snapshot
                    raise StateError(
                        f"Duplicate RDP logical_session_id {identity.logical_session_id!r}"
                    )
                affinity_route_key = self._affinity_route_key(identity.affinity)
                routed = affinity_route.routes.get_digest(affinity_route_key)
                if routed is not None:
                    raise StateError(
                        "RDP affinity already belongs to a retained logical session "
                        "or collided with its compact route token"
                    )

                channel, close_token = self._application.open_channel_with_token(
                    self._channel_identity(identity, transport)
                )
                generation = RdpTransportGeneration(
                    ordinal=0,
                    channel_id=transport.channel_id,
                    binding=transport.binding,
                    connected_at=transport.connected_at,
                    idle_deadline=channel.idle_deadline,
                )
                snapshot = RdpSessionSnapshot(
                    identity=identity,
                    state=RdpSessionState.CONNECTED,
                    generation=generation,
                    last_transition_at=started_at,
                )
                handle = shard.sessions.insert(snapshot)
                shard.sessions.set_close_token(handle, close_token)
                shard.sessions.set_route_metadata(
                    handle,
                    logical_route_key=logical_route_key,
                    affinity_route_key=affinity_route_key,
                    affinity_partition_id=affinity_route.partition_id,
                )
                shard.session_routes.set_digest(logical_route_key, handle)
                locator = self._pack_locator(shard.shard_id, handle)
                affinity_route.routes.set_digest(affinity_route_key, locator)
                shard.session_expiry.set(
                    handle,
                    self._effective_generation_deadline(snapshot).timestamp(),
                )
                shard.connected_sessions += 1
                shard.generation_high_water_mark = max(shard.generation_high_water_mark, 1)
                return snapshot

    def get(self, logical_session_id: str) -> RdpSessionSnapshot | None:
        """Return one retained logical session through its exact owner shard."""

        route_key = self._logical_route_key(logical_session_id)
        shard = self._shards.get(route_key % self._shard_count)
        if shard is None:
            return None
        with shard.lock:
            handle = shard.session_routes.get_digest(route_key)
            if handle is None:
                return None
            shard.logical_lookup_candidates_inspected += 1
            try:
                snapshot = shard.public_snapshot(route_key, handle)
            except KeyError:
                return None
            return snapshot if snapshot.logical_session_id == logical_session_id else None

    def find_by_affinity(self, affinity: RdpSessionAffinity) -> RdpSessionSnapshot | None:
        """Return one exact retained affinity after inspecting at most one candidate."""

        route = self._affinity_partition(affinity, create=False)
        if route is None:
            return None
        with route.lock:
            route_key = self._affinity_route_key(affinity)
            locator = route.routes.get_digest(route_key)
        if locator is None:
            return None
        shard_id, handle = self._unpack_locator(locator)
        shard = self._shards.get(shard_id)
        if shard is None:
            return None
        with _acquire_stable_locks([self._route_lock_entry(route), self._shard_lock_entry(shard)]):
            if route.routes.get_digest(route_key) != locator:
                return None
            route.lookup_candidates_inspected += 1
            try:
                snapshot = shard.sessions.get_by_handle(handle)
            except KeyError:
                return None
            return snapshot if snapshot.identity.affinity == affinity else None

    def reconnect(
        self,
        logical_session_id: str,
        *,
        affinity: RdpSessionAffinity,
        transport: RdpTransportPlan,
        expected_generation: int,
    ) -> RdpSessionSnapshot:
        """Reconnect one disconnected logical session on a new transport."""

        with self._gate.mutation():
            connected_at = self._require_window_time(
                transport.connected_at,
                "RDP reconnect connected_at",
            )
            self._reject_behind_watermark(connected_at, "reconnect")
            shard = self._shard(logical_session_id, create=False)
            if shard is None:
                raise StateError(f"Unknown RDP logical session {logical_session_id!r}")
            with shard.lock:
                found = self._lookup_locked(shard, logical_session_id)
                if found is None:
                    raise StateError(f"Unknown RDP logical session {logical_session_id!r}")
                handle, snapshot = found
                if affinity != snapshot.identity.affinity:
                    raise StateError("RDP reconnect affinity does not match the logical session")
                if snapshot.state is RdpSessionState.CONNECTED:
                    if (
                        snapshot.generation.ordinal == expected_generation
                        and self._same_transport_plan(snapshot.generation, transport)
                    ):
                        return snapshot
                    raise StateError("Connected RDP session must disconnect before reconnect")
                if snapshot.state is RdpSessionState.LOGGED_OUT:
                    raise StateError("Logged-out RDP session cannot reconnect")
                expected = snapshot.generation.ordinal + 1
                if expected_generation != expected:
                    raise StateError(
                        f"RDP reconnect generation {expected_generation} does not match {expected}"
                    )
                assert snapshot.reconnect_deadline is not None
                if connected_at < snapshot.last_transition_at:
                    raise StateError("RDP reconnect cannot precede its disconnect")
                if connected_at >= snapshot.reconnect_deadline:
                    raise StateError("RDP reconnect is at or after its reconnect deadline")
                if transport.channel_id == snapshot.generation.channel_id:
                    raise StateError("RDP reconnect requires a new immutable channel")
                if transport.binding.transport_id == snapshot.generation.binding.transport_id:
                    raise StateError("RDP reconnect requires a new immutable transport")

                channel, close_token = self._application.open_channel_with_token(
                    self._channel_identity(snapshot.identity, transport)
                )
                generation = RdpTransportGeneration(
                    ordinal=expected_generation,
                    channel_id=transport.channel_id,
                    binding=transport.binding,
                    connected_at=connected_at,
                    idle_deadline=channel.idle_deadline,
                )
                updated = replace(
                    snapshot,
                    state=RdpSessionState.CONNECTED,
                    generation=generation,
                    last_transition_at=connected_at,
                    reconnect_deadline=None,
                )
                self._replace_snapshot_locked(shard, handle, snapshot, updated)
                shard.sessions.set_close_token(handle, close_token)
                shard.disconnected_sessions -= 1
                shard.connected_sessions += 1
                shard.generation_high_water_mark = max(
                    shard.generation_high_water_mark,
                    expected_generation + 1,
                )
                shard.session_expiry.set(
                    handle,
                    self._effective_generation_deadline(updated).timestamp(),
                )
                return updated

    def _close_generation_channel_locked(
        self,
        shard: _RdpSessionShard,
        handle: int,
        snapshot: RdpSessionSnapshot,
        *,
        closed_at: datetime,
        reason: str,
    ) -> datetime:
        """Close one exact immutable transport without reconstructing app state."""

        result = self._application.close_channel_by_token(
            snapshot.generation.channel_id,
            token=shard.sessions.close_token(handle),
            closed_at=closed_at,
            reason=reason,
        )
        return result.closed_at

    def disconnect(
        self,
        logical_session_id: str,
        *,
        channel_id: str,
        disconnected_at: datetime,
        reason: str = "rdp_disconnect",
    ) -> RdpSessionSnapshot:
        """Close the current transport while preserving token/session identity."""

        with self._gate.mutation():
            canonical_time = self._require_window_time(
                disconnected_at,
                "RDP disconnected_at",
                allow_end_boundary=True,
            )
            self._reject_behind_watermark(canonical_time, "disconnect")
            shard = self._shard(logical_session_id, create=False)
            if shard is None:
                raise StateError(f"Unknown RDP logical session {logical_session_id!r}")
            with shard.lock:
                found = self._lookup_locked(shard, logical_session_id)
                if found is None:
                    raise StateError(f"Unknown RDP logical session {logical_session_id!r}")
                handle, snapshot = found
                if snapshot.generation.channel_id != channel_id:
                    raise StateError("RDP disconnect channel is not the current generation")
                if snapshot.state is RdpSessionState.DISCONNECTED:
                    if snapshot.generation.disconnected_at == canonical_time:
                        return snapshot
                    raise StateError("RDP session is already disconnected at another time")
                if snapshot.state is RdpSessionState.LOGGED_OUT:
                    raise StateError("Logged-out RDP session cannot disconnect")
                if snapshot.active_operations:
                    raise StateError("RDP session cannot disconnect with active operations")
                if canonical_time < snapshot.last_transition_at:
                    raise StateError("RDP disconnect cannot precede its connection")
                if canonical_time > self._effective_generation_deadline(snapshot):
                    raise StateError("RDP disconnect is after its active transport deadline")
                canonical_time = self._close_generation_channel_locked(
                    shard,
                    handle,
                    snapshot,
                    closed_at=canonical_time,
                    reason=reason,
                )
                generation = replace(snapshot.generation, disconnected_at=canonical_time)
                reconnect_deadline = min(
                    canonical_time + snapshot.identity.reconnect_timeout,
                    snapshot.identity.hard_deadline,
                    self._window_end,
                )
                updated = replace(
                    snapshot,
                    state=RdpSessionState.DISCONNECTED,
                    generation=generation,
                    last_transition_at=canonical_time,
                    reconnect_deadline=reconnect_deadline,
                )
                self._replace_snapshot_locked(shard, handle, snapshot, updated)
                shard.connected_sessions -= 1
                shard.disconnected_sessions += 1
                shard.session_expiry.set(handle, reconnect_deadline.timestamp())
                return updated

    def logout(
        self,
        logical_session_id: str,
        *,
        logged_out_at: datetime,
        reason: str = "rdp_logoff",
    ) -> RdpSessionSnapshot:
        """Finalize the logical session and begin bounded tombstone retention."""

        with self._gate.mutation():
            canonical_time = self._require_window_time(
                logged_out_at,
                "RDP logged_out_at",
                allow_end_boundary=True,
            )
            shard = self._shard(logical_session_id, create=False)
            if shard is None:
                raise StateError(f"Unknown RDP logical session {logical_session_id!r}")
            with shard.lock:
                found = self._lookup_locked(shard, logical_session_id)
                if found is None:
                    raise StateError(f"Unknown RDP logical session {logical_session_id!r}")
                handle, snapshot = found
                if snapshot.state is RdpSessionState.LOGGED_OUT:
                    if snapshot.logged_out_at == canonical_time:
                        return snapshot
                    assert snapshot.logged_out_at is not None
                    if canonical_time < snapshot.logged_out_at:
                        raise StateError(
                            "RDP logout cannot move an accepted terminal time backward"
                        )
                    retention_deadline = self._retention_deadline_locked(
                        shard,
                        logical_session_id,
                        canonical_time,
                    )
                    reconciled = replace(
                        snapshot,
                        last_transition_at=canonical_time,
                        logged_out_at=canonical_time,
                        retention_deadline=retention_deadline,
                    )
                    self._replace_snapshot_locked(shard, handle, snapshot, reconciled)
                    shard.session_expiry.set(handle, retention_deadline.timestamp())
                    return reconciled
                self._reject_behind_watermark(canonical_time, "logout")
                if snapshot.active_operations:
                    raise StateError("RDP session cannot log out with active operations")
                if canonical_time < snapshot.last_transition_at:
                    raise StateError("RDP logout cannot precede the latest transition")
                generation = snapshot.generation
                if snapshot.state is RdpSessionState.CONNECTED:
                    transport_deadline = self._effective_generation_deadline(snapshot)
                    channel_close_at = min(canonical_time, transport_deadline)
                    channel_close_at = self._close_generation_channel_locked(
                        shard,
                        handle,
                        snapshot,
                        closed_at=channel_close_at,
                        reason=reason,
                    )
                    generation = replace(generation, disconnected_at=channel_close_at)
                    shard.connected_sessions -= 1
                else:
                    shard.disconnected_sessions -= 1
                retention_deadline = self._retention_deadline_locked(
                    shard,
                    logical_session_id,
                    canonical_time,
                )
                updated = replace(
                    snapshot,
                    state=RdpSessionState.LOGGED_OUT,
                    generation=generation,
                    last_transition_at=canonical_time,
                    reconnect_deadline=None,
                    logged_out_at=canonical_time,
                    retention_deadline=retention_deadline,
                )
                self._replace_snapshot_locked(shard, handle, snapshot, updated)
                shard.logged_out_sessions += 1
                shard.session_expiry.set(handle, retention_deadline.timestamp())
                return updated

    def _retention_deadline_locked(
        self,
        shard: _RdpSessionShard,
        logical_session_id: str,
        logged_out_at: datetime,
    ) -> datetime:
        deadline = min(
            logged_out_at + self._post_logout_grace,
            self._retention_horizon,
        )
        leases = tuple(shard.leases.find_iter("logical_session", logical_session_id))
        if len(leases) > self._max_leases_per_session:
            raise StateError("RDP lease index exceeded its configured candidate bound")
        for lease in leases:
            deadline = max(deadline, lease.retain_until)
        return deadline

    def record_member_admission(
        self,
        logical_session_id: str,
        *,
        admitted_at: datetime,
    ) -> RdpSessionSnapshot:
        """Count one lifetime member admission without claiming close authority."""

        return self._record_relationship(
            logical_session_id,
            admitted_at=admitted_at,
            member=True,
        )

    def record_dependent_admission(
        self,
        logical_session_id: str,
        *,
        admitted_at: datetime,
    ) -> RdpSessionSnapshot:
        """Count one lifetime dependent admission without claiming close authority."""

        return self._record_relationship(
            logical_session_id,
            admitted_at=admitted_at,
            member=False,
        )

    def _record_relationship(
        self,
        logical_session_id: str,
        *,
        admitted_at: datetime,
        member: bool,
    ) -> RdpSessionSnapshot:
        with self._gate.mutation():
            canonical_time = self._require_window_time(
                admitted_at,
                "RDP relationship admitted_at",
                allow_end_boundary=True,
            )
            self._reject_behind_watermark(canonical_time, "relationship admission")
            shard = self._shard(logical_session_id, create=False)
            if shard is None:
                raise StateError(f"Unknown RDP logical session {logical_session_id!r}")
            with shard.lock:
                found = self._lookup_locked(shard, logical_session_id)
                if found is None:
                    raise StateError(f"Unknown RDP logical session {logical_session_id!r}")
                handle, snapshot = found
                if snapshot.state is RdpSessionState.LOGGED_OUT:
                    raise StateError("Logged-out RDP session cannot admit members or dependents")
                if canonical_time < snapshot.last_transition_at:
                    raise StateError("RDP relationship cannot precede the latest transition")
                if canonical_time > snapshot.identity.hard_deadline:
                    raise StateError("RDP relationship is after the logical hard deadline")
                updated = replace(
                    snapshot,
                    member_admissions=snapshot.member_admissions + int(member),
                    dependent_admissions=snapshot.dependent_admissions + int(not member),
                )
                self._replace_snapshot_locked(shard, handle, snapshot, updated)
                return updated

    def reserve_operation(
        self,
        logical_session_id: str,
        *,
        started_at: datetime,
        ended_at: datetime,
        initiator_bytes: int = 0,
        responder_bytes: int = 0,
        parent_operation_id: str = "",
    ) -> RdpOperationAdmission:
        """Reserve one operation inside the current logical and transport budget."""

        with self._gate.mutation():
            canonical_start = self._require_window_time(
                started_at,
                "RDP operation started_at",
            )
            canonical_end = self._require_window_time(
                ended_at,
                "RDP operation ended_at",
                allow_end_boundary=True,
            )
            self._reject_behind_watermark(canonical_start, "operation reserve")
            shard = self._shard(logical_session_id, create=False)
            if shard is None:
                raise StateError(f"Unknown RDP logical session {logical_session_id!r}")
            with shard.lock:
                found = self._lookup_locked(shard, logical_session_id)
                if found is None:
                    raise StateError(f"Unknown RDP logical session {logical_session_id!r}")
                handle, snapshot = found
                if snapshot.state is not RdpSessionState.CONNECTED:
                    raise StateError("RDP operations require a connected logical session")
                if canonical_start < snapshot.last_transition_at:
                    raise StateError("RDP operation cannot precede its transport connection")
                if canonical_end > self._effective_generation_deadline(snapshot):
                    raise StateError("RDP operation exceeds its active transport deadline")
                logical_budget = snapshot.identity.budget
                next_initiator = snapshot.reserved_initiator_bytes + initiator_bytes
                next_responder = snapshot.reserved_responder_bytes + responder_bytes
                next_operations = snapshot.reserved_operations + 1
                if next_initiator > logical_budget.initiator_bytes:
                    raise StateError("RDP operation exceeds logical initiator byte budget")
                if next_responder > logical_budget.responder_bytes:
                    raise StateError("RDP operation exceeds logical responder byte budget")
                if next_operations > logical_budget.operations:
                    raise StateError("RDP operation exceeds logical operation budget")
                channel = self._application.get(snapshot.generation.channel_id)
                if channel is None or not channel.is_open:
                    raise StateError("RDP current application channel is not open")
                ordinal = channel.reserved_operations
                operation_id = _operation_id(
                    logical_session_id,
                    snapshot.generation.ordinal,
                    ordinal,
                )
                if operation_id in shard.operations:
                    raise StateError("RDP deterministic operation identity is already active")
                if parent_operation_id and parent_operation_id not in shard.operations:
                    raise StateError("RDP parent operation is not active in this manager")
                reservation = ApplicationOperationReservation(
                    operation_id=operation_id,
                    channel_id=snapshot.generation.channel_id,
                    ordinal=ordinal,
                    started_at=canonical_start,
                    ended_at=canonical_end,
                    initiator_bytes=initiator_bytes,
                    responder_bytes=responder_bytes,
                    parent_operation_id=parent_operation_id,
                )
                channel = self._application.reserve_operation(reservation)
                generation = replace(
                    snapshot.generation,
                    idle_deadline=channel.idle_deadline,
                )
                updated = replace(
                    snapshot,
                    generation=generation,
                    reserved_initiator_bytes=next_initiator,
                    reserved_responder_bytes=next_responder,
                    reserved_operations=next_operations,
                    active_operations=snapshot.active_operations + 1,
                )
                self._replace_snapshot_locked(shard, handle, snapshot, updated)
                shard.operations[operation_id] = handle
                shard.active_operations += 1
                shard.session_expiry.set(
                    handle,
                    self._effective_generation_deadline(updated).timestamp(),
                )
                shard.blocker_expiry.set(
                    handle,
                    self._effective_generation_deadline(updated).timestamp(),
                )
                return RdpOperationAdmission(reservation=reservation, session=updated)

    def finalize_operation(self, logical_session_id: str, operation_id: str) -> bool:
        """Finalize one active operation; repeated finalization is a no-op."""

        with self._gate.mutation():
            shard = self._shard(logical_session_id, create=False)
            if shard is None:
                return False
            with shard.lock:
                handle = shard.operations.get(operation_id)
                if handle is None:
                    return False
                try:
                    snapshot = shard.sessions.get_by_handle(handle)
                except KeyError:
                    return False
                if snapshot.logical_session_id != logical_session_id:
                    raise StateError("RDP operation belongs to another logical session")
                if not self._application.finalize_operation(operation_id):
                    raise StateError("RDP/application operation state diverged during finalization")
                shard.operations.pop(operation_id, None)
                shard.operation_deletions += 1
                updated = replace(
                    snapshot,
                    completed_operations=snapshot.completed_operations + 1,
                    active_operations=snapshot.active_operations - 1,
                )
                self._replace_snapshot_locked(shard, handle, snapshot, updated)
                shard.active_operations -= 1
                if updated.active_operations:
                    shard.blocker_expiry.set(
                        handle,
                        self._effective_generation_deadline(updated).timestamp(),
                    )
                else:
                    shard.blocker_expiry.pop(handle, None)
                return True

    def add_retention_lease(self, lease: RdpRetentionLease) -> RdpRetentionLease:
        """Acquire one exact bounded lease, idempotently for an identical request."""

        with self._gate.mutation():
            acquired_at = self._require_window_time(
                lease.acquired_at,
                "RDP lease acquired_at",
                allow_end_boundary=True,
            )
            retain_until = self._require_retention_time(
                lease.retain_until,
                "RDP lease retain_until",
            )
            self._reject_behind_watermark(acquired_at, "lease acquisition")
            shard = self._shard(lease.logical_session_id, create=False)
            if shard is None:
                raise StateError(
                    f"Unknown RDP logical session {lease.logical_session_id!r} for lease"
                )
            with shard.lock:
                found = self._lookup_locked(shard, lease.logical_session_id)
                if found is None:
                    raise StateError(
                        f"Unknown RDP logical session {lease.logical_session_id!r} for lease"
                    )
                session_handle, snapshot = found
                key = (lease.logical_session_id, lease.lease_id)
                existing_handle = shard.lease_routes.get(key)
                if existing_handle is not None:
                    existing = shard.leases.get_by_handle(existing_handle)
                    if existing == lease:
                        return existing
                    raise StateError(f"Duplicate RDP lease_id {lease.lease_id!r}")
                if snapshot.active_leases >= self._max_leases_per_session:
                    raise StateError(
                        f"RDP session reached its {self._max_leases_per_session}-lease bound"
                    )
                if acquired_at < snapshot.last_transition_at:
                    raise StateError("RDP lease cannot precede the latest session transition")
                if (
                    snapshot.state is RdpSessionState.LOGGED_OUT
                    and snapshot.retention_deadline is not None
                    and acquired_at > snapshot.retention_deadline
                ):
                    raise StateError("RDP lease cannot revive an elapsed tombstone")
                lease_handle = shard.leases.insert(lease)
                shard.lease_routes[key] = lease_handle
                shard.lease_expiry.set(lease_handle, retain_until.timestamp())
                updated = replace(
                    snapshot,
                    active_leases=snapshot.active_leases + 1,
                    retention_deadline=(
                        max(snapshot.retention_deadline, retain_until)
                        if snapshot.retention_deadline is not None
                        else None
                    ),
                )
                self._replace_snapshot_locked(shard, session_handle, snapshot, updated)
                if updated.retention_deadline is not None:
                    shard.session_expiry.set(
                        session_handle,
                        updated.retention_deadline.timestamp(),
                    )
                shard.active_leases += 1
                shard.maximum_lease_bucket = max(
                    shard.maximum_lease_bucket,
                    updated.active_leases,
                )
                shard.estimated_value_bytes += _lease_estimated_bytes(lease)
                return lease

    def release_retention_lease(
        self,
        logical_session_id: str,
        lease_id: str,
        *,
        released_at: datetime,
    ) -> bool:
        """Release one active lease; repeated release is a no-op."""

        with self._gate.mutation():
            canonical_time = self._require_retention_time(
                released_at,
                "RDP lease released_at",
            )
            self._reject_behind_watermark(canonical_time, "lease release")
            shard = self._shard(logical_session_id, create=False)
            if shard is None:
                return False
            with shard.lock:
                key = (logical_session_id, lease_id.strip())
                lease_handle = shard.lease_routes.get(key)
                if lease_handle is None:
                    return False
                lease = shard.leases.get_by_handle(lease_handle)
                if canonical_time < lease.acquired_at:
                    raise StateError("RDP lease release cannot precede acquisition")
                found = self._lookup_locked(shard, logical_session_id)
                if found is None:
                    raise StateError("RDP lease retained no owning logical session")
                session_handle, snapshot = found
                self._remove_lease_locked(shard, lease_handle, lease)
                retention_deadline = snapshot.retention_deadline
                if snapshot.state is RdpSessionState.LOGGED_OUT:
                    assert snapshot.logged_out_at is not None
                    retention_deadline = self._retention_deadline_locked(
                        shard,
                        logical_session_id,
                        snapshot.logged_out_at,
                    )
                updated = replace(
                    snapshot,
                    active_leases=snapshot.active_leases - 1,
                    retention_deadline=retention_deadline,
                )
                self._replace_snapshot_locked(shard, session_handle, snapshot, updated)
                if retention_deadline is not None:
                    shard.session_expiry.set(
                        session_handle,
                        max(retention_deadline, self._watermark).timestamp(),
                    )
                return True

    def _remove_lease_locked(
        self,
        shard: _RdpSessionShard,
        lease_handle: int,
        lease: RdpRetentionLease,
    ) -> None:
        shard.lease_expiry.pop(lease_handle, None)
        shard.leases.delete(lease_handle)
        shard.lease_routes.pop((lease.logical_session_id, lease.lease_id), None)
        shard.lease_route_deletions += 1
        shard.active_leases -= 1
        shard.estimated_value_bytes -= _lease_estimated_bytes(lease)

    def _preflight_due_locked(
        self,
        shards: tuple[_RdpSessionShard, ...],
        cutoff: float,
    ) -> None:
        blockers: list[str] = []
        for shard in shards:
            due = shard.blocker_expiry.first_due_before(cutoff, inclusive=True)
            if due is None:
                continue
            handle, _deadline = due
            try:
                snapshot = shard.sessions.get_by_handle(handle)
            except KeyError:
                raise StateError("RDP blocker expiry retained a stale session handle") from None
            if snapshot.state is not RdpSessionState.CONNECTED or not snapshot.active_operations:
                raise StateError("RDP blocker expiry diverged from active operation state")
            blockers.append(snapshot.logical_session_id)
        if blockers:
            preview = ", ".join(repr(item) for item in blockers[:3])
            suffix = "" if len(blockers) <= 3 else f" and {len(blockers) - 3} more"
            raise StateError(
                f"RDP watermark cannot advance past active operations for {preview}{suffix}"
            )

    def _expire_leases_locked(
        self,
        shard: _RdpSessionShard,
        cutoff: float,
        *,
        limit: int,
    ) -> int:
        """Expire at most ``limit`` leases and return the consumed work."""

        page = shard.lease_expiry.expire_before_page(
            cutoff,
            inclusive=True,
            limit=limit,
        )
        for lease_handle, _deadline in page:
            try:
                lease = shard.leases.get_by_handle(lease_handle)
            except KeyError:
                continue
            found = self._lookup_locked(shard, lease.logical_session_id)
            if found is None:
                self._remove_lease_locked(shard, lease_handle, lease)
                continue
            session_handle, snapshot = found
            self._remove_lease_locked(shard, lease_handle, lease)
            updated = replace(snapshot, active_leases=snapshot.active_leases - 1)
            self._replace_snapshot_locked(shard, session_handle, snapshot, updated)
            if updated.state is not RdpSessionState.LOGGED_OUT:
                continue
            assert updated.logged_out_at is not None
            retention_deadline = self._retention_deadline_locked(
                shard,
                updated.logical_session_id,
                updated.logged_out_at,
            )
            retained = replace(updated, retention_deadline=retention_deadline)
            self._replace_snapshot_locked(shard, session_handle, updated, retained)
            shard.session_expiry.set(session_handle, retention_deadline.timestamp())
        return len(page)

    def _logout_due_locked(
        self,
        shard: _RdpSessionShard,
        handle: int,
        snapshot: RdpSessionSnapshot,
        logged_out_at: datetime,
        *,
        reason: str,
        closures: list[RdpSessionClosure],
    ) -> RdpSessionSnapshot:
        retention_deadline = self._retention_deadline_locked(
            shard,
            snapshot.logical_session_id,
            logged_out_at,
        )
        updated = replace(
            snapshot,
            state=RdpSessionState.LOGGED_OUT,
            last_transition_at=logged_out_at,
            reconnect_deadline=None,
            logged_out_at=logged_out_at,
            retention_deadline=retention_deadline,
        )
        self._replace_snapshot_locked(shard, handle, snapshot, updated)
        if snapshot.state is RdpSessionState.CONNECTED:
            shard.connected_sessions -= 1
        else:
            shard.disconnected_sessions -= 1
        shard.logged_out_sessions += 1
        affinity = updated.identity.affinity
        generation = updated.generation
        closures.append(
            RdpSessionClosure(
                logical_session_id=updated.logical_session_id,
                target_hostname=affinity.target_host,
                principal=affinity.principal,
                logon_id=affinity.logon_id,
                session_id=affinity.session_id,
                channel_id=generation.channel_id,
                transport_id=generation.binding.transport_id,
                generation_ordinal=generation.ordinal,
                closed_at=logged_out_at,
                reason=reason,
            )
        )
        return updated

    def _evict_session_locked(
        self,
        shard: _RdpSessionShard,
        handle: int,
        snapshot: RdpSessionSnapshot,
        affinity_routes: dict[int, _AffinityPartition],
    ) -> None:
        if snapshot.active_leases or snapshot.active_operations:
            raise StateError("RDP tombstone eviction encountered active references")
        self._evict_session_handle_locked(shard, handle, affinity_routes)

    def _evict_session_handle_locked(
        self,
        shard: _RdpSessionShard,
        handle: int,
        affinity_routes: dict[int, _AffinityPartition],
    ) -> None:
        """Evict one unreferenced logged-out handle without decoding its frozen rows."""

        locator = self._pack_locator(shard.shard_id, handle)
        logical_route_key, affinity_route_key, partition_id = shard.sessions.route_metadata(handle)
        route = affinity_routes.get(partition_id)
        if route is not None and route.routes.get_digest(affinity_route_key) == locator:
            route.routes.pop_digest(affinity_route_key, None)
            route.deletions += 1
        shard.session_routes.pop_digest(logical_route_key, None)
        shard.session_route_deletions += 1
        shard.blocker_expiry.pop(handle, None)
        shard.invalidate_snapshot(logical_route_key)
        shard.sessions.delete_handle(handle)
        shard.logged_out_sessions -= 1

    def _process_due_session_locked(
        self,
        shard: _RdpSessionShard,
        handle: int,
        deadline: datetime,
        cutoff: datetime,
        affinity_routes: dict[int, _AffinityPartition],
        closures: list[RdpSessionClosure],
    ) -> None:
        reference_counts = shard.sessions.logged_out_reference_counts(handle)
        if reference_counts is not None:
            active_operations, active_leases = reference_counts
            if active_operations:
                raise StateError("RDP tombstone eviction encountered active operations")
            if not active_leases:
                self._evict_session_handle_locked(shard, handle, affinity_routes)
                return
        try:
            snapshot = shard.sessions.get_by_handle(handle)
        except KeyError:
            return
        current_deadline = deadline
        while current_deadline <= cutoff:
            if snapshot.state is RdpSessionState.CONNECTED:
                closed_at = self._close_generation_channel_locked(
                    shard,
                    handle,
                    snapshot,
                    closed_at=current_deadline,
                    reason="rdp_deadline",
                )
                generation = replace(snapshot.generation, disconnected_at=closed_at)
                terminal_deadline = min(snapshot.identity.hard_deadline, self._window_end)
                if current_deadline >= terminal_deadline:
                    snapshot = replace(snapshot, generation=generation)
                    snapshot = self._logout_due_locked(
                        shard,
                        handle,
                        snapshot,
                        terminal_deadline,
                        reason="rdp_hard_deadline",
                        closures=closures,
                    )
                    current_deadline = snapshot.retention_deadline or cutoff + timedelta.max
                    break
                reconnect_deadline = min(
                    current_deadline + snapshot.identity.reconnect_timeout,
                    terminal_deadline,
                )
                updated = replace(
                    snapshot,
                    state=RdpSessionState.DISCONNECTED,
                    generation=generation,
                    last_transition_at=closed_at,
                    reconnect_deadline=reconnect_deadline,
                )
                self._replace_snapshot_locked(shard, handle, snapshot, updated)
                shard.connected_sessions -= 1
                shard.disconnected_sessions += 1
                snapshot = updated
                current_deadline = reconnect_deadline
                continue
            if snapshot.state is RdpSessionState.DISCONNECTED:
                snapshot = self._logout_due_locked(
                    shard,
                    handle,
                    snapshot,
                    current_deadline,
                    reason="rdp_reconnect_timeout",
                    closures=closures,
                )
                current_deadline = snapshot.retention_deadline or cutoff + timedelta.max
                break
            assert snapshot.retention_deadline is not None
            if snapshot.active_leases:
                current_deadline = self._retention_deadline_locked(
                    shard,
                    snapshot.logical_session_id,
                    snapshot.logged_out_at or snapshot.last_transition_at,
                )
                if current_deadline <= cutoff:
                    raise StateError("RDP retained lease deadline did not progress")
                updated = replace(snapshot, retention_deadline=current_deadline)
                self._replace_snapshot_locked(shard, handle, snapshot, updated)
                snapshot = updated
                break
            self._evict_session_locked(shard, handle, snapshot, affinity_routes)
            return
        shard.session_expiry.set(handle, current_deadline.timestamp())

    def watermark(
        self,
        at: datetime,
        *,
        limit: int = _PRIMARY_COMPACTION_WORK_PER_WATERMARK,
    ) -> RdpWatermarkResult:
        """Advance one bounded state/expiry page to a cutoff.

        This method intentionally does not advance the injected application
        registry.  Integration must call this manager first, then advance that
        shared registry once for all protocol owners at the same cutoff.  A
        caller must render returned closures outside manager locks and call the
        same cutoff again while ``has_more`` is true.
        """

        if limit <= 0:
            raise ValueError("RDP watermark limit must be positive")
        canonical_time = ensure_utc(at)
        closures: list[RdpSessionClosure] = []
        has_more = False
        with self._watermark_lane:
            with self._gate.watermark():
                if canonical_time < self._watermark:
                    raise StateError("RDP watermarks must be monotonic")
                with self._directory_lock:
                    shards = tuple(sorted(self._shards.values(), key=lambda item: item.shard_id))
                    routes = tuple(
                        route for route in self._affinity_partitions if route is not None
                    )
                lock_entries = [self._route_lock_entry(route) for route in routes]
                lock_entries.extend(self._shard_lock_entry(shard) for shard in shards)
                with _acquire_stable_locks(lock_entries):
                    cutoff = canonical_time.timestamp()
                    self._preflight_due_locked(shards, cutoff)
                    remaining = limit
                    for shard in shards:
                        if not remaining:
                            break
                        remaining -= self._expire_leases_locked(
                            shard,
                            cutoff,
                            limit=remaining,
                        )
                    affinity_routes = {route.partition_id: route for route in routes}
                    for shard in shards:
                        if not remaining:
                            break
                        page = shard.session_expiry.expire_before_page(
                            cutoff,
                            inclusive=True,
                            limit=remaining,
                        )
                        remaining -= len(page)
                        for handle, deadline in page:
                            self._process_due_session_locked(
                                shard,
                                handle,
                                datetime.fromtimestamp(deadline, tz=UTC),
                                canonical_time,
                                affinity_routes,
                                closures,
                            )
                    has_more = any(
                        shard.lease_expiry.first_due_before(cutoff, inclusive=True) is not None
                        or shard.session_expiry.first_due_before(cutoff, inclusive=True) is not None
                        for shard in shards
                    )
                    self._watermark = canonical_time
            self._compact_primary_maps(_PRIMARY_COMPACTION_WORK_PER_WATERMARK)
            self._compact_expiry_indexes(_EXPIRY_COMPACTION_WORK_PER_WATERMARK)
            return RdpWatermarkResult(
                census=self.census(),
                closures=tuple(closures),
                has_more=has_more,
            )

    @staticmethod
    def _compact_map(
        route: IncrementalExactMap[object, object] | PackedUniqueDigestMap,
        *,
        deletions: int,
        max_work: int,
    ) -> tuple[int, int]:
        metrics = route.metrics()
        if not deletions and not metrics.primary_compaction_pending:
            return 0, deletions
        work = route.compact_primary(
            max_entries=max_work,
            force=not metrics.primary_compaction_pending and bool(deletions) and not route,
        )
        if not route.metrics().primary_compaction_pending:
            deletions = 0
        return work, deletions

    def _compact_primary_maps(self, max_work: int) -> None:
        with self._directory_lock:
            routes = tuple(route for route in self._affinity_partitions if route is not None)
            shards = tuple(sorted(self._shards.values(), key=lambda item: item.shard_id))
        work = 0
        visited = 0
        while routes and visited < len(routes) and work < max_work:
            position = self._route_compaction_cursor % len(routes)
            route = routes[position]
            visited += 1
            with route.lock:
                consumed, route.deletions = self._compact_map(
                    route.routes,
                    deletions=route.deletions,
                    max_work=max_work - work,
                )
                work += consumed
                pending = route.routes.metrics().primary_compaction_pending
            self._route_compaction_cursor = position if pending else position + 1
            if pending:
                break
        visited = 0
        while shards and visited < len(shards) and work < max_work:
            position = self._shard_compaction_cursor % len(shards)
            shard = shards[position]
            visited += 1
            with shard.lock:
                maps: tuple[
                    tuple[IncrementalExactMap[object, object] | PackedUniqueDigestMap, str],
                    ...,
                ] = (
                    (shard.session_routes, "session_route_deletions"),
                    (shard.operations, "operation_deletions"),
                    (shard.lease_routes, "lease_route_deletions"),
                )
                map_position = shard.compaction_cursor % len(maps)
                route, deletion_field = maps[map_position]
                consumed, deletions = self._compact_map(
                    route,
                    deletions=getattr(shard, deletion_field),
                    max_work=max_work - work,
                )
                setattr(shard, deletion_field, deletions)
                work += consumed
                pending = route.metrics().primary_compaction_pending
                shard.compaction_cursor = map_position if pending else map_position + 1
            self._shard_compaction_cursor = position if pending else position + 1
            if pending:
                break

    def _compact_expiry_indexes(self, max_work: int) -> None:
        with self._directory_lock:
            shards = tuple(sorted(self._shards.values(), key=lambda item: item.shard_id))
        work = 0
        visited = 0
        while shards and visited < len(shards) and work < max_work:
            position = self._expiry_compaction_cursor % len(shards)
            shard = shards[position]
            visited += 1
            with shard.lock:
                indexes = (
                    shard.sessions,
                    shard.session_expiry,
                    shard.lease_expiry,
                    shard.blocker_expiry,
                )
                index_position = shard.expiry_compaction_cursor % len(indexes)
                index = indexes[index_position]
                work += index.compact(max_slots=max_work - work)
                pending = index.metrics().compaction_pending
                shard.expiry_compaction_cursor = index_position if pending else index_position + 1
            self._expiry_compaction_cursor = position if pending else position + 1
            if pending:
                break

    def census(self) -> RdpReconnectCensus:
        """Return a bounded structural census without traversing session values."""

        with self._directory_lock:
            shards = tuple(self._shards.values())
            routes = tuple(route for route in self._affinity_partitions if route is not None)
        lock_entries = [self._route_lock_entry(route) for route in routes]
        lock_entries.extend(self._shard_lock_entry(shard) for shard in shards)
        with _acquire_stable_locks(lock_entries):
            session_store_metrics = [
                shard.sessions.metrics(estimate_bytes=True) for shard in shards
            ]
            lease_store_metrics = [shard.leases.metrics(estimate_bytes=True) for shard in shards]
            map_metrics = [metric for shard in shards for metric in shard.map_metrics()]
            route_metrics = [route.routes.metrics(estimate_bytes=True) for route in routes]
            session_expiry_metrics = [
                shard.session_expiry.metrics(estimate_bytes=True) for shard in shards
            ]
            lease_expiry_metrics = [
                shard.lease_expiry.metrics(estimate_bytes=True) for shard in shards
            ]
            blocker_expiry_metrics = [
                shard.blocker_expiry.metrics(estimate_bytes=True) for shard in shards
            ]
            all_primary_metrics = (*map_metrics, *route_metrics)
            all_expiry_metrics = (
                *session_expiry_metrics,
                *lease_expiry_metrics,
                *blocker_expiry_metrics,
            )
            estimated_index_bytes = sum(
                metric.estimated_bytes
                for metric in (
                    *session_store_metrics,
                    *lease_store_metrics,
                    *all_primary_metrics,
                    *all_expiry_metrics,
                )
            )
            decoded_cache_entries = sum(len(shard.snapshot_cache) for shard in shards)
            decoded_cache_map_bytes = sum(sys.getsizeof(shard.snapshot_cache) for shard in shards)
            decoded_cache_value_bytes = sum(shard.snapshot_cache_value_bytes for shard in shards)
            estimated_index_bytes += decoded_cache_map_bytes
            estimated_bytes = (
                sys.getsizeof(self)
                + sys.getsizeof(self.__dict__)
                + sys.getsizeof(self._shards)
                + sys.getsizeof(self._affinity_partitions)
                + sum(
                    sys.getsizeof(shard)
                    + shard.estimated_value_bytes
                    + shard.sessions.estimated_value_bytes
                    + shard.snapshot_cache_value_bytes
                    for shard in shards
                )
                + sum(sys.getsizeof(route) for route in routes)
                + estimated_index_bytes
            )
            retained_sessions = sum(metric.live_entries for metric in session_store_metrics)
            logical_lookup_candidates = sum(
                shard.logical_lookup_candidates_inspected for shard in shards
            )
            affinity_lookup_candidates = sum(route.lookup_candidates_inspected for route in routes)
            result = RdpReconnectCensus(
                retained_sessions=retained_sessions,
                connected_sessions=sum(shard.connected_sessions for shard in shards),
                disconnected_sessions=sum(shard.disconnected_sessions for shard in shards),
                logged_out_sessions=sum(shard.logged_out_sessions for shard in shards),
                active_operations=sum(shard.active_operations for shard in shards),
                active_leases=sum(shard.active_leases for shard in shards),
                sidecar_shard_count=len(shards),
                affinity_partition_count=len(routes),
                max_shard_load=max(
                    (metric.live_entries for metric in session_store_metrics),
                    default=0,
                ),
                maximum_lease_bucket=max(
                    (shard.maximum_lease_bucket for shard in shards),
                    default=0,
                ),
                generation_high_water_mark=max(
                    (shard.generation_high_water_mark for shard in shards),
                    default=0,
                ),
                lookup_candidates_inspected=(
                    logical_lookup_candidates + affinity_lookup_candidates
                ),
                logical_lookup_candidates_inspected=logical_lookup_candidates,
                affinity_lookup_candidates_inspected=affinity_lookup_candidates,
                session_expiry_entries=sum(
                    metric.backing_entries for metric in session_expiry_metrics
                ),
                stale_session_expiry_entries=sum(
                    metric.stale_entries for metric in session_expiry_metrics
                ),
                lease_expiry_entries=sum(metric.backing_entries for metric in lease_expiry_metrics),
                stale_lease_expiry_entries=sum(
                    metric.stale_entries for metric in lease_expiry_metrics
                ),
                blocker_expiry_entries=sum(
                    metric.backing_entries for metric in blocker_expiry_metrics
                ),
                stale_blocker_expiry_entries=sum(
                    metric.stale_entries for metric in blocker_expiry_metrics
                ),
                compaction_pending=sum(
                    metric.primary_compaction_pending for metric in all_primary_metrics
                )
                + sum(metric.compaction_pending for metric in all_expiry_metrics)
                + sum(metric.compaction_pending for metric in session_store_metrics),
                compaction_rotations=sum(
                    metric.primary_compaction_rotations for metric in all_primary_metrics
                ),
                compaction_work=sum(
                    metric.primary_compaction_work for metric in all_primary_metrics
                )
                + sum(metric.compaction_work for metric in all_expiry_metrics)
                + sum(metric.compaction_work for metric in session_store_metrics),
                compaction_seconds=sum(
                    metric.primary_compaction_seconds for metric in all_primary_metrics
                )
                + sum(metric.compaction_seconds for metric in all_expiry_metrics),
                decoded_cache_entries=decoded_cache_entries,
                decoded_cache_capacity=len(shards) * _SNAPSHOT_CACHE_ENTRIES_PER_SHARD,
                decoded_cache_estimated_bytes=(decoded_cache_map_bytes + decoded_cache_value_bytes),
                estimated_bytes=estimated_bytes,
                estimated_index_bytes=estimated_index_bytes,
                primary_map_bytes=sum(
                    metric.primary_map_backing_bytes for metric in all_primary_metrics
                ),
                watermark=self._watermark,
                application=self._application.census(),
            )
        return result
