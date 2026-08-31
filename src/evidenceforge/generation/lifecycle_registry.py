# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Append-only, time-explicit canonical lifecycle registry foundation.

This module intentionally does not integrate with :class:`StateManager` yet.
It provides the isolated identity, transition, hold, closure, and retention
contract that later migration slices can adopt without changing existing
generation behavior.
"""

from __future__ import annotations

from array import array
from bisect import bisect_right
from collections import OrderedDict
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import FrozenInstanceError, dataclass, field, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_bytes
from struct import Struct
from sys import getsizeof
from threading import Condition, Lock, RLock, get_ident
from typing import Literal
from weakref import ReferenceType, WeakValueDictionary, ref

from evidenceforge.events.content_identity import (
    CompiledServiceDeploymentIdentity,
    RuntimeServiceDeploymentIdentity,
)
from evidenceforge.events.lifecycle import (
    LifecycleCloseBarrier,
    LifecycleClosureTicket,
    LifecycleEntityRef,
    LifecycleForegroundLease,
    LifecycleForegroundLeaseKey,
    LifecycleHold,
    LifecycleMembership,
    LifecycleRegistryStats,
    LifecycleRetentionLease,
    LifecycleSingletonLease,
    LifecycleSingletonLeaseKey,
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
    SessionLifecycleSnapshotView,
    TransportLifecycleIdentity,
    TransportLifecycleSnapshot,
    TransportSessionBindingIdentity,
    TransportSessionBindingSnapshot,
)
from evidenceforge.events.network import NetworkTuple
from evidenceforge.generation.indexes import (
    CompactIndexedStore,
    IncrementalExactMap,
    IndexMetrics,
    PackedByteRowStore,
    PackedHandleExpiryIndex,
    PackedUniqueDigestMap,
    SegmentedTemporalIndex,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.time import ensure_utc

_DEFAULT_CLOSED_RETENTION = timedelta(hours=48)
_DEFAULT_SNAPSHOT_HISTORY_LIMIT = 256
_DEFAULT_LEDGER_DETAIL_RETENTION = timedelta(hours=48)
_DEFAULT_SHARD_COUNT = 64
_LEDGER_COMPACTION_PAGE = 4_096
_PRIMARY_COMPACTION_PAGE = 4_096
_MAX_DURABLE_COMMITS_PER_ENTITY = 8
_STREAMED_TRANSITION_KINDS = frozenset({"dependent", "hold_acquired"})
_ESTIMATED_ENTITY_BYTES = 512
_ESTIMATED_DECODED_SNAPSHOT_BYTES = 3_584
_ESTIMATED_TRANSITION_BYTES = 192
_ESTIMATED_HOLD_BYTES = 176
_ESTIMATED_CONTROL_RECORD_BYTES = 160
_ESTIMATED_RESOURCE_LEASE_BINDING_BYTES = 40
_RESOURCE_LEASE_EXPIRY_PAGE = 4_096
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_SESSION_TEXT_FIELD_COUNT = 8
_SESSION_ROW_HEADER = Struct(">qQI8H")
_SERVICE_TEXT_FIELD_COUNT = 15
_SERVICE_ROW_HEADER = Struct(">qI15H")
_TRANSPORT_TEXT_FIELD_COUNT = 12
_TRANSPORT_ROW_HEADER = Struct(">qqHHI12H")
_PACKED_SESSION_ROW_BYTES = 256
_PACKED_SERVICE_ROW_BYTES = 192
_PACKED_TRANSPORT_ROW_BYTES = 224
_DECODED_SNAPSHOT_CACHE_CAPACITY = 16_384
_START_TRANSITION_KIND_COUNT = 3
_SESSION_START_TAG = 0
_SERVICE_START_TAG = 1
_TRANSPORT_START_TAG = 2
_MAX_ACTION_COHORT_OPERATIONS_PER_REQUEST = 256
_MAX_ACTION_COHORT_RESERVATIONS = 1_024
_MAX_ACTION_COHORT_RESERVED_KEYS = 65_536
_MAX_ACTION_COHORT_REQUEST_BYTES = 16 * 1_024 * 1_024
_MAX_ACTION_COHORT_COMMITTED_PROVENANCE = 4_096


class LifecycleLeaseConflictError(StateError):
    """An exact foreground/singleton resource is owned by another interval."""


class LifecycleClosedTransportPublicationInProgressError(StateError):
    """An exact retry is waiting for the reservation that currently owns its keys."""


class LifecycleServicePublicationInProgressError(StateError):
    """An exact service operation is waiting for a reservation that owns its keys."""


class LifecycleActionCohortInProgressError(StateError):
    """An exact action cohort is waiting for the reservation that owns its keys."""


def _semantic_hash(namespace: str, *parts: str) -> int:
    """Return a stable compact semantic lookup token.

    The retained token is 64 bits. A detected collision fails insertion rather
    than silently aliasing exact lifecycle identity.
    """

    digest = sha256()
    digest.update(namespace.encode("utf-8"))
    for part in parts:
        digest.update(b"\0")
        digest.update(part.encode("utf-8"))
    return int.from_bytes(digest.digest()[:8], "big")


def _datetime_to_microseconds(value: datetime) -> int:
    canonical = ensure_utc(value)
    delta = canonical - _EPOCH
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


def _datetime_from_microseconds(value: int) -> datetime:
    return _EPOCH + timedelta(microseconds=value)


class _SparseTemporalIndex:
    """Packed singleton temporal groups promoted only when identity is reused.

    Most lifecycle service identities and network tuples occur exactly once.
    Retaining a Python group key and a full segmented-group descriptor for each
    singleton is unnecessary: one packed digest-to-handle route plus the
    canonical start column answers the same predecessor/successor query. Groups
    promote into :class:`SegmentedTemporalIndex` on their second member, keeping
    reused and out-of-order history at ``O(log n + k)`` without charging every
    one-shot identity for that machinery.
    """

    __slots__ = (
        "_lookup_candidates_inspected",
        "_namespace",
        "_repeated",
        "_single",
        "_start_times_us",
        "_temporal",
        "_track_lookup_candidates",
    )

    def __init__(self, *, namespace: bytes, track_lookup_candidates: bool = False) -> None:
        self._namespace = namespace
        self._track_lookup_candidates = track_lookup_candidates
        self._single = PackedUniqueDigestMap(namespace)
        repeated_namespace = (namespace[:12] + b"-rep")[:16]
        self._repeated = PackedUniqueDigestMap(repeated_namespace)
        self._start_times_us = array("q")
        self._temporal: SegmentedTemporalIndex[int] = SegmentedTemporalIndex(
            track_lookup_candidates=track_lookup_candidates
        )
        self._lookup_candidates_inspected = 0

    def _ensure_handle(self, handle: int) -> None:
        missing = handle + 1 - len(self._start_times_us)
        if missing > 0:
            self._start_times_us.extend(array("q", [0]) * missing)

    def add(self, handle: int, group: int, event_time: datetime) -> None:
        """Add one current handle, promoting a reused group exactly once."""

        self._ensure_handle(handle)
        self._start_times_us[handle] = _datetime_to_microseconds(event_time)
        if self._repeated.get_digest(group) is not None:
            self._temporal.add(handle, group, event_time)
            return
        prior_handle = self._single.get_digest(group)
        if prior_handle is None:
            self._single.set_digest(group, handle)
            return
        if prior_handle == handle:
            raise StateError("Lifecycle temporal handle is already registered")
        self._single.pop_digest(group)
        self._repeated.set_digest(group, 0)
        self._temporal.add(
            prior_handle,
            group,
            _datetime_from_microseconds(self._start_times_us[prior_handle]),
        )
        self._temporal.add(handle, group, event_time)

    def latest_at_or_before(self, group: int, event_time: datetime) -> int | None:
        """Return one exact predecessor without scanning a history bucket."""

        if self._repeated.get_digest(group) is not None:
            return self._temporal.latest_at_or_before(group, event_time)
        handle = self._single.get_digest(group)
        if handle is None:
            return None
        self._lookup_candidates_inspected += 1
        return (
            handle
            if self._start_times_us[handle] <= _datetime_to_microseconds(event_time)
            else None
        )

    def iter_after(
        self,
        group: int,
        event_time: datetime,
        *,
        limit: int | None = None,
    ) -> Iterator[int]:
        """Iterate exact successors, bounded by ``limit`` when supplied."""

        if limit is not None and limit <= 0:
            return iter(())
        if self._repeated.get_digest(group) is not None:
            return self._temporal.iter_after(group, event_time, limit=limit)
        handle = self._single.get_digest(group)
        if handle is None:
            return iter(())
        self._lookup_candidates_inspected += 1
        if self._start_times_us[handle] <= _datetime_to_microseconds(event_time):
            return iter(())
        return iter((handle,))

    def remove(self, handle: int, group: int) -> None:
        """Remove one exact handle from its current singleton or reused group."""

        if self._repeated.get_digest(group) is not None:
            self._temporal.remove(handle)
            if self._temporal.latest_at_or_before(group, datetime.max.replace(tzinfo=UTC)) is None:
                self._repeated.pop_digest(group)
        else:
            retained = self._single.get_digest(group)
            if retained != handle:
                raise StateError("Lifecycle sparse temporal route changed before removal")
            self._single.pop_digest(group)
        if 0 <= handle < len(self._start_times_us):
            self._start_times_us[handle] = 0
        if len(self) == 0:
            self._start_times_us = array("q")

    def compact(self, *, max_groups: int = 8) -> int:
        """Advance bounded compaction for promoted histories."""

        return self._temporal.compact(max_groups=max_groups)

    def clear(self) -> None:
        """Release empty backing while preserving cumulative candidate telemetry."""

        candidates = self.metrics().lookup_candidates_inspected
        self._single = PackedUniqueDigestMap(self._namespace)
        repeated_namespace = (self._namespace[:12] + b"-rep")[:16]
        self._repeated = PackedUniqueDigestMap(repeated_namespace)
        self._start_times_us = array("q")
        self._temporal = SegmentedTemporalIndex(
            track_lookup_candidates=self._track_lookup_candidates
        )
        self._lookup_candidates_inspected = candidates

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return cached structural metrics without scanning temporal groups."""

        single = self._single.metrics(estimate_bytes=estimate_bytes)
        repeated = self._repeated.metrics(estimate_bytes=estimate_bytes)
        temporal = self._temporal.metrics(estimate_bytes=estimate_bytes)
        estimated = single.estimated_bytes + repeated.estimated_bytes + temporal.estimated_bytes
        if estimate_bytes:
            estimated += getsizeof(self) + getsizeof(self._start_times_us)
        return IndexMetrics(
            live_entries=single.live_entries + temporal.live_entries,
            backing_entries=single.backing_entries + temporal.backing_entries,
            stale_entries=temporal.stale_entries,
            allocated_slots=max(len(self._start_times_us), temporal.allocated_slots),
            secondary_buckets=single.live_entries + temporal.secondary_buckets,
            max_bucket_size=max(1 if single.live_entries else 0, temporal.max_bucket_size),
            high_water_mark=max(single.high_water_mark, temporal.high_water_mark),
            lookup_candidates_inspected=(
                self._lookup_candidates_inspected + temporal.lookup_candidates_inspected
            ),
            compaction_work=temporal.compaction_work,
            compaction_seconds=temporal.compaction_seconds,
            compaction_pending=temporal.compaction_pending,
            estimated_bytes=estimated,
            primary_map_entries=single.primary_map_entries + repeated.primary_map_entries,
            primary_map_backing_bytes=(
                single.primary_map_backing_bytes + repeated.primary_map_backing_bytes
            ),
        )

    def __len__(self) -> int:
        return len(self._single) + len(self._temporal)


def _transition_digest_value(transition: LifecycleTransition) -> int:
    payload = "\x1f".join(
        (
            transition.transition_id,
            transition.subject.kind,
            transition.subject.object_id,
            transition.kind,
            transition.canonical_time.isoformat(),
            transition.action_id,
            str(transition.transition_ordinal),
            transition.reason,
        )
    )
    return int.from_bytes(sha256(payload.encode("utf-8")).digest())


@dataclass(frozen=True, slots=True)
class _DecodedSessionRow:
    hostname: str
    object_id: str
    logon_id: str
    principal: str
    session_kind: str
    logon_guid: str
    transition_id: str
    action_id: str
    started_at: datetime
    session_id: int
    transition_ordinal: int


@dataclass(slots=True)
class _PackedSessionSnapshotCache:
    """Private lazy materialization cells for one immutable packed view."""

    decoded: _DecodedSessionRow | None = None
    identity: SessionLifecycleIdentity | None = None
    materialized: SessionLifecycleSnapshot | None = None


class _PackedSessionSnapshot:
    """Immutable lazy public view over one captured packed start-only row."""

    __slots__ = ("_cache", "_ledger_floor", "_row")

    def __init__(self, row: bytes, ledger_floor: datetime | None) -> None:
        object.__setattr__(self, "_row", row)
        object.__setattr__(self, "_ledger_floor", ledger_floor)
        object.__setattr__(self, "_cache", None)

    def __setattr__(self, name: str, value: object) -> None:
        raise FrozenInstanceError(f"cannot assign to field {name!r}")

    def _cache_value(self) -> _PackedSessionSnapshotCache:
        cache = self._cache
        if cache is None:
            cache = _PackedSessionSnapshotCache()
            object.__setattr__(self, "_cache", cache)
        return cache

    def _decoded(self) -> _DecodedSessionRow:
        cache = self._cache_value()
        if cache.decoded is None:
            cache.decoded = _decode_session_row(self._row)
        return cache.decoded

    def _identity(self) -> SessionLifecycleIdentity:
        cache = self._cache_value()
        if cache.identity is None:
            row = self._decoded()
            cache.identity = SessionLifecycleIdentity(
                hostname=row.hostname,
                object_id=row.object_id,
                logon_id=row.logon_id,
                principal=row.principal,
                session_kind=row.session_kind,
                started_at=row.started_at,
                session_id=row.session_id,
                logon_guid=row.logon_guid,
            )
        return cache.identity

    def _materialized(self) -> SessionLifecycleSnapshot:
        cache = self._cache_value()
        cached = cache.materialized
        if cached is not None:
            return cached
        row = self._decoded()
        identity = self._identity()
        transition = LifecycleTransition(
            transition_id=row.transition_id,
            subject=LifecycleEntityRef("session", row.object_id),
            kind="started",
            canonical_time=row.started_at,
            action_id=row.action_id,
            transition_ordinal=row.transition_ordinal,
        )
        transitions = (
            (transition,)
            if self._ledger_floor is None or transition.canonical_time > self._ledger_floor
            else ()
        )
        snapshot = SessionLifecycleSnapshot(
            identity=identity,
            transitions=transitions,
            holds=(),
            close_barrier=None,
            closure_ticket=None,
            closed_at=None,
            transition_count=1,
            compacted_transition_count=1 - len(transitions),
            transition_ledger_digest=f"{_transition_digest_value(transition):064x}",
            hold_count=0,
            compacted_hold_count=0,
            hold_ledger_digest=f"{0:064x}",
            latest_dependent_at=None,
            latest_hold_until=None,
        )
        cache.materialized = snapshot
        return snapshot

    @property
    def identity(self) -> SessionLifecycleIdentity:
        """Materialize the immutable identity only when the caller consumes it."""

        return self._identity()

    @property
    def transitions(self) -> tuple[LifecycleTransition, ...]:
        return self._materialized().transitions

    @property
    def holds(self) -> tuple[LifecycleHold, ...]:
        return ()

    @property
    def close_barrier(self) -> LifecycleCloseBarrier | None:
        return None

    @property
    def closure_ticket(self) -> LifecycleClosureTicket | None:
        return None

    @property
    def closed_at(self) -> datetime | None:
        return None

    @property
    def transition_count(self) -> int:
        return 1

    @property
    def compacted_transition_count(self) -> int:
        return 1 - len(self.transitions)

    @property
    def transition_ledger_digest(self) -> str:
        return self._materialized().transition_ledger_digest

    @property
    def hold_count(self) -> int:
        return 0

    @property
    def compacted_hold_count(self) -> int:
        return 0

    @property
    def hold_ledger_digest(self) -> str:
        return f"{0:064x}"

    @property
    def latest_dependent_at(self) -> datetime | None:
        return None

    @property
    def latest_hold_until(self) -> datetime | None:
        return None

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _PackedSessionSnapshot):
            return self._row == other._row and self._ledger_floor == other._ledger_floor
        return self._materialized() == other

    def __hash__(self) -> int:
        return hash(self._materialized())

    def __repr__(self) -> str:
        return repr(self._materialized())


def _pack_session_row(
    identity: SessionLifecycleIdentity,
    transition: LifecycleTransition,
) -> bytes:
    text = tuple(
        value.encode("utf-8")
        for value in (
            identity.hostname,
            identity.object_id,
            identity.logon_id,
            identity.principal,
            identity.session_kind,
            identity.logon_guid,
            transition.transition_id,
            transition.action_id,
        )
    )
    lengths = tuple(len(value) for value in text)
    if any(length >= 1 << 16 for length in lengths):
        raise ValueError("Lifecycle session text fields must be shorter than 65,536 bytes")
    header = _SESSION_ROW_HEADER.pack(
        _datetime_to_microseconds(identity.started_at),
        identity.session_id,
        transition.transition_ordinal,
        *lengths,
    )
    return header + b"".join(text)


def _decode_session_row(row: bytes) -> _DecodedSessionRow:
    values = _SESSION_ROW_HEADER.unpack_from(row)
    started_us, session_id, transition_ordinal = values[:3]
    lengths = values[3 : 3 + _SESSION_TEXT_FIELD_COUNT]
    offset = _SESSION_ROW_HEADER.size
    decoded: list[str] = []
    for length in lengths:
        decoded.append(row[offset : offset + length].decode("utf-8"))
        offset += length
    return _DecodedSessionRow(
        hostname=decoded[0],
        object_id=decoded[1],
        logon_id=decoded[2],
        principal=decoded[3],
        session_kind=decoded[4],
        logon_guid=decoded[5],
        transition_id=decoded[6],
        action_id=decoded[7],
        started_at=_datetime_from_microseconds(started_us),
        session_id=session_id,
        transition_ordinal=transition_ordinal,
    )


def _session_hostname_from_row(row: bytes) -> str:
    values = _SESSION_ROW_HEADER.unpack_from(row)
    hostname_length = values[3]
    offset = _SESSION_ROW_HEADER.size
    return row[offset : offset + hostname_length].decode("utf-8")


def _session_started_at_from_row(row: bytes) -> datetime:
    started_us = _SESSION_ROW_HEADER.unpack_from(row)[0]
    return _datetime_from_microseconds(started_us)


def _pack_text_fields(
    header: bytes,
    text: tuple[str, ...],
    *,
    label: str,
) -> bytes:
    encoded = tuple(value.encode("utf-8") for value in text)
    if any(len(value) >= 1 << 16 for value in encoded):
        raise ValueError(f"Lifecycle {label} text fields must be shorter than 65,536 bytes")
    return header + b"".join(encoded)


def _decode_text_fields(
    row: bytes | memoryview,
    offset: int,
    lengths: tuple[int, ...],
) -> tuple[str, ...]:
    decoded: list[str] = []
    for length in lengths:
        value = row[offset : offset + length]
        decoded.append(bytes(value).decode("utf-8"))
        offset += length
    return tuple(decoded)


@dataclass(frozen=True, slots=True)
class _DecodedServiceRow:
    logical_identity: LogicalServiceIdentity
    identity: ServiceInstanceLifecycleIdentity
    transition_id: str
    action_id: str
    transition_ordinal: int


def _pack_service_row(
    logical: LogicalServiceIdentity,
    identity: ServiceInstanceLifecycleIdentity,
    transition: LifecycleTransition,
) -> bytes:
    deployment = logical.deployment_identity
    if isinstance(deployment, CompiledServiceDeploymentIdentity):
        deployment_fields = (
            deployment.identity_kind,
            deployment.hostname,
            deployment.service_id,
            "",
        )
    elif isinstance(deployment, RuntimeServiceDeploymentIdentity):
        deployment_fields = (
            deployment.identity_kind,
            deployment.hostname,
            deployment.canonical_name,
            deployment.action_id,
        )
    else:
        deployment_fields = ("", "", "", "")
    text = (
        identity.hostname,
        identity.object_id,
        identity.logical_service_id,
        logical.canonical_name,
        logical.service_kind,
        logical.deployment_service_id,
        identity.boot_id,
        identity.instance_id,
        identity.parent_service_object_id,
        transition.transition_id,
        transition.action_id,
        *deployment_fields,
    )
    lengths = tuple(len(value.encode("utf-8")) for value in text)
    if any(length >= 1 << 16 for length in lengths):
        raise ValueError("Lifecycle service text fields must be shorter than 65,536 bytes")
    header = _SERVICE_ROW_HEADER.pack(
        _datetime_to_microseconds(identity.started_at),
        transition.transition_ordinal,
        *lengths,
    )
    return _pack_text_fields(header, text, label="service")


def _decode_service_row(row: bytes | memoryview) -> _DecodedServiceRow:
    values = _SERVICE_ROW_HEADER.unpack_from(row)
    started_us, transition_ordinal = values[:2]
    lengths = tuple(values[2 : 2 + _SERVICE_TEXT_FIELD_COUNT])
    text = _decode_text_fields(row, _SERVICE_ROW_HEADER.size, lengths)
    deployment_kind = text[11]
    if deployment_kind == "compiled_service":
        deployment_identity = CompiledServiceDeploymentIdentity(
            hostname=text[12],
            service_id=text[13],
        )
    elif deployment_kind == "runtime_created_service":
        deployment_identity = RuntimeServiceDeploymentIdentity(
            hostname=text[12],
            canonical_name=text[13],
            action_id=text[14],
        )
    elif deployment_kind:
        raise StateError(f"Unsupported packed service deployment kind {deployment_kind!r}")
    else:
        deployment_identity = None
    logical = LogicalServiceIdentity(
        hostname=text[0],
        logical_service_id=text[2],
        canonical_name=text[3],
        service_kind=text[4],  # type: ignore[arg-type]
        deployment_service_id=text[5],
        deployment_identity=deployment_identity,
    )
    identity = ServiceInstanceLifecycleIdentity(
        hostname=text[0],
        object_id=text[1],
        logical_service_id=text[2],
        boot_id=text[6],
        instance_id=text[7],
        started_at=_datetime_from_microseconds(started_us),
        parent_service_object_id=text[8],
    )
    return _DecodedServiceRow(
        logical_identity=logical,
        identity=identity,
        transition_id=text[9],
        action_id=text[10],
        transition_ordinal=transition_ordinal,
    )


@dataclass(frozen=True, slots=True)
class _DecodedTransportRow:
    identity: TransportLifecycleIdentity
    transition_id: str
    action_id: str
    transition_ordinal: int


def _pack_transport_row(
    identity: TransportLifecycleIdentity,
    transition: LifecycleTransition,
) -> bytes:
    text = (
        identity.hostname,
        identity.object_id,
        identity.transport_id,
        identity.src_hostname,
        identity.dst_hostname,
        identity.network_tuple.src_ip,
        identity.network_tuple.dst_ip,
        identity.network_tuple.protocol,
        identity.zeek_uid,
        identity.conn_id,
        transition.transition_id,
        transition.action_id,
    )
    lengths = tuple(len(value.encode("utf-8")) for value in text)
    if any(length >= 1 << 16 for length in lengths):
        raise ValueError("Lifecycle transport text fields must be shorter than 65,536 bytes")
    header = _TRANSPORT_ROW_HEADER.pack(
        _datetime_to_microseconds(identity.opened_at),
        _datetime_to_microseconds(identity.close_deadline),
        identity.network_tuple.src_port,
        identity.network_tuple.dst_port,
        transition.transition_ordinal,
        *lengths,
    )
    return _pack_text_fields(header, text, label="transport")


def _decode_transport_row(row: bytes | memoryview) -> _DecodedTransportRow:
    values = _TRANSPORT_ROW_HEADER.unpack_from(row)
    opened_us, deadline_us, src_port, dst_port, transition_ordinal = values[:5]
    lengths = tuple(values[5 : 5 + _TRANSPORT_TEXT_FIELD_COUNT])
    text = _decode_text_fields(row, _TRANSPORT_ROW_HEADER.size, lengths)
    identity = TransportLifecycleIdentity(
        hostname=text[0],
        object_id=text[1],
        transport_id=text[2],
        src_hostname=text[3],
        dst_hostname=text[4],
        network_tuple=NetworkTuple(
            src_ip=text[5],
            src_port=src_port,
            dst_ip=text[6],
            dst_port=dst_port,
            protocol=text[7],
        ),
        opened_at=_datetime_from_microseconds(opened_us),
        close_deadline=_datetime_from_microseconds(deadline_us),
        zeek_uid=text[8],
        conn_id=text[9],
    )
    return _DecodedTransportRow(
        identity=identity,
        transition_id=text[10],
        action_id=text[11],
        transition_ordinal=transition_ordinal,
    )


@dataclass(slots=True)
class _LifecycleState:
    """Mutable append state kept behind an immutable indexed identity."""

    transitions: LifecycleTransition | list[LifecycleTransition] | None = None
    holds: LifecycleHold | list[LifecycleHold] | None = None
    close_barrier: LifecycleCloseBarrier | None = None
    closure_ticket: LifecycleClosureTicket | None = None
    closed_at: datetime | None = None
    transition_count: int = 0
    hold_count: int = 0
    transition_digest: int = 0
    hold_digest: int = 0
    latest_dependent_at: datetime | None = None
    latest_hold_until: datetime | None = None
    commits: dict[tuple[str, int], str] | None = None
    commit_deletions: int = 0
    durable_transition_ids: str | tuple[str, ...] | None = None


class _StartedLifecycleState:
    """Inline minimal state for the overwhelmingly common start-only entity."""

    __slots__ = ("transition_digest", "transitions")

    holds = None
    close_barrier = None
    closure_ticket = None
    closed_at = None
    transition_count = 1
    hold_count = 0
    hold_digest = 0
    latest_dependent_at = None
    latest_hold_until = None
    commits = None
    commit_deletions = 0

    def __init__(self, transition: LifecycleTransition, transition_digest: int) -> None:
        self.transitions = transition
        self.transition_digest = transition_digest

    @property
    def durable_transition_ids(self) -> str:
        """Return the one start transition retained with this entity."""

        return self.transitions.transition_id


_LifecycleStateRecord = _LifecycleState | _StartedLifecycleState


@dataclass(slots=True)
class _DependentClosureAggregate:
    """Constant-time descendant closure authority summary."""

    unclosed: int = 0
    latest_closed_at: datetime | None = None

    def register(self) -> None:
        """Record one newly live child or session member."""

        self.unclosed += 1

    def close(self, closed_at: datetime) -> None:
        """Record one child's resolved canonical close."""

        if self.unclosed <= 0:
            raise StateError("Lifecycle dependent closure aggregate underflow")
        self.unclosed -= 1
        if self.latest_closed_at is None or closed_at > self.latest_closed_at:
            self.latest_closed_at = closed_at

    def blocks_close_at(self, canonical_time: datetime) -> bool:
        """Return whether any descendant remains active at canonical time."""

        return self.unclosed > 0 or (
            self.latest_closed_at is not None and self.latest_closed_at > canonical_time
        )


@dataclass(frozen=True, slots=True)
class _LiveChildBinding:
    """Exact compact route from one parent to one still-live child process."""

    parent_object_id: str
    child_object_id: str


@dataclass(frozen=True, slots=True)
class _LiveSessionMemberBinding:
    """Exact compact route from one session to one still-live member process."""

    session_object_id: str
    process_object_id: str


@dataclass(frozen=True, slots=True)
class _LiveTransportBinding:
    """Session-side exact route to one still-live cross-host transport binding."""

    binding_id: str
    transport_object_id: str
    session_object_id: str


@dataclass(frozen=True, slots=True)
class _ForegroundLeaseEntry:
    """One canonical foreground lease plus its latest deterministic commit."""

    lease: LifecycleForegroundLease
    commit_time: datetime
    commit_action_id: str
    commit_ordinal: int

    @property
    def resource_key(self) -> LifecycleForegroundLeaseKey:
        return self.lease.resource_key

    @property
    def process_object_id(self) -> str:
        return self.lease.process_object_id

    @property
    def session_object_id(self) -> str:
        return self.lease.session_object_id

    @property
    def commit_key(self) -> tuple[datetime, str, int]:
        return (self.commit_time, self.commit_action_id, self.commit_ordinal)


@dataclass(frozen=True, slots=True)
class _SingletonLeaseEntry:
    """One canonical singleton interval plus its latest deterministic commit."""

    lease: LifecycleSingletonLease
    commit_time: datetime
    commit_action_id: str
    commit_ordinal: int

    @property
    def resource_key(self) -> LifecycleSingletonLeaseKey:
        return self.lease.resource_key

    @property
    def process_object_id(self) -> str:
        return self.lease.process_object_id

    @property
    def session_object_id(self) -> str:
        return self.lease.session_object_id

    @property
    def commit_key(self) -> tuple[datetime, str, int]:
        return (self.commit_time, self.commit_action_id, self.commit_ordinal)


class _IndexedLeaseDeadlineHeap:
    """Exact mutable max-heap for one subject's compact lease handles.

    Unlike a lazy versioned heap, removal and renewal update a token's exact
    heap position in O(log n).  A close therefore reads the maximum deadline
    in O(1) without ever repairing an unbounded stale prefix.
    """

    def __init__(self) -> None:
        self._tokens = array("Q")
        self._deadlines_us = array("q")
        self._positions: dict[int, int] = {}

    def __len__(self) -> int:
        return len(self._tokens)

    @staticmethod
    def _higher(deadline_us: int, token: int, other_deadline_us: int, other_token: int) -> bool:
        return (deadline_us, -token) > (other_deadline_us, -other_token)

    def _higher_at(self, position: int, other: int) -> bool:
        return self._higher(
            self._deadlines_us[position],
            self._tokens[position],
            self._deadlines_us[other],
            self._tokens[other],
        )

    def _swap(self, left: int, right: int) -> None:
        left_token = self._tokens[left]
        right_token = self._tokens[right]
        self._tokens[left], self._tokens[right] = right_token, left_token
        self._deadlines_us[left], self._deadlines_us[right] = (
            self._deadlines_us[right],
            self._deadlines_us[left],
        )
        self._positions[left_token] = right
        self._positions[right_token] = left

    def _sift_up(self, position: int) -> None:
        while position:
            parent = (position - 1) // 2
            if not self._higher_at(position, parent):
                return
            self._swap(position, parent)
            position = parent

    def _sift_down(self, position: int) -> None:
        size = len(self._tokens)
        while True:
            left = position * 2 + 1
            if left >= size:
                return
            right = left + 1
            higher = right if right < size and self._higher_at(right, left) else left
            if not self._higher_at(higher, position):
                return
            self._swap(position, higher)
            position = higher

    def set(self, token: int, deadline: datetime) -> bool:
        """Insert/update one compact token and return whether it was newly bound."""

        deadline_us = _datetime_to_microseconds(deadline)
        position = self._positions.get(token)
        if position is None:
            position = len(self._tokens)
            self._positions[token] = position
            self._tokens.append(token)
            self._deadlines_us.append(deadline_us)
            self._sift_up(position)
            return True
        prior = self._deadlines_us[position]
        self._deadlines_us[position] = deadline_us
        if deadline_us > prior:
            self._sift_up(position)
        elif deadline_us < prior:
            self._sift_down(position)
        return False

    def remove(self, token: int) -> bool:
        """Remove one exact compact token in O(log n)."""

        position = self._positions.pop(token, None)
        if position is None:
            return False
        last = len(self._tokens) - 1
        if position != last:
            last_token = self._tokens[last]
            self._tokens[position] = last_token
            self._deadlines_us[position] = self._deadlines_us[last]
            self._positions[last_token] = position
        self._tokens.pop()
        self._deadlines_us.pop()
        if position < len(self._tokens):
            parent = (position - 1) // 2 if position else None
            if parent is not None and self._higher_at(position, parent):
                self._sift_up(position)
            else:
                self._sift_down(position)
        return True

    def latest(self) -> datetime | None:
        """Return the exact maximum deadline without inspecting lease history."""

        return (
            None if not self._deadlines_us else _datetime_from_microseconds(self._deadlines_us[0])
        )

    def estimated_bytes(self) -> int:
        """Return shallow compact-array/map backing bytes."""

        return sum(
            getsizeof(value) for value in (self, self._tokens, self._deadlines_us, self._positions)
        )


class _HostCommitLanes:
    """Lazy bounded stable hash lanes with no per-host retained keys."""

    def __init__(self, *, shard_count: int = _DEFAULT_SHARD_COUNT) -> None:
        if shard_count <= 0:
            raise ValueError("Lifecycle host shard_count must be positive")
        self._shard_count = shard_count
        self._lanes: dict[int, RLock] = {}
        self._map_lock = Lock()

    def _shard_id(self, hostname: str) -> int:
        if self._shard_count == 1:
            return 0
        digest = sha256(f"lifecycle-host\0{hostname}".encode()).digest()
        return int.from_bytes(digest[:8], "big") % self._shard_count

    def lane(self, hostname: str) -> RLock:
        """Return one stable lane without holding the map lock while waiting."""

        shard_id = self._shard_id(hostname)
        with self._map_lock:
            lane = self._lanes.get(shard_id)
            if lane is None:
                lane = RLock()
                self._lanes[shard_id] = lane
            return lane

    def existing_lane(self, hostname: str) -> RLock | None:
        """Return an existing lane without growing state for a miss-only query."""

        with self._map_lock:
            return self._lanes.get(self._shard_id(hostname))

    def __len__(self) -> int:
        with self._map_lock:
            return len(self._lanes)


class _MutationGate:
    """Admit disjoint shard work concurrently and serialize watermarks."""

    def __init__(self) -> None:
        self._condition = Condition(Lock())
        self._readers = 0
        self._writer = False
        self._waiting_writers = 0

    @contextmanager
    def mutation(self) -> Iterator[None]:
        """Enter the shared mutation lane."""

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
        """Enter the exclusive watermark lane after active mutations finish."""

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


@dataclass(frozen=True, slots=True)
class _ProcessEntry:
    """Immutable indexed process identity with separately owned append state."""

    identity: ProcessLifecycleIdentity
    token: ProcessTokenIdentity
    membership: LifecycleMembership
    state: _LifecycleStateRecord = field(compare=False, repr=False)

    @property
    def transitions(self) -> tuple[LifecycleTransition, ...]:
        """Return private append-only transitions."""

        details = self.state.transitions
        if details is None:
            return ()
        if isinstance(details, list):
            return tuple(details)
        return (details,)

    @property
    def holds(self) -> tuple[LifecycleHold, ...]:
        """Return private append-only holds."""

        details = self.state.holds
        if details is None:
            return ()
        if isinstance(details, list):
            return tuple(details)
        return (details,)

    @property
    def close_barrier(self) -> LifecycleCloseBarrier | None:
        """Return the immutable close barrier, when accepted."""

        return self.state.close_barrier

    @property
    def closure_ticket(self) -> LifecycleClosureTicket | None:
        """Return the resolved closure ticket, when accepted."""

        return self.state.closure_ticket

    @property
    def closed_at(self) -> datetime | None:
        """Return canonical closure time, when closed."""

        return self.state.closed_at


@dataclass(slots=True)
class _PreparedSessionPartitionStart:
    """Validated session start retained while its partition locks are held."""

    identity: SessionLifecycleIdentity
    transition: LifecycleTransition
    existing: _SessionEntry | None
    snapshot: SessionLifecycleSnapshotView
    committed: bool = False
    handle: int = -1


@dataclass(slots=True)
class _PreparedProcessPartitionStart:
    """Validated process start retained while its partition locks are held."""

    entry: _ProcessEntry
    transition: LifecycleTransition
    existing: _ProcessEntry | None
    snapshot: ProcessLifecycleSnapshot
    committed: bool = False


@dataclass(slots=True)
class _PreparedServicePartitionStart:
    """Validated service start retained while its partition locks are held."""

    logical_identity: LogicalServiceIdentity
    identity: ServiceInstanceLifecycleIdentity
    transition: LifecycleTransition
    existing: _ServiceEntry | None
    snapshot: ServiceInstanceLifecycleSnapshot
    packed_row: bytes | None
    committed: bool = False


@dataclass(slots=True)
class _PreparedTransportPartitionStart:
    """Validated transport start retained while its partition locks are held."""

    identity: TransportLifecycleIdentity
    transition: LifecycleTransition
    existing: _TransportEntry | None
    snapshot: TransportLifecycleSnapshot
    packed_row: bytes | None
    object_route_digest: int
    committed: bool = False


@dataclass(slots=True)
class _PreparedServiceProcessBinding:
    """Validated service/process relation whose commit performs primitive writes."""

    identity: ServiceProcessBindingIdentity
    existing: ServiceProcessBindingSnapshot | None = None
    committed: bool = False


class _ServiceEntry:
    """Ephemeral immutable view over one packed service-instance row."""

    __slots__ = (
        "_decoded",
        "_generation",
        "_handle",
        "_start_state",
        "_start_transition_value",
        "_store",
    )

    def __init__(self, store: _ServiceIndex, handle: int, generation: int) -> None:
        self._store = store
        self._handle = handle
        self._generation = generation
        self._decoded: _DecodedServiceRow | None = None
        self._start_state: _StartedLifecycleState | None = None
        self._start_transition_value: LifecycleTransition | None = None

    @property
    def handle(self) -> int:
        return self._handle

    @property
    def generation(self) -> int:
        return self._generation

    def _decoded_row(self) -> _DecodedServiceRow:
        if self._decoded is None:
            self._decoded = _decode_service_row(self._store.row(self._handle, self._generation))
        return self._decoded

    @property
    def logical_identity(self) -> LogicalServiceIdentity:
        return self._decoded_row().logical_identity

    @property
    def identity(self) -> ServiceInstanceLifecycleIdentity:
        return self._decoded_row().identity

    @property
    def state(self) -> _LifecycleStateRecord:
        promoted = self._store.promoted_state(self._handle, self._generation)
        if promoted is not None:
            return promoted
        if self._start_state is None:
            transition = self._start_transition()
            self._start_state = _StartedLifecycleState(
                transition,
                _transition_digest_value(transition),
            )
        return self._start_state

    def promote_state(self) -> _LifecycleState:
        return self._store.promote(self)

    def _start_transition(self) -> LifecycleTransition:
        if self._start_transition_value is None:
            row = self._decoded_row()
            self._start_transition_value = LifecycleTransition(
                transition_id=row.transition_id,
                subject=LifecycleEntityRef("service", row.identity.object_id),
                kind="started",
                canonical_time=row.identity.started_at,
                action_id=row.action_id,
                transition_ordinal=row.transition_ordinal,
            )
        return self._start_transition_value

    @property
    def transitions(self) -> tuple[LifecycleTransition, ...]:
        details = self.state.transitions
        if details is None:
            return ()
        if isinstance(details, list):
            return tuple(details)
        return (details,)

    @property
    def holds(self) -> tuple[LifecycleHold, ...]:
        details = self.state.holds
        if details is None:
            return ()
        if isinstance(details, list):
            return tuple(details)
        return (details,)

    @property
    def close_barrier(self) -> LifecycleCloseBarrier | None:
        return self.state.close_barrier

    @property
    def closure_ticket(self) -> LifecycleClosureTicket | None:
        return self.state.closure_ticket

    @property
    def closed_at(self) -> datetime | None:
        return self.state.closed_at


class _TransportEntry:
    """Ephemeral immutable view over one packed canonical transport row."""

    __slots__ = (
        "_decoded",
        "_generation",
        "_handle",
        "_start_state",
        "_start_transition_value",
        "_store",
    )

    def __init__(self, store: _TransportIndex, handle: int, generation: int) -> None:
        self._store = store
        self._handle = handle
        self._generation = generation
        self._decoded: _DecodedTransportRow | None = None
        self._start_state: _StartedLifecycleState | None = None
        self._start_transition_value: LifecycleTransition | None = None

    @property
    def handle(self) -> int:
        return self._handle

    @property
    def generation(self) -> int:
        return self._generation

    def _decoded_row(self) -> _DecodedTransportRow:
        if self._decoded is None:
            self._decoded = _decode_transport_row(self._store.row(self._handle, self._generation))
        return self._decoded

    @property
    def identity(self) -> TransportLifecycleIdentity:
        return self._decoded_row().identity

    @property
    def state(self) -> _LifecycleStateRecord:
        promoted = self._store.promoted_state(self._handle, self._generation)
        if promoted is not None:
            return promoted
        if self._start_state is None:
            transition = self._start_transition()
            self._start_state = _StartedLifecycleState(
                transition,
                _transition_digest_value(transition),
            )
        return self._start_state

    def promote_state(self) -> _LifecycleState:
        return self._store.promote(self)

    def _start_transition(self) -> LifecycleTransition:
        if self._start_transition_value is None:
            row = self._decoded_row()
            self._start_transition_value = LifecycleTransition(
                transition_id=row.transition_id,
                subject=LifecycleEntityRef("transport", row.identity.object_id),
                kind="started",
                canonical_time=row.identity.opened_at,
                action_id=row.action_id,
                transition_ordinal=row.transition_ordinal,
            )
        return self._start_transition_value

    @property
    def active_binding_count(self) -> int:
        return self._store.active_binding_count(self._handle, self._generation)

    @active_binding_count.setter
    def active_binding_count(self, value: int) -> None:
        self._store.set_active_binding_count(self._handle, self._generation, value)

    @property
    def transitions(self) -> tuple[LifecycleTransition, ...]:
        details = self.state.transitions
        if details is None:
            return ()
        if isinstance(details, list):
            return tuple(details)
        return (details,)

    @property
    def holds(self) -> tuple[LifecycleHold, ...]:
        details = self.state.holds
        if details is None:
            return ()
        if isinstance(details, list):
            return tuple(details)
        return (details,)

    @property
    def close_barrier(self) -> LifecycleCloseBarrier | None:
        return self.state.close_barrier

    @property
    def closure_ticket(self) -> LifecycleClosureTicket | None:
        return self.state.closure_ticket

    @property
    def closed_at(self) -> datetime | None:
        return self.state.closed_at


@dataclass(slots=True)
class _ServiceProcessBindingEntry:
    """Mutable closure state behind one immutable service/process relation."""

    identity: ServiceProcessBindingIdentity
    closed_at: datetime | None = None
    close_action_id: str = ""
    close_transition_ordinal: int = 0


@dataclass(slots=True)
class _TransportSessionBindingEntry:
    """Mutable closure state behind one immutable transport/session relation."""

    identity: TransportSessionBindingIdentity
    closed_at: datetime | None = None
    close_action_id: str = ""
    close_transition_ordinal: int = 0


class _PackedSessionStartState:
    """On-demand view of one packed start-only session state."""

    __slots__ = ("_entry",)

    holds = None
    close_barrier = None
    closure_ticket = None
    closed_at = None
    transition_count = 1
    hold_count = 0
    hold_digest = 0
    latest_dependent_at = None
    latest_hold_until = None
    commits = None
    commit_deletions = 0

    def __init__(self, entry: _SessionEntry) -> None:
        self._entry = entry

    @property
    def transitions(self) -> LifecycleTransition:
        return self._entry._start_transition()

    @property
    def transition_digest(self) -> int:
        return _transition_digest_value(self._entry._start_transition())

    @property
    def durable_transition_ids(self) -> str:
        return self._entry._decoded_row().transition_id


class _SessionEntry:
    """Ephemeral immutable view over one packed session column handle."""

    __slots__ = (
        "_decoded",
        "_generation",
        "_handle",
        "_start_state",
        "_start_transition_value",
        "_store",
    )

    def __init__(self, store: _SessionIndex, handle: int, generation: int) -> None:
        self._store = store
        self._handle = handle
        self._generation = generation
        self._decoded: _DecodedSessionRow | None = None
        self._start_state: _PackedSessionStartState | None = None
        self._start_transition_value: LifecycleTransition | None = None

    @property
    def handle(self) -> int:
        return self._handle

    @property
    def generation(self) -> int:
        return self._generation

    def _decoded_row(self) -> _DecodedSessionRow:
        if self._decoded is None:
            self._decoded = _decode_session_row(self._store.row(self._handle, self._generation))
        return self._decoded

    @property
    def identity(self) -> SessionLifecycleIdentity:
        row = self._decoded_row()
        return SessionLifecycleIdentity(
            hostname=row.hostname,
            object_id=row.object_id,
            logon_id=row.logon_id,
            principal=row.principal,
            session_kind=row.session_kind,
            started_at=row.started_at,
            session_id=row.session_id,
            logon_guid=row.logon_guid,
        )

    @property
    def state(self) -> _LifecycleState | _PackedSessionStartState:
        promoted = self._store.promoted_state(self._handle, self._generation)
        if promoted is not None:
            return promoted
        if self._start_state is None:
            self._start_state = _PackedSessionStartState(self)
        return self._start_state

    def promote_state(self) -> _LifecycleState:
        return self._store.promote(self)

    def _start_transition(self) -> LifecycleTransition:
        if self._start_transition_value is None:
            row = self._decoded_row()
            self._start_transition_value = LifecycleTransition(
                transition_id=row.transition_id,
                subject=LifecycleEntityRef("session", row.object_id),
                kind="started",
                canonical_time=row.started_at,
                action_id=row.action_id,
                transition_ordinal=row.transition_ordinal,
            )
        return self._start_transition_value

    @property
    def transitions(self) -> tuple[LifecycleTransition, ...]:
        """Return private append-only transitions."""

        details = self.state.transitions
        if details is None:
            return ()
        if isinstance(details, list):
            return tuple(details)
        return (details,)

    @property
    def holds(self) -> tuple[LifecycleHold, ...]:
        """Return private append-only holds."""

        details = self.state.holds
        if details is None:
            return ()
        if isinstance(details, list):
            return tuple(details)
        return (details,)

    @property
    def close_barrier(self) -> LifecycleCloseBarrier | None:
        """Return the immutable close barrier, when accepted."""

        return self.state.close_barrier

    @property
    def closure_ticket(self) -> LifecycleClosureTicket | None:
        """Return the resolved closure ticket, when accepted."""

        return self.state.closure_ticket

    @property
    def closed_at(self) -> datetime | None:
        """Return canonical closure time, when closed."""

        return self.state.closed_at


_LifecycleEntry = _ProcessEntry | _SessionEntry | _ServiceEntry | _TransportEntry


class _ProcessIndex:
    """Exact semantic process lookup backed by reusable compact handles."""

    def __init__(self) -> None:
        self._store: CompactIndexedStore[str, _ProcessEntry] = CompactIndexedStore()

    def get(self, object_id: str) -> _ProcessEntry | None:
        """Return one process by its exact object identity."""

        return self._store.get(object_id)

    def add(self, entry: _ProcessEntry) -> int:
        """Add one process identity and return its compact handle."""

        self._store[entry.identity.object_id] = entry
        return self._store.handle_for(entry.identity.object_id)

    def remove(self, object_id: str) -> _ProcessEntry | None:
        """Remove and return one retained process identity."""

        return self._store.pop(object_id, None)

    def handle_for(self, object_id: str) -> int:
        """Return the compact handle for one exact semantic identity."""

        return self._store.handle_for(object_id)

    def get_by_handle(self, handle: int) -> _ProcessEntry | None:
        """Resolve a live compact handle without exposing it publicly."""

        try:
            return self._store.get_by_handle(handle)
        except KeyError:
            return None

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return low-cost primary-index metrics."""

        return self._store.metrics(estimate_bytes=estimate_bytes)

    def compact_primary(self, *, max_slots: int = _PRIMARY_COMPACTION_PAGE) -> int:
        """Advance bounded semantic-key map rotation at a watermark."""

        return self._store.compact_primary(max_slots=max_slots)

    def __len__(self) -> int:
        return len(self._store)


class _SessionIndex:
    """Packed session rows with exact hashed semantic handles."""

    def __init__(self) -> None:
        self._handles: IncrementalExactMap[int, int] = IncrementalExactMap()
        self._rows: list[bytes | None] = []
        self._generations = array("I")
        self._active = bytearray()
        self._free_handles: list[int] = []
        self._states: IncrementalExactMap[int, _LifecycleState] = IncrementalExactMap()
        self._live_count = 0
        self._high_water_mark = 0
        self._row_backing_bytes = 0

    @staticmethod
    def _key(object_id: str) -> int:
        return _semantic_hash("lifecycle-session-object", object_id)

    def get(self, object_id: str) -> _SessionEntry | None:
        """Return one session by its exact object identity."""

        handle = self._handles.get(self._key(object_id))
        return self.get_by_handle(handle) if handle is not None else None

    def add(
        self,
        identity: SessionLifecycleIdentity,
        transition: LifecycleTransition,
    ) -> int:
        """Pack one immutable session row and return its reusable handle."""

        semantic_key = self._key(identity.object_id)
        if semantic_key in self._handles:
            existing = self.get_by_handle(self._handles[semantic_key])
            if existing is not None and existing.identity.object_id != identity.object_id:
                raise StateError("Lifecycle session semantic hash collision")
            raise StateError(f"Session lifecycle object {identity.object_id} is already registered")
        row = _pack_session_row(identity, transition)
        if self._free_handles:
            handle = self._free_handles.pop()
            self._rows[handle] = row
            self._generations[handle] += 1
            self._active[handle] = 1
        else:
            handle = len(self._rows)
            self._rows.append(row)
            self._generations.append(1)
            self._active.append(1)
        self._row_backing_bytes += getsizeof(row)
        self._handles[semantic_key] = handle
        self._live_count += 1
        self._high_water_mark = max(self._high_water_mark, self._live_count)
        return handle

    def remove(self, object_id: str) -> _SessionEntry | None:
        """Remove and return one retained session identity."""

        semantic_key = self._key(object_id)
        handle = self._handles.get(semantic_key)
        if handle is None:
            return None
        entry = self.get_by_handle(handle)
        if entry is None:
            return None
        entry._decoded_row()
        self._handles.pop(semantic_key)
        row = self._rows[handle]
        assert row is not None
        self._row_backing_bytes -= getsizeof(row)
        self._rows[handle] = None
        self._active[handle] = 0
        self._states.pop(handle, None)
        self._free_handles.append(handle)
        self._live_count -= 1
        return entry

    def handle_for(self, object_id: str) -> int:
        """Return the compact handle for one exact semantic identity."""

        handle = self._handles.get(self._key(object_id))
        if handle is None:
            raise KeyError(object_id)
        return handle

    def get_by_handle(self, handle: int) -> _SessionEntry | None:
        """Resolve a live compact handle without exposing it publicly."""

        if handle < 0 or handle >= len(self._rows) or not self._active[handle]:
            return None
        return _SessionEntry(self, handle, self._generations[handle])

    def row(self, handle: int, generation: int) -> bytes:
        """Return one current packed row or reject a reused-handle view."""

        if (
            handle < 0
            or handle >= len(self._rows)
            or not self._active[handle]
            or self._generations[handle] != generation
        ):
            raise StateError("Lifecycle session handle changed during access")
        row = self._rows[handle]
        assert row is not None
        return row

    def is_current(self, entry: _SessionEntry) -> bool:
        """Return whether an ephemeral view still names the same handle generation."""

        return (
            entry.handle < len(self._rows)
            and bool(self._active[entry.handle])
            and self._generations[entry.handle] == entry.generation
        )

    def promoted_state(self, handle: int, generation: int) -> _LifecycleState | None:
        self.row(handle, generation)
        return self._states.get(handle)

    def promote(self, entry: _SessionEntry) -> _LifecycleState:
        """Materialize mutable state only for sessions that gain later transitions."""

        existing = self.promoted_state(entry.handle, entry.generation)
        if existing is not None:
            return existing
        start = entry._start_transition()
        promoted = _LifecycleState(
            transitions=start,
            transition_count=1,
            transition_digest=_transition_digest_value(start),
            durable_transition_ids=start.transition_id,
        )
        self._states[entry.handle] = promoted
        return promoted

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return low-cost primary-index metrics."""

        handles = self._handles.metrics(estimate_bytes=estimate_bytes)
        states = self._states.metrics(estimate_bytes=estimate_bytes)
        estimated_bytes = 0
        if estimate_bytes:
            estimated_bytes = (
                handles.estimated_bytes
                + states.estimated_bytes
                + getsizeof(self)
                + getsizeof(self._rows)
                + getsizeof(self._generations)
                + getsizeof(self._active)
                + getsizeof(self._free_handles)
            )
        return IndexMetrics(
            live_entries=self._live_count,
            backing_entries=len(self._rows),
            stale_entries=len(self._free_handles),
            allocated_slots=len(self._rows),
            high_water_mark=self._high_water_mark,
            estimated_bytes=estimated_bytes,
            primary_map_entries=(handles.primary_map_entries + states.primary_map_entries),
            primary_map_backing_bytes=(
                handles.primary_map_backing_bytes + states.primary_map_backing_bytes
            ),
            primary_compaction_pending=(
                handles.primary_compaction_pending or states.primary_compaction_pending
            ),
            primary_compaction_rotations=(
                handles.primary_compaction_rotations + states.primary_compaction_rotations
            ),
            primary_compaction_work=(
                handles.primary_compaction_work + states.primary_compaction_work
            ),
            primary_compaction_seconds=(
                handles.primary_compaction_seconds + states.primary_compaction_seconds
            ),
        )

    def compact_primary(self, *, max_slots: int = _PRIMARY_COMPACTION_PAGE) -> int:
        """Advance bounded semantic-key map rotation at a watermark."""

        handles_page = max_slots // 2
        return self._handles.compact_primary(
            max_entries=handles_page
        ) + self._states.compact_primary(
            max_entries=max_slots - handles_page,
            force=not self._states,
        )

    def __len__(self) -> int:
        return self._live_count


class _ServiceIndex:
    """Packed service rows with exact object/logical/instance digest routes."""

    def __init__(self) -> None:
        self._rows = PackedByteRowStore(inline_slot_bytes=_PACKED_SERVICE_ROW_BYTES)
        self._objects = PackedUniqueDigestMap(b"lc-svc-object")
        self._logical = PackedUniqueDigestMap(b"lc-svc-logical")
        self._instances = PackedUniqueDigestMap(b"lc-svc-inst")
        self._generations = array("I")
        self._states: IncrementalExactMap[int, _LifecycleState] = IncrementalExactMap()

    @staticmethod
    def _logical_key(hostname: str, logical_service_id: str) -> str:
        return f"{hostname.strip().casefold()}\0{logical_service_id.strip().casefold()}"

    @staticmethod
    def _instance_key(
        hostname: str,
        boot_id: str,
        logical_service_id: str,
        instance_id: str,
    ) -> str:
        return "\0".join(
            (
                hostname.strip().casefold(),
                boot_id,
                logical_service_id.strip().casefold(),
                instance_id,
            )
        )

    def _entry_for_route(
        self,
        route: PackedUniqueDigestMap,
        semantic_id: str,
    ) -> _ServiceEntry | None:
        handle = route.get(semantic_id)
        if handle is None:
            return None
        return self.get_by_handle(handle)

    def get(self, object_id: str) -> _ServiceEntry | None:
        entry = self._entry_for_route(self._objects, object_id)
        if entry is None:
            return None
        if entry.identity.object_id != object_id:
            raise StateError("Lifecycle service object digest collision")
        return entry

    def get_logical(self, hostname: str, logical_service_id: str) -> _ServiceEntry | None:
        key = self._logical_key(hostname, logical_service_id)
        entry = self._entry_for_route(self._logical, key)
        if entry is None:
            return None
        if entry.logical_identity.host_logical_key != (
            hostname.strip().casefold(),
            logical_service_id.strip().casefold(),
        ):
            raise StateError("Lifecycle logical-service digest collision")
        return entry

    def get_instance(
        self,
        hostname: str,
        boot_id: str,
        logical_service_id: str,
        instance_id: str,
    ) -> _ServiceEntry | None:
        key = self._instance_key(hostname, boot_id, logical_service_id, instance_id)
        entry = self._entry_for_route(self._instances, key)
        if entry is None:
            return None
        expected = (
            hostname.strip().casefold(),
            boot_id,
            logical_service_id.strip().casefold(),
            instance_id,
        )
        if entry.identity.host_instance_key != expected:
            raise StateError("Lifecycle service-instance digest collision")
        return entry

    def add(
        self,
        logical: LogicalServiceIdentity,
        identity: ServiceInstanceLifecycleIdentity,
        transition: LifecycleTransition,
    ) -> int:
        if self.get(identity.object_id) is not None:
            raise StateError(f"Service lifecycle object {identity.object_id} is already registered")
        if self.get_instance(*identity.host_instance_key) is not None:
            raise StateError("Service instance key is already registered for this host and boot")
        row = _pack_service_row(logical, identity, transition)
        return self.add_prepared(logical, identity, row)

    def add_prepared(
        self,
        logical: LogicalServiceIdentity,
        identity: ServiceInstanceLifecycleIdentity,
        row: bytes,
    ) -> int:
        """Insert one prevalidated packed service row using primitive writes only."""

        handle = self._rows.insert(row)
        if handle == len(self._generations):
            self._generations.append(1)
        else:
            self._generations[handle] += 1
        self._objects[identity.object_id] = handle
        self._logical[self._logical_key(identity.hostname, identity.logical_service_id)] = handle
        self._instances[
            self._instance_key(
                identity.hostname,
                identity.boot_id,
                identity.logical_service_id,
                identity.instance_id,
            )
        ] = handle
        return handle

    def remove(
        self,
        object_id: str,
        *,
        logical_replacement_handle: int | None,
    ) -> _ServiceEntry | None:
        entry = self.get(object_id)
        if entry is None:
            return None
        entry._decoded_row()
        handle = entry.handle
        identity = entry.identity
        logical_key = self._logical_key(identity.hostname, identity.logical_service_id)
        self._objects.pop(object_id)
        self._instances.pop(
            self._instance_key(
                identity.hostname,
                identity.boot_id,
                identity.logical_service_id,
                identity.instance_id,
            )
        )
        if self._logical.get(logical_key) == handle:
            if logical_replacement_handle is None:
                self._logical.pop(logical_key)
            else:
                replacement = self.get_by_handle(logical_replacement_handle)
                if (
                    replacement is None
                    or replacement.logical_identity.host_logical_key
                    != entry.logical_identity.host_logical_key
                ):
                    raise StateError("Invalid logical-service route replacement")
                self._logical[logical_key] = logical_replacement_handle
        self._states.pop(handle, None)
        self._rows.delete(handle)
        return entry

    def handle_for(self, object_id: str) -> int:
        entry = self.get(object_id)
        if entry is None:
            raise KeyError(object_id)
        return entry.handle

    def get_by_handle(self, handle: int | None) -> _ServiceEntry | None:
        if handle is None or handle < 0 or handle >= len(self._generations):
            return None
        try:
            self._rows.get_by_handle(handle)
        except KeyError:
            return None
        return _ServiceEntry(self, handle, self._generations[handle])

    def row(self, handle: int, generation: int) -> bytes | memoryview:
        if handle >= len(self._generations) or self._generations[handle] != generation:
            raise StateError("Lifecycle service handle changed during access")
        try:
            return self._rows.get_by_handle(handle)
        except KeyError as exc:
            raise StateError("Lifecycle service handle changed during access") from exc

    def is_current(self, entry: _ServiceEntry) -> bool:
        return (
            entry.handle < len(self._generations)
            and self._generations[entry.handle] == entry.generation
            and self.get_by_handle(entry.handle) is not None
        )

    def promoted_state(self, handle: int, generation: int) -> _LifecycleState | None:
        self.row(handle, generation)
        return self._states.get(handle)

    def promote(self, entry: _ServiceEntry) -> _LifecycleState:
        existing = self.promoted_state(entry.handle, entry.generation)
        if existing is not None:
            return existing
        start = entry._start_transition()
        promoted = _LifecycleState(
            transitions=start,
            transition_count=1,
            transition_digest=_transition_digest_value(start),
            durable_transition_ids=start.transition_id,
        )
        self._states[entry.handle] = promoted
        return promoted

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        maps = tuple(
            route.metrics(estimate_bytes=estimate_bytes)
            for route in (self._objects, self._logical, self._instances)
        )
        rows = self._rows.metrics(estimate_bytes=estimate_bytes)
        states = self._states.metrics(estimate_bytes=estimate_bytes)
        return IndexMetrics(
            live_entries=len(self),
            backing_entries=rows.backing_entries,
            stale_entries=rows.stale_entries,
            allocated_slots=rows.allocated_slots,
            high_water_mark=rows.high_water_mark,
            estimated_bytes=(
                sum(metric.estimated_bytes for metric in maps)
                + rows.estimated_bytes
                + states.estimated_bytes
                + (getsizeof(self._generations) if estimate_bytes else 0)
            ),
            primary_map_entries=sum(metric.primary_map_entries for metric in maps)
            + states.primary_map_entries,
            primary_map_backing_bytes=sum(metric.primary_map_backing_bytes for metric in maps)
            + states.primary_map_backing_bytes,
            primary_compaction_pending=states.primary_compaction_pending,
            primary_compaction_rotations=states.primary_compaction_rotations,
            primary_compaction_work=states.primary_compaction_work,
            primary_compaction_seconds=states.primary_compaction_seconds,
        )

    @property
    def estimated_value_bytes(self) -> int:
        return self._rows.estimated_value_bytes

    def compact_primary(self, *, max_slots: int = _PRIMARY_COMPACTION_PAGE) -> int:
        return self._states.compact_primary(
            max_entries=max_slots,
            force=not self._states,
        )

    def iter_entries(self) -> Iterator[_ServiceEntry]:
        """Yield every current packed entry in stable handle order."""

        for handle in range(len(self._generations)):
            entry = self.get_by_handle(handle)
            if entry is not None:
                yield entry

    def clear(self) -> None:
        """Release all packed rows and exact routes after a proven full eviction."""

        self.__init__()

    def __len__(self) -> int:
        return len(self._rows)


class _TransportIndex:
    """Packed transport rows with one partition-local object route.

    Canonical transport IDs and Zeek UIDs are globally unique and therefore
    live only in the router's packed locator maps. Duplicating those maps in
    every owner partition adds no authority and costs two tables per transport.
    """

    def __init__(self) -> None:
        self._rows = PackedByteRowStore(inline_slot_bytes=_PACKED_TRANSPORT_ROW_BYTES)
        self._objects = PackedUniqueDigestMap(b"lc-tr-object")
        self._generations = array("I")
        self._active_binding_counts = array("I")
        self._states: IncrementalExactMap[int, _LifecycleState] = IncrementalExactMap()

    def _entry_for_route(
        self,
        route: PackedUniqueDigestMap,
        semantic_id: str,
    ) -> _TransportEntry | None:
        handle = route.get(semantic_id)
        return self.get_by_handle(handle) if handle is not None else None

    def object_route_digest(self, object_id: str) -> int:
        """Return the exact digest owned by this transport object route."""

        return self._objects.digest(object_id)

    def get_digest(self, object_id: str, route_digest: int) -> _TransportEntry | None:
        """Resolve one prehashed object route and verify its canonical identity."""

        handle = self._objects.get_digest(route_digest)
        entry = self.get_by_handle(handle) if handle is not None else None
        if entry is not None and entry.identity.object_id != object_id:
            raise StateError("Lifecycle transport object digest collision")
        return entry

    def get(self, object_id: str) -> _TransportEntry | None:
        entry = self._entry_for_route(self._objects, object_id)
        if entry is None:
            return None
        if entry.identity.object_id != object_id:
            raise StateError("Lifecycle transport object digest collision")
        return entry

    def add(self, identity: TransportLifecycleIdentity, transition: LifecycleTransition) -> int:
        if self.get(identity.object_id) is not None:
            raise StateError(
                f"Transport lifecycle object {identity.object_id} is already registered"
            )
        row = _pack_transport_row(identity, transition)
        return self.add_prepared(identity, row)

    def add_prepared(
        self,
        identity: TransportLifecycleIdentity,
        row: bytes,
        *,
        object_route_digest: int | None = None,
    ) -> int:
        """Insert one prevalidated packed transport row using primitive writes only."""

        handle = self._rows.insert(row)
        if handle == len(self._generations):
            self._generations.append(1)
            self._active_binding_counts.append(0)
        else:
            self._generations[handle] += 1
            self._active_binding_counts[handle] = 0
        route_digest = (
            self.object_route_digest(identity.object_id)
            if object_route_digest is None
            else object_route_digest
        )
        self._objects.set_digest(route_digest, handle)
        return handle

    def remove(self, object_id: str) -> _TransportEntry | None:
        entry = self.get(object_id)
        if entry is None:
            return None
        entry._decoded_row()
        handle = entry.handle
        self._objects.pop(object_id)
        self._states.pop(handle, None)
        self._active_binding_counts[handle] = 0
        self._rows.delete(handle)
        return entry

    def handle_for(self, object_id: str) -> int:
        entry = self.get(object_id)
        if entry is None:
            raise KeyError(object_id)
        return entry.handle

    def get_by_handle(self, handle: int | None) -> _TransportEntry | None:
        if handle is None or handle < 0 or handle >= len(self._generations):
            return None
        try:
            self._rows.get_by_handle(handle)
        except KeyError:
            return None
        return _TransportEntry(self, handle, self._generations[handle])

    def row(self, handle: int, generation: int) -> bytes | memoryview:
        if handle >= len(self._generations) or self._generations[handle] != generation:
            raise StateError("Lifecycle transport handle changed during access")
        try:
            return self._rows.get_by_handle(handle)
        except KeyError as exc:
            raise StateError("Lifecycle transport handle changed during access") from exc

    def is_current(self, entry: _TransportEntry) -> bool:
        return (
            entry.handle < len(self._generations)
            and self._generations[entry.handle] == entry.generation
            and self.get_by_handle(entry.handle) is not None
        )

    def promoted_state(self, handle: int, generation: int) -> _LifecycleState | None:
        self.row(handle, generation)
        return self._states.get(handle)

    def promote(self, entry: _TransportEntry) -> _LifecycleState:
        existing = self.promoted_state(entry.handle, entry.generation)
        if existing is not None:
            return existing
        start = entry._start_transition()
        promoted = _LifecycleState(
            transitions=start,
            transition_count=1,
            transition_digest=_transition_digest_value(start),
            durable_transition_ids=start.transition_id,
        )
        self._states[entry.handle] = promoted
        return promoted

    def active_binding_count(self, handle: int, generation: int) -> int:
        self.row(handle, generation)
        return self._active_binding_counts[handle]

    def set_active_binding_count(self, handle: int, generation: int, value: int) -> None:
        self.row(handle, generation)
        if value < 0:
            raise StateError("Transport active binding count cannot be negative")
        self._active_binding_counts[handle] = value

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        maps = (self._objects.metrics(estimate_bytes=estimate_bytes),)
        rows = self._rows.metrics(estimate_bytes=estimate_bytes)
        states = self._states.metrics(estimate_bytes=estimate_bytes)
        return IndexMetrics(
            live_entries=len(self),
            backing_entries=rows.backing_entries,
            stale_entries=rows.stale_entries,
            allocated_slots=rows.allocated_slots,
            high_water_mark=rows.high_water_mark,
            estimated_bytes=(
                sum(metric.estimated_bytes for metric in maps)
                + rows.estimated_bytes
                + states.estimated_bytes
                + (
                    getsizeof(self._generations) + getsizeof(self._active_binding_counts)
                    if estimate_bytes
                    else 0
                )
            ),
            primary_map_entries=sum(metric.primary_map_entries for metric in maps)
            + states.primary_map_entries,
            primary_map_backing_bytes=sum(metric.primary_map_backing_bytes for metric in maps)
            + states.primary_map_backing_bytes,
            primary_compaction_pending=states.primary_compaction_pending,
            primary_compaction_rotations=states.primary_compaction_rotations,
            primary_compaction_work=states.primary_compaction_work,
            primary_compaction_seconds=states.primary_compaction_seconds,
        )

    @property
    def estimated_value_bytes(self) -> int:
        return self._rows.estimated_value_bytes

    def compact_primary(self, *, max_slots: int = _PRIMARY_COMPACTION_PAGE) -> int:
        return self._states.compact_primary(
            max_entries=max_slots,
            force=not self._states,
        )

    def iter_entries(self) -> Iterator[_TransportEntry]:
        """Yield every current packed entry in stable handle order."""

        for handle in range(len(self._generations)):
            entry = self.get_by_handle(handle)
            if entry is not None:
                yield entry

    def clear(self) -> None:
        """Release all packed rows and exact routes after a proven full eviction."""

        self.__init__()

    def __len__(self) -> int:
        return len(self._rows)


class _RetentionDeadlineIndex:
    """Narrow adapter for deadline-driven closed-identity eviction."""

    def __init__(self) -> None:
        self._index = PackedHandleExpiryIndex()
        self._deadline_upper_bound: float | None = None

    def set(self, handle: int, deadline: datetime) -> None:
        """Insert or replace one compact handle's retention deadline."""

        canonical = ensure_utc(deadline).timestamp()
        self._index.set(handle, canonical)
        if self._deadline_upper_bound is None or canonical > self._deadline_upper_bound:
            self._deadline_upper_bound = canonical

    def all_due(self, cutoff: datetime, *, expected_entries: int) -> bool:
        """Return whether every expected live handle is provably due.

        The cached value is an upper bound: removals and deadline reductions may
        leave it conservatively high, but it can never make this predicate
        return a false positive. This enables an O(1) complete-flush preflight
        without scanning a deadline heap.
        """

        metrics = self._index.metrics()
        return (
            expected_entries > 0
            and metrics.live_entries == expected_entries
            and self._deadline_upper_bound is not None
            and self._deadline_upper_bound <= ensure_utc(cutoff).timestamp()
        )

    def expire_page(
        self,
        cutoff: datetime,
        *,
        limit: int = _LEDGER_COMPACTION_PAGE,
    ) -> tuple[int, ...]:
        """Return one bounded page of elapsed compact handles."""

        return tuple(
            handle
            for handle, _deadline in self._index.expire_before_page(
                ensure_utc(cutoff).timestamp(),
                inclusive=True,
                limit=limit,
            )
        )

    def expire(self, cutoff: datetime) -> tuple[int, ...]:
        """Compatibility helper that explicitly materializes every due page."""

        expired: list[int] = []
        while page := self.expire_page(cutoff):
            expired.extend(page)
        return tuple(expired)

    def remove(self, handle: int) -> None:
        """Remove a handle deadline when its retained identity is evicted."""

        self._index.pop(handle, None)

    def clear(self) -> None:
        """Release every deadline backing after a proven complete flush."""

        self._index = PackedHandleExpiryIndex()
        self._deadline_upper_bound = None

    def deadline(self, handle: int) -> datetime | None:
        """Return the current UTC retention deadline for one handle."""

        deadline = self._index.get(handle)
        return datetime.fromtimestamp(deadline, tz=UTC) if deadline is not None else None

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return low-cost deadline-index metrics."""

        return self._index.metrics(estimate_bytes=estimate_bytes)

    def compact(self, *, max_entries: int = _PRIMARY_COMPACTION_PAGE) -> int:
        """Advance bounded stale deadline-heap rebuilding."""

        return self._index.compact(max_slots=max_entries)


class _LeaseDeadlineIndex:
    """Narrow adapter for bounded lifecycle reference leases."""

    def __init__(self) -> None:
        self._index = PackedHandleExpiryIndex()

    def set(self, handle: int, lease: LifecycleRetentionLease) -> None:
        """Insert one lease through a compact temporal-index handle."""

        self._index.set(handle, lease.retain_until.timestamp())

    def remove(self, handle: int) -> float | None:
        """Remove and return one lease deadline."""

        return self._index.pop(handle, None)

    def expire_page(
        self,
        cutoff: datetime,
        *,
        limit: int = _LEDGER_COMPACTION_PAGE,
    ) -> tuple[int, ...]:
        """Return one bounded page of lease handles whose deadlines elapsed."""

        return tuple(
            handle
            for handle, _deadline in self._index.expire_before_page(
                ensure_utc(cutoff).timestamp(),
                inclusive=True,
                limit=limit,
            )
        )

    def expire(self, cutoff: datetime) -> tuple[int, ...]:
        """Compatibility helper that explicitly materializes every due page."""

        expired: list[int] = []
        while page := self.expire_page(cutoff):
            expired.extend(page)
        return tuple(expired)

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return low-cost lease-deadline metrics."""

        return self._index.metrics(estimate_bytes=estimate_bytes)

    def compact(self, *, max_entries: int = _PRIMARY_COMPACTION_PAGE) -> int:
        """Advance bounded stale deadline-heap rebuilding."""

        return self._index.compact(max_slots=max_entries)


class _LifecyclePartition:
    """One independently locked lifecycle state partition.

    Every query takes either an exact object identity or an explicit canonical
    time. Closing a future lifecycle therefore never removes its earlier
    historical validity. Closed identities remain queryable until the bounded
    retention watermark evicts them.
    """

    def __init__(
        self,
        *,
        closed_retention: timedelta = _DEFAULT_CLOSED_RETENTION,
        snapshot_history_limit: int = _DEFAULT_SNAPSHOT_HISTORY_LIMIT,
        ledger_detail_retention: timedelta = _DEFAULT_LEDGER_DETAIL_RETENTION,
    ) -> None:
        """Create an empty registry with an explicit closed-identity horizon."""

        if closed_retention <= timedelta(0):
            raise ValueError("Lifecycle closed_retention must be positive")
        if snapshot_history_limit <= 0:
            raise ValueError("Lifecycle snapshot_history_limit must be positive")
        if ledger_detail_retention < timedelta(0):
            raise ValueError("Lifecycle ledger_detail_retention must be non-negative")
        self._closed_retention = closed_retention
        self._snapshot_history_limit = snapshot_history_limit
        self._ledger_detail_retention = ledger_detail_retention
        self._processes = _ProcessIndex()
        self._sessions = _SessionIndex()
        self._services = _ServiceIndex()
        self._transports = _TransportIndex()
        self._service_process_bindings: CompactIndexedStore[str, _ServiceProcessBindingEntry] = (
            CompactIndexedStore(
                service=lambda item: item.identity.service_object_id,
                process=lambda item: item.identity.process_object_id,
            )
        )
        self._service_process_tombstones: CompactIndexedStore[
            str, ServiceProcessBindingSnapshot
        ] = CompactIndexedStore()
        self._transport_session_bindings: CompactIndexedStore[
            str, _TransportSessionBindingEntry
        ] = CompactIndexedStore(
            transport=lambda item: item.identity.transport_object_id,
            session=lambda item: item.identity.session_object_id,
        )
        self._transport_session_tombstones: CompactIndexedStore[
            str, TransportSessionBindingSnapshot
        ] = CompactIndexedStore()
        self._process_starts: SegmentedTemporalIndex[tuple[str, int]] = SegmentedTemporalIndex(
            track_lookup_candidates=True
        )
        self._session_starts: SegmentedTemporalIndex[int] = SegmentedTemporalIndex(
            track_lookup_candidates=True
        )
        self._service_starts = _SparseTemporalIndex(
            namespace=b"lc-svc-time",
            track_lookup_candidates=True,
        )
        self._transport_starts = _SparseTemporalIndex(
            namespace=b"lc-tr-time",
            track_lookup_candidates=True,
        )
        self._process_retention_deadlines = _RetentionDeadlineIndex()
        self._session_retention_deadlines = _RetentionDeadlineIndex()
        self._service_retention_deadlines = _RetentionDeadlineIndex()
        self._transport_retention_deadlines = _RetentionDeadlineIndex()
        self._service_process_tombstone_deadlines = _RetentionDeadlineIndex()
        self._transport_session_tombstone_deadlines = _RetentionDeadlineIndex()
        self._lease_deadlines = _LeaseDeadlineIndex()
        self._transitions: CompactIndexedStore[str, LifecycleTransition] = CompactIndexedStore(
            commit=lambda item: (
                item.subject.kind,
                item.subject.object_id,
                item.action_id,
                item.transition_ordinal,
            ),
        )
        self._holds: CompactIndexedStore[str, LifecycleHold] = CompactIndexedStore()
        self._transition_times: SegmentedTemporalIndex[int] = SegmentedTemporalIndex()
        self._hold_times: SegmentedTemporalIndex[int] = SegmentedTemporalIndex()
        self._barriers: CompactIndexedStore[str, LifecycleCloseBarrier] = CompactIndexedStore()
        self._tickets: CompactIndexedStore[str, LifecycleClosureTicket] = CompactIndexedStore()
        self._leases: CompactIndexedStore[str, LifecycleRetentionLease] = CompactIndexedStore(
            subject=lambda item: item.subject,
        )
        self._foreground_leases: CompactIndexedStore[str, _ForegroundLeaseEntry] = (
            CompactIndexedStore(
                resource=lambda item: item.resource_key,
                process=lambda item: item.process_object_id,
                session=lambda item: item.session_object_id,
            )
        )
        self._singleton_leases: CompactIndexedStore[str, _SingletonLeaseEntry] = (
            CompactIndexedStore(
                resource=lambda item: item.resource_key,
                process=lambda item: item.process_object_id,
                session=lambda item: item.session_object_id,
            )
        )
        self._foreground_lease_deadlines = _RetentionDeadlineIndex()
        self._singleton_lease_deadlines = _RetentionDeadlineIndex()
        self._singleton_lease_starts: SegmentedTemporalIndex[LifecycleSingletonLeaseKey] = (
            SegmentedTemporalIndex(track_lookup_candidates=True)
        )
        self._resource_lease_deadlines: CompactIndexedStore[
            LifecycleEntityRef, _IndexedLeaseDeadlineHeap
        ] = CompactIndexedStore()
        self._resource_lease_deadline_bindings = 0
        self._resource_lease_max_subject_bindings = 0
        self._resource_lease_candidates_inspected = 0
        self._retention_lease_deadlines: CompactIndexedStore[
            LifecycleEntityRef, _IndexedLeaseDeadlineHeap
        ] = CompactIndexedStore()
        self._retention_lease_deadline_bindings = 0
        self._retention_lease_max_subject_bindings = 0
        self._retention_lease_candidates_inspected = 0
        self._dependent_aggregate_candidates_inspected = 0
        self._exact_lookup_candidates_inspected = 0
        self._children_by_parent: CompactIndexedStore[str, _DependentClosureAggregate] = (
            CompactIndexedStore()
        )
        self._live_children: CompactIndexedStore[str, _LiveChildBinding] = CompactIndexedStore(
            parent=lambda item: item.parent_object_id,
        )
        self._live_session_members: CompactIndexedStore[str, _LiveSessionMemberBinding] = (
            CompactIndexedStore(
                session=lambda item: item.session_object_id,
            )
        )
        self._members_by_session: CompactIndexedStore[str, _DependentClosureAggregate] = (
            CompactIndexedStore()
        )
        self._service_children_by_parent: CompactIndexedStore[str, _DependentClosureAggregate] = (
            CompactIndexedStore()
        )
        self._live_service_children: CompactIndexedStore[str, _LiveChildBinding] = (
            CompactIndexedStore(parent=lambda item: item.parent_object_id)
        )
        self._service_processes_by_service: CompactIndexedStore[str, _DependentClosureAggregate] = (
            CompactIndexedStore()
        )
        self._transport_bindings_by_session: CompactIndexedStore[
            str, _DependentClosureAggregate
        ] = CompactIndexedStore()
        self._live_transport_bindings_by_session: CompactIndexedStore[
            str, _LiveTransportBinding
        ] = CompactIndexedStore(session=lambda item: item.session_object_id)
        self._service_bindings_by_process: CompactIndexedStore[str, _DependentClosureAggregate] = (
            CompactIndexedStore()
        )
        self._live_processes = 0
        self._live_sessions = 0
        self._live_service_instances = 0
        self._live_transports = 0
        self._active_service_process_bindings = 0
        self._active_transport_session_bindings = 0
        self._evicted_processes = 0
        self._evicted_sessions = 0
        self._evicted_services = 0
        self._evicted_transports = 0
        self._evicted_bindings = 0
        self._high_water_processes = 0
        self._high_water_sessions = 0
        self._watermark: datetime | None = None
        self._ledger_floor: datetime | None = None
        self._compacted_transitions = 0
        self._compacted_holds = 0
        self._commit_map_entries = 0
        self._commit_map_backing_bytes = 0
        self._transition_compaction_pending = False
        self._hold_compaction_pending = False
        self._route_removals: list[tuple[str, str]] = []
        self._host_lanes = _HostCommitLanes(shard_count=1)
        self._catalog_lock = RLock()
        self._index_lock = RLock()
        self._watermark_gate = Lock()

    @property
    def closed_retention(self) -> timedelta:
        """Return the configured closed-identity retention horizon."""

        return self._closed_retention

    @property
    def snapshot_history_limit(self) -> int:
        """Return the maximum detailed transitions and holds per snapshot."""

        return self._snapshot_history_limit

    @property
    def ledger_detail_retention(self) -> timedelta:
        """Return the exact-detail horizon behind the sealed watermark."""

        return self._ledger_detail_retention

    def register_session(
        self,
        identity: SessionLifecycleIdentity,
        *,
        action_id: str,
        transition_id: str,
        transition_ordinal: int = 0,
    ) -> SessionLifecycleSnapshotView:
        """Register one immutable session identity and its start transition."""

        transition = LifecycleTransition(
            transition_id=transition_id,
            subject=identity.ref,
            kind="started",
            canonical_time=identity.started_at,
            action_id=action_id,
            transition_ordinal=transition_ordinal,
        )
        with (
            self._host_lanes.lane(identity.hostname),
            self._catalog_lock,
            self._index_lock,
        ):
            prepared = self._prepare_session_registration_locked(
                identity,
                transition=transition,
            )
            return self._commit_prepared_session_locked(prepared)

    def _prepare_session_registration_locked(
        self,
        identity: SessionLifecycleIdentity,
        *,
        transition: LifecycleTransition,
    ) -> _PreparedSessionPartitionStart:
        """Validate a session start without mutating partition state."""

        existing = self._sessions.get(identity.object_id)
        if existing is not None:
            if existing.identity == identity and self._entry_has_transition(existing, transition):
                snapshot = self._session_snapshot(existing)
                return _PreparedSessionPartitionStart(
                    identity=identity,
                    transition=transition,
                    existing=existing,
                    snapshot=snapshot,
                    handle=existing.handle,
                )
            raise StateError(f"Session lifecycle object {identity.object_id} is already registered")
        self._reject_behind_watermark(identity.started_at, "session start")
        self._reject_overlapping_logon_identity(identity)
        self._validate_transition_claim(transition)
        transition_digest = self._transition_digest(transition)
        snapshot = SessionLifecycleSnapshot(
            identity=identity,
            transitions=(transition,),
            holds=(),
            close_barrier=None,
            closure_ticket=None,
            closed_at=None,
            transition_count=1,
            compacted_transition_count=0,
            transition_ledger_digest=f"{transition_digest:064x}",
            hold_count=0,
            compacted_hold_count=0,
            hold_ledger_digest=f"{0:064x}",
            latest_dependent_at=None,
            latest_hold_until=None,
        )
        return _PreparedSessionPartitionStart(
            identity=identity,
            transition=transition,
            existing=None,
            snapshot=snapshot,
        )

    def _commit_prepared_session_locked(
        self,
        prepared: _PreparedSessionPartitionStart,
    ) -> SessionLifecycleSnapshotView:
        """Publish a previously validated session using primitive index writes."""

        if prepared.committed or prepared.existing is not None:
            prepared.committed = True
            return prepared.snapshot
        handle = self._sessions.add(prepared.identity, prepared.transition)
        prepared.handle = handle
        self._session_starts.add(
            handle,
            self._session_group(prepared.identity.hostname, prepared.identity.logon_id),
            prepared.identity.started_at,
        )
        self._live_sessions += 1
        self._high_water_sessions = max(self._high_water_sessions, len(self._sessions))
        prepared.committed = True
        return prepared.snapshot

    def register_process(
        self,
        identity: ProcessLifecycleIdentity,
        *,
        token: ProcessTokenIdentity,
        membership: LifecycleMembership,
        action_id: str,
        transition_id: str,
        transition_ordinal: int = 0,
    ) -> ProcessLifecycleSnapshot:
        """Register one process object with immutable token and membership."""

        transition = LifecycleTransition(
            transition_id=transition_id,
            subject=identity.ref,
            kind="started",
            canonical_time=identity.started_at,
            action_id=action_id,
            transition_ordinal=transition_ordinal,
        )
        with (
            self._host_lanes.lane(identity.hostname),
            self._catalog_lock,
            self._index_lock,
        ):
            prepared = self._prepare_process_registration_locked(
                identity,
                token=token,
                membership=membership,
                transition=transition,
            )
            return self._commit_prepared_process_locked(prepared)

    def _prepare_process_registration_locked(
        self,
        identity: ProcessLifecycleIdentity,
        *,
        token: ProcessTokenIdentity,
        membership: LifecycleMembership,
        transition: LifecycleTransition,
        staged_sessions: dict[str, SessionLifecycleIdentity] | None = None,
        staged_processes: dict[str, ProcessLifecycleIdentity] | None = None,
    ) -> _PreparedProcessPartitionStart:
        """Validate a process start without mutating partition state."""

        existing = self._processes.get(identity.object_id)
        if existing is not None:
            if (
                existing.identity == identity
                and existing.token == token
                and existing.membership == membership
                and self._entry_has_transition(existing, transition)
            ):
                return _PreparedProcessPartitionStart(
                    entry=existing,
                    transition=transition,
                    existing=existing,
                    snapshot=self._process_snapshot(existing),
                )
            raise StateError(f"Process lifecycle object {identity.object_id} is already registered")
        self._reject_behind_watermark(identity.started_at, "process start")
        self._validate_process_parent(identity, staged_processes=staged_processes)
        self._validate_process_membership(
            identity,
            membership,
            staged_sessions=staged_sessions,
        )
        self._reject_overlapping_pid_identity(identity)
        self._validate_transition_claim(transition)
        entry = _ProcessEntry(
            identity=identity,
            token=token,
            membership=membership,
            state=_StartedLifecycleState(
                transition,
                self._transition_digest(transition),
            ),
        )
        return _PreparedProcessPartitionStart(
            entry=entry,
            transition=transition,
            existing=None,
            snapshot=self._process_snapshot(entry),
        )

    def _commit_prepared_process_locked(
        self,
        prepared: _PreparedProcessPartitionStart,
    ) -> ProcessLifecycleSnapshot:
        """Publish a previously validated process using primitive index writes."""

        if prepared.committed or prepared.existing is not None:
            prepared.committed = True
            return prepared.snapshot
        entry = prepared.entry
        identity = entry.identity
        membership = entry.membership
        handle = self._processes.add(entry)
        self._process_starts.add(
            handle,
            (identity.hostname, identity.pid),
            identity.started_at,
        )
        if identity.parent_object_id:
            parent = self._processes.get(identity.parent_object_id)
            assert parent is not None
            if parent.identity.role != "bootstrap_handoff":
                aggregate = self._children_by_parent.get(identity.parent_object_id)
                if aggregate is None:
                    aggregate = _DependentClosureAggregate()
                    self._children_by_parent[identity.parent_object_id] = aggregate
                aggregate.register()
                self._live_children[identity.object_id] = _LiveChildBinding(
                    parent_object_id=identity.parent_object_id,
                    child_object_id=identity.object_id,
                )
        if membership.session_object_id:
            aggregate = self._members_by_session.get(membership.session_object_id)
            if aggregate is None:
                aggregate = _DependentClosureAggregate()
                self._members_by_session[membership.session_object_id] = aggregate
            aggregate.register()
            self._live_session_members[identity.object_id] = _LiveSessionMemberBinding(
                session_object_id=membership.session_object_id,
                process_object_id=identity.object_id,
            )
        self._live_processes += 1
        self._high_water_processes = max(self._high_water_processes, len(self._processes))
        prepared.committed = True
        return prepared.snapshot

    def register_service_instance(
        self,
        logical_identity: LogicalServiceIdentity,
        identity: ServiceInstanceLifecycleIdentity,
        *,
        action_id: str,
        transition_id: str,
        transition_ordinal: int = 0,
    ) -> tuple[ServiceInstanceLifecycleSnapshot, int]:
        """Register one immutable logical service and boot-scoped instance."""

        if logical_identity.hostname != identity.hostname:
            raise StateError("Logical service and runtime instance must use the same host")
        if logical_identity.logical_service_id != identity.logical_service_id:
            raise StateError("Service instance logical identity does not match its service")
        transition = LifecycleTransition(
            transition_id=transition_id,
            subject=identity.ref,
            kind="started",
            canonical_time=identity.started_at,
            action_id=action_id,
            transition_ordinal=transition_ordinal,
        )
        with self._host_lanes.lane(identity.hostname), self._catalog_lock, self._index_lock:
            prepared = self._prepare_service_registration_locked(
                logical_identity,
                identity,
                transition=transition,
            )
            return self._commit_prepared_service_locked(prepared)

    def _prepare_service_registration_locked(
        self,
        logical_identity: LogicalServiceIdentity,
        identity: ServiceInstanceLifecycleIdentity,
        *,
        transition: LifecycleTransition,
    ) -> _PreparedServicePartitionStart:
        """Validate and pack one service start without publishing it."""

        if logical_identity.hostname != identity.hostname:
            raise StateError("Logical service and runtime instance must use the same host")
        if logical_identity.logical_service_id != identity.logical_service_id:
            raise StateError("Service instance logical identity does not match its service")
        existing = self._services.get(identity.object_id)
        if existing is not None:
            if (
                existing.logical_identity == logical_identity
                and existing.identity == identity
                and self._entry_has_transition(existing, transition)
            ):
                return _PreparedServicePartitionStart(
                    logical_identity=logical_identity,
                    identity=identity,
                    transition=transition,
                    existing=existing,
                    snapshot=self._service_snapshot(existing),
                    packed_row=None,
                )
            raise StateError(f"Service lifecycle object {identity.object_id} is already registered")
        logical_entry = self._services.get_logical(
            logical_identity.hostname,
            logical_identity.logical_service_id,
        )
        if logical_entry is not None and logical_entry.logical_identity != logical_identity:
            if self._entry_active_at(logical_entry, identity.started_at):
                raise StateError(
                    "Service lifecycle logical identity already has an active instance"
                )
            raise StateError("Host/logical service identity is already bound to different metadata")
        instance = self._services.get_instance(
            identity.hostname,
            identity.boot_id,
            identity.logical_service_id,
            identity.instance_id,
        )
        if instance is not None:
            raise StateError("Service instance key is already registered for this host and boot")
        self._reject_behind_watermark(identity.started_at, "service start")
        if identity.parent_service_object_id:
            parent = self._services.get(identity.parent_service_object_id)
            if parent is None:
                raise StateError(
                    f"Service instance {identity.object_id} references unknown parent "
                    f"{identity.parent_service_object_id}"
                )
            if parent.identity.hostname != identity.hostname:
                raise StateError("Service instances cannot use a cross-host parent")
            if not self._entry_active_at(parent, identity.started_at):
                raise StateError("Service parent is not active at child start")
            if parent.close_barrier is not None:
                raise StateError("Service parent already accepted a close barrier")
        self._reject_overlapping_service_identity(identity)
        self._validate_transition_claim(transition)
        digest = _transition_digest_value(transition)
        return _PreparedServicePartitionStart(
            logical_identity=logical_identity,
            identity=identity,
            transition=transition,
            existing=None,
            snapshot=ServiceInstanceLifecycleSnapshot(
                logical_identity=logical_identity,
                identity=identity,
                transitions=(transition,),
                holds=(),
                close_barrier=None,
                closure_ticket=None,
                closed_at=None,
                transition_count=1,
                compacted_transition_count=0,
                transition_ledger_digest=f"{digest:064x}",
                hold_count=0,
                compacted_hold_count=0,
                hold_ledger_digest=f"{0:064x}",
                latest_dependent_at=None,
                latest_hold_until=None,
            ),
            packed_row=_pack_service_row(logical_identity, identity, transition),
        )

    def _commit_prepared_service_locked(
        self,
        prepared: _PreparedServicePartitionStart,
    ) -> tuple[ServiceInstanceLifecycleSnapshot, int]:
        """Publish one validated service using primitive index writes."""

        if prepared.committed or prepared.existing is not None:
            prepared.committed = True
            existing = prepared.existing
            assert existing is not None
            return prepared.snapshot, existing.handle
        row = prepared.packed_row
        assert row is not None
        identity = prepared.identity
        logical_identity = prepared.logical_identity
        handle = self._services.add_prepared(logical_identity, identity, row)
        self._service_starts.add(
            handle,
            self._service_group(logical_identity.hostname, logical_identity.logical_service_id),
            identity.started_at,
        )
        if identity.parent_service_object_id:
            aggregate = self._service_children_by_parent.get(identity.parent_service_object_id)
            if aggregate is None:
                aggregate = _DependentClosureAggregate()
                self._service_children_by_parent[identity.parent_service_object_id] = aggregate
            aggregate.register()
            self._live_service_children[identity.object_id] = _LiveChildBinding(
                parent_object_id=identity.parent_service_object_id,
                child_object_id=identity.object_id,
            )
        self._live_service_instances += 1
        prepared.committed = True
        return prepared.snapshot, handle

    def register_transport(
        self,
        identity: TransportLifecycleIdentity,
        *,
        action_id: str,
        transition_id: str,
        transition_ordinal: int = 0,
    ) -> tuple[TransportLifecycleSnapshot, int]:
        """Register one canonical network-plan transport without allocating identity."""

        transition = LifecycleTransition(
            transition_id=transition_id,
            subject=identity.ref,
            kind="started",
            canonical_time=identity.opened_at,
            action_id=action_id,
            transition_ordinal=transition_ordinal,
        )
        with self._host_lanes.lane(identity.hostname), self._catalog_lock, self._index_lock:
            prepared = self._prepare_transport_registration_locked(
                identity,
                transition=transition,
            )
            return self._commit_prepared_transport_locked(prepared)

    def _prepare_transport_registration_locked(
        self,
        identity: TransportLifecycleIdentity,
        *,
        transition: LifecycleTransition,
    ) -> _PreparedTransportPartitionStart:
        """Validate and pack one transport start without publishing it."""

        object_route_digest = self._transports.object_route_digest(identity.object_id)
        existing = self._transports.get_digest(identity.object_id, object_route_digest)
        if existing is not None:
            if existing.identity == identity and self._entry_has_transition(existing, transition):
                return _PreparedTransportPartitionStart(
                    identity=identity,
                    transition=transition,
                    existing=existing,
                    snapshot=self._transport_snapshot(existing),
                    packed_row=None,
                    object_route_digest=object_route_digest,
                )
            raise StateError(
                f"Transport lifecycle object {identity.object_id} is already registered"
            )
        self._reject_behind_watermark(identity.opened_at, "transport start")
        self._reject_overlapping_transport_tuple(identity)
        self._validate_transition_claim(
            transition,
            subject_route_digest=object_route_digest,
        )
        digest = _transition_digest_value(transition)
        return _PreparedTransportPartitionStart(
            identity=identity,
            transition=transition,
            existing=None,
            snapshot=TransportLifecycleSnapshot(
                identity=identity,
                transitions=(transition,),
                holds=(),
                close_barrier=None,
                closure_ticket=None,
                closed_at=None,
                active_binding_count=0,
                transition_count=1,
                compacted_transition_count=0,
                transition_ledger_digest=f"{digest:064x}",
                hold_count=0,
                compacted_hold_count=0,
                hold_ledger_digest=f"{0:064x}",
                latest_dependent_at=None,
                latest_hold_until=None,
            ),
            packed_row=_pack_transport_row(identity, transition),
            object_route_digest=object_route_digest,
        )

    def _commit_prepared_transport_locked(
        self,
        prepared: _PreparedTransportPartitionStart,
    ) -> tuple[TransportLifecycleSnapshot, int]:
        """Publish one validated transport using primitive index writes."""

        if prepared.committed or prepared.existing is not None:
            prepared.committed = True
            existing = prepared.existing
            assert existing is not None
            return prepared.snapshot, existing.handle
        row = prepared.packed_row
        assert row is not None
        identity = prepared.identity
        handle = self._transports.add_prepared(
            identity,
            row,
            object_route_digest=prepared.object_route_digest,
        )
        self._transport_starts.add(
            handle,
            self._transport_group(identity.tuple_key),
            identity.opened_at,
        )
        self._live_transports += 1
        prepared.committed = True
        return prepared.snapshot, handle

    def get_process(self, object_id: str) -> ProcessLifecycleSnapshot | None:
        """Return a frozen process snapshot by exact object identity."""

        with self._catalog_lock:
            entry = self._processes.get(object_id)
            return None if entry is None else self._process_snapshot(entry)

    def get_session(self, object_id: str) -> SessionLifecycleSnapshotView | None:
        """Return a frozen session snapshot by exact object identity."""

        with self._catalog_lock:
            entry = self._sessions.get(object_id)
            return None if entry is None else self._session_snapshot(entry)

    def get_service_instance(self, object_id: str) -> ServiceInstanceLifecycleSnapshot | None:
        """Return one service instance by exact object identity."""

        with self._catalog_lock:
            entry = self._services.get(object_id)
            return None if entry is None else self._service_snapshot(entry)

    def get_transport(self, object_id: str) -> TransportLifecycleSnapshot | None:
        """Return one canonical transport by exact object identity."""

        with self._catalog_lock:
            entry = self._transports.get(object_id)
            return None if entry is None else self._transport_snapshot(entry)

    def get_transport_by_handle(
        self,
        handle: int,
        *,
        count_candidate: bool = False,
    ) -> TransportLifecycleSnapshot | None:
        """Return one canonical transport through a globally verified locator."""

        with self._catalog_lock:
            entry = self._transports.get_by_handle(handle)
            if entry is not None and count_candidate:
                self._exact_lookup_candidates_inspected += 1
            return None if entry is None else self._transport_snapshot(entry)

    def get_service_by_handle(
        self,
        handle: int,
        *,
        count_candidate: bool = False,
    ) -> ServiceInstanceLifecycleSnapshot | None:
        """Return one service instance through a globally verified locator."""

        with self._catalog_lock:
            entry = self._services.get_by_handle(handle)
            if entry is not None and count_candidate:
                self._exact_lookup_candidates_inspected += 1
            return None if entry is None else self._service_snapshot(entry)

    def service_instance_at(
        self,
        object_id: str,
        canonical_time: datetime,
    ) -> ServiceInstanceLifecycleSnapshot | None:
        """Resolve one exact service instance at explicit canonical time."""

        with self._catalog_lock:
            entry = self._services.get(object_id)
            if entry is None or not self._entry_active_at(entry, ensure_utc(canonical_time)):
                return None
            return self._service_snapshot(entry)

    def service_for_logical_at(
        self,
        hostname: str,
        logical_service_id: str,
        canonical_time: datetime,
    ) -> ServiceInstanceLifecycleSnapshot | None:
        """Resolve the active service instance through one temporal predecessor."""

        at = ensure_utc(canonical_time)
        expected = (hostname.strip().casefold(), logical_service_id.strip().casefold())
        group = self._service_group(hostname, logical_service_id)
        with self._catalog_lock, self._index_lock:
            handle = self._service_starts.latest_at_or_before(group, at)
            if handle is None:
                return None
            entry = self._services.get_by_handle(handle)
            if entry is None:
                return None
            if entry.logical_identity.host_logical_key != expected:
                raise StateError("Lifecycle logical-service temporal digest collision")
            if not self._entry_active_at(entry, at):
                return None
            return self._service_snapshot(entry)

    def service_for_instance_key(
        self,
        hostname: str,
        boot_id: str,
        logical_service_id: str,
        instance_id: str,
    ) -> ServiceInstanceLifecycleSnapshot | None:
        """Resolve one boot-scoped service instance through its exact key."""

        with self._catalog_lock:
            entry = self._services.get_instance(
                hostname,
                boot_id,
                logical_service_id,
                instance_id,
            )
            return None if entry is None else self._service_snapshot(entry)

    def transport_at(
        self,
        object_id: str,
        canonical_time: datetime,
    ) -> TransportLifecycleSnapshot | None:
        """Resolve one exact transport at explicit canonical time."""

        with self._catalog_lock:
            entry = self._transports.get(object_id)
            if entry is None or not self._entry_active_at(entry, ensure_utc(canonical_time)):
                return None
            return self._transport_snapshot(entry)

    def transport_for_tuple_at(
        self,
        tuple_key: tuple[str, int, str, int, str],
        canonical_time: datetime,
    ) -> TransportLifecycleSnapshot | None:
        """Resolve one reused canonical tuple through one temporal predecessor."""

        at = ensure_utc(canonical_time)
        normalized = (*tuple_key[:4], tuple_key[4].casefold())
        with self._catalog_lock, self._index_lock:
            handle = self._transport_starts.latest_at_or_before(
                self._transport_group(normalized),
                at,
            )
            if handle is None:
                return None
            entry = self._transports.get_by_handle(handle)
            if entry is None:
                return None
            if entry.identity.tuple_key != normalized:
                raise StateError("Lifecycle transport tuple temporal digest collision")
            if not self._entry_active_at(entry, at):
                return None
            return self._transport_snapshot(entry)

    def bind_service_process(
        self,
        identity: ServiceProcessBindingIdentity,
    ) -> ServiceProcessBindingSnapshot:
        """Bind one service instance to a process without aliasing either identity."""

        with self._catalog_lock:
            service = self._services.get(identity.service_object_id)
            hostname = None if service is None else service.identity.hostname
        if hostname is None:
            raise StateError(f"Unknown service lifecycle object {identity.service_object_id}")
        with self._host_lanes.lane(hostname), self._catalog_lock, self._index_lock:
            prepared = self._prepare_service_process_binding_locked(identity)
            return self._commit_prepared_service_process_binding_locked(prepared)

    def _prepare_service_process_binding_locked(
        self,
        identity: ServiceProcessBindingIdentity,
        *,
        staged_service: ServiceInstanceLifecycleIdentity | None = None,
        staged_process: ProcessLifecycleIdentity | None = None,
    ) -> _PreparedServiceProcessBinding:
        """Validate one service/process relation without publishing it."""

        existing = self._service_process_bindings.get(identity.binding_id)
        if existing is not None:
            if existing.identity == identity:
                return _PreparedServiceProcessBinding(
                    identity=identity,
                    existing=ServiceProcessBindingSnapshot(existing.identity),
                )
            raise StateError(f"Service/process binding {identity.binding_id} is already used")
        tombstone = self._service_process_tombstones.get(identity.binding_id)
        if tombstone is not None:
            if tombstone.identity == identity:
                return _PreparedServiceProcessBinding(identity=identity, existing=tombstone)
            raise StateError(f"Service/process binding {identity.binding_id} is already used")
        service = self._services.get(identity.service_object_id)
        if service is None:
            if staged_service is None or staged_service.object_id != identity.service_object_id:
                raise StateError(f"Unknown service lifecycle object {identity.service_object_id}")
            service_identity = staged_service
            service_barrier = None
            service_closed_at = None
        else:
            service_identity = service.identity
            service_barrier = service.close_barrier
            service_closed_at = service.closed_at
        process = self._processes.get(identity.process_object_id)
        if process is None:
            if staged_process is None or staged_process.object_id != identity.process_object_id:
                raise StateError(f"Unknown process lifecycle object {identity.process_object_id}")
            process_identity = staged_process
            process_barrier = None
            process_active = identity.bound_at >= staged_process.started_at
        else:
            process_identity = process.identity
            if staged_process is not None and staged_process != process_identity:
                raise StateError("Staged service process identity changed before publication")
            process_barrier = process.close_barrier
            process_active = self._entry_active_at(process, identity.bound_at)
        if service_identity.hostname != process_identity.hostname:
            raise StateError("Service/process bindings cannot cross hosts")
        self._reject_behind_watermark(identity.bound_at, "service/process binding")
        if identity.bound_at < service_identity.started_at or (
            service_closed_at is not None and identity.bound_at >= service_closed_at
        ):
            raise StateError("Service/process binding service is not active")
        if service_barrier is not None:
            raise StateError("Service/process binding service already accepted a close barrier")
        if not process_active:
            raise StateError("Service/process binding process is not active")
        if process_barrier is not None:
            raise StateError("Service/process binding process already accepted a close barrier")
        return _PreparedServiceProcessBinding(identity=identity)

    def _commit_prepared_service_process_binding_locked(
        self,
        prepared: _PreparedServiceProcessBinding,
    ) -> ServiceProcessBindingSnapshot:
        """Publish one validated service/process relation using primitive writes."""

        if prepared.committed or prepared.existing is not None:
            prepared.committed = True
            existing = prepared.existing
            assert existing is not None
            return existing
        identity = prepared.identity
        self._service_process_bindings[identity.binding_id] = _ServiceProcessBindingEntry(identity)
        for store, object_id in (
            (self._service_processes_by_service, identity.service_object_id),
            (self._service_bindings_by_process, identity.process_object_id),
        ):
            aggregate = store.get(object_id)
            if aggregate is None:
                aggregate = _DependentClosureAggregate()
                store[object_id] = aggregate
            aggregate.register()
        self._active_service_process_bindings += 1
        prepared.committed = True
        return ServiceProcessBindingSnapshot(identity)

    def service_process_binding(
        self,
        binding_id: str,
    ) -> ServiceProcessBindingSnapshot | None:
        """Return one active or retained service/process binding by exact ID."""

        with self._catalog_lock:
            active = self._service_process_bindings.get(binding_id)
            if active is not None:
                return ServiceProcessBindingSnapshot(active.identity)
            return self._service_process_tombstones.get(binding_id)

    def close_service_process_binding(
        self,
        binding_id: str,
        *,
        expected_identity: ServiceProcessBindingIdentity,
        closed_at: datetime,
        action_id: str,
        transition_ordinal: int = 0,
    ) -> ServiceProcessBindingSnapshot:
        """Close one ownership relation before either owning lifecycle closes."""

        if not action_id:
            raise ValueError("Service/process binding closure requires an action_id")
        if transition_ordinal < 0:
            raise ValueError("Service/process binding closure ordinal must be non-negative")
        at = ensure_utc(closed_at)
        with self._catalog_lock:
            active = self._service_process_bindings.get(binding_id)
            if active is None:
                tombstone = self._service_process_tombstones.get(binding_id)
                if tombstone is None:
                    raise StateError(f"Unknown service/process binding {binding_id}")
                if tombstone.identity != expected_identity:
                    raise StateError(
                        f"Service/process binding {binding_id} identity changed before close"
                    )
                if (
                    tombstone.closed_at == at
                    and tombstone.close_action_id == action_id
                    and tombstone.close_transition_ordinal == transition_ordinal
                ):
                    return tombstone
                raise StateError(f"Service/process binding {binding_id} is already closed")
            if active.identity != expected_identity:
                raise StateError(
                    f"Service/process binding {binding_id} identity changed before close"
                )
            service = self._services.get(active.identity.service_object_id)
            if service is None:
                raise StateError("Service/process binding owner disappeared before close")
            hostname = service.identity.hostname
        with self._host_lanes.lane(hostname), self._catalog_lock, self._index_lock:
            active = self._service_process_bindings.get(binding_id)
            if active is None:
                tombstone = self._service_process_tombstones.get(binding_id)
                if tombstone is not None:
                    if (
                        tombstone.identity == expected_identity
                        and tombstone.closed_at == at
                        and tombstone.close_action_id == action_id
                        and tombstone.close_transition_ordinal == transition_ordinal
                    ):
                        return tombstone
                    raise StateError(f"Service/process binding {binding_id} is already closed")
                raise StateError(f"Unknown service/process binding {binding_id}")
            if active.identity != expected_identity:
                raise StateError(
                    f"Service/process binding {binding_id} identity changed before close"
                )
            self._reject_behind_watermark(at, "service/process binding close")
            if at < active.identity.bound_at:
                raise StateError("Service/process binding close precedes binding start")
            for store, object_id in (
                (self._service_processes_by_service, active.identity.service_object_id),
                (self._service_bindings_by_process, active.identity.process_object_id),
            ):
                aggregate = store.get(object_id)
                if aggregate is None:
                    raise StateError("Missing service/process closure aggregate")
                aggregate.close(at)
            snapshot = ServiceProcessBindingSnapshot(
                identity=active.identity,
                closed_at=at,
                close_action_id=action_id,
                close_transition_ordinal=transition_ordinal,
            )
            self._service_process_bindings.pop(binding_id)
            self._service_process_tombstones[binding_id] = snapshot
            handle = self._service_process_tombstones.handle_for(binding_id)
            self._service_process_tombstone_deadlines.set(
                handle,
                at + self._closed_retention,
            )
            self._active_service_process_bindings -= 1
            return snapshot

    def _validate_session_transport_binding_locked(
        self,
        identity: TransportSessionBindingIdentity,
    ) -> None:
        session = self._sessions.get(identity.session_object_id)
        if session is None:
            raise StateError(f"Unknown session lifecycle object {identity.session_object_id}")
        self._reject_behind_watermark(identity.bound_at, "transport/session binding")
        if not self._entry_active_at(session, identity.bound_at):
            raise StateError("Transport/session binding session is not active")
        if session.close_barrier is not None:
            raise StateError("Transport/session binding session accepted a close barrier")

    def _register_session_transport_binding_locked(
        self,
        identity: TransportSessionBindingIdentity,
    ) -> None:
        self._validate_session_transport_binding_locked(identity)
        aggregate = self._transport_bindings_by_session.get(identity.session_object_id)
        if aggregate is None:
            aggregate = _DependentClosureAggregate()
            self._transport_bindings_by_session[identity.session_object_id] = aggregate
        aggregate.register()
        self._live_transport_bindings_by_session[identity.binding_id] = _LiveTransportBinding(
            binding_id=identity.binding_id,
            transport_object_id=identity.transport_object_id,
            session_object_id=identity.session_object_id,
        )

    def _register_transport_session_binding_locked(
        self,
        identity: TransportSessionBindingIdentity,
    ) -> TransportSessionBindingSnapshot:
        existing = self._transport_session_bindings.get(identity.binding_id)
        if existing is not None:
            if existing.identity == identity:
                return TransportSessionBindingSnapshot(existing.identity)
            raise StateError(f"Transport/session binding {identity.binding_id} is already used")
        tombstone = self._transport_session_tombstones.get(identity.binding_id)
        if tombstone is not None:
            if tombstone.identity == identity:
                return tombstone
            raise StateError(f"Transport/session binding {identity.binding_id} is already used")
        transport = self._validate_transport_session_binding_locked(identity)
        self._transport_session_bindings[identity.binding_id] = _TransportSessionBindingEntry(
            identity
        )
        transport.active_binding_count += 1
        self._active_transport_session_bindings += 1
        return TransportSessionBindingSnapshot(identity)

    def _validate_transport_session_binding_locked(
        self,
        identity: TransportSessionBindingIdentity,
    ) -> _TransportEntry:
        transport = self._transports.get(identity.transport_object_id)
        if transport is None:
            raise StateError(f"Unknown transport lifecycle object {identity.transport_object_id}")
        self._reject_behind_watermark(identity.bound_at, "transport/session binding")
        if not self._entry_active_at(transport, identity.bound_at):
            raise StateError("Transport/session binding transport is not active")
        if identity.bound_at >= transport.identity.close_deadline:
            raise StateError("Transport/session binding must start before transport close deadline")
        if transport.close_barrier is not None:
            raise StateError("Transport/session binding transport accepted a close barrier")
        return transport

    def _validate_transport_session_binding_close_locked(
        self,
        identity: TransportSessionBindingIdentity,
        closed_at: datetime,
    ) -> None:
        """Preflight the transport-owned half before any cross-shard mutation."""

        active = self._transport_session_bindings.get(identity.binding_id)
        if active is None or active.identity != identity:
            raise StateError(
                f"Transport/session binding {identity.binding_id} identity changed before close"
            )
        self._reject_behind_watermark(closed_at, "transport/session binding close")
        if closed_at < identity.bound_at:
            raise StateError("Transport/session binding close precedes binding start")
        transport = self._transports.get(identity.transport_object_id)
        if transport is None:
            raise StateError("Transport/session binding transport disappeared")
        if closed_at > transport.identity.close_deadline:
            raise StateError("Transport/session binding closes after transport deadline")

    def _close_transport_session_binding_locked(
        self,
        binding_id: str,
        *,
        expected_identity: TransportSessionBindingIdentity,
        closed_at: datetime,
        action_id: str,
        transition_ordinal: int,
    ) -> TransportSessionBindingSnapshot:
        active = self._transport_session_bindings.get(binding_id)
        if active is None:
            tombstone = self._transport_session_tombstones.get(binding_id)
            if tombstone is None:
                raise StateError(f"Unknown transport/session binding {binding_id}")
            if tombstone.identity != expected_identity:
                raise StateError(
                    f"Transport/session binding {binding_id} identity changed before close"
                )
            if (
                tombstone.closed_at == closed_at
                and tombstone.close_action_id == action_id
                and tombstone.close_transition_ordinal == transition_ordinal
            ):
                return tombstone
            raise StateError(f"Transport/session binding {binding_id} is already closed")
        self._validate_transport_session_binding_close_locked(expected_identity, closed_at)
        transport = self._transports.get(active.identity.transport_object_id)
        assert transport is not None
        snapshot = TransportSessionBindingSnapshot(
            identity=active.identity,
            closed_at=closed_at,
            close_action_id=action_id,
            close_transition_ordinal=transition_ordinal,
        )
        self._transport_session_bindings.pop(binding_id)
        self._transport_session_tombstones[binding_id] = snapshot
        handle = self._transport_session_tombstones.handle_for(binding_id)
        self._transport_session_tombstone_deadlines.set(
            handle,
            closed_at + self._closed_retention,
        )
        transport.active_binding_count -= 1
        self._active_transport_session_bindings -= 1
        return snapshot

    def _close_session_transport_binding_locked(
        self,
        identity: TransportSessionBindingIdentity,
        closed_at: datetime,
    ) -> None:
        aggregate = self._transport_bindings_by_session.get(identity.session_object_id)
        if aggregate is None:
            raise StateError("Missing transport/session closure aggregate")
        aggregate.close(closed_at)
        self._live_transport_bindings_by_session.pop(identity.binding_id, None)

    def _validate_session_transport_binding_close_locked(
        self,
        identity: TransportSessionBindingIdentity,
    ) -> None:
        """Preflight the session-owned half before any cross-shard mutation."""

        aggregate = self._transport_bindings_by_session.get(identity.session_object_id)
        if aggregate is None or aggregate.unclosed <= 0:
            raise StateError("Missing active transport/session closure aggregate")
        live = self._live_transport_bindings_by_session.get(identity.binding_id)
        if (
            live is None
            or live.transport_object_id != identity.transport_object_id
            or live.session_object_id != identity.session_object_id
        ):
            raise StateError(
                f"Transport/session binding {identity.binding_id} session membership changed"
            )

    def transport_session_binding(
        self,
        binding_id: str,
    ) -> TransportSessionBindingSnapshot | None:
        """Return one active or retained transport/session binding by exact ID."""

        with self._catalog_lock:
            active = self._transport_session_bindings.get(binding_id)
            if active is not None:
                return TransportSessionBindingSnapshot(active.identity)
            return self._transport_session_tombstones.get(binding_id)

    def transport_binding_page(
        self,
        transport_object_id: str,
        *,
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[TransportSessionBindingSnapshot, ...], int | None]:
        """Return one bounded exact page of active bindings for a transport."""

        with self._catalog_lock:
            handles, cursor = self._transport_session_bindings.find_handle_page(
                "transport",
                transport_object_id,
                after_handle=after_handle,
                limit=limit,
            )
            return (
                tuple(
                    TransportSessionBindingSnapshot(
                        self._transport_session_bindings.get_by_handle(handle).identity
                    )
                    for handle in handles
                ),
                cursor,
            )

    def session_transport_binding_id_page(
        self,
        session_object_id: str,
        *,
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[str, ...], int | None]:
        """Return one bounded session-side page of active cross-host binding IDs."""

        with self._catalog_lock:
            handles, cursor = self._live_transport_bindings_by_session.find_handle_page(
                "session",
                session_object_id,
                after_handle=after_handle,
                limit=limit,
            )
            return (
                tuple(
                    self._live_transport_bindings_by_session.get_by_handle(handle).binding_id
                    for handle in handles
                ),
                cursor,
            )

    def session_member_close_deadline(self, session_object_id: str) -> datetime | None:
        """Return the latest member close once every exact member is closed.

        Registration and closure maintain one compact aggregate, so this query
        examines a single entry regardless of session-member history.
        """

        with self._catalog_lock:
            self._dependent_aggregate_candidates_inspected += 1
            aggregate = self._members_by_session.get(session_object_id)
            if aggregate is None:
                return None
            if aggregate.unclosed:
                raise StateError(
                    f"Lifecycle session {session_object_id} still has "
                    f"{aggregate.unclosed} unclosed members"
                )
            return aggregate.latest_closed_at

    def process_child_close_deadline(self, process_object_id: str) -> datetime | None:
        """Return the latest direct-child close once every exact child is closed."""

        with self._catalog_lock:
            self._dependent_aggregate_candidates_inspected += 1
            aggregate = self._children_by_parent.get(process_object_id)
            if aggregate is None:
                return None
            if aggregate.unclosed:
                raise StateError(
                    f"Lifecycle process {process_object_id} still has "
                    f"{aggregate.unclosed} unclosed children"
                )
            return aggregate.latest_closed_at

    def process_latest_closed_child_at(self, process_object_id: str) -> datetime | None:
        """Return the latest retained direct-child close even while siblings remain live."""

        with self._catalog_lock:
            self._dependent_aggregate_candidates_inspected += 1
            aggregate = self._children_by_parent.get(process_object_id)
            return None if aggregate is None else aggregate.latest_closed_at

    def session_latest_closed_member_at(self, session_object_id: str) -> datetime | None:
        """Return the latest retained member close even while other members remain live."""

        with self._catalog_lock:
            self._dependent_aggregate_candidates_inspected += 1
            aggregate = self._members_by_session.get(session_object_id)
            return None if aggregate is None else aggregate.latest_closed_at

    def resource_lease_deadline(self, subject: LifecycleEntityRef) -> datetime | None:
        """Return one subject's exact cached live resource-lease deadline."""

        with self._catalog_lock:
            return self._resource_lease_deadline_for(subject)

    def live_child_process_page(
        self,
        parent_object_id: str,
        *,
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[ProcessLifecycleSnapshot, ...], int | None]:
        """Return one bounded exact page of still-live direct child processes."""

        with self._catalog_lock:
            handles, cursor = self._live_children.find_handle_page(
                "parent",
                parent_object_id,
                after_handle=after_handle,
                limit=limit,
            )
            children: list[ProcessLifecycleSnapshot] = []
            for handle in handles:
                binding = self._live_children.get_by_handle(handle)
                child = self._processes.get(binding.child_object_id)
                if child is not None and child.closed_at is None:
                    children.append(self._process_snapshot(child))
            return tuple(children), cursor

    def live_session_member_process_page(
        self,
        session_object_id: str,
        *,
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[ProcessLifecycleSnapshot, ...], int | None]:
        """Return one bounded indexed page of still-live session members.

        The cursor is valid while its binding remains live. A caller that
        closes the returned members should request the first page again; each
        successful close removes that exact binding, so repeated first-page
        drains remain bounded and terminate without scanning retained history.
        """

        with self._catalog_lock:
            handles, cursor = self._live_session_members.find_handle_page(
                "session",
                session_object_id,
                after_handle=after_handle,
                limit=limit,
            )
            self._dependent_aggregate_candidates_inspected += len(handles)
            members: list[ProcessLifecycleSnapshot] = []
            for handle in handles:
                binding = self._live_session_members.get_by_handle(handle)
                process = self._processes.get(binding.process_object_id)
                if process is not None and process.closed_at is None:
                    members.append(self._process_snapshot(process))
            return tuple(members), cursor

    def live_child_service_page(
        self,
        parent_service_object_id: str,
        *,
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[ServiceInstanceLifecycleSnapshot, ...], int | None]:
        """Return one bounded indexed page of live child service instances."""

        with self._catalog_lock:
            handles, cursor = self._live_service_children.find_handle_page(
                "parent",
                parent_service_object_id,
                after_handle=after_handle,
                limit=limit,
            )
            children: list[ServiceInstanceLifecycleSnapshot] = []
            for handle in handles:
                binding = self._live_service_children.get_by_handle(handle)
                child = self._services.get(binding.child_object_id)
                if child is not None and child.closed_at is None:
                    children.append(self._service_snapshot(child))
            return tuple(children), cursor

    def service_process_binding_page(
        self,
        *,
        service_object_id: str = "",
        process_object_id: str = "",
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[ServiceProcessBindingSnapshot, ...], int | None]:
        """Return one bounded exact page for either side of service ownership."""

        if bool(service_object_id) == bool(process_object_id):
            raise ValueError("Specify exactly one service or process object for binding pages")
        index_name = "service" if service_object_id else "process"
        object_id = service_object_id or process_object_id
        with self._catalog_lock:
            handles, cursor = self._service_process_bindings.find_handle_page(
                index_name,
                object_id,
                after_handle=after_handle,
                limit=limit,
            )
            return (
                tuple(
                    ServiceProcessBindingSnapshot(
                        self._service_process_bindings.get_by_handle(handle).identity
                    )
                    for handle in handles
                ),
                cursor,
            )

    def service_child_close_deadline(self, service_object_id: str) -> datetime | None:
        """Return the latest child-service close after every child closes."""

        with self._catalog_lock:
            self._dependent_aggregate_candidates_inspected += 1
            aggregate = self._service_children_by_parent.get(service_object_id)
            if aggregate is None:
                return None
            if aggregate.unclosed:
                raise StateError(
                    f"Lifecycle service {service_object_id} still has "
                    f"{aggregate.unclosed} unclosed child services"
                )
            return aggregate.latest_closed_at

    def service_process_close_deadline(self, service_object_id: str) -> datetime | None:
        """Return the latest process-unbind time after every binding closes."""

        with self._catalog_lock:
            self._dependent_aggregate_candidates_inspected += 1
            aggregate = self._service_processes_by_service.get(service_object_id)
            if aggregate is None:
                return None
            if aggregate.unclosed:
                raise StateError(
                    f"Lifecycle service {service_object_id} still has "
                    f"{aggregate.unclosed} active process bindings"
                )
            return aggregate.latest_closed_at

    def session_transport_close_deadline(self, session_object_id: str) -> datetime | None:
        """Return the latest transport-unbind time after every binding closes."""

        with self._catalog_lock:
            self._dependent_aggregate_candidates_inspected += 1
            aggregate = self._transport_bindings_by_session.get(session_object_id)
            if aggregate is None:
                return None
            if aggregate.unclosed:
                raise StateError(
                    f"Lifecycle session {session_object_id} still has "
                    f"{aggregate.unclosed} active transport bindings"
                )
            return aggregate.latest_closed_at

    def get_session_by_handle(self, handle: int) -> SessionLifecycleSnapshotView | None:
        """Return one session through an already-authorized compact locator."""

        with self._catalog_lock:
            entry = self._sessions.get_by_handle(handle)
            return None if entry is None else self._session_snapshot(entry)

    def process_at(
        self,
        object_id: str,
        canonical_time: datetime,
    ) -> ProcessLifecycleSnapshot | None:
        """Return one exact process only when its interval contains canonical time."""

        at = ensure_utc(canonical_time)
        with self._catalog_lock:
            entry = self._processes.get(object_id)
        if entry is None:
            return None
        with self._host_lanes.lane(entry.identity.hostname), self._catalog_lock:
            if not self._same_entry(self._processes.get(object_id), entry):
                return None
            if entry is None or not self._entry_active_at(entry, at):
                return None
            return self._process_snapshot(entry)

    def session_at(
        self,
        object_id: str,
        canonical_time: datetime,
    ) -> SessionLifecycleSnapshotView | None:
        """Return one exact session only when its interval contains canonical time."""

        at = ensure_utc(canonical_time)
        with self._catalog_lock:
            entry = self._sessions.get(object_id)
            if entry is None or not self._entry_active_at(entry, at):
                return None
            return self._session_snapshot(entry)

    def session_at_by_handle(
        self,
        handle: int,
        canonical_time: datetime,
    ) -> SessionLifecycleSnapshotView | None:
        """Resolve one already-authorized session locator at canonical time."""

        at = ensure_utc(canonical_time)
        with self._catalog_lock:
            entry = self._sessions.get_by_handle(handle)
            if entry is None or not self._entry_active_at(entry, at):
                return None
            return self._session_snapshot(entry)

    def process_for_pid_at(
        self,
        hostname: str,
        pid: int,
        canonical_time: datetime,
    ) -> ProcessLifecycleSnapshot | None:
        """Resolve PID reuse through host, PID, and explicit canonical time."""

        at = ensure_utc(canonical_time)
        lane = self._host_lanes.existing_lane(hostname)
        if lane is None:
            return None
        with lane, self._catalog_lock, self._index_lock:
            handle = self._process_starts.latest_at_or_before((hostname, pid), at)
            entry = self._processes.get_by_handle(handle) if handle is not None else None
            if entry is None or not self._entry_active_at(entry, at):
                return None
            return self._process_snapshot(entry)

    def session_for_logon_at(
        self,
        hostname: str,
        logon_id: str,
        canonical_time: datetime,
    ) -> SessionLifecycleSnapshotView | None:
        """Resolve LogonID reuse through host, LogonID, and canonical time."""

        at = ensure_utc(canonical_time)
        lane = self._host_lanes.existing_lane(hostname)
        if lane is None:
            return None
        with lane, self._catalog_lock, self._index_lock:
            handle = self._session_starts.latest_at_or_before(
                self._session_group(hostname, logon_id),
                at,
            )
            entry = self._sessions.get_by_handle(handle) if handle is not None else None
            if entry is None or not self._entry_active_at(entry, at):
                return None
            return self._session_snapshot(entry)

    def transition(self, transition_id: str) -> LifecycleTransition | None:
        """Return one append-only transition by exact identity."""

        with self._catalog_lock:
            return self._transitions.get(transition_id)

    def session_handle_for(self, object_id: str) -> int:
        """Return one packed session handle for the outer exact router."""

        with self._catalog_lock:
            return self._sessions.handle_for(object_id)

    def session_row_for_handle(self, handle: int) -> bytes:
        """Return one immutable packed row for a globally authorized route."""

        with self._catalog_lock:
            entry = self._sessions.get_by_handle(handle)
            if entry is None:
                raise StateError(f"Unknown packed lifecycle session handle {handle}")
            return self._sessions.row(handle, entry.generation)

    def session_start_transition(
        self,
        handle: int,
        transition_id: str,
    ) -> LifecycleTransition | None:
        """Reconstruct one packed session start transition by compact locator."""

        with self._catalog_lock:
            entry = self._sessions.get_by_handle(handle)
            if entry is None:
                return None
            transition = entry._start_transition()
            return transition if transition.transition_id == transition_id else None

    def service_handle_for(self, object_id: str) -> int:
        """Return one packed service handle for the outer exact router."""

        with self._catalog_lock:
            return self._services.handle_for(object_id)

    def service_start_transition(
        self,
        handle: int,
        transition_id: str,
    ) -> LifecycleTransition | None:
        """Reconstruct one packed service start transition by compact locator."""

        with self._catalog_lock:
            entry = self._services.get_by_handle(handle)
            if entry is None:
                return None
            transition = entry._start_transition()
            return transition if transition.transition_id == transition_id else None

    def transport_handle_for(self, object_id: str) -> int:
        """Return one packed transport handle for the outer exact router."""

        with self._catalog_lock:
            return self._transports.handle_for(object_id)

    def transport_start_transition(
        self,
        handle: int,
        transition_id: str,
    ) -> LifecycleTransition | None:
        """Reconstruct one packed transport start transition by compact locator."""

        with self._catalog_lock:
            entry = self._transports.get_by_handle(handle)
            if entry is None:
                return None
            transition = entry._start_transition()
            return transition if transition.transition_id == transition_id else None

    def hold(self, hold_id: str) -> LifecycleHold | None:
        """Return one hold by exact identity."""

        with self._catalog_lock:
            return self._holds.get(hold_id)

    def close_barrier(self, barrier_id: str) -> LifecycleCloseBarrier | None:
        """Return one close barrier by exact identity."""

        with self._catalog_lock:
            return self._barriers.get(barrier_id)

    def closure_ticket(self, ticket_id: str) -> LifecycleClosureTicket | None:
        """Return one closure ticket by exact identity."""

        with self._catalog_lock:
            return self._tickets.get(ticket_id)

    def record_dependent(
        self,
        subject: LifecycleEntityRef,
        *,
        transition_id: str,
        canonical_time: datetime,
        action_id: str,
        reason: str = "",
        transition_ordinal: int = 0,
    ) -> LifecycleTransition:
        """Append a dependent transition before the entity's close barrier."""

        transition = LifecycleTransition(
            transition_id=transition_id,
            subject=subject,
            kind="dependent",
            canonical_time=canonical_time,
            action_id=action_id,
            reason=reason,
            transition_ordinal=transition_ordinal,
        )
        with self._locked_subject(subject) as entry, self._catalog_lock:
            existing = self._transitions.get(transition_id)
            if existing is not None:
                if existing == transition:
                    return existing
                raise StateError(f"Lifecycle transition ID {transition_id} is already in use")
            self._reject_behind_watermark(transition.canonical_time, "dependent transition")
            self._validate_dependent_time(entry, transition.canonical_time)
            self._append_transition(entry, transition)
            return transition

    def add_hold(self, hold: LifecycleHold) -> LifecycleHold:
        """Append one typed hold before closure resolution."""

        transition = LifecycleTransition(
            transition_id=f"{hold.hold_id}:acquired",
            subject=hold.subject,
            kind="hold_acquired",
            canonical_time=hold.acquired_at,
            action_id=hold.action_id,
            reason=hold.reason,
            transition_ordinal=hold.transition_ordinal,
        )
        with self._locked_subject(hold.subject) as entry, self._catalog_lock:
            existing = self._holds.get(hold.hold_id)
            if existing is not None:
                if existing == hold:
                    return existing
                raise StateError(f"Lifecycle hold ID {hold.hold_id} is already in use")
            self._reject_behind_watermark(hold.acquired_at, "hold acquisition")
            if entry.close_barrier is not None:
                raise StateError(
                    f"Cannot add hold {hold.hold_id}: lifecycle {hold.subject.object_id} "
                    "already has a close barrier"
                )
            self._validate_dependent_time(entry, hold.acquired_at)
            if entry.closed_at is not None and hold.hold_until >= entry.closed_at:
                raise StateError(
                    f"Lifecycle hold {hold.hold_id} extends beyond an already closed entity"
                )
            if (
                isinstance(entry, _TransportEntry)
                and hold.hold_until > entry.identity.close_deadline
            ):
                raise StateError("Transport lifecycle hold extends beyond its canonical deadline")
            self._validate_transition_claim(transition)
            self._append_hold(entry, hold)
            self._append_transition(entry, transition, claim_validated=True)
            return hold

    def request_close(
        self,
        barrier: LifecycleCloseBarrier,
        *,
        ticket_id: str,
    ) -> LifecycleClosureTicket:
        """Freeze a close barrier and resolve its effective canonical close time."""

        with self._locked_subject(barrier.subject) as entry, self._catalog_lock:
            prior_barrier = self._barriers.get(barrier.barrier_id)
            if prior_barrier is not None:
                if prior_barrier != barrier:
                    raise StateError(
                        f"Lifecycle close barrier ID {barrier.barrier_id} is already in use"
                    )
                if entry.closure_ticket is None or entry.closure_ticket.ticket_id != ticket_id:
                    raise StateError(
                        f"Close barrier {barrier.barrier_id} already resolved to another ticket"
                    )
                return entry.closure_ticket

            self._reject_behind_watermark(barrier.requested_at, "close barrier")
            if entry.close_barrier is not None:
                raise StateError(
                    f"Lifecycle {barrier.subject.object_id} already has close barrier "
                    f"{entry.close_barrier.barrier_id}"
                )
            if entry.closed_at is not None:
                raise StateError(f"Lifecycle {barrier.subject.object_id} is already closed")
            if barrier.requested_at < self._entry_started_at(entry):
                raise StateError(
                    f"Lifecycle close for {barrier.subject.object_id} precedes its start"
                )
            if (
                isinstance(entry, _TransportEntry)
                and barrier.requested_at != entry.identity.close_deadline
            ):
                raise StateError(
                    "Transport close barrier must equal the canonical network-plan deadline"
                )
            latest_dependent_at = entry.state.latest_dependent_at
            if latest_dependent_at is not None and latest_dependent_at >= barrier.requested_at:
                raise StateError(
                    f"Lifecycle close barrier for {barrier.subject.object_id} precedes "
                    "an existing dependent transition"
                )

            latest_hold = entry.state.latest_hold_until or barrier.requested_at
            latest_resource_lease = self._resource_lease_deadline_for(barrier.subject)
            latest_dependency = max(
                latest_hold,
                latest_resource_lease or barrier.requested_at,
            )
            if barrier.authority == "authoritative" and latest_dependency > barrier.requested_at:
                if latest_resource_lease is not None and latest_resource_lease > latest_hold:
                    raise StateError(
                        f"Authoritative close for {barrier.subject.object_id} at "
                        f"{barrier.requested_at.isoformat()} conflicts with a resource lease "
                        f"through {latest_resource_lease.isoformat()}"
                    )
                raise StateError(
                    f"Authoritative close for {barrier.subject.object_id} at "
                    f"{barrier.requested_at.isoformat()} conflicts with a hold through "
                    f"{latest_hold.isoformat()}"
                )
            effective_at = max(barrier.requested_at, latest_dependency)
            ticket = LifecycleClosureTicket(
                ticket_id=ticket_id,
                barrier_id=barrier.barrier_id,
                subject=barrier.subject,
                requested_at=barrier.requested_at,
                effective_at=effective_at,
                authority=barrier.authority,
                action_id=barrier.action_id,
            )
            requested_transition = LifecycleTransition(
                transition_id=f"{barrier.barrier_id}:requested",
                subject=barrier.subject,
                kind="close_requested",
                canonical_time=barrier.requested_at,
                action_id=barrier.action_id,
                transition_ordinal=0,
            )
            scheduled_transition = LifecycleTransition(
                transition_id=f"{ticket.ticket_id}:scheduled",
                subject=barrier.subject,
                kind="close_scheduled",
                canonical_time=ticket.effective_at,
                action_id=barrier.action_id,
                transition_ordinal=1,
            )
            self._validate_barrier_claim(barrier)
            self._validate_ticket_claim(ticket)
            self._validate_transition_claim(requested_transition)
            self._validate_transition_claim(scheduled_transition)

            self._ensure_full_state(entry)
            entry.state.close_barrier = barrier
            entry.state.closure_ticket = ticket
            self._barriers[barrier.barrier_id] = barrier
            self._tickets[ticket.ticket_id] = ticket
            self._append_transition(entry, requested_transition, claim_validated=True)
            self._append_transition(entry, scheduled_transition, claim_validated=True)
            return ticket

    def close(
        self,
        ticket_id: str,
    ) -> (
        ProcessLifecycleSnapshot
        | SessionLifecycleSnapshotView
        | ServiceInstanceLifecycleSnapshot
        | TransportLifecycleSnapshot
    ):
        """Append the terminal transition owned by one resolved closure ticket."""

        with self._catalog_lock:
            ticket = self._tickets.get(ticket_id)
        if ticket is None:
            raise StateError(f"Unknown lifecycle closure ticket {ticket_id}")
        with self._locked_subject(ticket.subject) as entry, self._catalog_lock:
            if self._tickets.get(ticket_id) is not ticket:
                raise StateError(f"Lifecycle closure ticket {ticket_id} changed during close")
            if entry.closed_at is not None:
                if entry.closure_ticket == ticket and entry.closed_at == ticket.effective_at:
                    return self._snapshot(entry)
                raise StateError(f"Lifecycle {ticket.subject.object_id} is already closed")
            self._reject_behind_watermark(ticket.effective_at, "lifecycle close")
            transition = LifecycleTransition(
                transition_id=f"{ticket.ticket_id}:closed",
                subject=ticket.subject,
                kind="closed",
                canonical_time=ticket.effective_at,
                action_id=ticket.action_id,
                transition_ordinal=2,
            )
            self._validate_descendants_closed(ticket.subject, ticket.effective_at)
            self._validate_transition_claim(transition)
            entry.state.closed_at = ticket.effective_at
            self._append_transition(entry, transition, claim_validated=True)
            if ticket.subject.kind == "process":
                assert isinstance(entry, _ProcessEntry)
                self._record_process_closed(entry, ticket.effective_at)
                self._live_processes -= 1
            elif ticket.subject.kind == "session":
                self._live_sessions -= 1
            elif ticket.subject.kind == "service":
                assert isinstance(entry, _ServiceEntry)
                self._record_service_closed(entry, ticket.effective_at)
                self._live_service_instances -= 1
            else:
                self._live_transports -= 1
            self._schedule_retention(ticket.subject, entry)
            return self._snapshot(entry)

    def add_retention_lease(self, lease: LifecycleRetentionLease) -> LifecycleRetentionLease:
        """Retain one exact identity until a bounded canonical deadline."""

        with self._locked_subject(lease.subject) as entry, self._catalog_lock, self._index_lock:
            existing = self._leases.get(lease.lease_id)
            if existing is not None:
                if existing == lease:
                    return existing
                raise StateError(f"Lifecycle retention lease ID {lease.lease_id} is already in use")
            if self._watermark is not None and lease.retain_until <= self._watermark:
                raise StateError(
                    f"Lifecycle retention lease {lease.lease_id} does not extend past "
                    "the current watermark"
                )
            self._leases[lease.lease_id] = lease
            handle = self._leases.handle_for(lease.lease_id)
            self._lease_deadlines.set(handle, lease)
            self._set_retention_lease_deadline(lease, handle)
            if entry.closed_at is not None:
                self._schedule_retention(lease.subject, entry)
            return lease

    def release_retention_lease(self, lease_id: str) -> bool:
        """Release one explicit retention lease before its deadline."""

        with self._catalog_lock:
            lease = self._leases.get(lease_id)
            if lease is None:
                return False
            entry = self._require_entry(lease.subject)
            hostname = entry.identity.hostname
        with self._host_lanes.lane(hostname), self._catalog_lock, self._index_lock:
            if self._leases.get(lease_id) is not lease or not self._same_entry(
                self._entry(lease.subject), entry
            ):
                return False
            handle = self._leases.handle_for(lease_id)
            self._remove_retention_lease_deadline(lease, handle)
            self._leases.pop(lease_id)
            self._lease_deadlines.remove(handle)
            if entry.closed_at is not None:
                self._schedule_retention(lease.subject, entry)
            return True

    def acquire_foreground_lease(
        self,
        lease: LifecycleForegroundLease,
    ) -> LifecycleForegroundLease:
        """Acquire one exact shell foreground resource without scanning peers."""

        with self._host_lanes.lane(lease.hostname), self._catalog_lock, self._index_lock:
            existing = self._foreground_leases.get(lease.lease_id)
            if existing is not None and self._resource_lease_expired(existing.lease.lease_until):
                self._remove_foreground_lease(lease.lease_id)
                existing = None
            if existing is not None:
                if existing.lease == lease:
                    return existing.lease
                raise StateError(
                    f"Lifecycle foreground lease ID {lease.lease_id} is already in use"
                )
            self._reject_behind_watermark(lease.acquired_at, "foreground lease acquisition")
            self._validate_foreground_lease_owner(lease, lease.acquired_at)
            owner = self._foreground_leases.find_one("resource", lease.resource_key)
            if owner is not None and owner.lease.lease_until > lease.acquired_at:
                raise LifecycleLeaseConflictError(
                    "Lifecycle foreground resource is already leased: "
                    f"{lease.resource_key!r} through {owner.lease.lease_until.isoformat()}"
                )
            if owner is not None:
                self._remove_foreground_lease(owner.lease.lease_id, route_removal=True)
            entry = _ForegroundLeaseEntry(
                lease=lease,
                commit_time=lease.acquired_at,
                commit_action_id=lease.action_id,
                commit_ordinal=lease.transition_ordinal,
            )
            self._foreground_leases[lease.lease_id] = entry
            handle = self._foreground_leases.handle_for(lease.lease_id)
            self._foreground_lease_deadlines.set(handle, lease.lease_until)
            self._set_resource_lease_deadline(lease, handle, singleton=False)
            return lease

    def foreground_lease(self, lease_id: str) -> LifecycleForegroundLease | None:
        """Return one foreground lease by exact lease identity."""

        with self._catalog_lock:
            entry = self._foreground_leases.get(lease_id)
            if entry is None:
                return None
            if self._resource_lease_expired(entry.lease.lease_until):
                return None
            return entry.lease

    def foreground_lease_for(
        self,
        resource_key: LifecycleForegroundLeaseKey,
    ) -> LifecycleForegroundLease | None:
        """Return the owner of one normalized foreground resource key."""

        with self._catalog_lock:
            entry = self._foreground_leases.find_one("resource", resource_key)
            if entry is None:
                return None
            if self._resource_lease_expired(entry.lease.lease_until):
                return None
            return entry.lease

    def renew_foreground_lease(
        self,
        lease_id: str,
        *,
        expected_lease_until: datetime,
        lease_until: datetime,
        canonical_time: datetime,
        action_id: str,
        concurrency_group_id: str | None = None,
        transition_ordinal: int = 0,
    ) -> LifecycleForegroundLease:
        """CAS-renew one foreground lease under deterministic commit ordering."""

        at = ensure_utc(canonical_time)
        expected = ensure_utc(expected_lease_until)
        deadline = ensure_utc(lease_until)
        with self._catalog_lock:
            current = self._foreground_leases.get(lease_id)
            if current is None or self._resource_lease_expired(current.lease.lease_until):
                raise StateError(f"Unknown lifecycle foreground lease {lease_id}")
            hostname = current.lease.hostname
        with self._host_lanes.lane(hostname), self._catalog_lock, self._index_lock:
            current = self._foreground_leases.get(lease_id)
            if current is None or self._resource_lease_expired(current.lease.lease_until):
                raise StateError(f"Unknown lifecycle foreground lease {lease_id}")
            self._reject_behind_watermark(at, "foreground lease renewal")
            if deadline < at:
                raise StateError("Lifecycle foreground lease renewal cannot end before its commit")
            commit_key = self._resource_lease_commit_key(at, action_id, transition_ordinal)
            if current.lease.lease_until == deadline and current.commit_key == commit_key:
                return current.lease
            if current.lease.lease_until != expected:
                raise StateError(
                    f"Lifecycle foreground lease {lease_id} deadline changed; expected "
                    f"{expected.isoformat()}, found {current.lease.lease_until.isoformat()}"
                )
            self._validate_resource_lease_commit(current.commit_key, commit_key, lease_id)
            if (
                concurrency_group_id is not None
                and concurrency_group_id != current.lease.concurrency_group_id
            ):
                raise StateError(
                    f"Lifecycle foreground lease {lease_id} concurrency group is immutable"
                )
            renewed = replace(
                current.lease,
                lease_until=deadline,
                action_id=action_id,
                concurrency_group_id=(
                    current.lease.concurrency_group_id
                    if concurrency_group_id is None
                    else concurrency_group_id
                ),
                transition_ordinal=transition_ordinal,
            )
            self._validate_foreground_lease_owner(renewed, at)
            self._foreground_leases[lease_id] = _ForegroundLeaseEntry(
                renewed,
                at,
                action_id,
                transition_ordinal,
            )
            self._foreground_lease_deadlines.set(
                self._foreground_leases.handle_for(lease_id),
                deadline,
            )
            self._set_resource_lease_deadline(
                renewed,
                self._foreground_leases.handle_for(lease_id),
                singleton=False,
            )
            return renewed

    def release_foreground_lease(
        self,
        lease_id: str,
        *,
        released_at: datetime,
        action_id: str,
        transition_ordinal: int = 0,
    ) -> bool:
        """Release one exact foreground lease without touching unrelated keys."""

        at = ensure_utc(released_at)
        with self._catalog_lock:
            current = self._foreground_leases.get(lease_id)
            if current is None or self._resource_lease_expired(current.lease.lease_until):
                return False
            hostname = current.lease.hostname
        with self._host_lanes.lane(hostname), self._catalog_lock, self._index_lock:
            current = self._foreground_leases.get(lease_id)
            if current is None or self._resource_lease_expired(current.lease.lease_until):
                return False
            self._reject_behind_watermark(at, "foreground lease release")
            if at < current.lease.acquired_at:
                raise StateError("Lifecycle foreground lease release precedes acquisition")
            commit_key = self._resource_lease_commit_key(at, action_id, transition_ordinal)
            self._validate_resource_lease_commit(current.commit_key, commit_key, lease_id)
            self._remove_foreground_lease(lease_id)
            return True

    def acquire_singleton_lease(
        self,
        lease: LifecycleSingletonLease,
    ) -> LifecycleSingletonLease:
        """Acquire one exact non-overlapping singleton application interval."""

        with self._host_lanes.lane(lease.hostname), self._catalog_lock, self._index_lock:
            existing = self._singleton_leases.get(lease.lease_id)
            if existing is not None and self._resource_lease_expired(existing.lease.lease_until):
                self._remove_singleton_lease(lease.lease_id)
                existing = None
            if existing is not None:
                if existing.lease == lease:
                    return existing.lease
                raise StateError(f"Lifecycle singleton lease ID {lease.lease_id} is already in use")
            self._reject_behind_watermark(lease.acquired_at, "singleton lease acquisition")
            self._validate_singleton_lease_owner(lease, lease.acquired_at)
            self._validate_singleton_lease_overlap(lease)
            entry = _SingletonLeaseEntry(
                lease=lease,
                commit_time=lease.acquired_at,
                commit_action_id=lease.action_id,
                commit_ordinal=lease.transition_ordinal,
            )
            self._singleton_leases[lease.lease_id] = entry
            handle = self._singleton_leases.handle_for(lease.lease_id)
            self._singleton_lease_starts.add(handle, lease.resource_key, lease.acquired_at)
            self._singleton_lease_deadlines.set(handle, lease.lease_until)
            self._set_resource_lease_deadline(lease, handle, singleton=True)
            return lease

    def singleton_lease(self, lease_id: str) -> LifecycleSingletonLease | None:
        """Return one singleton lease by exact lease identity."""

        with self._catalog_lock:
            entry = self._singleton_leases.get(lease_id)
            if entry is None:
                return None
            if self._resource_lease_expired(entry.lease.lease_until):
                return None
            return entry.lease

    def singleton_lease_for(
        self,
        resource_key: LifecycleSingletonLeaseKey,
        canonical_time: datetime,
    ) -> LifecycleSingletonLease | None:
        """Resolve the exact singleton owner at explicit canonical time."""

        at = ensure_utc(canonical_time)
        with self._catalog_lock, self._index_lock:
            handle = self._singleton_lease_starts.latest_at_or_before(resource_key, at)
            if handle is None:
                return None
            try:
                entry = self._singleton_leases.get_by_handle(handle)
            except KeyError:
                return None
            if self._resource_lease_expired(entry.lease.lease_until):
                return None
            return entry.lease if at < entry.lease.lease_until else None

    def singleton_lease_for_process(
        self,
        process_object_id: str,
    ) -> LifecycleSingletonLease | None:
        """Return the exact live singleton lease bound to one process object."""

        with self._catalog_lock:
            entry = self._singleton_leases.find_one("process", process_object_id)
            if entry is None or self._resource_lease_expired(entry.lease.lease_until):
                return None
            return entry.lease

    def bind_singleton_lease(
        self,
        lease_id: str,
        *,
        process_object_id: str,
        canonical_time: datetime,
        action_id: str,
        transition_ordinal: int = 0,
    ) -> LifecycleSingletonLease:
        """Bind a pre-allocation singleton claim to its realized process identity."""

        if not process_object_id:
            raise ValueError("Singleton lease binding requires a process_object_id")
        at = ensure_utc(canonical_time)
        with self._catalog_lock:
            current = self._singleton_leases.get(lease_id)
            if current is None or self._resource_lease_expired(current.lease.lease_until):
                raise StateError(f"Unknown lifecycle singleton lease {lease_id}")
            hostname = current.lease.hostname
        with self._host_lanes.lane(hostname), self._catalog_lock, self._index_lock:
            current = self._singleton_leases.get(lease_id)
            if current is None or self._resource_lease_expired(current.lease.lease_until):
                raise StateError(f"Unknown lifecycle singleton lease {lease_id}")
            self._reject_behind_watermark(at, "singleton lease binding")
            commit_key = self._resource_lease_commit_key(at, action_id, transition_ordinal)
            if (
                current.lease.process_object_id == process_object_id
                and current.commit_key == commit_key
            ):
                return current.lease
            if current.lease.process_object_id:
                raise StateError(
                    f"Lifecycle singleton lease {lease_id} is already bound to "
                    f"{current.lease.process_object_id}"
                )
            self._validate_resource_lease_commit(current.commit_key, commit_key, lease_id)
            bound = replace(
                current.lease,
                process_object_id=process_object_id,
                action_id=action_id,
                transition_ordinal=transition_ordinal,
            )
            self._validate_singleton_lease_owner(bound, at)
            self._singleton_leases[lease_id] = _SingletonLeaseEntry(
                bound,
                at,
                action_id,
                transition_ordinal,
            )
            self._set_resource_lease_deadline(
                bound,
                self._singleton_leases.handle_for(lease_id),
                singleton=True,
            )
            return bound

    def renew_singleton_lease(
        self,
        lease_id: str,
        *,
        expected_lease_until: datetime,
        lease_until: datetime,
        canonical_time: datetime,
        action_id: str,
        transition_ordinal: int = 0,
    ) -> LifecycleSingletonLease:
        """CAS-renew one singleton interval after bounded successor validation."""

        at = ensure_utc(canonical_time)
        expected = ensure_utc(expected_lease_until)
        deadline = ensure_utc(lease_until)
        with self._catalog_lock:
            current = self._singleton_leases.get(lease_id)
            if current is None or self._resource_lease_expired(current.lease.lease_until):
                raise StateError(f"Unknown lifecycle singleton lease {lease_id}")
            hostname = current.lease.hostname
        with self._host_lanes.lane(hostname), self._catalog_lock, self._index_lock:
            current = self._singleton_leases.get(lease_id)
            if current is None or self._resource_lease_expired(current.lease.lease_until):
                raise StateError(f"Unknown lifecycle singleton lease {lease_id}")
            self._reject_behind_watermark(at, "singleton lease renewal")
            if deadline < at:
                raise StateError("Lifecycle singleton lease renewal cannot end before its commit")
            commit_key = self._resource_lease_commit_key(at, action_id, transition_ordinal)
            if current.lease.lease_until == deadline and current.commit_key == commit_key:
                return current.lease
            if current.lease.lease_until != expected:
                raise StateError(
                    f"Lifecycle singleton lease {lease_id} deadline changed; expected "
                    f"{expected.isoformat()}, found {current.lease.lease_until.isoformat()}"
                )
            self._validate_resource_lease_commit(current.commit_key, commit_key, lease_id)
            renewed = replace(
                current.lease,
                lease_until=deadline,
                action_id=action_id,
                transition_ordinal=transition_ordinal,
            )
            self._validate_singleton_lease_owner(renewed, at)
            self._validate_singleton_lease_overlap(renewed, exclude_lease_id=lease_id)
            self._singleton_leases[lease_id] = _SingletonLeaseEntry(
                renewed,
                at,
                action_id,
                transition_ordinal,
            )
            self._singleton_lease_deadlines.set(
                self._singleton_leases.handle_for(lease_id),
                deadline,
            )
            self._set_resource_lease_deadline(
                renewed,
                self._singleton_leases.handle_for(lease_id),
                singleton=True,
            )
            return renewed

    def release_singleton_lease(
        self,
        lease_id: str,
        *,
        released_at: datetime,
        action_id: str,
        transition_ordinal: int = 0,
    ) -> bool:
        """Release one exact singleton lease and its compact temporal record."""

        at = ensure_utc(released_at)
        with self._catalog_lock:
            current = self._singleton_leases.get(lease_id)
            if current is None or self._resource_lease_expired(current.lease.lease_until):
                return False
            hostname = current.lease.hostname
        with self._host_lanes.lane(hostname), self._catalog_lock, self._index_lock:
            current = self._singleton_leases.get(lease_id)
            if current is None or self._resource_lease_expired(current.lease.lease_until):
                return False
            self._reject_behind_watermark(at, "singleton lease release")
            if at < current.lease.acquired_at:
                raise StateError("Lifecycle singleton lease release precedes acquisition")
            commit_key = self._resource_lease_commit_key(at, action_id, transition_ordinal)
            self._validate_resource_lease_commit(current.commit_key, commit_key, lease_id)
            self._remove_singleton_lease(lease_id)
            return True

    def retention_deadline(self, subject: LifecycleEntityRef) -> datetime | None:
        """Return the current bounded eviction deadline for a closed identity."""

        with self._locked_subject(subject), self._catalog_lock, self._index_lock:
            return self._retention_index(subject).deadline(self._handle_for(subject))

    def retention_deadline_by_handle(
        self,
        kind: Literal["service", "transport"],
        handle: int,
    ) -> datetime | None:
        """Return one packed entity deadline from its exact routed handle."""

        with self._catalog_lock, self._index_lock:
            index = (
                self._service_retention_deadlines
                if kind == "service"
                else self._transport_retention_deadlines
            )
            return index.deadline(handle)

    def advance_watermark(self, cutoff: datetime) -> tuple[LifecycleEntityRef, ...]:
        """Expire bounded leases and evict due closed identities.

        Watermarks are monotonic. The method returns exact references for
        observability and for future cold-ledger integration.
        """

        canonical_cutoff = ensure_utc(cutoff)
        with self._watermark_gate:
            with self._catalog_lock, self._index_lock:
                if self._watermark is not None and canonical_cutoff < self._watermark:
                    raise StateError(
                        f"Lifecycle watermark cannot move backward: "
                        f"{canonical_cutoff.isoformat()} < {self._watermark.isoformat()}"
                    )
                self._watermark = canonical_cutoff

            evicted: list[LifecycleEntityRef] = []
            while True:
                with self._catalog_lock, self._index_lock:
                    lease_handles = self._lease_deadlines.expire_page(canonical_cutoff)
                    for handle in lease_handles:
                        try:
                            lease = self._leases.get_by_handle(handle)
                        except KeyError:
                            continue
                        if self._leases.handle_for(lease.lease_id) != handle:
                            continue
                        self._remove_retention_lease_deadline(lease, handle)
                        self._leases.pop(lease.lease_id)
                        self._route_removals.append(("lease", lease.lease_id))
                if not lease_handles:
                    break

            with self._catalog_lock, self._index_lock:
                foreground_handles = self._foreground_lease_deadlines.expire_page(
                    canonical_cutoff,
                    limit=_RESOURCE_LEASE_EXPIRY_PAGE,
                )
                for handle in foreground_handles:
                    try:
                        entry = self._foreground_leases.get_by_handle(handle)
                    except KeyError:
                        continue
                    if self._foreground_leases.handle_for(entry.lease.lease_id) != handle:
                        continue
                    self._remove_foreground_lease(
                        entry.lease.lease_id,
                        route_removal=True,
                    )
                singleton_handles = self._singleton_lease_deadlines.expire_page(
                    canonical_cutoff,
                    limit=_RESOURCE_LEASE_EXPIRY_PAGE,
                )
                for handle in singleton_handles:
                    try:
                        entry = self._singleton_leases.get_by_handle(handle)
                    except KeyError:
                        continue
                    if self._singleton_leases.handle_for(entry.lease.lease_id) != handle:
                        continue
                    self._remove_singleton_lease(
                        entry.lease.lease_id,
                        route_removal=True,
                    )

            tombstone_indexes = (
                (
                    "service_process_binding",
                    self._service_process_tombstones,
                    self._service_process_tombstone_deadlines,
                ),
                (
                    "transport_session_binding",
                    self._transport_session_tombstones,
                    self._transport_session_tombstone_deadlines,
                ),
            )
            for route_kind, store, deadline_index in tombstone_indexes:
                while True:
                    with self._catalog_lock, self._index_lock:
                        handles = deadline_index.expire_page(canonical_cutoff)
                        for handle in handles:
                            try:
                                semantic_id = store.key_by_handle(handle)
                            except KeyError:
                                continue
                            store.pop(semantic_id, None)
                            self._route_removals.append((route_kind, semantic_id))
                            self._evicted_bindings += 1
                    if not handles:
                        break

            with self._catalog_lock, self._index_lock:
                if self._service_retention_deadlines.all_due(
                    canonical_cutoff,
                    expected_entries=len(self._services),
                ):
                    evicted.extend(self._bulk_evict_packed_kind("service"))
                if self._transport_retention_deadlines.all_due(
                    canonical_cutoff,
                    expected_entries=len(self._transports),
                ):
                    evicted.extend(self._bulk_evict_packed_kind("transport"))

            deadline_indexes = (
                ("process", self._process_retention_deadlines),
                ("session", self._session_retention_deadlines),
                ("service", self._service_retention_deadlines),
                ("transport", self._transport_retention_deadlines),
            )
            for kind, deadline_index in deadline_indexes:
                while True:
                    with self._catalog_lock, self._index_lock:
                        handles = deadline_index.expire_page(canonical_cutoff)
                        candidates: list[tuple[datetime, int, _LifecycleEntry]] = []
                        for handle in handles:
                            if kind == "process":
                                entry = self._processes.get_by_handle(handle)
                            elif kind == "session":
                                entry = self._sessions.get_by_handle(handle)
                            elif kind == "service":
                                try:
                                    entry = self._services.get_by_handle(handle)
                                except KeyError:
                                    entry = None
                            else:
                                try:
                                    entry = self._transports.get_by_handle(handle)
                                except KeyError:
                                    entry = None
                            if entry is None:
                                continue
                            deadline = self._retention_deadline_for(entry.identity.ref, entry)
                            candidates.append((deadline, handle, entry))
                    if not handles:
                        break
                    candidates.sort(key=lambda item: (item[0], item[2].identity.object_id))
                    for _prior_deadline, handle, entry in candidates:
                        with (
                            self._host_lanes.lane(entry.identity.hostname),
                            self._catalog_lock,
                            self._index_lock,
                        ):
                            if kind == "process":
                                current = self._processes.get_by_handle(handle)
                            elif kind == "session":
                                current = self._sessions.get_by_handle(handle)
                            elif kind == "service":
                                try:
                                    current = self._services.get_by_handle(handle)
                                except KeyError:
                                    current = None
                            else:
                                try:
                                    current = self._transports.get_by_handle(handle)
                                except KeyError:
                                    current = None
                            if not self._same_entry(current, entry):
                                continue
                            subject = entry.identity.ref
                            deadline = self._retention_deadline_for(subject, entry)
                            if deadline > canonical_cutoff:
                                self._retention_index(subject).set(handle, deadline)
                                continue
                            if self._resource_lease_deadline_for(subject) is not None:
                                self._retention_index(subject).set(
                                    handle,
                                    canonical_cutoff + timedelta(microseconds=1),
                                )
                                continue
                            self._evict(subject, entry)
                            evicted.append(subject)

            with self._catalog_lock, self._index_lock:
                self._compact_ledger_details(canonical_cutoff)
                self._process_starts.compact(max_groups=8)
                self._session_starts.compact(max_groups=8)
                self._service_starts.compact(max_groups=8)
                self._transport_starts.compact(max_groups=8)
                self._compact_indexes()
            return tuple(evicted)

    def drain_route_removals(self) -> tuple[tuple[str, str], ...]:
        """Return and clear semantic routes removed by a sealed watermark."""

        with self._catalog_lock:
            removals = tuple(self._route_removals)
            self._route_removals.clear()
            return removals

    def _compact_ledger_details(self, cutoff: datetime) -> None:
        """Stream one bounded page of sealed detail into entity aggregates."""

        ledger_floor = cutoff - self._ledger_detail_retention
        if self._ledger_floor is None or ledger_floor > self._ledger_floor:
            self._ledger_floor = ledger_floor
        assert self._ledger_floor is not None

        transition_handles = self._transition_times.pop_before(
            0,
            self._ledger_floor,
            limit=_LEDGER_COMPACTION_PAGE,
            inclusive=True,
        )
        for handle in transition_handles:
            try:
                transition_id = self._transitions.key_by_handle(handle)
            except KeyError:  # pragma: no cover - temporal/store mutation invariant
                continue
            self._transitions.pop(transition_id, None)
            self._route_removals.append(("transition", transition_id))
            self._compacted_transitions += 1

        hold_handles = self._hold_times.pop_before(
            0,
            self._ledger_floor,
            limit=_LEDGER_COMPACTION_PAGE,
            inclusive=True,
        )
        for handle in hold_handles:
            try:
                hold_id = self._holds.key_by_handle(handle)
            except KeyError:  # pragma: no cover - temporal/store mutation invariant
                continue
            self._holds.pop(hold_id, None)
            self._route_removals.append(("hold", hold_id))
            self._compacted_holds += 1

        self._transition_compaction_pending = (
            self._transition_times.latest_at_or_before(0, self._ledger_floor) is not None
        )
        self._hold_compaction_pending = (
            self._hold_times.latest_at_or_before(0, self._ledger_floor) is not None
        )

    def _compact_indexes(self) -> None:
        """Advance every partition-local rebuild with fixed watermark work."""

        compact_stores = (
            self._service_process_bindings,
            self._service_process_tombstones,
            self._transport_session_bindings,
            self._transport_session_tombstones,
            self._transitions,
            self._holds,
            self._barriers,
            self._tickets,
            self._leases,
            self._foreground_leases,
            self._singleton_leases,
            self._resource_lease_deadlines,
            self._retention_lease_deadlines,
            self._children_by_parent,
            self._live_children,
            self._live_session_members,
            self._members_by_session,
            self._service_children_by_parent,
            self._live_service_children,
            self._service_processes_by_service,
            self._service_bindings_by_process,
            self._transport_bindings_by_session,
            self._live_transport_bindings_by_session,
        )
        page = max(1, _PRIMARY_COMPACTION_PAGE // (len(compact_stores) + 2))
        self._processes.compact_primary(max_slots=page)
        self._sessions.compact_primary(max_slots=page)
        self._services.compact_primary(max_slots=page)
        self._transports.compact_primary(max_slots=page)
        for store in compact_stores:
            store.compact_primary(max_slots=page, force=not store)
        deadline_page = max(1, _PRIMARY_COMPACTION_PAGE // 3)
        self._process_retention_deadlines.compact(max_entries=deadline_page)
        self._session_retention_deadlines.compact(max_entries=deadline_page)
        self._service_retention_deadlines.compact(max_entries=deadline_page)
        self._transport_retention_deadlines.compact(max_entries=deadline_page)
        self._service_process_tombstone_deadlines.compact(max_entries=deadline_page)
        self._transport_session_tombstone_deadlines.compact(max_entries=deadline_page)
        self._lease_deadlines.compact(max_entries=deadline_page)
        self._foreground_lease_deadlines.compact(max_entries=deadline_page)
        self._singleton_lease_deadlines.compact(max_entries=deadline_page)
        self._singleton_lease_starts.compact(max_groups=8)

    def stats(self) -> LifecycleRegistryStats:
        """Return a constant-time live/retained registry census."""

        with self._catalog_lock, self._index_lock:
            process_entries = len(self._processes)
            session_entries = len(self._sessions)
            service_entries = len(self._services)
            transport_entries = len(self._transports)
            process_index = self._processes.metrics(estimate_bytes=True)
            session_index = self._sessions.metrics(estimate_bytes=True)
            service_index = self._services.metrics(estimate_bytes=True)
            transport_index = self._transports.metrics(estimate_bytes=True)
            service_binding_index = self._service_process_bindings.metrics(estimate_bytes=True)
            transport_binding_index = self._transport_session_bindings.metrics(estimate_bytes=True)
            process_temporal = self._process_starts.metrics(estimate_bytes=True)
            session_temporal = self._session_starts.metrics(estimate_bytes=True)
            service_temporal = self._service_starts.metrics(estimate_bytes=True)
            transport_temporal = self._transport_starts.metrics(estimate_bytes=True)
            transition_temporal = self._transition_times.metrics(estimate_bytes=True)
            hold_temporal = self._hold_times.metrics(estimate_bytes=True)
            process_retention = self._process_retention_deadlines.metrics(estimate_bytes=True)
            session_retention = self._session_retention_deadlines.metrics(estimate_bytes=True)
            service_retention = self._service_retention_deadlines.metrics(estimate_bytes=True)
            transport_retention = self._transport_retention_deadlines.metrics(estimate_bytes=True)
            service_binding_retention = self._service_process_tombstone_deadlines.metrics(
                estimate_bytes=True
            )
            transport_binding_retention = self._transport_session_tombstone_deadlines.metrics(
                estimate_bytes=True
            )
            lease_deadlines = self._lease_deadlines.metrics(estimate_bytes=True)
            foreground_deadlines = self._foreground_lease_deadlines.metrics(estimate_bytes=True)
            singleton_deadlines = self._singleton_lease_deadlines.metrics(estimate_bytes=True)
            singleton_temporal = self._singleton_lease_starts.metrics(estimate_bytes=True)
            compact_metrics = (
                process_index,
                session_index,
                service_index,
                transport_index,
                service_binding_index,
                self._service_process_tombstones.metrics(estimate_bytes=True),
                transport_binding_index,
                self._transport_session_tombstones.metrics(estimate_bytes=True),
                self._transitions.metrics(estimate_bytes=True),
                self._holds.metrics(estimate_bytes=True),
                self._barriers.metrics(estimate_bytes=True),
                self._tickets.metrics(estimate_bytes=True),
                self._leases.metrics(estimate_bytes=True),
                self._foreground_leases.metrics(estimate_bytes=True),
                self._singleton_leases.metrics(estimate_bytes=True),
                self._resource_lease_deadlines.metrics(estimate_bytes=True),
                self._retention_lease_deadlines.metrics(estimate_bytes=True),
                self._live_children.metrics(estimate_bytes=True),
                self._live_session_members.metrics(estimate_bytes=True),
                self._children_by_parent.metrics(estimate_bytes=True),
                self._members_by_session.metrics(estimate_bytes=True),
                self._service_children_by_parent.metrics(estimate_bytes=True),
                self._live_service_children.metrics(estimate_bytes=True),
                self._service_processes_by_service.metrics(estimate_bytes=True),
                self._service_bindings_by_process.metrics(estimate_bytes=True),
                self._transport_bindings_by_session.metrics(estimate_bytes=True),
                self._live_transport_bindings_by_session.metrics(estimate_bytes=True),
            )
            retention_entries = (
                process_retention.live_entries
                + session_retention.live_entries
                + service_retention.live_entries
                + transport_retention.live_entries
            )
            retention_backing = (
                process_retention.backing_entries
                + session_retention.backing_entries
                + service_retention.backing_entries
                + transport_retention.backing_entries
            )
            temporal_metrics = (
                process_temporal,
                session_temporal,
                service_temporal,
                transport_temporal,
                transition_temporal,
                hold_temporal,
                singleton_temporal,
            )
            deadline_metrics = (
                process_retention,
                session_retention,
                service_retention,
                transport_retention,
                service_binding_retention,
                transport_binding_retention,
                lease_deadlines,
                foreground_deadlines,
                singleton_deadlines,
            )
            primary_map_backing_bytes = sum(
                metric.primary_map_backing_bytes for metric in compact_metrics
            )
            estimated_index_bytes = sum(
                metric.estimated_bytes
                for metric in (*compact_metrics, *temporal_metrics, *deadline_metrics)
            ) + (
                (self._resource_lease_deadline_bindings + self._retention_lease_deadline_bindings)
                * _ESTIMATED_RESOURCE_LEASE_BINDING_BYTES
            )
            estimated_bytes = (
                estimated_index_bytes
                + (process_entries + session_entries + service_entries + transport_entries)
                * _ESTIMATED_ENTITY_BYTES
                + len(self._transitions) * _ESTIMATED_TRANSITION_BYTES
                + len(self._holds) * _ESTIMATED_HOLD_BYTES
                + (
                    len(self._barriers)
                    + len(self._tickets)
                    + len(self._leases)
                    + len(self._foreground_leases)
                    + len(self._singleton_leases)
                    + len(self._service_process_bindings)
                    + len(self._service_process_tombstones)
                    + len(self._transport_session_bindings)
                    + len(self._transport_session_tombstones)
                )
                * _ESTIMATED_CONTROL_RECORD_BYTES
            )
            return LifecycleRegistryStats(
                process_entries=process_entries,
                session_entries=session_entries,
                live_processes=self._live_processes,
                live_sessions=self._live_sessions,
                retained_processes=process_entries - self._live_processes,
                retained_sessions=session_entries - self._live_sessions,
                transitions=len(self._transitions),
                holds=len(self._holds),
                close_barriers=len(self._barriers),
                closure_tickets=len(self._tickets),
                retention_leases=len(self._leases),
                evicted_processes=self._evicted_processes,
                evicted_sessions=self._evicted_sessions,
                high_water_processes=self._high_water_processes,
                high_water_sessions=self._high_water_sessions,
                watermark=self._watermark,
                process_index_backing_entries=process_index.backing_entries,
                session_index_backing_entries=session_index.backing_entries,
                process_temporal_live_entries=process_temporal.live_entries,
                process_temporal_backing_entries=process_temporal.backing_entries,
                process_temporal_groups=process_temporal.secondary_buckets,
                session_temporal_live_entries=session_temporal.live_entries,
                session_temporal_backing_entries=session_temporal.backing_entries,
                session_temporal_groups=session_temporal.secondary_buckets,
                temporal_stale_entries=(
                    process_temporal.stale_entries
                    + session_temporal.stale_entries
                    + singleton_temporal.stale_entries
                ),
                retention_deadline_entries=retention_entries,
                retention_deadline_backing_entries=retention_backing,
                lease_deadline_backing_entries=lease_deadlines.backing_entries,
                lookup_candidates_inspected=(
                    process_temporal.lookup_candidates_inspected
                    + session_temporal.lookup_candidates_inspected
                    + service_temporal.lookup_candidates_inspected
                    + transport_temporal.lookup_candidates_inspected
                    + singleton_temporal.lookup_candidates_inspected
                    + self._resource_lease_candidates_inspected
                    + self._retention_lease_candidates_inspected
                    + self._dependent_aggregate_candidates_inspected
                    + self._exact_lookup_candidates_inspected
                ),
                estimated_bytes=estimated_bytes,
                estimated_index_bytes=estimated_index_bytes,
                detailed_transition_entries=len(self._transitions),
                detailed_hold_entries=len(self._holds),
                compacted_transition_entries=self._compacted_transitions,
                compacted_hold_entries=self._compacted_holds,
                ledger_floor=self._ledger_floor,
                ledger_temporal_backing_entries=(
                    transition_temporal.backing_entries + hold_temporal.backing_entries
                ),
                ledger_compaction_pending=(
                    self._transition_compaction_pending or self._hold_compaction_pending
                ),
                ledger_commit_map_entries=self._commit_map_entries,
                ledger_commit_map_backing_bytes=self._commit_map_backing_bytes,
                maximum_shard_entries=(
                    process_entries + session_entries + service_entries + transport_entries
                ),
                primary_map_backing_bytes=primary_map_backing_bytes,
                primary_compaction_pending=any(
                    metric.primary_compaction_pending for metric in compact_metrics
                ),
                primary_compaction_work=sum(
                    metric.primary_compaction_work for metric in compact_metrics
                ),
                foreground_leases=len(self._foreground_leases),
                singleton_leases=len(self._singleton_leases),
                resource_lease_deadline_entries=(
                    foreground_deadlines.live_entries + singleton_deadlines.live_entries
                ),
                resource_lease_deadline_backing_entries=(
                    foreground_deadlines.backing_entries + singleton_deadlines.backing_entries
                ),
                resource_lease_subjects=len(self._resource_lease_deadlines),
                resource_lease_subject_bindings=self._resource_lease_deadline_bindings,
                resource_lease_deadline_candidates_inspected=(
                    self._resource_lease_candidates_inspected
                ),
                resource_lease_max_subject_bindings=(self._resource_lease_max_subject_bindings),
                retention_lease_subjects=len(self._retention_lease_deadlines),
                retention_lease_subject_bindings=self._retention_lease_deadline_bindings,
                retention_lease_deadline_candidates_inspected=(
                    self._retention_lease_candidates_inspected
                ),
                retention_lease_max_subject_bindings=(self._retention_lease_max_subject_bindings),
                singleton_lease_temporal_live_entries=singleton_temporal.live_entries,
                singleton_lease_temporal_backing_entries=singleton_temporal.backing_entries,
                singleton_lease_temporal_groups=singleton_temporal.secondary_buckets,
                logical_service_entries=service_temporal.secondary_buckets,
                service_instance_entries=service_entries,
                live_service_instances=self._live_service_instances,
                retained_service_instances=service_entries - self._live_service_instances,
                transport_entries=transport_entries,
                live_transports=self._live_transports,
                retained_transports=transport_entries - self._live_transports,
                service_process_bindings=(
                    len(self._service_process_bindings) + len(self._service_process_tombstones)
                ),
                active_service_process_bindings=self._active_service_process_bindings,
                transport_session_bindings=(
                    len(self._transport_session_bindings) + len(self._transport_session_tombstones)
                ),
                active_transport_session_bindings=(self._active_transport_session_bindings),
                service_index_backing_entries=service_index.backing_entries,
                transport_index_backing_entries=transport_index.backing_entries,
                binding_index_backing_entries=(
                    service_binding_index.backing_entries + transport_binding_index.backing_entries
                ),
                service_temporal_live_entries=service_temporal.live_entries,
                service_temporal_backing_entries=service_temporal.backing_entries,
                service_temporal_groups=service_temporal.secondary_buckets,
                transport_temporal_live_entries=transport_temporal.live_entries,
                transport_temporal_backing_entries=transport_temporal.backing_entries,
                transport_temporal_groups=transport_temporal.secondary_buckets,
                service_retention_deadline_entries=service_retention.live_entries,
                transport_retention_deadline_entries=transport_retention.live_entries,
                service_evictions=self._evicted_services,
                transport_evictions=self._evicted_transports,
                binding_evictions=self._evicted_bindings,
            )

    def census(self) -> LifecycleRegistryStats:
        """Return the public structural census used by scale probes."""

        return self.stats()

    @staticmethod
    def _resource_lease_commit_key(
        canonical_time: datetime,
        action_id: str,
        transition_ordinal: int,
    ) -> tuple[datetime, str, int]:
        if not action_id:
            raise ValueError("Lifecycle resource lease mutations require an action_id")
        if transition_ordinal < 0:
            raise ValueError("Lifecycle resource lease ordinal must be non-negative")
        return (ensure_utc(canonical_time), action_id, transition_ordinal)

    @staticmethod
    def _validate_resource_lease_commit(
        previous: tuple[datetime, str, int],
        incoming: tuple[datetime, str, int],
        lease_id: str,
    ) -> None:
        if incoming <= previous:
            raise StateError(
                f"Lifecycle resource lease {lease_id} mutation order {incoming!r} "
                f"does not follow {previous!r}"
            )

    @staticmethod
    def _canonical_lease_image(image: str) -> str:
        return image.strip().replace("\\", "/").casefold()

    def _validate_resource_session(
        self,
        *,
        hostname: str,
        principal: str,
        session_object_id: str,
        canonical_time: datetime,
        lease_until: datetime,
        logon_id: str = "",
    ) -> _SessionEntry:
        session = self._sessions.get(session_object_id)
        if session is None:
            raise StateError(
                f"Lifecycle resource lease references unknown session {session_object_id}"
            )
        identity = session.identity
        if identity.hostname.casefold() != hostname.casefold():
            raise StateError("Lifecycle resource lease cannot use a cross-host session")
        if identity.principal.casefold() != principal.casefold():
            raise StateError("Lifecycle resource lease principal disagrees with its session")
        if logon_id and identity.logon_id.casefold() != logon_id.casefold():
            raise StateError("Lifecycle singleton lease LogonID disagrees with its session")
        if not self._entry_active_at(session, canonical_time):
            raise StateError(
                f"Lifecycle resource lease session {session_object_id} is not active at "
                f"{canonical_time.isoformat()}"
            )
        if session.close_barrier is not None and lease_until > session.close_barrier.requested_at:
            raise StateError(
                f"Lifecycle resource lease extends past session close barrier "
                f"{session.close_barrier.barrier_id}"
            )
        return session

    def _validate_resource_process(
        self,
        *,
        hostname: str,
        principal: str,
        session_object_id: str,
        process_object_id: str,
        canonical_time: datetime,
        lease_until: datetime,
        canonical_image: str = "",
        require_shell: bool = False,
    ) -> _ProcessEntry:
        process = self._processes.get(process_object_id)
        if process is None:
            raise StateError(
                f"Lifecycle resource lease references unknown process {process_object_id}"
            )
        if process.identity.hostname.casefold() != hostname.casefold():
            raise StateError("Lifecycle resource lease cannot use a cross-host process")
        if process.token.principal.casefold() != principal.casefold():
            raise StateError("Lifecycle resource lease principal disagrees with its process token")
        if process.membership.session_object_id != session_object_id:
            raise StateError("Lifecycle resource lease process is not a member of its session")
        if not self._entry_active_at(process, canonical_time):
            raise StateError(
                f"Lifecycle resource lease process {process_object_id} is not active at "
                f"{canonical_time.isoformat()}"
            )
        if process.close_barrier is not None and lease_until > process.close_barrier.requested_at:
            raise StateError(
                f"Lifecycle resource lease extends past process close barrier "
                f"{process.close_barrier.barrier_id}"
            )
        if require_shell and process.identity.role != "shell":
            raise StateError("Lifecycle foreground lease holder must be a shell process")
        if canonical_image and self._canonical_lease_image(
            process.identity.image
        ) != self._canonical_lease_image(canonical_image):
            raise StateError("Lifecycle singleton lease image disagrees with its process")
        return process

    def _validate_foreground_lease_owner(
        self,
        lease: LifecycleForegroundLease,
        canonical_time: datetime,
    ) -> None:
        self._validate_resource_session(
            hostname=lease.hostname,
            principal=lease.principal,
            session_object_id=lease.session_object_id,
            canonical_time=canonical_time,
            lease_until=lease.lease_until,
        )
        self._validate_resource_process(
            hostname=lease.hostname,
            principal=lease.principal,
            session_object_id=lease.session_object_id,
            process_object_id=lease.process_object_id,
            canonical_time=canonical_time,
            lease_until=lease.lease_until,
            require_shell=True,
        )

    def _validate_singleton_lease_owner(
        self,
        lease: LifecycleSingletonLease,
        canonical_time: datetime,
    ) -> None:
        self._validate_resource_session(
            hostname=lease.hostname,
            principal=lease.principal,
            session_object_id=lease.session_object_id,
            canonical_time=canonical_time,
            lease_until=lease.lease_until,
            logon_id=lease.logon_id,
        )
        if lease.process_object_id:
            self._validate_resource_process(
                hostname=lease.hostname,
                principal=lease.principal,
                session_object_id=lease.session_object_id,
                process_object_id=lease.process_object_id,
                canonical_time=canonical_time,
                lease_until=lease.lease_until,
                canonical_image=lease.canonical_image,
            )

    def _validate_singleton_lease_overlap(
        self,
        lease: LifecycleSingletonLease,
        *,
        exclude_lease_id: str = "",
    ) -> None:
        group = lease.resource_key
        previous_handle = self._singleton_lease_starts.latest_at_or_before(
            group,
            lease.acquired_at,
        )
        if previous_handle is not None:
            try:
                previous = self._singleton_leases.get_by_handle(previous_handle)
            except KeyError:  # pragma: no cover - synchronized index invariant
                previous = None
            if (
                previous is not None
                and previous.lease.lease_id != exclude_lease_id
                and previous.lease.lease_until > lease.acquired_at
            ):
                raise LifecycleLeaseConflictError(
                    "Lifecycle singleton resource interval overlaps lease "
                    f"{previous.lease.lease_id}"
                )
        next_handle = next(
            self._singleton_lease_starts.iter_after(group, lease.acquired_at, limit=1),
            None,
        )
        if next_handle is None:
            return
        try:
            following = self._singleton_leases.get_by_handle(next_handle)
        except KeyError:  # pragma: no cover - synchronized index invariant
            return
        if (
            following.lease.lease_id != exclude_lease_id
            and following.lease.acquired_at < lease.lease_until
        ):
            raise LifecycleLeaseConflictError(
                f"Lifecycle singleton resource interval overlaps lease {following.lease.lease_id}"
            )

    def _remove_foreground_lease(
        self,
        lease_id: str,
        *,
        route_removal: bool = False,
    ) -> None:
        entry = self._foreground_leases.get(lease_id)
        if entry is None:
            return
        handle = self._foreground_leases.handle_for(lease_id)
        self._remove_resource_lease_deadline(entry.lease, handle, singleton=False)
        self._foreground_lease_deadlines.remove(handle)
        self._foreground_leases.pop(lease_id)
        if route_removal:
            self._route_removals.append(("foreground_lease", lease_id))

    def _remove_singleton_lease(
        self,
        lease_id: str,
        *,
        route_removal: bool = False,
    ) -> None:
        entry = self._singleton_leases.get(lease_id)
        if entry is None:
            return
        handle = self._singleton_leases.handle_for(lease_id)
        self._remove_resource_lease_deadline(entry.lease, handle, singleton=True)
        self._singleton_lease_deadlines.remove(handle)
        self._singleton_lease_starts.remove(handle)
        self._singleton_leases.pop(lease_id)
        if route_removal:
            self._route_removals.append(("singleton_lease", lease_id))

    def _resource_lease_deadline_for(
        self,
        subject: LifecycleEntityRef,
    ) -> datetime | None:
        """Return one subject's cached maximum live resource-lease deadline."""

        deadlines = self._resource_lease_deadlines.get(subject)
        if deadlines is None:
            return None
        self._resource_lease_candidates_inspected += 1
        latest = deadlines.latest()
        if latest is None or self._resource_lease_expired(latest):
            return None
        return latest

    def _retention_lease_deadline_for(
        self,
        subject: LifecycleEntityRef,
    ) -> datetime | None:
        """Return one subject's exact maximum explicit retention deadline."""

        deadlines = self._retention_lease_deadlines.get(subject)
        if deadlines is None:
            return None
        self._retention_lease_candidates_inspected += 1
        return deadlines.latest()

    def _set_retention_lease_deadline(
        self,
        lease: LifecycleRetentionLease,
        handle: int,
    ) -> None:
        """Bind one explicit lease into its subject's indexed maximum."""

        deadlines = self._retention_lease_deadlines.get(lease.subject)
        if deadlines is None:
            deadlines = _IndexedLeaseDeadlineHeap()
            self._retention_lease_deadlines[lease.subject] = deadlines
        if deadlines.set(handle, lease.retain_until):
            self._retention_lease_deadline_bindings += 1
            self._retention_lease_max_subject_bindings = max(
                self._retention_lease_max_subject_bindings,
                len(deadlines),
            )

    def _remove_retention_lease_deadline(
        self,
        lease: LifecycleRetentionLease,
        handle: int,
    ) -> None:
        """Remove one exact explicit-lease deadline without a subject scan."""

        deadlines = self._retention_lease_deadlines.get(lease.subject)
        if deadlines is None or not deadlines.remove(handle):
            return
        self._retention_lease_deadline_bindings -= 1
        if not deadlines:
            self._retention_lease_deadlines.pop(lease.subject, None)

    @staticmethod
    def _resource_lease_token(handle: int, *, singleton: bool) -> int:
        """Pack one store-local lease handle and its family into a uint64 token."""

        token = (handle << 1) | int(singleton)
        if token >= 1 << 64:
            raise OverflowError("Lifecycle resource lease handle exceeds uint64 capacity")
        return token

    @staticmethod
    def _resource_lease_subjects(
        lease: LifecycleForegroundLease | LifecycleSingletonLease,
    ) -> tuple[LifecycleEntityRef, ...]:
        """Return the exact session/process subjects whose close the lease can extend."""

        subjects = [LifecycleEntityRef("session", lease.session_object_id)]
        if lease.process_object_id:
            subjects.append(LifecycleEntityRef("process", lease.process_object_id))
        return tuple(subjects)

    def _set_resource_lease_deadline(
        self,
        lease: LifecycleForegroundLease | LifecycleSingletonLease,
        handle: int,
        *,
        singleton: bool,
    ) -> None:
        """Insert/update exact per-subject max-deadline aggregates."""

        token = self._resource_lease_token(handle, singleton=singleton)
        for subject in self._resource_lease_subjects(lease):
            deadlines = self._resource_lease_deadlines.get(subject)
            if deadlines is None:
                deadlines = _IndexedLeaseDeadlineHeap()
                self._resource_lease_deadlines[subject] = deadlines
            if deadlines.set(token, lease.lease_until):
                self._resource_lease_deadline_bindings += 1
                self._resource_lease_max_subject_bindings = max(
                    self._resource_lease_max_subject_bindings,
                    len(deadlines),
                )

    def _remove_resource_lease_deadline(
        self,
        lease: LifecycleForegroundLease | LifecycleSingletonLease,
        handle: int,
        *,
        singleton: bool,
    ) -> None:
        """Remove exact per-subject deadline bindings without stale repair."""

        token = self._resource_lease_token(handle, singleton=singleton)
        for subject in self._resource_lease_subjects(lease):
            deadlines = self._resource_lease_deadlines.get(subject)
            if deadlines is None or not deadlines.remove(token):
                continue
            self._resource_lease_deadline_bindings -= 1
            if not deadlines:
                self._resource_lease_deadlines.pop(subject, None)

    def _resource_lease_expired(self, lease_until: datetime) -> bool:
        """Return whether the sealed frontier makes one retained lease non-authoritative."""

        return self._watermark is not None and lease_until <= self._watermark

    def _validate_process_parent(
        self,
        identity: ProcessLifecycleIdentity,
        *,
        staged_processes: dict[str, ProcessLifecycleIdentity] | None = None,
    ) -> None:
        if not identity.parent_object_id:
            return
        parent = self._processes.get(identity.parent_object_id)
        if parent is None:
            staged = (
                None
                if staged_processes is None
                else staged_processes.get(identity.parent_object_id)
            )
            if staged is not None:
                if staged.hostname != identity.hostname:
                    raise StateError(
                        f"Process lifecycle {identity.object_id} cannot use a cross-host parent"
                    )
                if staged.started_at > identity.started_at:
                    raise StateError(
                        f"Process lifecycle parent {identity.parent_object_id} starts after child "
                        f"{identity.object_id}"
                    )
                return
            raise StateError(
                f"Process lifecycle {identity.object_id} references unknown parent "
                f"{identity.parent_object_id}"
            )
        if parent.identity.hostname != identity.hostname:
            raise StateError(
                f"Process lifecycle {identity.object_id} cannot use a cross-host parent"
            )
        if parent.closed_at is not None or not self._entry_active_at(parent, identity.started_at):
            raise StateError(
                f"Process lifecycle parent {identity.parent_object_id} is not active at "
                f"child start {identity.started_at.isoformat()}"
            )
        if parent.close_barrier is not None:
            raise StateError(
                f"Process lifecycle parent {identity.parent_object_id} has accepted close "
                f"barrier {parent.close_barrier.barrier_id} before child start"
            )

    def _validate_process_membership(
        self,
        identity: ProcessLifecycleIdentity,
        membership: LifecycleMembership,
        *,
        staged_sessions: dict[str, SessionLifecycleIdentity] | None = None,
    ) -> None:
        if not membership.session_object_id:
            return
        session = self._sessions.get(membership.session_object_id)
        if session is None:
            staged = (
                None
                if staged_sessions is None
                else staged_sessions.get(membership.session_object_id)
            )
            if staged is not None:
                if staged.hostname != identity.hostname:
                    raise StateError(
                        f"Process lifecycle {identity.object_id} cannot use cross-host "
                        "session membership"
                    )
                if staged.started_at > identity.started_at:
                    raise StateError(
                        f"Process lifecycle session {membership.session_object_id} starts after "
                        f"process {identity.object_id}"
                    )
                return
            raise StateError(
                f"Process lifecycle {identity.object_id} references unknown session "
                f"{membership.session_object_id}"
            )
        if session.identity.hostname != identity.hostname:
            raise StateError(
                f"Process lifecycle {identity.object_id} cannot use cross-host session membership"
            )
        if session.closed_at is not None or not self._entry_active_at(session, identity.started_at):
            raise StateError(
                f"Process lifecycle session {membership.session_object_id} is not active at "
                f"process start {identity.started_at.isoformat()}"
            )
        if session.close_barrier is not None:
            raise StateError(
                f"Process lifecycle session {membership.session_object_id} has accepted close "
                f"barrier {session.close_barrier.barrier_id} before process start"
            )

    def _validate_descendants_closed(
        self,
        subject: LifecycleEntityRef,
        canonical_time: datetime,
    ) -> None:
        if subject.kind == "process":
            aggregates = (
                (self._children_by_parent.get(subject.object_id), "child processes"),
                (
                    self._service_bindings_by_process.get(subject.object_id),
                    "service ownership bindings",
                ),
            )
        elif subject.kind == "session":
            aggregates = (
                (self._members_by_session.get(subject.object_id), "session members"),
                (
                    self._transport_bindings_by_session.get(subject.object_id),
                    "transport bindings",
                ),
            )
        elif subject.kind == "service":
            aggregates = (
                (
                    self._service_children_by_parent.get(subject.object_id),
                    "child service instances",
                ),
                (
                    self._service_processes_by_service.get(subject.object_id),
                    "service process bindings",
                ),
            )
        else:
            entry = self._transports.get(subject.object_id)
            aggregates = (
                (
                    None
                    if entry is None or entry.active_binding_count == 0
                    else _DependentClosureAggregate(unclosed=entry.active_binding_count),
                    "session bindings",
                ),
            )
        for aggregate, relationship in aggregates:
            if aggregate is None or not aggregate.blocks_close_at(canonical_time):
                continue
            raise StateError(
                f"Cannot close lifecycle {subject.object_id} at {canonical_time.isoformat()}: "
                f"{relationship} remain active"
            )

    def _record_process_closed(
        self,
        entry: _ProcessEntry,
        closed_at: datetime,
    ) -> None:
        live_child = self._live_children.get(entry.identity.object_id)
        if live_child is not None:
            aggregate = self._children_by_parent.get(live_child.parent_object_id)
            if aggregate is None:
                raise StateError("Missing lifecycle parent closure aggregate")
            aggregate.close(closed_at)
            self._live_children.pop(entry.identity.object_id, None)
        if entry.membership.session_object_id:
            aggregate = self._members_by_session.get(entry.membership.session_object_id)
            if aggregate is None:
                raise StateError("Missing lifecycle session-member closure aggregate")
            aggregate.close(closed_at)
            self._live_session_members.pop(entry.identity.object_id, None)

    def _record_service_closed(
        self,
        entry: _ServiceEntry,
        closed_at: datetime,
    ) -> None:
        live_child = self._live_service_children.get(entry.identity.object_id)
        if live_child is None:
            return
        aggregate = self._service_children_by_parent.get(live_child.parent_object_id)
        if aggregate is None:
            raise StateError("Missing lifecycle service-parent closure aggregate")
        aggregate.close(closed_at)
        self._live_service_children.pop(entry.identity.object_id, None)

    def _reject_overlapping_pid_identity(self, identity: ProcessLifecycleIdentity) -> None:
        group = (identity.hostname, identity.pid)
        prior_handle = self._process_starts.latest_at_or_before(group, identity.started_at)
        prior = self._processes.get_by_handle(prior_handle) if prior_handle is not None else None
        if prior is not None and (prior.closed_at is None or prior.closed_at > identity.started_at):
            raise StateError(
                f"Process lifecycle PID overlap on {identity.hostname} pid={identity.pid}"
            )
        future_handle = next(
            self._process_starts.iter_after(group, identity.started_at, limit=1),
            None,
        )
        if future_handle is not None:
            raise StateError(
                f"Process lifecycle PID overlap on {identity.hostname} pid={identity.pid}"
            )

    def _reject_overlapping_logon_identity(self, identity: SessionLifecycleIdentity) -> None:
        group = self._session_group(identity.hostname, identity.logon_id)
        prior_handle = self._session_starts.latest_at_or_before(group, identity.started_at)
        prior = self._sessions.get_by_handle(prior_handle) if prior_handle is not None else None
        if prior is not None and (prior.closed_at is None or prior.closed_at > identity.started_at):
            raise StateError(
                f"Session lifecycle LogonID overlap on {identity.hostname} "
                f"LogonID={identity.logon_id}"
            )
        future_handle = next(
            self._session_starts.iter_after(group, identity.started_at, limit=1),
            None,
        )
        if future_handle is not None:
            raise StateError(
                f"Session lifecycle LogonID overlap on {identity.hostname} "
                f"LogonID={identity.logon_id}"
            )

    def _reject_overlapping_service_identity(
        self,
        identity: ServiceInstanceLifecycleIdentity,
    ) -> None:
        """Reject ambiguous live intervals for one host/logical service."""

        expected = (
            identity.hostname.strip().casefold(),
            identity.logical_service_id.strip().casefold(),
        )
        group = self._service_group(identity.hostname, identity.logical_service_id)
        prior_handle = self._service_starts.latest_at_or_before(group, identity.started_at)
        if prior_handle is not None:
            try:
                prior = self._services.get_by_handle(prior_handle)
            except KeyError:
                prior = None
            if prior is not None and prior.logical_identity.host_logical_key != expected:
                raise StateError("Lifecycle logical-service temporal digest collision")
            if prior is not None and (
                prior.closed_at is None or prior.closed_at > identity.started_at
            ):
                raise StateError("Logical service instance intervals cannot overlap")
        future_handle = next(
            self._service_starts.iter_after(group, identity.started_at, limit=1),
            None,
        )
        if future_handle is not None:
            raise StateError("Logical service instance intervals cannot overlap")

    def _reject_overlapping_transport_tuple(
        self,
        identity: TransportLifecycleIdentity,
    ) -> None:
        expected = identity.tuple_key
        group = self._transport_group(expected)
        prior_handle = self._transport_starts.latest_at_or_before(group, identity.opened_at)
        if prior_handle is not None:
            try:
                prior = self._transports.get_by_handle(prior_handle)
            except KeyError:
                prior = None
            if prior is not None and prior.identity.tuple_key != expected:
                raise StateError("Lifecycle transport tuple temporal digest collision")
            if prior is not None:
                prior_end = prior.closed_at or prior.identity.close_deadline
                if (
                    prior.identity.object_id != identity.object_id
                    and prior_end > identity.opened_at
                ):
                    raise StateError("Canonical transport tuple intervals cannot overlap")
        future_handle = next(
            self._transport_starts.iter_after(group, identity.opened_at, limit=1),
            None,
        )
        if future_handle is None:
            return
        try:
            future = self._transports.get_by_handle(future_handle)
        except KeyError:
            return
        if future.identity.tuple_key != expected:
            raise StateError("Lifecycle transport tuple temporal digest collision")
        if identity.close_deadline > future.identity.opened_at:
            raise StateError("Canonical transport tuple intervals cannot overlap")

    @staticmethod
    def _session_group(hostname: str, logon_id: str) -> int:
        return _semantic_hash("lifecycle-session-logon", hostname, logon_id)

    @staticmethod
    def _service_group(hostname: str, logical_service_id: str) -> int:
        return _semantic_hash(
            "lifecycle-service-logical", hostname.casefold(), logical_service_id.casefold()
        )

    @staticmethod
    def _transport_group(tuple_key: tuple[str, int, str, int, str]) -> int:
        return _semantic_hash(
            "lifecycle-transport-tuple",
            tuple_key[0],
            str(tuple_key[1]),
            tuple_key[2],
            str(tuple_key[3]),
            tuple_key[4].casefold(),
        )

    def _validate_dependent_time(self, entry: _LifecycleEntry, canonical_time: datetime) -> None:
        if canonical_time < self._entry_started_at(entry):
            raise StateError("Lifecycle dependent cannot precede its owning entity start")
        if entry.closed_at is not None and canonical_time >= entry.closed_at:
            raise StateError("Lifecycle dependent cannot occur at or after entity closure")
        if entry.close_barrier is not None and canonical_time >= entry.close_barrier.requested_at:
            raise StateError("Lifecycle dependent cannot occur at or after its close barrier")
        if isinstance(entry, _TransportEntry) and canonical_time > entry.identity.close_deadline:
            raise StateError("Transport dependent exceeds its canonical close deadline")

    def _reject_behind_watermark(self, canonical_time: datetime, operation: str) -> None:
        """Reject new canonical mutation at or behind the sealed frontier."""

        at = ensure_utc(canonical_time)
        if self._watermark is not None and at <= self._watermark:
            raise StateError(
                f"Lifecycle {operation} at {at.isoformat()} is at or behind watermark "
                f"{self._watermark.isoformat()}"
            )

    @staticmethod
    def _entry_has_transition(
        entry: _LifecycleEntry,
        transition: LifecycleTransition,
    ) -> bool:
        """Resolve an idempotent durable transition without a duplicate global row."""

        if transition in entry.transitions:
            return True
        commits = entry.state.commits
        return (
            commits is not None
            and commits.get((transition.action_id, transition.transition_ordinal))
            == transition.transition_id
        )

    def _validate_transition_claim(
        self,
        transition: LifecycleTransition,
        *,
        subject_route_digest: int | None = None,
    ) -> None:
        existing = self._transitions.get(transition.transition_id)
        if existing is not None and existing != transition:
            raise StateError(
                f"Lifecycle transition ID {transition.transition_id} is already in use"
            )
        if existing == transition:
            raise StateError(
                f"Lifecycle transition {transition.transition_id} is already registered"
            )
        streamed_commit = self._transitions.find_one(
            "commit",
            (
                transition.subject.kind,
                transition.subject.object_id,
                transition.action_id,
                transition.transition_ordinal,
            ),
        )
        if streamed_commit is not None:
            raise StateError(
                "Lifecycle action commit identity is already in use: "
                f"{transition.action_id}[{transition.transition_ordinal}] for "
                f"{transition.subject.object_id}"
            )
        entry = (
            self._transports.get_digest(
                transition.subject.object_id,
                subject_route_digest,
            )
            if transition.subject.kind == "transport" and subject_route_digest is not None
            else self._entry(transition.subject)
        )
        committed_id: str | None = None
        if entry is not None:
            commit_key = (transition.action_id, transition.transition_ordinal)
            if entry.state.commits is not None:
                committed_id = entry.state.commits.get(commit_key)
            else:
                committed_id = next(
                    (
                        prior.transition_id
                        for prior in entry.transitions
                        if (prior.action_id, prior.transition_ordinal) == commit_key
                    ),
                    None,
                )
        if committed_id is not None:
            raise StateError(
                "Lifecycle action commit identity is already in use: "
                f"{transition.action_id}[{transition.transition_ordinal}] for "
                f"{transition.subject.object_id}"
            )

    def _validate_barrier_claim(self, barrier: LifecycleCloseBarrier) -> None:
        if barrier.barrier_id in self._barriers:
            raise StateError(f"Lifecycle close barrier ID {barrier.barrier_id} is already in use")

    def _validate_ticket_claim(self, ticket: LifecycleClosureTicket) -> None:
        if ticket.ticket_id in self._tickets:
            raise StateError(f"Lifecycle closure ticket ID {ticket.ticket_id} is already in use")

    def _append_transition(
        self,
        entry: _LifecycleEntry,
        transition: LifecycleTransition,
        *,
        claim_validated: bool = False,
    ) -> None:
        with self._catalog_lock, self._index_lock:
            self._ensure_full_state(entry)
            if not claim_validated:
                self._validate_transition_claim(transition)
            self._record_transition_commit(entry, transition)
            self._insert_transition_detail(entry, transition)
            entry.state.transition_count += 1
            entry.state.transition_digest ^= self._transition_digest(transition)
            if transition.kind in {"dependent", "hold_acquired"}:
                latest = entry.state.latest_dependent_at
                if latest is None or transition.canonical_time > latest:
                    entry.state.latest_dependent_at = transition.canonical_time
            if transition.kind in {"dependent", "hold_acquired"}:
                self._transitions[transition.transition_id] = transition
                self._transition_times.add(
                    self._transitions.handle_for(transition.transition_id),
                    0,
                    transition.canonical_time,
                )
            else:
                durable_ids = entry.state.durable_transition_ids
                if durable_ids is None:
                    entry.state.durable_transition_ids = transition.transition_id
                elif isinstance(durable_ids, str):
                    entry.state.durable_transition_ids = (
                        durable_ids,
                        transition.transition_id,
                    )
                else:
                    entry.state.durable_transition_ids = (
                        *durable_ids,
                        transition.transition_id,
                    )

    def _append_hold(self, entry: _LifecycleEntry, hold: LifecycleHold) -> None:
        with self._catalog_lock, self._index_lock:
            self._ensure_full_state(entry)
            self._insert_hold_detail(entry, hold)
            entry.state.hold_count += 1
            entry.state.hold_digest ^= self._hold_digest(hold)
            latest = entry.state.latest_hold_until
            if latest is None or hold.hold_until > latest:
                entry.state.latest_hold_until = hold.hold_until
            self._holds[hold.hold_id] = hold
            self._hold_times.add(
                self._holds.handle_for(hold.hold_id),
                0,
                hold.acquired_at,
            )

    @staticmethod
    def _ensure_full_state(entry: _LifecycleEntry) -> _LifecycleState:
        """Promote a start-only inline state immediately before its first mutation."""

        state = entry.state
        if isinstance(state, _LifecycleState):
            return state
        if isinstance(entry, (_SessionEntry, _ServiceEntry, _TransportEntry)):
            return entry.promote_state()
        promoted = _LifecycleState(
            transitions=state.transitions,
            transition_count=1,
            transition_digest=state.transition_digest,
            durable_transition_ids=state.durable_transition_ids,
        )
        object.__setattr__(entry, "state", promoted)
        return promoted

    def _record_transition_commit(
        self,
        entry: _LifecycleEntry,
        transition: LifecycleTransition,
    ) -> None:
        """Retain only bounded durable commits on an entity.

        Dependent and hold-acquired commits live in the streamed global detail
        ledger's compact equality index.  They disappear with detail beyond
        the sealed retention horizon instead of growing one per-entity dict.
        """

        commit_key = (transition.action_id, transition.transition_ordinal)
        commits = entry.state.commits
        if commits is not None:
            if transition.kind in _STREAMED_TRANSITION_KINDS:
                return
            prior_bytes = getsizeof(commits)
            is_new = commit_key not in commits
            if is_new and len(commits) >= _MAX_DURABLE_COMMITS_PER_ENTITY:
                raise StateError(
                    f"Lifecycle durable commit bound exceeded for {transition.subject.object_id}"
                )
            commits[commit_key] = transition.transition_id
            if is_new:
                self._commit_map_entries += 1
            self._commit_map_backing_bytes += getsizeof(commits) - prior_bytes
            return
        if entry.state.transition_count == 0:
            return
        commits = {
            (prior.action_id, prior.transition_ordinal): prior.transition_id
            for prior in entry.transitions
            if prior.kind not in _STREAMED_TRANSITION_KINDS
        }
        if transition.kind not in _STREAMED_TRANSITION_KINDS:
            commits[commit_key] = transition.transition_id
        if len(commits) > _MAX_DURABLE_COMMITS_PER_ENTITY:
            raise StateError(
                f"Lifecycle durable commit bound exceeded for {transition.subject.object_id}"
            )
        entry.state.commits = commits
        self._commit_map_entries += len(commits)
        self._commit_map_backing_bytes += getsizeof(commits)

    def _insert_transition_detail(
        self,
        entry: _LifecycleEntry,
        transition: LifecycleTransition,
    ) -> None:
        """Insert into an inline-one, bounded deterministic detail ledger."""

        details = entry.state.transitions
        if details is None:
            entry.state.transitions = transition
            return
        if isinstance(details, LifecycleTransition):
            ordered = sorted((details, transition), key=lambda item: item.order_key)
        else:
            position = bisect_right(
                details,
                transition.order_key,
                key=lambda item: item.order_key,
            )
            details.insert(position, transition)
            ordered = details
        if len(ordered) > self._snapshot_history_limit:
            del ordered[: len(ordered) - self._snapshot_history_limit]
        entry.state.transitions = ordered[0] if len(ordered) == 1 else ordered

    def _insert_hold_detail(self, entry: _LifecycleEntry, hold: LifecycleHold) -> None:
        """Insert into an inline-one, bounded deterministic hold ledger."""

        details = entry.state.holds
        if details is None:
            entry.state.holds = hold
            return
        hold_key = (hold.acquired_at, hold.action_id, hold.transition_ordinal, hold.hold_id)
        if isinstance(details, LifecycleHold):
            ordered = sorted(
                (details, hold),
                key=lambda item: (
                    item.acquired_at,
                    item.action_id,
                    item.transition_ordinal,
                    item.hold_id,
                ),
            )
        else:
            position = bisect_right(
                details,
                hold_key,
                key=lambda item: (
                    item.acquired_at,
                    item.action_id,
                    item.transition_ordinal,
                    item.hold_id,
                ),
            )
            details.insert(position, hold)
            ordered = details
        if len(ordered) > self._snapshot_history_limit:
            del ordered[: len(ordered) - self._snapshot_history_limit]
        entry.state.holds = ordered[0] if len(ordered) == 1 else ordered

    @staticmethod
    def _transition_digest(transition: LifecycleTransition) -> int:
        return _transition_digest_value(transition)

    @staticmethod
    def _hold_digest(hold: LifecycleHold) -> int:
        payload = "\x1f".join(
            (
                hold.hold_id,
                hold.subject.kind,
                hold.subject.object_id,
                hold.acquired_at.isoformat(),
                hold.hold_until.isoformat(),
                hold.action_id,
                str(hold.transition_ordinal),
                hold.reason,
            )
        )
        return int.from_bytes(sha256(payload.encode("utf-8")).digest())

    def _require_entry(self, subject: LifecycleEntityRef) -> _LifecycleEntry:
        entry = self._entry(subject)
        if entry is None:
            raise StateError(f"Unknown {subject.kind} lifecycle object {subject.object_id}")
        return entry

    @contextmanager
    def _locked_subject(self, subject: LifecycleEntityRef) -> Iterator[_LifecycleEntry]:
        """Lock one stable host lane and reject an evict/reinsert ABA race."""

        with self._catalog_lock:
            entry = self._require_entry(subject)
            hostname = entry.identity.hostname
        with self._host_lanes.lane(hostname):
            with self._catalog_lock:
                current = self._entry(subject)
                if not self._same_entry(current, entry):
                    raise StateError(
                        f"Lifecycle {subject.object_id} changed while awaiting its host lane"
                    )
            yield entry

    def _entry(self, subject: LifecycleEntityRef) -> _LifecycleEntry | None:
        if subject.kind == "process":
            return self._processes.get(subject.object_id)
        if subject.kind == "session":
            return self._sessions.get(subject.object_id)
        if subject.kind == "service":
            return self._services.get(subject.object_id)
        return self._transports.get(subject.object_id)

    @staticmethod
    def _same_entry(
        left: _LifecycleEntry | None,
        right: _LifecycleEntry | None,
    ) -> bool:
        if isinstance(left, _SessionEntry) and isinstance(right, _SessionEntry):
            return left.handle == right.handle and left.generation == right.generation
        if isinstance(left, _ServiceEntry) and isinstance(right, _ServiceEntry):
            return left.handle == right.handle and left.generation == right.generation
        if isinstance(left, _TransportEntry) and isinstance(right, _TransportEntry):
            return left.handle == right.handle and left.generation == right.generation
        return left is right

    @staticmethod
    def _entry_started_at(entry: _LifecycleEntry) -> datetime:
        return entry.identity.started_at

    @classmethod
    def _entry_active_at(cls, entry: _LifecycleEntry, canonical_time: datetime) -> bool:
        return entry.identity.started_at <= canonical_time and (
            entry.closed_at is None or canonical_time < entry.closed_at
        )

    def _process_snapshot(self, entry: _ProcessEntry) -> ProcessLifecycleSnapshot:
        transitions = tuple(
            transition
            for transition in entry.transitions
            if self._ledger_floor is None or transition.canonical_time > self._ledger_floor
        )
        holds = tuple(
            hold
            for hold in entry.holds
            if self._ledger_floor is None or hold.acquired_at > self._ledger_floor
        )
        return ProcessLifecycleSnapshot(
            identity=entry.identity,
            token=entry.token,
            membership=entry.membership,
            transitions=transitions,
            holds=holds,
            close_barrier=entry.close_barrier,
            closure_ticket=entry.closure_ticket,
            closed_at=entry.closed_at,
            transition_count=entry.state.transition_count,
            compacted_transition_count=entry.state.transition_count - len(transitions),
            transition_ledger_digest=f"{entry.state.transition_digest:064x}",
            hold_count=entry.state.hold_count,
            compacted_hold_count=entry.state.hold_count - len(holds),
            hold_ledger_digest=f"{entry.state.hold_digest:064x}",
            latest_dependent_at=entry.state.latest_dependent_at,
            latest_hold_until=entry.state.latest_hold_until,
        )

    def _session_snapshot(self, entry: _SessionEntry) -> SessionLifecycleSnapshotView:
        state = self._sessions.promoted_state(entry.handle, entry.generation)
        if state is None:
            return _PackedSessionSnapshot(
                self._sessions.row(entry.handle, entry.generation),
                self._ledger_floor,
            )
        transition_details = state.transitions
        if transition_details is None:
            transition_values: tuple[LifecycleTransition, ...] = ()
        elif isinstance(transition_details, list):
            transition_values = tuple(transition_details)
        else:
            transition_values = (transition_details,)
        hold_details = state.holds
        if hold_details is None:
            hold_values: tuple[LifecycleHold, ...] = ()
        elif isinstance(hold_details, list):
            hold_values = tuple(hold_details)
        else:
            hold_values = (hold_details,)
        transitions = tuple(
            transition
            for transition in transition_values
            if self._ledger_floor is None or transition.canonical_time > self._ledger_floor
        )
        holds = tuple(
            hold
            for hold in hold_values
            if self._ledger_floor is None or hold.acquired_at > self._ledger_floor
        )
        return SessionLifecycleSnapshot(
            identity=entry.identity,
            transitions=transitions,
            holds=holds,
            close_barrier=state.close_barrier,
            closure_ticket=state.closure_ticket,
            closed_at=state.closed_at,
            transition_count=state.transition_count,
            compacted_transition_count=state.transition_count - len(transitions),
            transition_ledger_digest=f"{state.transition_digest:064x}",
            hold_count=state.hold_count,
            compacted_hold_count=state.hold_count - len(holds),
            hold_ledger_digest=f"{state.hold_digest:064x}",
            latest_dependent_at=state.latest_dependent_at,
            latest_hold_until=state.latest_hold_until,
        )

    def _service_snapshot(self, entry: _ServiceEntry) -> ServiceInstanceLifecycleSnapshot:
        transitions = tuple(
            transition
            for transition in entry.transitions
            if self._ledger_floor is None or transition.canonical_time > self._ledger_floor
        )
        holds = tuple(
            hold
            for hold in entry.holds
            if self._ledger_floor is None or hold.acquired_at > self._ledger_floor
        )
        return ServiceInstanceLifecycleSnapshot(
            logical_identity=entry.logical_identity,
            identity=entry.identity,
            transitions=transitions,
            holds=holds,
            close_barrier=entry.close_barrier,
            closure_ticket=entry.closure_ticket,
            closed_at=entry.closed_at,
            transition_count=entry.state.transition_count,
            compacted_transition_count=entry.state.transition_count - len(transitions),
            transition_ledger_digest=f"{entry.state.transition_digest:064x}",
            hold_count=entry.state.hold_count,
            compacted_hold_count=entry.state.hold_count - len(holds),
            hold_ledger_digest=f"{entry.state.hold_digest:064x}",
            latest_dependent_at=entry.state.latest_dependent_at,
            latest_hold_until=entry.state.latest_hold_until,
        )

    def _transport_snapshot(self, entry: _TransportEntry) -> TransportLifecycleSnapshot:
        transitions = tuple(
            transition
            for transition in entry.transitions
            if self._ledger_floor is None or transition.canonical_time > self._ledger_floor
        )
        holds = tuple(
            hold
            for hold in entry.holds
            if self._ledger_floor is None or hold.acquired_at > self._ledger_floor
        )
        return TransportLifecycleSnapshot(
            identity=entry.identity,
            transitions=transitions,
            holds=holds,
            close_barrier=entry.close_barrier,
            closure_ticket=entry.closure_ticket,
            closed_at=entry.closed_at,
            active_binding_count=entry.active_binding_count,
            transition_count=entry.state.transition_count,
            compacted_transition_count=entry.state.transition_count - len(transitions),
            transition_ledger_digest=f"{entry.state.transition_digest:064x}",
            hold_count=entry.state.hold_count,
            compacted_hold_count=entry.state.hold_count - len(holds),
            hold_ledger_digest=f"{entry.state.hold_digest:064x}",
            latest_dependent_at=entry.state.latest_dependent_at,
            latest_hold_until=entry.state.latest_hold_until,
        )

    def _snapshot(
        self,
        entry: _LifecycleEntry,
    ) -> (
        ProcessLifecycleSnapshot
        | SessionLifecycleSnapshotView
        | ServiceInstanceLifecycleSnapshot
        | TransportLifecycleSnapshot
    ):
        if isinstance(entry, _ProcessEntry):
            return self._process_snapshot(entry)
        if isinstance(entry, _SessionEntry):
            return self._session_snapshot(entry)
        if isinstance(entry, _ServiceEntry):
            return self._service_snapshot(entry)
        return self._transport_snapshot(entry)

    def _schedule_retention(
        self,
        subject: LifecycleEntityRef,
        entry: _LifecycleEntry,
    ) -> None:
        with self._index_lock:
            self._retention_index(subject).set(
                self._handle_for(subject),
                self._retention_deadline_for(subject, entry),
            )

    def _retention_deadline_for(
        self,
        subject: LifecycleEntityRef,
        entry: _LifecycleEntry,
    ) -> datetime:
        if entry.closed_at is None:
            raise StateError("Cannot schedule retention for a live lifecycle identity")
        deadline = entry.closed_at + self._closed_retention
        lease_deadline = self._retention_lease_deadline_for(subject)
        return deadline if lease_deadline is None else max(deadline, lease_deadline)

    def _bulk_evict_packed_kind(
        self,
        kind: Literal["service", "transport"],
    ) -> tuple[LifecycleEntityRef, ...]:
        """Evict a proven all-due packed family without per-row index repair."""

        entries: Iterator[_ServiceEntry | _TransportEntry]
        if kind == "service":
            entries = self._services.iter_entries()
        else:
            entries = self._transports.iter_entries()
        evicted: list[LifecycleEntityRef] = []
        for entry in entries:
            subject = entry.identity.ref
            self._evict(
                subject,
                entry,
                handle=entry.handle,
                packed_bulk=True,
                retention_removed=True,
            )
            evicted.append(subject)
        if kind == "service":
            self._services.clear()
            self._service_starts.clear()
            self._service_retention_deadlines.clear()
        else:
            self._transports.clear()
            self._transport_starts.clear()
            self._transport_retention_deadlines.clear()
        return tuple(evicted)

    def _evict(
        self,
        subject: LifecycleEntityRef,
        entry: _LifecycleEntry,
        *,
        handle: int | None = None,
        packed_bulk: bool = False,
        retention_removed: bool = False,
    ) -> None:
        if entry.closed_at is None:
            raise StateError("Cannot evict a live lifecycle identity")
        if self._retention_lease_deadlines.get(subject) is not None:
            raise StateError("Cannot evict a lifecycle identity with active retention leases")
        if entry.state.commits is not None:
            self._commit_map_entries -= len(entry.state.commits)
            self._commit_map_backing_bytes -= getsizeof(entry.state.commits)
        durable_ids = entry.state.durable_transition_ids
        transition_ids = {transition.transition_id for transition in entry.transitions}
        if isinstance(durable_ids, str):
            transition_ids.add(durable_ids)
        elif durable_ids is not None:
            transition_ids.update(durable_ids)
        for transition_id in sorted(transition_ids):
            if transition_id in self._transitions:
                transition_handle = self._transitions.handle_for(transition_id)
                self._transition_times.remove(transition_handle)
                self._transitions.pop(transition_id, None)
            self._route_removals.append(("transition", transition_id))
        for hold_id in sorted(hold.hold_id for hold in entry.holds):
            if hold_id not in self._holds:
                continue
            hold_handle = self._holds.handle_for(hold_id)
            self._hold_times.remove(hold_handle)
            self._holds.pop(hold_id, None)
            self._route_removals.append(("hold", hold_id))
        if entry.close_barrier is not None:
            self._barriers.pop(entry.close_barrier.barrier_id, None)
            self._route_removals.append(("barrier", entry.close_barrier.barrier_id))
        if entry.closure_ticket is not None:
            self._tickets.pop(entry.closure_ticket.ticket_id, None)
            self._route_removals.append(("ticket", entry.closure_ticket.ticket_id))
        if handle is None:
            handle = self._handle_for(subject)
        if not retention_removed:
            self._retention_index(subject).remove(handle)
        if subject.kind == "process":
            self._process_starts.remove(handle)
            self._processes.remove(subject.object_id)
            self._children_by_parent.pop(subject.object_id, None)
            self._evicted_processes += 1
            self._route_removals.append(("process", subject.object_id))
        elif subject.kind == "session":
            self._session_starts.remove(handle)
            self._sessions.remove(subject.object_id)
            self._members_by_session.pop(subject.object_id, None)
            self._transport_bindings_by_session.pop(subject.object_id, None)
            self._evicted_sessions += 1
            self._route_removals.append(("session", subject.object_id))
        elif subject.kind == "service":
            assert isinstance(entry, _ServiceEntry)
            if not packed_bulk:
                logical_key = entry.logical_identity.host_logical_key
                service_group = self._service_group(*logical_key)
                self._service_starts.remove(handle, service_group)
                replacement_handle = self._service_starts.latest_at_or_before(
                    service_group,
                    datetime.max.replace(tzinfo=UTC),
                )
                self._services.remove(
                    subject.object_id,
                    logical_replacement_handle=replacement_handle,
                )
            self._service_children_by_parent.pop(subject.object_id, None)
            self._service_processes_by_service.pop(subject.object_id, None)
            self._evicted_services += 1
            self._route_removals.append(("service", subject.object_id))
        else:
            assert isinstance(entry, _TransportEntry)
            if not packed_bulk:
                self._transport_starts.remove(
                    handle,
                    self._transport_group(entry.identity.tuple_key),
                )
                self._transports.remove(subject.object_id)
            self._evicted_transports += 1
            self._route_removals.append(("transport", subject.object_id))
            self._route_removals.append(("transport_id", entry.identity.transport_id))
            self._route_removals.append(("transport_uid", entry.identity.zeek_uid))

    def _handle_for(self, subject: LifecycleEntityRef) -> int:
        try:
            if subject.kind == "process":
                return self._processes.handle_for(subject.object_id)
            if subject.kind == "session":
                return self._sessions.handle_for(subject.object_id)
            if subject.kind == "service":
                return self._services.handle_for(subject.object_id)
            return self._transports.handle_for(subject.object_id)
        except KeyError as exc:
            raise StateError(
                f"Unknown {subject.kind} lifecycle object {subject.object_id}"
            ) from exc

    def _retention_index(self, subject: LifecycleEntityRef) -> _RetentionDeadlineIndex:
        if subject.kind == "process":
            return self._process_retention_deadlines
        if subject.kind == "session":
            return self._session_retention_deadlines
        if subject.kind == "service":
            return self._service_retention_deadlines
        return self._transport_retention_deadlines

    @staticmethod
    def _service_logical_route_id_for_partition(
        hostname: str,
        logical_service_id: str,
    ) -> str:
        return f"{hostname.strip().casefold()}\0{logical_service_id.strip().casefold()}"

    @staticmethod
    def _service_instance_route_id_for_partition(
        identity: ServiceInstanceLifecycleIdentity,
    ) -> str:
        return "\0".join(
            (
                identity.hostname.strip().casefold(),
                identity.boot_id,
                identity.logical_service_id.strip().casefold(),
                identity.instance_id,
            )
        )


_ROUTE_KINDS = frozenset(
    {
        "process",
        "session",
        "service",
        "transport",
        "transport_id",
        "transport_uid",
        "service_process_binding",
        "transport_session_binding",
        "transition",
        "hold",
        "barrier",
        "ticket",
        "lease",
        "foreground_lease",
        "singleton_lease",
    }
)

_PACKED_ROUTE_KINDS = frozenset(
    {
        "process",
        "service",
        "transport",
        "transport_id",
        "transport_uid",
        "service_process_binding",
        "transport_session_binding",
        "foreground_lease",
        "singleton_lease",
    }
)


class _LifecycleRouteShard:
    """One independently locked family of exact semantic routes."""

    def __init__(self, *, snapshot_cache_capacity: int) -> None:
        self.lock = RLock()
        self.maps: dict[str, IncrementalExactMap[int, object]] = {}
        self.packed_maps: dict[str, PackedUniqueDigestMap] = {}
        self.start_transitions = PackedUniqueDigestMap(b"lc-start-route")
        self.deleted: dict[str, int] = {}
        self.lookup_candidates_inspected = 0
        self.snapshot_cache_capacity = snapshot_cache_capacity
        self.snapshot_cache: OrderedDict[
            tuple[str, str], ServiceInstanceLifecycleSnapshot | TransportLifecycleSnapshot
        ] = OrderedDict()

    def route_map(self, kind: str, *, create: bool) -> IncrementalExactMap[int, object] | None:
        route_map = self.maps.get(kind)
        if route_map is None and create:
            route_map = IncrementalExactMap()
            self.maps[kind] = route_map
        return route_map


@dataclass(frozen=True, slots=True)
class _LifecycleRouteMetrics:
    counts: dict[str, int]
    estimated_bytes: int
    primary_map_backing_bytes: int
    compaction_pending: bool
    compaction_work: int
    snapshot_cache_entries: int
    snapshot_cache_capacity: int
    snapshot_cache_estimated_bytes: int
    lookup_candidates_inspected: int


class _LifecycleRoutes:
    """Bounded exact-route shards with incremental backing-map rotation."""

    def __init__(self, shard_count: int) -> None:
        cache_base, cache_remainder = divmod(_DECODED_SNAPSHOT_CACHE_CAPACITY, shard_count)
        self._shards = tuple(
            _LifecycleRouteShard(
                snapshot_cache_capacity=cache_base + int(shard_id < cache_remainder)
            )
            for shard_id in range(shard_count)
        )
        self._shard_count = shard_count
        self._compaction_cursor = 0

    @staticmethod
    def _route_hash(kind: str, semantic_id: str) -> int:
        if kind not in _ROUTE_KINDS:
            raise KeyError(f"Unknown lifecycle route kind {kind!r}")
        return _semantic_hash(f"lifecycle-route-{kind}", semantic_id)

    def _shard_id(self, kind: str, semantic_id: str) -> int:
        return self._route_hash(kind, semantic_id) % self._shard_count

    @contextmanager
    def locked(self, keys: tuple[tuple[str, str], ...]) -> Iterator[None]:
        """Acquire every affected route shard in deterministic order."""

        shard_ids = sorted({self._shard_id(kind, key) for kind, key in keys})
        locks = [self._shards[shard_id].lock for shard_id in shard_ids]
        for lock in locks:
            lock.acquire()
        try:
            yield
        finally:
            for lock in reversed(locks):
                lock.release()

    def get_locked(self, kind: str, semantic_id: str) -> object | None:
        route_hash = self._route_hash(kind, semantic_id)
        shard = self._shards[route_hash % self._shard_count]
        if kind in _PACKED_ROUTE_KINDS:
            route_map = shard.packed_maps.get(kind)
            return None if route_map is None else route_map.get_digest(route_hash)
        if kind == "transition":
            route_map = shard.route_map(kind, create=False)
            retained = None if route_map is None else route_map.get(route_hash)
            if retained is not None:
                return retained
            start_locator = shard.start_transitions.get_digest(route_hash)
            return None if start_locator is None else -(start_locator + 1)
        route_map = shard.route_map(kind, create=False)
        return None if route_map is None else route_map.get(route_hash)

    def get_entity_with_cached_snapshot(
        self,
        kind: str,
        semantic_id: str,
    ) -> tuple[object | None, ServiceInstanceLifecycleSnapshot | TransportLifecycleSnapshot | None]:
        """Resolve one entity route and its bounded decoded view under one shard lock."""

        shard = self._shards[self._shard_id(kind, semantic_id)]
        cache_key = (kind, semantic_id)
        with shard.lock:
            cached = shard.snapshot_cache.get(cache_key)
            if cached is not None:
                shard.snapshot_cache.move_to_end(cache_key)
            route = self.get_locked(kind, semantic_id)
            if route is not None:
                shard.lookup_candidates_inspected += 1
            return route, cached

    def cache_snapshot_locked(
        self,
        kind: str,
        semantic_id: str,
        snapshot: ServiceInstanceLifecycleSnapshot | TransportLifecycleSnapshot,
    ) -> None:
        """Publish one decoded immutable view while its exact route shard is locked."""

        shard = self._shards[self._shard_id(kind, semantic_id)]
        if shard.snapshot_cache_capacity <= 0:
            return
        cache_key = (kind, semantic_id)
        shard.snapshot_cache[cache_key] = snapshot
        shard.snapshot_cache.move_to_end(cache_key)
        while len(shard.snapshot_cache) > shard.snapshot_cache_capacity:
            shard.snapshot_cache.popitem(last=False)

    def invalidate_snapshot_locked(self, kind: str, semantic_id: str) -> None:
        """Invalidate a decoded view before mutating its canonical row state."""

        shard = self._shards[self._shard_id(kind, semantic_id)]
        shard.snapshot_cache.pop((kind, semantic_id), None)

    def invalidate_subject_snapshot_locked(self, subject: LifecycleEntityRef) -> None:
        """Invalidate cacheable service/transport views for one subject."""

        if subject.kind in {"service", "transport"}:
            self.invalidate_snapshot_locked(subject.kind, subject.object_id)

    def set_locked(self, kind: str, semantic_id: str, value: object) -> None:
        route_hash = self._route_hash(kind, semantic_id)
        shard = self._shards[route_hash % self._shard_count]
        if kind in _PACKED_ROUTE_KINDS:
            if not isinstance(value, int) or value < 0:
                raise TypeError(f"Packed lifecycle route {kind!r} requires a locator")
            route_map = shard.packed_maps.get(kind)
            if route_map is None:
                route_map = PackedUniqueDigestMap(b"lc-int-route")
                shard.packed_maps[kind] = route_map
            route_map.set_digest(route_hash, value)
            return
        if kind == "transition" and isinstance(value, int) and value < 0:
            shard.start_transitions.set_digest(route_hash, -value - 1)
            return
        route_map = shard.route_map(kind, create=True)
        assert route_map is not None
        route_map[route_hash] = value

    def remove_locked(self, kind: str, semantic_id: str) -> bool:
        route_hash = self._route_hash(kind, semantic_id)
        shard = self._shards[route_hash % self._shard_count]
        if kind in {"service", "transport"}:
            shard.snapshot_cache.pop((kind, semantic_id), None)
        if kind in _PACKED_ROUTE_KINDS:
            route_map = shard.packed_maps.get(kind)
            if route_map is None or route_map.pop_digest(route_hash) is None:
                return False
            shard.deleted[kind] = shard.deleted.get(kind, 0) + 1
            return True
        if kind == "transition" and shard.start_transitions.pop_digest(route_hash) is not None:
            shard.deleted[kind] = shard.deleted.get(kind, 0) + 1
            return True
        route_map = shard.route_map(kind, create=False)
        if route_map is None or route_hash not in route_map:
            return False
        route_map.pop(route_hash)
        shard.deleted[kind] = shard.deleted.get(kind, 0) + 1
        return True

    def get(self, kind: str, semantic_id: str) -> object | None:
        route_hash = self._route_hash(kind, semantic_id)
        shard = self._shards[route_hash % self._shard_count]
        with shard.lock:
            if kind in _PACKED_ROUTE_KINDS:
                route_map = shard.packed_maps.get(kind)
                return None if route_map is None else route_map.get_digest(route_hash)
            if kind == "transition":
                route_map = shard.route_map(kind, create=False)
                retained = None if route_map is None else route_map.get(route_hash)
                if retained is not None:
                    return retained
                start_locator = shard.start_transitions.get_digest(route_hash)
                return None if start_locator is None else -(start_locator + 1)
            route_map = shard.route_map(kind, create=False)
            return None if route_map is None else route_map.get(route_hash)

    def remove_many(self, removals: tuple[tuple[str, str], ...]) -> None:
        """Remove a deterministic watermark batch without an entry-sized rebuild."""

        if not removals:
            return
        grouped: dict[str, set[str]] = {}
        for kind, semantic_id in removals:
            grouped.setdefault(kind, set()).add(semantic_id)
        shard_ids = tuple(range(self._shard_count))
        locks = tuple(self._shards[shard_id].lock for shard_id in shard_ids)
        for lock in locks:
            lock.acquire()
        try:
            for kind, semantic_ids in grouped.items():
                if len(semantic_ids) == self._kind_count_locked(kind):
                    self._clear_kind_locked(kind)
                    continue
                for semantic_id in semantic_ids:
                    self.remove_locked(kind, semantic_id)
        finally:
            for lock in reversed(locks):
                lock.release()

    def _kind_count_locked(self, kind: str) -> int:
        """Return one route family's live count while every shard is locked."""

        total = 0
        for shard in self._shards:
            if kind in _PACKED_ROUTE_KINDS:
                route_map = shard.packed_maps.get(kind)
                total += 0 if route_map is None else len(route_map)
            else:
                route_map = shard.maps.get(kind)
                total += 0 if route_map is None else len(route_map)
                if kind == "transition":
                    total += len(shard.start_transitions)
        return total

    def _clear_kind_locked(self, kind: str) -> None:
        """Release one complete exact-route family in fixed-shard work."""

        for shard in self._shards:
            if kind in _PACKED_ROUTE_KINDS:
                shard.packed_maps.pop(kind, None)
            else:
                shard.maps.pop(kind, None)
                if kind == "transition":
                    shard.start_transitions = PackedUniqueDigestMap(b"lc-start-route")
            shard.deleted.pop(kind, None)
            if kind in {"service", "transport"} and shard.snapshot_cache:
                stale = tuple(key for key in shard.snapshot_cache if key[0] == kind)
                for key in stale:
                    shard.snapshot_cache.pop(key, None)

    def compact(self, *, max_entries: int = _PRIMARY_COMPACTION_PAGE) -> int:
        """Advance route-map rotations with one global bounded work budget."""

        if max_entries < 0:
            raise ValueError("Lifecycle route compaction budget must be non-negative")
        pairs = [
            (shard_id, kind)
            for shard_id, shard in enumerate(self._shards)
            for kind in sorted(shard.maps)
        ]
        work = 0
        for shard in self._shards:
            with shard.lock:
                for kind, route_map in shard.packed_maps.items():
                    route_map.compact_primary(
                        max_entries=0,
                        force=shard.deleted.get(kind, 0) > 0,
                    )
                    if len(route_map) == 0:
                        shard.deleted.pop(kind, None)
                shard.start_transitions.compact_primary(
                    max_entries=0,
                    force=shard.deleted.get("transition", 0) > 0,
                )
                if len(shard.start_transitions) == 0:
                    shard.deleted.pop("transition", None)
        if not pairs:
            return 0
        start = self._compaction_cursor % len(pairs)
        for offset in range(len(pairs)):
            shard_id, kind = pairs[(start + offset) % len(pairs)]
            shard = self._shards[shard_id]
            with shard.lock:
                route_map = shard.maps.get(kind)
                if route_map is None:
                    continue
                remaining = max_entries - work
                deleted = shard.deleted.get(kind, 0)
                work += route_map.compact_primary(
                    max_entries=remaining,
                    force=deleted > 0,
                )
                if not route_map.metrics().primary_compaction_pending:
                    shard.deleted.pop(kind, None)
            if work >= max_entries:
                self._compaction_cursor = (start + offset + 1) % len(pairs)
                return work
        self._compaction_cursor = (start + len(pairs)) % len(pairs)
        return work

    def metrics(self) -> _LifecycleRouteMetrics:
        """Return a fixed-shard, entry-independent exact-route census."""

        counts = {kind: 0 for kind in _ROUTE_KINDS}
        estimated_bytes = 0
        primary_map_backing_bytes = 0
        pending = False
        work = 0
        snapshot_cache_entries = 0
        snapshot_cache_capacity = 0
        snapshot_cache_estimated_bytes = 0
        lookup_candidates_inspected = 0
        for shard in self._shards:
            with shard.lock:
                for kind, route_map in shard.maps.items():
                    metric = route_map.metrics(estimate_bytes=True)
                    counts[kind] += metric.live_entries
                    estimated_bytes += metric.estimated_bytes
                    primary_map_backing_bytes += metric.primary_map_backing_bytes
                    pending = pending or metric.primary_compaction_pending
                    work += metric.primary_compaction_work
                for kind, route_map in shard.packed_maps.items():
                    metric = route_map.metrics(estimate_bytes=True)
                    counts[kind] += metric.live_entries
                    estimated_bytes += metric.estimated_bytes
                    primary_map_backing_bytes += metric.primary_map_backing_bytes
                start_metric = shard.start_transitions.metrics(estimate_bytes=True)
                counts["transition"] += start_metric.live_entries
                estimated_bytes += start_metric.estimated_bytes
                primary_map_backing_bytes += start_metric.primary_map_backing_bytes
                snapshot_cache_entries += len(shard.snapshot_cache)
                snapshot_cache_capacity += shard.snapshot_cache_capacity
                snapshot_cache_estimated_bytes += getsizeof(shard.snapshot_cache) + (
                    len(shard.snapshot_cache) * _ESTIMATED_DECODED_SNAPSHOT_BYTES
                )
                lookup_candidates_inspected += shard.lookup_candidates_inspected
        return _LifecycleRouteMetrics(
            counts=counts,
            estimated_bytes=estimated_bytes,
            primary_map_backing_bytes=primary_map_backing_bytes,
            compaction_pending=pending,
            compaction_work=work,
            snapshot_cache_entries=snapshot_cache_entries,
            snapshot_cache_capacity=snapshot_cache_capacity,
            snapshot_cache_estimated_bytes=snapshot_cache_estimated_bytes,
            lookup_candidates_inspected=lookup_candidates_inspected,
        )


@dataclass(frozen=True, slots=True)
class LifecycleSessionStartRequest:
    """One immutable session-start request admitted as part of an atomic batch."""

    identity: SessionLifecycleIdentity
    action_id: str
    transition_id: str
    transition_ordinal: int = 0


@dataclass(frozen=True, slots=True)
class LifecycleProcessStartRequest:
    """One immutable process-start request admitted as part of an atomic batch."""

    identity: ProcessLifecycleIdentity
    token: ProcessTokenIdentity
    membership: LifecycleMembership
    action_id: str
    transition_id: str
    transition_ordinal: int = 0


@dataclass(frozen=True, slots=True)
class LifecycleClosedTransportStartMember:
    """One exact State plan token paired with its lifecycle start request.

    The registry deliberately treats ``publication_token`` as opaque.  It binds
    the exact token and request into its own authenticated admission/receipt so
    a later composite authority can prove that State and lifecycle committed
    the same parent-ordered batch without a StateManager lookup here.
    """

    request: LifecycleSessionStartRequest | LifecycleProcessStartRequest
    publication_token: str

    def __post_init__(self) -> None:
        """Reject anonymous external materialization authority."""

        if not self.publication_token:
            raise ValueError("Closed-transport start members require a publication token")


@dataclass(frozen=True, slots=True)
class LifecycleClosedTransportPublicationRequest:
    """Frozen all-or-none lifecycle publication for one completed transport."""

    identity: TransportLifecycleIdentity
    start_members: tuple[LifecycleClosedTransportStartMember, ...]
    process_holds: tuple[LifecycleHold, ...]
    binding_identity: TransportSessionBindingIdentity | None
    start_action_id: str
    start_transition_id: str
    start_transition_ordinal: int
    binding_close_action_id: str
    binding_close_transition_ordinal: int
    barrier: LifecycleCloseBarrier
    ticket_id: str

    def __post_init__(self) -> None:
        """Validate exact ordering, relation ownership, and closure identity."""

        if not self.start_action_id or not self.start_transition_id or not self.ticket_id:
            raise ValueError(
                "Closed-transport publication requires start, transition, and ticket IDs"
            )
        if self.start_transition_ordinal < 0:
            raise ValueError("Closed-transport start ordinal must be non-negative")
        if self.binding_close_transition_ordinal < 0:
            raise ValueError("Closed-transport binding-close ordinal must be non-negative")
        if self.barrier.subject != self.identity.ref:
            raise ValueError("Closed-transport barrier must target the transport identity")
        if self.barrier.requested_at != self.identity.close_deadline:
            raise ValueError("Closed-transport barrier must equal the canonical close deadline")
        binding = self.binding_identity
        if binding is None:
            if self.binding_close_action_id:
                raise ValueError("Binding-close action requires a transport/session binding")
        else:
            if binding.transport_object_id != self.identity.object_id:
                raise ValueError("Closed-transport binding references another transport")
            if not self.binding_close_action_id:
                raise ValueError("Closed transport/session binding requires a close action")
            if not self.identity.opened_at <= binding.bound_at <= self.identity.close_deadline:
                raise ValueError("Transport/session binding time must lie inside the transport")

        session_members = [
            member
            for member in self.start_members
            if isinstance(member.request, LifecycleSessionStartRequest)
        ]
        if len(session_members) > 1:
            raise ValueError("Closed-transport start batch supports at most one session")
        if session_members and self.start_members[0] is not session_members[0]:
            raise ValueError("Closed-transport staged session must be the first start member")
        if len({member.publication_token for member in self.start_members}) != len(
            self.start_members
        ):
            raise ValueError("Closed-transport start batch repeats a publication token")
        hold_ids = [hold.hold_id for hold in self.process_holds]
        if len(set(hold_ids)) != len(hold_ids):
            raise ValueError("Closed-transport publication repeats a process hold ID")
        seen_objects: set[str] = set()
        staged_session_id = ""
        for ordinal, member in enumerate(self.start_members):
            request = member.request
            object_id = request.identity.object_id
            if object_id in seen_objects:
                raise ValueError("Closed-transport start batch repeats a lifecycle object")
            seen_objects.add(object_id)
            if isinstance(request, LifecycleSessionStartRequest):
                if ordinal != 0:
                    raise ValueError("Closed-transport session start must precede process starts")
                staged_session_id = object_id
                continue
            parent_id = request.identity.parent_object_id
            if (
                parent_id
                and parent_id
                in {candidate.request.identity.object_id for candidate in self.start_members}
                and parent_id not in seen_objects
            ):
                raise ValueError("Closed-transport staged process parent must precede its child")
            session_id = request.membership.session_object_id
            if session_id and session_id == staged_session_id:
                continue
        if binding is not None and staged_session_id:
            if binding.session_object_id != staged_session_id:
                raise ValueError(
                    "Closed-transport binding must target the exact staged session member"
                )
        staged_process_ids = {
            member.request.identity.object_id
            for member in self.start_members
            if isinstance(member.request, LifecycleProcessStartRequest)
        }
        for hold in self.process_holds:
            if hold.subject.kind != "process":
                raise ValueError("Closed-transport holds must target process lifecycles")
            if hold.hold_until < self.identity.close_deadline:
                raise ValueError(
                    "Closed-transport process holds must retain through transport close"
                )
            if hold.subject.object_id in staged_process_ids:
                continue

    @property
    def start_plan_tokens(self) -> tuple[str, ...]:
        """Return the exact ordered opaque State publication tokens."""

        return tuple(member.publication_token for member in self.start_members)

    @property
    def linearization_time(self) -> datetime:
        """Return the earliest canonical time fenced by this publication."""

        candidates = [self.identity.opened_at]
        candidates.extend(member.request.identity.started_at for member in self.start_members)
        candidates.extend(hold.acquired_at for hold in self.process_holds)
        return min(candidates)


@dataclass(frozen=True, slots=True)
class LifecycleClosedTransportAdmissionToken:
    """Opaque authenticated reservation for one closed-transport publication."""

    request: LifecycleClosedTransportPublicationRequest
    registry_id: str
    preparation_id: int
    expected_watermark: datetime | None
    plan_digest: str
    _integrity: str = field(repr=False)

    @property
    def publication_token(self) -> str:
        """Return the opaque preparation proof suitable for a composite HMAC."""

        return self._integrity


@dataclass(frozen=True, slots=True, weakref_slot=True)
class LifecycleClosedTransportPublicationReceipt:
    """Authenticated proof of one complete lifecycle publication."""

    request: LifecycleClosedTransportPublicationRequest
    transport: TransportLifecycleSnapshot
    binding: TransportSessionBindingSnapshot | None
    session_snapshots: tuple[SessionLifecycleSnapshotView, ...]
    process_snapshots: tuple[ProcessLifecycleSnapshot, ...]
    process_holds: tuple[LifecycleHold, ...]
    registry_id: str
    plan_digest: str
    committed_digest: str
    _integrity: str = field(repr=False)

    @property
    def start_plan_tokens(self) -> tuple[str, ...]:
        """Return the exact ordered external plan tokens authenticated by this receipt."""

        return self.request.start_plan_tokens

    @property
    def publication_token(self) -> str:
        """Return the opaque receipt proof suitable for a composite HMAC."""

        return self._integrity


@dataclass(frozen=True, slots=True)
class LifecycleClosedTransportPreparationCensus:
    """Constant-time census of transient closed-transport capabilities."""

    reservations: int
    claimed_reservations: int
    reserved_keys: int
    capability_locators: int


@dataclass(frozen=True, slots=True)
class LifecycleServiceStagedProcessBindingMember:
    """Exact staged process start authorized to receive one service binding.

    The registry treats ``state_publication_token`` as an opaque value.  The
    owning State/lifecycle coordinator authenticates it against the matching
    allocation-free StateManager plan before this member may commit.
    """

    binding_id: str
    process_start: LifecycleProcessStartRequest
    state_publication_token: str

    def __post_init__(self) -> None:
        """Require stable exact identities for the staged relation."""

        if not self.binding_id or not self.state_publication_token:
            raise ValueError("Staged service/process binding requires exact proof IDs")


@dataclass(frozen=True, slots=True)
class LifecycleServicePublicationRequest:
    """Frozen all-or-none service instance and process-binding publication."""

    logical_identity: LogicalServiceIdentity
    identity: ServiceInstanceLifecycleIdentity
    process_bindings: tuple[ServiceProcessBindingIdentity, ...]
    action_id: str
    transition_id: str
    transition_ordinal: int = 0
    staged_process_bindings: tuple[LifecycleServiceStagedProcessBindingMember, ...] = ()

    def __post_init__(self) -> None:
        """Reject incomplete, duplicated, or cross-service publication inputs."""

        if not self.action_id or not self.transition_id:
            raise ValueError("Service publication requires action and transition IDs")
        if self.transition_ordinal < 0:
            raise ValueError("Service publication ordinal must be non-negative")
        if self.logical_identity.hostname != self.identity.hostname:
            raise ValueError("Logical service and instance hosts must match")
        if self.logical_identity.logical_service_id != self.identity.logical_service_id:
            raise ValueError("Logical service and instance IDs must match")
        binding_ids = [binding.binding_id for binding in self.process_bindings]
        process_ids = [binding.process_object_id for binding in self.process_bindings]
        if len(set(binding_ids)) != len(binding_ids):
            raise ValueError("Service publication repeats a binding ID")
        if len(set(process_ids)) != len(process_ids):
            raise ValueError("Service publication repeats a process binding")
        if any(
            binding.service_object_id != self.identity.object_id
            for binding in self.process_bindings
        ):
            raise ValueError("Service publication binding references another service")
        binding_by_id = {binding.binding_id: binding for binding in self.process_bindings}
        binding_position = {
            binding.binding_id: index for index, binding in enumerate(self.process_bindings)
        }
        staged_binding_ids = [member.binding_id for member in self.staged_process_bindings]
        if len(set(staged_binding_ids)) != len(staged_binding_ids):
            raise ValueError("Service publication repeats a staged binding member")
        staged_tokens = [member.state_publication_token for member in self.staged_process_bindings]
        staged_object_ids = [
            member.process_start.identity.object_id for member in self.staged_process_bindings
        ]
        staged_pid_keys = [
            (
                member.process_start.identity.hostname.strip().casefold(),
                member.process_start.identity.pid,
            )
            for member in self.staged_process_bindings
        ]
        staged_transition_ids = [
            member.process_start.transition_id for member in self.staged_process_bindings
        ]
        for values, message in (
            (staged_tokens, "Service publication repeats a State start token"),
            (staged_object_ids, "Service publication repeats a staged process object"),
            (staged_pid_keys, "Service publication repeats a staged process PID"),
            (staged_transition_ids, "Service publication repeats a process transition"),
        ):
            if len(set(values)) != len(values):
                raise ValueError(message)
        if self.transition_id in staged_transition_ids:
            raise ValueError("Service and staged process transitions must be distinct")
        staged_positions: list[int] = []
        staged_order = {object_id: index for index, object_id in enumerate(staged_object_ids)}
        for member in self.staged_process_bindings:
            binding = binding_by_id.get(member.binding_id)
            if binding is None:
                raise ValueError("Staged service process is missing its exact binding")
            process_identity = member.process_start.identity
            if binding.process_object_id != process_identity.object_id:
                raise ValueError("Staged service binding references another process")
            if process_identity.hostname != self.identity.hostname:
                raise ValueError("Staged service process cannot cross hosts")
            if binding.bound_at < process_identity.started_at:
                raise ValueError("Staged service binding precedes its process start")
            parent_id = process_identity.parent_object_id
            if (
                parent_id in staged_order
                and staged_order[parent_id] >= staged_order[process_identity.object_id]
            ):
                raise ValueError("Staged service process parent must precede its child")
            staged_positions.append(binding_position[member.binding_id])
        if staged_positions != sorted(staged_positions):
            raise ValueError("Staged service process bindings must preserve binding order")

    @property
    def linearization_time(self) -> datetime:
        """Return the earliest canonical time fenced by this publication."""

        return min(
            (
                self.identity.started_at,
                *(item.bound_at for item in self.process_bindings),
                *(
                    member.process_start.identity.started_at
                    for member in self.staged_process_bindings
                ),
            )
        )


@dataclass(frozen=True, slots=True)
class LifecycleServiceAdmissionToken:
    """Opaque authenticated reservation for one service publication."""

    request: LifecycleServicePublicationRequest
    registry_id: str
    preparation_id: int
    expected_watermark: datetime | None
    plan_digest: str
    _integrity: str = field(repr=False)

    @property
    def publication_token(self) -> str:
        """Return the opaque proof suitable for a composite authority HMAC."""

        return self._integrity


@dataclass(frozen=True, slots=True, weakref_slot=True)
class LifecycleServicePublicationReceipt:
    """Authenticated proof of one complete service publication."""

    request: LifecycleServicePublicationRequest
    service: ServiceInstanceLifecycleSnapshot
    bindings: tuple[ServiceProcessBindingSnapshot, ...]
    registry_id: str
    plan_digest: str
    committed_digest: str
    _integrity: str = field(repr=False)
    processes: tuple[ProcessLifecycleSnapshot, ...] = ()
    start_plan_tokens: tuple[str, ...] = ()

    @property
    def publication_token(self) -> str:
        """Return the opaque receipt proof suitable for a composite HMAC."""

        return self._integrity


@dataclass(frozen=True, slots=True)
class LifecycleServiceProcessBindingClosure:
    """Frozen exact closure of one service/process ownership relation."""

    identity: ServiceProcessBindingIdentity
    closed_at: datetime
    action_id: str
    transition_ordinal: int = 0

    def __post_init__(self) -> None:
        """Normalize closure time and require stable action ordering."""

        if not self.action_id:
            raise ValueError("Service/process binding closure requires an action ID")
        if self.transition_ordinal < 0:
            raise ValueError("Service/process binding closure ordinal must be non-negative")
        closed_at = ensure_utc(self.closed_at)
        if closed_at < self.identity.bound_at:
            raise ValueError("Service/process binding close precedes its bind time")
        object.__setattr__(self, "closed_at", closed_at)


@dataclass(frozen=True, slots=True)
class LifecycleSubjectClosureControl:
    """Exact barrier/ticket pair for one lifecycle subject terminalization."""

    barrier: LifecycleCloseBarrier
    ticket_id: str

    def __post_init__(self) -> None:
        """Require stable ticket identity and a supported closable subject."""

        if not self.ticket_id:
            raise ValueError("Lifecycle subject closure requires a ticket ID")
        if self.barrier.subject.kind not in {"process", "service", "session"}:
            raise ValueError(
                "Lifecycle closure controls support process, service, or session subjects"
            )


LifecycleActionCohortOperation = (
    LifecycleSessionStartRequest
    | LifecycleProcessStartRequest
    | LifecycleTransition
    | LifecycleHold
    | LifecycleSubjectClosureControl
)
LifecycleActionCohortOperationResult = (
    SessionLifecycleSnapshotView | ProcessLifecycleSnapshot | LifecycleTransition | LifecycleHold
)


@dataclass(frozen=True, slots=True)
class LifecycleActionCohortRequest:
    """One author-ordered lifecycle transaction bound to an opaque State plan."""

    state_publication_token: str
    operations: tuple[LifecycleActionCohortOperation, ...]

    def __post_init__(self) -> None:
        """Reject incomplete, unordered, duplicated, or causally invalid operations."""

        if type(self.state_publication_token) is not str or not self.state_publication_token:
            raise ValueError("Lifecycle action cohorts require an opaque State publication token")
        if type(self.operations) is not tuple or not self.operations:
            raise ValueError("Lifecycle action cohorts require an ordered operation tuple")
        if len(self.operations) > _MAX_ACTION_COHORT_OPERATIONS_PER_REQUEST:
            raise ValueError(
                "Lifecycle action cohort operation capacity exceeded: "
                f"{len(self.operations)} > {_MAX_ACTION_COHORT_OPERATIONS_PER_REQUEST}"
            )

        supported = {
            LifecycleSessionStartRequest,
            LifecycleProcessStartRequest,
            LifecycleTransition,
            LifecycleHold,
            LifecycleSubjectClosureControl,
        }
        if any(type(operation) not in supported for operation in self.operations):
            raise TypeError("Lifecycle action cohort contains an unsupported operation type")

        start_positions: dict[LifecycleEntityRef, int] = {}
        session_starts: dict[str, LifecycleSessionStartRequest] = {}
        process_starts: dict[str, LifecycleProcessStartRequest] = {}
        object_ids: set[str] = set()
        session_groups: set[tuple[str, str]] = set()
        process_groups: set[tuple[str, int]] = set()
        for position, operation in enumerate(self.operations):
            if type(operation) is LifecycleSessionStartRequest:
                identity = operation.identity
                if type(identity) is not SessionLifecycleIdentity:
                    raise TypeError("Lifecycle cohort session starts require exact identities")
                if (
                    type(operation.action_id) is not str
                    or type(operation.transition_id) is not str
                    or not operation.action_id
                    or not operation.transition_id
                ):
                    raise ValueError(
                        "Lifecycle cohort session starts require action and transition IDs"
                    )
                if (
                    type(operation.transition_ordinal) is not int
                    or operation.transition_ordinal < 0
                ):
                    raise ValueError("Lifecycle cohort session start ordinal must be non-negative")
                if identity.object_id in object_ids:
                    raise ValueError("Lifecycle action cohort repeats a lifecycle object")
                group = (
                    identity.hostname.strip().casefold(),
                    identity.logon_id.strip().casefold(),
                )
                if group in session_groups:
                    raise ValueError("Lifecycle action cohort repeats a session LogonID interval")
                object_ids.add(identity.object_id)
                session_groups.add(group)
                session_starts[identity.object_id] = operation
                start_positions[identity.ref] = position
            elif type(operation) is LifecycleProcessStartRequest:
                identity = operation.identity
                if (
                    type(identity) is not ProcessLifecycleIdentity
                    or type(operation.token) is not ProcessTokenIdentity
                    or type(operation.membership) is not LifecycleMembership
                ):
                    raise TypeError(
                        "Lifecycle cohort process starts require exact lifecycle values"
                    )
                if (
                    type(operation.action_id) is not str
                    or type(operation.transition_id) is not str
                    or not operation.action_id
                    or not operation.transition_id
                ):
                    raise ValueError(
                        "Lifecycle cohort process starts require action and transition IDs"
                    )
                if (
                    type(operation.transition_ordinal) is not int
                    or operation.transition_ordinal < 0
                ):
                    raise ValueError("Lifecycle cohort process start ordinal must be non-negative")
                if identity.object_id in object_ids:
                    raise ValueError("Lifecycle action cohort repeats a lifecycle object")
                group = (identity.hostname.strip().casefold(), identity.pid)
                if group in process_groups:
                    raise ValueError("Lifecycle action cohort repeats a process PID interval")
                object_ids.add(identity.object_id)
                process_groups.add(group)
                process_starts[identity.object_id] = operation
                start_positions[identity.ref] = position

        transition_ids: set[str] = set()
        transition_commits: set[tuple[LifecycleEntityRef, str, int]] = set()
        hold_ids: set[str] = set()
        barrier_ids: set[str] = set()
        ticket_ids: set[str] = set()
        closed_subjects: set[LifecycleEntityRef] = set()
        prior_time: datetime | None = None
        equal_time_ordinals: dict[tuple[LifecycleEntityRef, datetime, str], int] = {}

        def claim_transition(
            transition_id: str,
            subject: LifecycleEntityRef,
            action_id: str,
            ordinal: int,
            canonical_time: datetime,
        ) -> None:
            if transition_id in transition_ids:
                raise ValueError("Lifecycle action cohort repeats a transition ID")
            transition_ids.add(transition_id)
            commit = (subject, action_id, ordinal)
            if commit in transition_commits:
                raise ValueError("Lifecycle action cohort repeats an action commit ordinal")
            transition_commits.add(commit)
            order_key = (subject, canonical_time, action_id)
            prior_ordinal = equal_time_ordinals.get(order_key)
            if prior_ordinal is not None and ordinal <= prior_ordinal:
                raise ValueError(
                    "Lifecycle action cohort ordinals must preserve equal-time operation order"
                )
            equal_time_ordinals[order_key] = ordinal

        for position, operation in enumerate(self.operations):
            if type(operation) is LifecycleSessionStartRequest:
                subject = operation.identity.ref
                canonical_time = operation.identity.started_at
                action_id = operation.action_id
                ordinal = operation.transition_ordinal
                transition_id = operation.transition_id
            elif type(operation) is LifecycleProcessStartRequest:
                subject = operation.identity.ref
                canonical_time = operation.identity.started_at
                action_id = operation.action_id
                ordinal = operation.transition_ordinal
                transition_id = operation.transition_id
                parent_id = operation.identity.parent_object_id
                if parent_id in process_starts:
                    parent = process_starts[parent_id]
                    if start_positions[parent.identity.ref] >= position:
                        raise ValueError(
                            "Lifecycle action cohort process parent must start before its child"
                        )
                    if parent.identity.ref in closed_subjects:
                        raise ValueError(
                            "Lifecycle action cohort starts a child after parent close"
                        )
                session_id = operation.membership.session_object_id
                if session_id in session_starts:
                    session = session_starts[session_id]
                    if start_positions[session.identity.ref] >= position:
                        raise ValueError(
                            "Lifecycle action cohort session must start before its member process"
                        )
                    if session.identity.ref in closed_subjects:
                        raise ValueError(
                            "Lifecycle action cohort starts a member after session close"
                        )
            elif type(operation) is LifecycleTransition:
                if (
                    type(operation.subject) is not LifecycleEntityRef
                    or type(operation.transition_id) is not str
                    or type(operation.action_id) is not str
                    or type(operation.reason) is not str
                    or type(operation.transition_ordinal) is not int
                ):
                    raise TypeError("Lifecycle action cohort dependent fields must be exact")
                if operation.kind != "dependent" or operation.subject.kind not in {
                    "process",
                    "session",
                }:
                    raise ValueError(
                        "Lifecycle action cohort transitions must be process/session dependents"
                    )
                subject = operation.subject
                canonical_time = operation.canonical_time
                action_id = operation.action_id
                ordinal = operation.transition_ordinal
                transition_id = operation.transition_id
            elif type(operation) is LifecycleHold:
                if (
                    type(operation.subject) is not LifecycleEntityRef
                    or type(operation.hold_id) is not str
                    or type(operation.action_id) is not str
                    or type(operation.reason) is not str
                    or type(operation.transition_ordinal) is not int
                ):
                    raise TypeError("Lifecycle action cohort hold fields must be exact")
                if operation.subject.kind not in {"process", "session"}:
                    raise ValueError(
                        "Lifecycle action cohort holds must target process or session subjects"
                    )
                subject = operation.subject
                canonical_time = operation.acquired_at
                action_id = operation.action_id
                ordinal = operation.transition_ordinal
                transition_id = f"{operation.hold_id}:acquired"
                if operation.hold_id in hold_ids:
                    raise ValueError("Lifecycle action cohort repeats a hold ID")
                hold_ids.add(operation.hold_id)
            else:
                assert type(operation) is LifecycleSubjectClosureControl
                barrier = operation.barrier
                if (
                    type(barrier) is not LifecycleCloseBarrier
                    or type(barrier.subject) is not LifecycleEntityRef
                    or type(operation.ticket_id) is not str
                ):
                    raise TypeError("Lifecycle action cohort closure fields must be exact")
                if barrier.subject.kind not in {"process", "session"}:
                    raise ValueError(
                        "Lifecycle action cohort closures must target process or session subjects"
                    )
                subject = barrier.subject
                canonical_time = barrier.requested_at
                action_id = barrier.action_id
                ordinal = 0
                transition_id = f"{barrier.barrier_id}:requested"
                if barrier.barrier_id in barrier_ids:
                    raise ValueError("Lifecycle action cohort repeats a close barrier")
                if operation.ticket_id in ticket_ids:
                    raise ValueError("Lifecycle action cohort repeats a closure ticket")
                barrier_ids.add(barrier.barrier_id)
                ticket_ids.add(operation.ticket_id)

            staged_position = start_positions.get(subject)
            if staged_position is not None and staged_position > position:
                raise ValueError("Lifecycle action cohort operation precedes its staged start")
            if subject in closed_subjects:
                raise ValueError("Lifecycle action cohort contains an operation after closure")
            if prior_time is not None and canonical_time < prior_time:
                raise ValueError("Lifecycle action cohort operations must be time ordered")
            prior_time = canonical_time

            claim_transition(transition_id, subject, action_id, ordinal, canonical_time)
            if type(operation) is LifecycleSubjectClosureControl:
                claim_transition(
                    f"{operation.ticket_id}:scheduled",
                    subject,
                    action_id,
                    1,
                    canonical_time,
                )
                claim_transition(
                    f"{operation.ticket_id}:closed",
                    subject,
                    action_id,
                    2,
                    canonical_time,
                )
                for process in process_starts.values():
                    process_ref = process.identity.ref
                    if (
                        subject.kind == "process"
                        and process.identity.parent_object_id == subject.object_id
                    ):
                        if (
                            start_positions[process_ref] < position
                            and process_ref not in closed_subjects
                        ):
                            raise ValueError(
                                "Lifecycle action cohort must close staged children before parent"
                            )
                    if (
                        subject.kind == "session"
                        and process.membership.session_object_id == subject.object_id
                        and start_positions[process_ref] < position
                        and process_ref not in closed_subjects
                    ):
                        raise ValueError(
                            "Lifecycle action cohort must close staged members before session"
                        )
                closed_subjects.add(subject)

    @property
    def linearization_time(self) -> datetime:
        """Return the first canonical operation time fenced by this cohort."""

        operation = self.operations[0]
        if type(operation) is LifecycleSessionStartRequest:
            return operation.identity.started_at
        if type(operation) is LifecycleProcessStartRequest:
            return operation.identity.started_at
        if type(operation) is LifecycleTransition:
            return operation.canonical_time
        if type(operation) is LifecycleHold:
            return operation.acquired_at
        assert type(operation) is LifecycleSubjectClosureControl
        return operation.barrier.requested_at


@dataclass(frozen=True, slots=True, weakref_slot=True)
class LifecycleActionCohortAdmissionToken:
    """Opaque authenticated reservation for one lifecycle action cohort."""

    request: LifecycleActionCohortRequest
    registry_id: str
    preparation_id: int
    expected_watermark: datetime | None
    plan_digest: str
    _integrity: str = field(repr=False)

    @property
    def publication_token(self) -> str:
        """Return the opaque preparation proof for a composite authority."""

        return self._integrity


@dataclass(frozen=True, slots=True, weakref_slot=True)
class LifecycleActionCohortReceipt:
    """Authenticated proof of one complete ordered lifecycle transaction."""

    request: LifecycleActionCohortRequest
    operation_results: tuple[LifecycleActionCohortOperationResult, ...]
    registry_id: str
    plan_digest: str
    committed_digest: str
    _integrity: str = field(repr=False)

    @property
    def state_publication_token(self) -> str:
        """Return the exact opaque State plan token bound by this receipt."""

        return self.request.state_publication_token

    @property
    def publication_token(self) -> str:
        """Return the opaque receipt proof for a composite authority."""

        return self._integrity

    def _results_for(self, operation_type: type[object]) -> tuple[object, ...]:
        return tuple(
            result
            for operation, result in zip(
                self.request.operations,
                self.operation_results,
                strict=True,
            )
            if type(operation) is operation_type
        )

    @property
    def started_sessions(self) -> tuple[SessionLifecycleSnapshotView, ...]:
        """Return final snapshots for session-start operations in author order."""

        return self._results_for(LifecycleSessionStartRequest)  # type: ignore[return-value]

    @property
    def started_processes(self) -> tuple[ProcessLifecycleSnapshot, ...]:
        """Return final snapshots for process-start operations in author order."""

        return self._results_for(LifecycleProcessStartRequest)  # type: ignore[return-value]

    @property
    def dependents(self) -> tuple[LifecycleTransition, ...]:
        """Return dependent transitions in author order."""

        return self._results_for(LifecycleTransition)  # type: ignore[return-value]

    @property
    def holds(self) -> tuple[LifecycleHold, ...]:
        """Return holds in author order."""

        return self._results_for(LifecycleHold)  # type: ignore[return-value]

    @property
    def closed_processes(self) -> tuple[ProcessLifecycleSnapshot, ...]:
        """Return final process-closure snapshots in author order."""

        return tuple(
            result
            for operation, result in zip(
                self.request.operations,
                self.operation_results,
                strict=True,
            )
            if type(operation) is LifecycleSubjectClosureControl
            and operation.barrier.subject.kind == "process"
        )  # type: ignore[return-value]

    @property
    def closed_sessions(self) -> tuple[SessionLifecycleSnapshotView, ...]:
        """Return final session-closure snapshots in author order."""

        return tuple(
            result
            for operation, result in zip(
                self.request.operations,
                self.operation_results,
                strict=True,
            )
            if type(operation) is LifecycleSubjectClosureControl
            and operation.barrier.subject.kind == "session"
        )  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class LifecycleActionCohortPreparationCensus:
    """Constant-time census of transient action-cohort capabilities."""

    reservations: int
    unclaimed_reservations: int
    claimed_reservations: int
    committing_reservations: int
    reserved_keys: int
    capability_locators: int
    claimed_capability_locators: int
    certified_authorization_locators: int
    expected_receipt_authorities: int
    committed_receipt_authorities: int
    retained_request_bytes: int
    committed_provenance: int
    pending_provenance_insertions: int
    pending_provenance_evictions: int
    operation_capacity_per_request: int
    reservation_capacity: int
    reserved_key_capacity: int
    request_byte_capacity: int
    committed_provenance_capacity: int
    receipt_authority_capacity: int


@dataclass(frozen=True, slots=True)
class LifecycleServiceProcessClosureRequest:
    """Frozen binding-first process/service terminalization transaction."""

    binding_closures: tuple[LifecycleServiceProcessBindingClosure, ...]
    process_closures: tuple[LifecycleSubjectClosureControl, ...] = ()
    service_closures: tuple[LifecycleSubjectClosureControl, ...] = ()

    def __post_init__(self) -> None:
        """Reject duplicates, wrong kinds, and empty closure transactions."""

        if not (self.binding_closures or self.process_closures or self.service_closures):
            raise ValueError("Service/process closure request cannot be empty")
        binding_ids = [item.identity.binding_id for item in self.binding_closures]
        process_ids = [item.barrier.subject.object_id for item in self.process_closures]
        service_ids = [item.barrier.subject.object_id for item in self.service_closures]
        if len(set(binding_ids)) != len(binding_ids):
            raise ValueError("Service/process closure repeats a binding")
        if len(set(process_ids)) != len(process_ids):
            raise ValueError("Service/process closure repeats a process")
        if len(set(service_ids)) != len(service_ids):
            raise ValueError("Service/process closure repeats a service")
        if any(item.barrier.subject.kind != "process" for item in self.process_closures):
            raise ValueError("Process closure controls must target process subjects")
        if any(item.barrier.subject.kind != "service" for item in self.service_closures):
            raise ValueError("Service closure controls must target service subjects")
        barrier_ids = [
            item.barrier.barrier_id for item in (*self.process_closures, *self.service_closures)
        ]
        ticket_ids = [item.ticket_id for item in (*self.process_closures, *self.service_closures)]
        if len(set(barrier_ids)) != len(barrier_ids):
            raise ValueError("Service/process closure repeats a close barrier")
        if len(set(ticket_ids)) != len(ticket_ids):
            raise ValueError("Service/process closure repeats a close ticket")

    @property
    def linearization_time(self) -> datetime:
        """Return the earliest canonical time fenced by this closure."""

        return min(
            *(item.closed_at for item in self.binding_closures),
            *(
                item.barrier.requested_at
                for item in (*self.process_closures, *self.service_closures)
            ),
        )


@dataclass(frozen=True, slots=True)
class LifecycleServiceClosureAdmissionToken:
    """Opaque authenticated reservation for one service/process closure."""

    request: LifecycleServiceProcessClosureRequest
    registry_id: str
    preparation_id: int
    expected_watermark: datetime | None
    plan_digest: str
    _integrity: str = field(repr=False)

    @property
    def publication_token(self) -> str:
        """Return the opaque proof suitable for a composite authority HMAC."""

        return self._integrity


@dataclass(frozen=True, slots=True, weakref_slot=True)
class LifecycleServiceProcessClosureReceipt:
    """Authenticated proof of exact binding/process/service terminalization."""

    request: LifecycleServiceProcessClosureRequest
    bindings: tuple[ServiceProcessBindingSnapshot, ...]
    processes: tuple[ProcessLifecycleSnapshot, ...]
    services: tuple[ServiceInstanceLifecycleSnapshot, ...]
    registry_id: str
    plan_digest: str
    committed_digest: str
    _integrity: str = field(repr=False)

    @property
    def publication_token(self) -> str:
        """Return the opaque receipt proof suitable for a composite HMAC."""

        return self._integrity


@dataclass(frozen=True, slots=True)
class LifecycleServicePreparationCensus:
    """Constant-time census of transient service publication capabilities."""

    publication_reservations: int
    closure_reservations: int
    claimed_publications: int
    claimed_closures: int
    reserved_keys: int
    capability_locators: int


@dataclass(slots=True)
class PreparedSessionRegistration:
    """Lock-scoped validated session start whose commit performs no validation."""

    _registry: LifecycleRegistry
    _partition_id: int
    _prepared: _PreparedSessionPartitionStart
    _prior_session_route: object | None
    _active: bool = True
    _result: SessionLifecycleSnapshotView | None = None

    @property
    def committed(self) -> bool:
        """Return whether this ticket has published its prepared start."""

        return self._result is not None

    def commit(self) -> SessionLifecycleSnapshotView:
        """Publish the already-validated start while all authority locks remain held."""

        if not self._active:
            raise StateError("Prepared lifecycle session ticket is no longer active")
        if self._result is not None:
            return self._result
        partition = self._registry._partitions[self._partition_id]
        snapshot = partition._commit_prepared_session_locked(self._prepared)
        handle = self._prepared.handle
        row = partition.session_row_for_handle(handle)
        self._registry._routes.set_locked(
            "session",
            self._prepared.identity.object_id,
            self._prior_session_route if isinstance(self._prior_session_route, int) else row,
        )
        self._registry._routes.set_locked(
            "transition",
            self._prepared.transition.transition_id,
            self._registry._session_start_locator(self._partition_id, handle),
        )
        self._result = snapshot
        return snapshot


@dataclass(slots=True)
class PreparedProcessRegistration:
    """Lock-scoped validated process start whose commit performs no validation."""

    _registry: LifecycleRegistry
    _partition_id: int
    _prepared: _PreparedProcessPartitionStart
    _membership: LifecycleMembership
    _active: bool = True
    _result: ProcessLifecycleSnapshot | None = None

    @property
    def committed(self) -> bool:
        """Return whether this ticket has published its prepared start."""

        return self._result is not None

    def commit(self) -> ProcessLifecycleSnapshot:
        """Publish the already-validated start while all authority locks remain held."""

        if not self._active:
            raise StateError("Prepared lifecycle process ticket is no longer active")
        if self._result is not None:
            return self._result
        partition = self._registry._partitions[self._partition_id]
        snapshot = partition._commit_prepared_process_locked(self._prepared)
        if self._membership.session_object_id:
            self._registry._promote_session_route_locked(
                LifecycleEntityRef("session", self._membership.session_object_id),
                self._partition_id,
            )
        identity = self._prepared.entry.identity
        self._registry._routes.set_locked("process", identity.object_id, self._partition_id)
        self._registry._routes.set_locked(
            "transition",
            self._prepared.transition.transition_id,
            self._prepared.transition,
        )
        self._result = snapshot
        return snapshot


@dataclass(slots=True)
class PreparedLifecycleStartBatch:
    """Validated multi-partition start batch committed under one sorted lock set."""

    _registry: LifecycleRegistry
    _sessions: tuple[tuple[int, _PreparedSessionPartitionStart, object | None], ...]
    _processes: tuple[tuple[int, _PreparedProcessPartitionStart, LifecycleMembership], ...]
    _service_publication: PreparedLifecycleServicePublication | None = None
    _service_plan: _PreparedServiceCommitPlan | None = None
    _active: bool = True
    _committed: bool = False
    _session_results: tuple[SessionLifecycleSnapshotView, ...] = ()
    _process_results: tuple[ProcessLifecycleSnapshot, ...] = ()
    _service_result: LifecycleServicePublicationReceipt | None = None

    @property
    def committed(self) -> bool:
        """Return whether every start in this batch has been published."""

        return self._committed

    @property
    def service_receipt(self) -> LifecycleServicePublicationReceipt | None:
        """Return the atomic service result when this is a composite ticket."""

        return self._service_result

    def commit(
        self,
    ) -> tuple[
        tuple[SessionLifecycleSnapshotView, ...],
        tuple[ProcessLifecycleSnapshot, ...],
    ]:
        """Publish every validated start in parent-before-child order."""

        if not self._active:
            raise StateError("Prepared lifecycle start batch is no longer active")
        if self._committed:
            return self._session_results, self._process_results
        session_results: list[SessionLifecycleSnapshotView] = []
        for partition_id, prepared, prior_route in self._sessions:
            ticket = PreparedSessionRegistration(
                _registry=self._registry,
                _partition_id=partition_id,
                _prepared=prepared,
                _prior_session_route=prior_route,
            )
            session_results.append(ticket.commit())
        process_results: list[ProcessLifecycleSnapshot] = []
        for partition_id, prepared, membership in self._processes:
            ticket = PreparedProcessRegistration(
                _registry=self._registry,
                _partition_id=partition_id,
                _prepared=prepared,
                _membership=membership,
            )
            process_results.append(ticket.commit())
        if self._service_publication is not None:
            service_plan = self._service_plan
            if service_plan is None:
                raise AssertionError("Composite lifecycle start has no service commit plan")
            self._service_result = self._service_publication._commit_prevalidated_locked(
                service_plan,
                staged_processes=tuple(process_results),
            )
        self._session_results = tuple(session_results)
        self._process_results = tuple(process_results)
        self._committed = True
        return self._session_results, self._process_results


@dataclass(slots=True)
class _PreparedServiceCommitPlan:
    """Validated primitive service writes retained by one claimed reservation."""

    token: LifecycleServiceAdmissionToken
    partition_id: int
    service: _PreparedServicePartitionStart
    bindings: tuple[_PreparedServiceProcessBinding, ...]


@dataclass(slots=True)
class _PreparedServiceClosureCommitPlan:
    """Validated binding-first terminal writes retained by one claimed reservation."""

    token: LifecycleServiceClosureAdmissionToken
    already_terminal: bool = False


@dataclass(slots=True)
class _ServicePublicationReservation:
    """Transient exact-key service publication reservation with no canonical rows."""

    token: LifecycleServiceAdmissionToken
    canonical_token: LifecycleServiceAdmissionToken
    keys: tuple[tuple[str, str], ...]
    claimed: bool = False
    claim_thread_id: int | None = None
    commit_plan: _PreparedServiceCommitPlan | None = None


@dataclass(slots=True)
class _ServiceClosureReservation:
    """Transient exact-key service closure reservation with no canonical writes."""

    token: LifecycleServiceClosureAdmissionToken
    canonical_token: LifecycleServiceClosureAdmissionToken
    keys: tuple[tuple[str, str], ...]
    claimed: bool = False
    claim_thread_id: int | None = None
    commit_plan: _PreparedServiceClosureCommitPlan | None = None


class PreparedLifecycleServicePublication:
    """One-shot no-validation commit capability for a claimed service publication."""

    __slots__ = ("_active", "_committed", "_registry", "_result", "_token")

    def __init__(self, registry: LifecycleRegistry, token: LifecycleServiceAdmissionToken) -> None:
        self._registry = registry
        self._token = token
        self._active = True
        self._committed = False
        self._result: LifecycleServicePublicationReceipt | None = None

    @property
    def committed(self) -> bool:
        """Return whether this exact capability has committed."""

        return self._committed

    @property
    def receipt(self) -> LifecycleServicePublicationReceipt | None:
        """Return the authenticated receipt after successful commit."""

        return self._result

    def commit_no_fail(self) -> LifecycleServicePublicationReceipt:
        """Publish every prevalidated primitive write exactly once."""

        if not self._active:
            raise StateError("Prepared lifecycle service publication is no longer active")
        if self._committed:
            raise StateError("Prepared lifecycle service publication is already committed")
        self._result = self._registry._commit_claimed_service_publication(self._token)
        self._committed = True
        return self._result

    def _commit_prevalidated_locked(
        self,
        plan: _PreparedServiceCommitPlan,
        *,
        staged_processes: tuple[ProcessLifecycleSnapshot, ...],
    ) -> LifecycleServicePublicationReceipt:
        """Publish primitives already covered by a combined sorted lock set."""

        if not self._active:
            raise StateError("Prepared lifecycle service publication is no longer active")
        if self._committed:
            raise StateError("Prepared lifecycle service publication is already committed")
        self._result = self._registry._commit_service_primitives_locked(
            plan,
            staged_processes=staged_processes,
        )
        self._committed = True
        return self._result

    def _close(self) -> None:
        self._active = False


class PreparedLifecycleServiceProcessClosure:
    """One-shot no-validation commit capability for a claimed service closure."""

    __slots__ = ("_active", "_committed", "_registry", "_result", "_token")

    def __init__(
        self,
        registry: LifecycleRegistry,
        token: LifecycleServiceClosureAdmissionToken,
    ) -> None:
        self._registry = registry
        self._token = token
        self._active = True
        self._committed = False
        self._result: LifecycleServiceProcessClosureReceipt | None = None

    @property
    def committed(self) -> bool:
        """Return whether this exact capability has committed."""

        return self._committed

    @property
    def receipt(self) -> LifecycleServiceProcessClosureReceipt | None:
        """Return the authenticated receipt after successful commit."""

        return self._result

    def commit_no_fail(self) -> LifecycleServiceProcessClosureReceipt:
        """Publish every prevalidated closure primitive exactly once."""

        if not self._active:
            raise StateError("Prepared lifecycle service closure is no longer active")
        if self._committed:
            raise StateError("Prepared lifecycle service closure is already committed")
        self._result = self._registry._commit_claimed_service_closure(self._token)
        self._committed = True
        return self._result

    def _close(self) -> None:
        self._active = False


@dataclass(slots=True)
class _PreparedClosedTransportCommitPlan:
    """Validated primitive writes retained by one claimed reservation."""

    token: LifecycleClosedTransportAdmissionToken
    sessions: tuple[tuple[int, _PreparedSessionPartitionStart, object | None], ...]
    processes: tuple[tuple[int, _PreparedProcessPartitionStart, LifecycleMembership], ...]
    process_holds: tuple[tuple[int, LifecycleHold, bool], ...]
    transport_partition_id: int
    transport: _PreparedTransportPartitionStart
    prior_transport_route: object | None
    binding: TransportSessionBindingSnapshot | None
    session_partition_id: int | None
    already_terminal: bool = False


@dataclass(slots=True)
class _ClosedTransportReservation:
    """Transient exact-key reservation with no canonical lifecycle rows."""

    token: LifecycleClosedTransportAdmissionToken
    canonical_token: LifecycleClosedTransportAdmissionToken
    keys: tuple[tuple[str, str], ...]
    claimed: bool = False
    claim_thread_id: int | None = None
    commit_plan: _PreparedClosedTransportCommitPlan | None = None


class PreparedLifecycleClosedTransportPublication:
    """One-shot no-validation commit capability for a claimed publication."""

    __slots__ = ("_active", "_committed", "_registry", "_result", "_token")

    def __init__(
        self,
        registry: LifecycleRegistry,
        token: LifecycleClosedTransportAdmissionToken,
    ) -> None:
        self._registry = registry
        self._token = token
        self._active = True
        self._committed = False
        self._result: LifecycleClosedTransportPublicationReceipt | None = None

    @property
    def committed(self) -> bool:
        """Return whether this exact capability has committed."""

        return self._committed

    @property
    def receipt(self) -> LifecycleClosedTransportPublicationReceipt | None:
        """Return the authenticated receipt after a successful commit."""

        return self._result

    def commit_no_fail(self) -> LifecycleClosedTransportPublicationReceipt:
        """Publish every prevalidated primitive write exactly once."""

        if not self._active:
            raise StateError("Prepared closed-transport publication is no longer active")
        if self._committed:
            raise StateError("Prepared closed-transport publication is already committed")
        self._result = self._registry._commit_claimed_closed_transport_publication(self._token)
        self._committed = True
        return self._result

    def _close(self) -> None:
        self._active = False


@dataclass(slots=True)
class _ActionCohortSubjectState:
    """Allocation-free shadow of one staged or live cohort subject."""

    subject: LifecycleEntityRef
    partition_id: int
    started_at: datetime
    parent_object_id: str = ""
    session_object_id: str = ""
    process_role: str = ""
    close_barrier: LifecycleCloseBarrier | None = None
    closure_ticket: LifecycleClosureTicket | None = None
    closed_at: datetime | None = None
    latest_dependent_at: datetime | None = None
    latest_hold_until: datetime | None = None


@dataclass(slots=True)
class _PreparedActionCohortOperation:
    """One validated operation retained by a claimed action-cohort token."""

    operation: LifecycleActionCohortOperation
    partition_id: int
    session_start: _PreparedSessionPartitionStart | None = None
    session_registration: PreparedSessionRegistration | None = None
    process_start: _PreparedProcessPartitionStart | None = None
    process_registration: PreparedProcessRegistration | None = None
    prior_session_route: object | None = None
    hold_transition: LifecycleTransition | None = None
    closure_ticket: LifecycleClosureTicket | None = None
    closure_transitions: (
        tuple[
            LifecycleTransition,
            LifecycleTransition,
            LifecycleTransition,
        ]
        | None
    ) = None
    effective_at: datetime | None = None
    already_present: bool = False


@dataclass(slots=True)
class _PreparedActionCohortCommitPlan:
    """Every prevalidated primitive needed for one no-fail cohort commit."""

    token: LifecycleActionCohortAdmissionToken
    operations: tuple[_PreparedActionCohortOperation, ...]
    partition_ids: tuple[int, ...]
    route_keys: tuple[tuple[str, str], ...]
    reservation_keys: tuple[tuple[str, str], ...]
    receipt_request_preimage: bytes
    operations_digest: str
    retry_receipt: LifecycleActionCohortReceipt | None = None
    expected_receipt: LifecycleActionCohortReceipt | None = None
    terminal_receipt_template: LifecycleActionCohortReceipt | None = None
    provenance_receipt: LifecycleActionCohortReceipt | None = None
    provenance_record: _CommittedActionCohortProvenance | None = None
    already_present: bool = False


@dataclass(frozen=True, slots=True)
class _CommittedActionCohortProvenance:
    """Bounded durable proof that one exact State/lifecycle cohort already committed."""

    binding: tuple[str, str]
    operations_digest: str
    receipt: LifecycleActionCohortReceipt


@dataclass(slots=True)
class _ActionCohortReservation:
    """Transient exact-key action-cohort reservation with no canonical rows."""

    token_ref: ReferenceType[LifecycleActionCohortAdmissionToken]
    token_id: int
    canonical_token: LifecycleActionCohortAdmissionToken
    keys: tuple[tuple[str, str], ...]
    partition_ids: tuple[int, ...]
    request_bytes: int
    provenance_binding: tuple[str, str]
    operations_digest: str
    provenance_new: bool
    provenance_eviction: tuple[str, str] | None = None
    retry_receipt: LifecycleActionCohortReceipt | None = None
    claimed: bool = False
    committing: bool = False
    composite_certified: bool = False
    claim_exhausted: bool = False
    claimed_capability_id: int | None = None
    certified_capability_id: int | None = None
    receipt_authority_id: int | None = None
    claim_thread_id: int | None = None
    commit_plan: _PreparedActionCohortCommitPlan | None = None


@dataclass(slots=True)
class _ActionCohortReceiptAuthority:
    """Registry-owned exact authority for one claim-local receipt object."""

    receipt_ref: ReferenceType[LifecycleActionCohortReceipt]
    preparation_id: int
    plan_digest: str
    state_publication_token: str
    request_id: int
    results_id: int
    committed_digest: str
    integrity: str
    committed: bool = False


@dataclass(frozen=True, slots=True)
class _ActionCohortCommitAuthorization:
    """Private trusted references retained after one complete commit sweep."""

    reservation: _ActionCohortReservation
    commit_plan: _PreparedActionCohortCommitPlan
    expected_receipt: LifecycleActionCohortReceipt
    receipt_authority: _ActionCohortReceiptAuthority
    provenance_record: _CommittedActionCohortProvenance | None


@dataclass(frozen=True, slots=True)
class _ActionCohortClaimedCapabilityLocator:
    """Registry-owned exact wrapper binding for one active claimed reservation."""

    capability_ref: ReferenceType[PreparedLifecycleActionCohort]
    reservation: _ActionCohortReservation


@dataclass(frozen=True, slots=True)
class _ActionCohortCertifiedAuthorizationLocator:
    """Registry-owned exact capability binding for one certified authorization."""

    capability_ref: ReferenceType[PreparedLifecycleActionCohort]
    authorization: _ActionCohortCommitAuthorization


class PreparedLifecycleActionCohort:
    """One-shot claimed action cohort with a preauthenticated expected receipt."""

    __slots__ = (
        "__weakref__",
        "_active",
        "_claim_thread_id",
        "_committed",
        "_expected_receipt",
        "_registry",
        "_result",
        "_token",
    )

    def __init__(
        self,
        registry: LifecycleRegistry,
        token: LifecycleActionCohortAdmissionToken,
        expected_receipt: LifecycleActionCohortReceipt,
        *,
        claim_thread_id: int,
    ) -> None:
        self._registry = registry
        self._token = token
        self._expected_receipt = expected_receipt
        self._claim_thread_id = claim_thread_id
        self._active = True
        self._committed = False
        self._result: LifecycleActionCohortReceipt | None = None

    @property
    def committed(self) -> bool:
        """Return whether this exact capability has committed."""

        return self._committed

    @property
    def receipt(self) -> LifecycleActionCohortReceipt | None:
        """Return the authenticated receipt after a successful commit."""

        return self._result

    @property
    def expected_receipt(self) -> LifecycleActionCohortReceipt:
        """Return the exact immutable receipt authenticated by this active claim."""

        if not self._active:
            raise StateError("Prepared lifecycle action cohort is no longer active")
        return self._expected_receipt

    def certify_composite_commit(
        self,
        expected_receipt: LifecycleActionCohortReceipt,
    ) -> None:
        """Authenticate this exact claim once for a composite commit tail."""

        if not self._active:
            raise StateError("Prepared lifecycle action cohort is no longer active")
        if self._committed:
            raise StateError("Prepared lifecycle action cohort is already committed")
        if get_ident() != self._claim_thread_id:
            raise StateError("Lifecycle action cohort must be certified on its claiming thread")
        if expected_receipt is not self._expected_receipt:
            raise StateError(
                "Lifecycle action-cohort composite certification requires its exact "
                "expected receipt object"
            )
        self._registry._certify_claimed_action_cohort(
            self,
            self._token,
            expected_receipt=expected_receipt,
        )

    def commit_no_fail(self) -> LifecycleActionCohortReceipt:
        """Publish every prevalidated primitive exactly once."""

        if not self._active:
            raise StateError("Prepared lifecycle action cohort is no longer active")
        if self._committed:
            raise StateError("Prepared lifecycle action cohort is already committed")
        if get_ident() != self._claim_thread_id:
            raise StateError("Lifecycle action cohort must commit on its claiming thread")
        self._result = self._registry._commit_prepared_action_cohort(
            self,
            token=self._token,
            expected_receipt=self._expected_receipt,
        )
        self._committed = True
        return self._result

    def _close(self) -> None:
        self._active = False


class LifecycleRegistry:
    """Bounded stable-host shards around the strict lifecycle authority."""

    def __init__(
        self,
        *,
        closed_retention: timedelta = _DEFAULT_CLOSED_RETENTION,
        snapshot_history_limit: int = _DEFAULT_SNAPSHOT_HISTORY_LIMIT,
        ledger_detail_retention: timedelta = _DEFAULT_LEDGER_DETAIL_RETENTION,
        shard_count: int = _DEFAULT_SHARD_COUNT,
    ) -> None:
        """Create fixed owner shards and independently sharded exact routes."""

        if shard_count <= 0:
            raise ValueError("Lifecycle shard_count must be positive")
        self._closed_retention = closed_retention
        self._snapshot_history_limit = snapshot_history_limit
        self._ledger_detail_retention = ledger_detail_retention
        self._shard_count = shard_count
        self._partitions = tuple(
            _LifecyclePartition(
                closed_retention=closed_retention,
                snapshot_history_limit=snapshot_history_limit,
                ledger_detail_retention=ledger_detail_retention,
            )
            for _ in range(shard_count)
        )
        self._routes = _LifecycleRoutes(shard_count)
        self._gate = _MutationGate()
        self._watermark: datetime | None = None
        self._ledger_floor: datetime | None = None
        self._closed_transport_registry_id = token_bytes(16).hex()
        self._closed_transport_preparation_lock = RLock()
        self._closed_transport_preparation_condition = Condition(
            self._closed_transport_preparation_lock
        )
        self._next_closed_transport_preparation_id = 1
        self._closed_transport_reservations: dict[int, _ClosedTransportReservation] = {}
        self._closed_transport_claimed_reservations = 0
        self._closed_transport_capability_locators: dict[int, int] = {}
        self._closed_transport_receipts: WeakValueDictionary[
            int, LifecycleClosedTransportPublicationReceipt
        ] = WeakValueDictionary()
        self._closed_transport_reserved_keys: dict[tuple[str, str], int] = {}
        self._closed_transport_mutating_keys: dict[tuple[str, str], int] = {}
        self._service_registry_id = token_bytes(16).hex()
        self._next_service_preparation_id = 1
        self._service_publication_reservations: dict[int, _ServicePublicationReservation] = {}
        self._service_closure_reservations: dict[int, _ServiceClosureReservation] = {}
        self._service_claimed_publications = 0
        self._service_claimed_closures = 0
        self._service_capability_locators: dict[int, tuple[str, int]] = {}
        self._service_publication_receipts: WeakValueDictionary[
            int, LifecycleServicePublicationReceipt
        ] = WeakValueDictionary()
        self._service_closure_receipts: WeakValueDictionary[
            int, LifecycleServiceProcessClosureReceipt
        ] = WeakValueDictionary()
        self._service_reserved_keys: dict[tuple[str, str], tuple[str, int]] = {}
        self._action_cohort_registry_id = token_bytes(16).hex()
        self._next_action_cohort_preparation_id = 1
        self._action_cohort_reservations: dict[int, _ActionCohortReservation] = {}
        self._action_cohort_claimed_reservations = 0
        self._action_cohort_committing_reservations = 0
        self._action_cohort_capability_locators: dict[int, int] = {}
        self._action_cohort_claimed_capabilities: dict[
            int, _ActionCohortClaimedCapabilityLocator
        ] = {}
        self._action_cohort_certified_authorizations: dict[
            int, _ActionCohortCertifiedAuthorizationLocator
        ] = {}
        self._action_cohort_receipt_authorities: OrderedDict[int, _ActionCohortReceiptAuthority] = (
            OrderedDict()
        )
        self._action_cohort_expected_receipt_authorities = 0
        self._action_cohort_committed_receipt_authorities = 0
        self._action_cohort_reserved_keys: dict[tuple[str, str], int] = {}
        self._action_cohort_retained_request_bytes = 0
        self._action_cohort_operation_capacity = _MAX_ACTION_COHORT_OPERATIONS_PER_REQUEST
        self._action_cohort_reservation_capacity = _MAX_ACTION_COHORT_RESERVATIONS
        self._action_cohort_reserved_key_capacity = _MAX_ACTION_COHORT_RESERVED_KEYS
        self._action_cohort_request_byte_capacity = _MAX_ACTION_COHORT_REQUEST_BYTES
        self._action_cohort_provenance_capacity = _MAX_ACTION_COHORT_COMMITTED_PROVENANCE
        self._action_cohort_receipt_authority_capacity = (
            _MAX_ACTION_COHORT_COMMITTED_PROVENANCE + _MAX_ACTION_COHORT_RESERVATIONS
        )
        self._action_cohort_committed_provenance: OrderedDict[
            tuple[str, str], _CommittedActionCohortProvenance
        ] = OrderedDict()
        self._action_cohort_provenance_by_operations: dict[str, tuple[str, str]] = {}
        self._action_cohort_pending_provenance_insertions = 0
        self._action_cohort_pending_provenance_evictions: set[tuple[str, str]] = set()
        self._action_cohort_provenance_pins: dict[tuple[str, str], int] = {}

    @property
    def closed_retention(self) -> timedelta:
        """Return the configured closed-identity retention horizon."""

        return self._closed_retention

    @property
    def snapshot_history_limit(self) -> int:
        """Return the maximum detailed transitions and holds per snapshot."""

        return self._snapshot_history_limit

    @property
    def ledger_detail_retention(self) -> timedelta:
        """Return the exact-detail horizon behind the sealed watermark."""

        return self._ledger_detail_retention

    def _partition_id(self, hostname: str) -> int:
        digest = sha256(f"lifecycle-state\0{hostname}".encode()).digest()
        return int.from_bytes(digest[:8], "big") % self._shard_count

    def _session_locator(self, partition_id: int, handle: int) -> int:
        return handle * self._shard_count + partition_id

    def _decode_session_locator(self, locator: int) -> tuple[int, int]:
        return locator % self._shard_count, locator // self._shard_count

    def _session_partition_from_route(self, value: object) -> int | None:
        if isinstance(value, int):
            return self._decode_session_locator(value)[0]
        if isinstance(value, bytes):
            return self._partition_id(_session_hostname_from_row(value))
        return None

    def _session_start_locator(self, partition_id: int, handle: int) -> int:
        return self._start_transition_locator(
            partition_id,
            handle,
            _SESSION_START_TAG,
        )

    def _start_transition_locator(self, partition_id: int, handle: int, tag: int) -> int:
        locator = self._session_locator(partition_id, handle)
        return -(locator * _START_TRANSITION_KIND_COUNT + tag + 1)

    def _transition_from_route(
        self,
        value: object | None,
        transition_id: str,
    ) -> LifecycleTransition | None:
        if isinstance(value, LifecycleTransition):
            return value
        if isinstance(value, int) and value < 0:
            encoded = -value - 1
            tag = encoded % _START_TRANSITION_KIND_COUNT
            locator = encoded // _START_TRANSITION_KIND_COUNT
            partition_id, handle = self._decode_session_locator(locator)
            partition = self._partitions[partition_id]
            if tag == _SESSION_START_TAG:
                return partition.session_start_transition(handle, transition_id)
            if tag == _SERVICE_START_TAG:
                return partition.service_start_transition(handle, transition_id)
            if tag == _TRANSPORT_START_TAG:
                return partition.transport_start_transition(handle, transition_id)
        return None

    @staticmethod
    def _entity_kind(subject: LifecycleEntityRef) -> str:
        return subject.kind

    def _subject_partition_locked(self, subject: LifecycleEntityRef) -> int:
        value = self._routes.get_locked(self._entity_kind(subject), subject.object_id)
        if subject.kind in {"session", "service", "transport"}:
            partition_id = self._session_partition_from_route(value)
            if partition_id is not None:
                return partition_id
        elif isinstance(value, int):
            return value
        raise StateError(f"Unknown {subject.kind} lifecycle object {subject.object_id}")

    def _resource_partition_locked(
        self,
        *,
        hostname: str,
        session_object_id: str,
        process_object_id: str = "",
    ) -> int:
        expected = self._partition_id(hostname)
        session_route = self._routes.get_locked("session", session_object_id)
        session_partition = self._session_partition_from_route(session_route)
        if session_partition is None:
            raise StateError(f"Unknown session lifecycle object {session_object_id}")
        if session_partition != expected:
            raise StateError("Lifecycle resource lease cannot use a cross-host session")
        if process_object_id:
            process_partition = self._routes.get_locked("process", process_object_id)
            if not isinstance(process_partition, int):
                raise StateError(f"Unknown process lifecycle object {process_object_id}")
            if process_partition != expected:
                raise StateError("Lifecycle resource lease cannot use a cross-host process")
        return expected

    @contextmanager
    def _locked_partition_ids(self, partition_ids: tuple[int, ...]) -> Iterator[None]:
        """Lock several host partitions in one deterministic global order."""

        ordered = tuple(sorted(set(partition_ids)))
        partitions = tuple(self._partitions[partition_id] for partition_id in ordered)
        lanes = tuple(
            partition._host_lanes.lane("cross-partition-lifecycle") for partition in partitions
        )
        for lane in lanes:
            lane.acquire()
        try:
            for partition in partitions:
                partition._catalog_lock.acquire()
            try:
                for partition in partitions:
                    partition._index_lock.acquire()
                try:
                    yield
                finally:
                    for partition in reversed(partitions):
                        partition._index_lock.release()
            finally:
                for partition in reversed(partitions):
                    partition._catalog_lock.release()
        finally:
            for lane in reversed(lanes):
                lane.release()

    def _promote_session_route_locked(
        self,
        subject: LifecycleEntityRef,
        partition_id: int,
    ) -> None:
        if subject.kind != "session":
            return
        handle = self._partitions[partition_id].session_handle_for(subject.object_id)
        self._routes.set_locked(
            "session",
            subject.object_id,
            self._session_locator(partition_id, handle),
        )

    @staticmethod
    def _reject_exact_conflict(kind: str, semantic_id: str) -> None:
        label = {
            "transition": "Lifecycle transition ID",
            "hold": "Lifecycle hold ID",
            "barrier": "Lifecycle close barrier ID",
            "ticket": "Lifecycle closure ticket ID",
            "lease": "Lifecycle retention lease ID",
            "foreground_lease": "Lifecycle foreground lease ID",
            "singleton_lease": "Lifecycle singleton lease ID",
        }.get(kind, f"Lifecycle {kind} ID")
        raise StateError(f"{label} {semantic_id} is already in use")

    @staticmethod
    def _closed_transport_plan_digest(
        request: LifecycleClosedTransportPublicationRequest,
    ) -> str:
        """Return a compact label for one trusted canonical publication."""

        return sha256(
            f"closed-transport:{request.identity.object_id}:{request.start_action_id}".encode()
        ).hexdigest()

    @staticmethod
    def _closed_transport_watermark_text(watermark: datetime | None) -> str:
        return "" if watermark is None else watermark.isoformat()

    def _closed_transport_token_integrity(
        self,
        *,
        preparation_id: int,
        expected_watermark: datetime | None,
        plan_digest: str,
    ) -> str:
        return sha256(
            (
                "lifecycle-closed-transport-admission\0"
                f"{self._closed_transport_registry_id}\0{preparation_id}\0"
                f"{self._closed_transport_watermark_text(expected_watermark)}\0{plan_digest}"
            ).encode()
        ).hexdigest()

    def _closed_transport_receipt_integrity(
        self,
        *,
        plan_digest: str,
        committed_digest: str,
    ) -> str:
        return sha256(
            (
                "lifecycle-closed-transport-receipt\0"
                f"{self._closed_transport_registry_id}\0{plan_digest}\0{committed_digest}"
            ).encode()
        ).hexdigest()

    @staticmethod
    def _closed_transport_subject_key(subject: LifecycleEntityRef) -> tuple[str, str]:
        return ("subject", f"{subject.kind}\0{subject.object_id}")

    @staticmethod
    def _resource_lease_subject_key(subject: LifecycleEntityRef) -> tuple[str, str]:
        return ("resource_lease_subject", f"{subject.kind}\0{subject.object_id}")

    @staticmethod
    def _closed_transport_tuple_key(identity: TransportLifecycleIdentity) -> tuple[str, str]:
        return (
            "transport_tuple",
            repr((identity.hostname.strip().casefold(), identity.tuple_key)),
        )

    def _closed_transport_reservation_keys(
        self,
        request: LifecycleClosedTransportPublicationRequest,
    ) -> tuple[tuple[str, str], ...]:
        """Return every exact identity whose mutation could invalidate admission."""

        identity = request.identity
        keys: list[tuple[str, str]] = [
            self._closed_transport_subject_key(identity.ref),
            ("transport_id", identity.transport_id),
            ("transport_uid", identity.zeek_uid),
            self._closed_transport_tuple_key(identity),
            ("transition", request.start_transition_id),
            ("barrier", request.barrier.barrier_id),
            ("ticket", request.ticket_id),
            ("transition", f"{request.barrier.barrier_id}:requested"),
            ("transition", f"{request.ticket_id}:scheduled"),
            ("transition", f"{request.ticket_id}:closed"),
        ]
        binding = request.binding_identity
        if binding is not None:
            keys.extend(
                (
                    ("transport_session_binding", binding.binding_id),
                    self._closed_transport_subject_key(
                        LifecycleEntityRef("session", binding.session_object_id)
                    ),
                )
            )
        for member in request.start_members:
            start = member.request
            keys.extend(
                (
                    self._closed_transport_subject_key(start.identity.ref),
                    ("transition", start.transition_id),
                )
            )
            if isinstance(start, LifecycleSessionStartRequest):
                keys.append(
                    (
                        "session_logon",
                        repr(
                            (
                                start.identity.hostname.strip().casefold(),
                                start.identity.logon_id.strip().casefold(),
                            )
                        ),
                    )
                )
            else:
                keys.append(
                    (
                        "process_pid",
                        repr(
                            (
                                start.identity.hostname.strip().casefold(),
                                start.identity.pid,
                            )
                        ),
                    )
                )
                if start.identity.parent_object_id:
                    keys.append(
                        self._closed_transport_subject_key(
                            LifecycleEntityRef("process", start.identity.parent_object_id)
                        )
                    )
                if start.membership.session_object_id:
                    keys.append(
                        self._closed_transport_subject_key(
                            LifecycleEntityRef("session", start.membership.session_object_id)
                        )
                    )
        for hold in request.process_holds:
            keys.extend(
                (
                    self._closed_transport_subject_key(hold.subject),
                    ("hold", hold.hold_id),
                    ("transition", f"{hold.hold_id}:acquired"),
                )
            )
        return tuple(dict.fromkeys(keys))

    def _closed_transport_route_keys(
        self,
        request: LifecycleClosedTransportPublicationRequest,
    ) -> tuple[tuple[str, str], ...]:
        """Return every exact route shard acquired for validation and commit."""

        identity = request.identity
        keys: list[tuple[str, str]] = [
            ("transport", identity.object_id),
            ("transport_id", identity.transport_id),
            ("transport_uid", identity.zeek_uid),
            ("transition", request.start_transition_id),
            ("barrier", request.barrier.barrier_id),
            ("ticket", request.ticket_id),
            ("transition", f"{request.barrier.barrier_id}:requested"),
            ("transition", f"{request.ticket_id}:scheduled"),
            ("transition", f"{request.ticket_id}:closed"),
        ]
        binding = request.binding_identity
        if binding is not None:
            keys.extend(
                (
                    ("session", binding.session_object_id),
                    ("transport_session_binding", binding.binding_id),
                )
            )
        for member in request.start_members:
            start = member.request
            keys.extend(
                (
                    (start.identity.ref.kind, start.identity.object_id),
                    ("transition", start.transition_id),
                )
            )
            if isinstance(start, LifecycleProcessStartRequest):
                if start.identity.parent_object_id:
                    keys.append(("process", start.identity.parent_object_id))
                if start.membership.session_object_id:
                    keys.append(("session", start.membership.session_object_id))
        for hold in request.process_holds:
            keys.extend(
                (
                    ("process", hold.subject.object_id),
                    ("hold", hold.hold_id),
                    ("transition", f"{hold.hold_id}:acquired"),
                )
            )
        return tuple(dict.fromkeys(keys))

    def _closed_transport_partition_ids_locked(
        self,
        request: LifecycleClosedTransportPublicationRequest,
    ) -> tuple[int, ...]:
        """Resolve every existing/staged owner before acquiring sorted partitions."""

        partition_ids = {self._partition_id(request.identity.hostname)}
        staged_ids = {member.request.identity.object_id for member in request.start_members}
        for member in request.start_members:
            start = member.request
            partition_ids.add(self._partition_id(start.identity.hostname))
            if isinstance(start, LifecycleProcessStartRequest):
                parent_id = start.identity.parent_object_id
                if parent_id and parent_id not in staged_ids:
                    parent_partition = self._routes.get_locked("process", parent_id)
                    if not isinstance(parent_partition, int):
                        raise StateError(f"Unknown parent process lifecycle object {parent_id}")
                    partition_ids.add(parent_partition)
                session_id = start.membership.session_object_id
                if session_id and session_id not in staged_ids:
                    session_route = self._routes.get_locked("session", session_id)
                    session_partition = self._session_partition_from_route(session_route)
                    if session_partition is None:
                        raise StateError(f"Unknown session lifecycle object {session_id}")
                    partition_ids.add(session_partition)
        for hold in request.process_holds:
            if hold.subject.object_id in staged_ids:
                continue
            process_partition = self._routes.get_locked("process", hold.subject.object_id)
            if not isinstance(process_partition, int):
                raise StateError(f"Unknown process lifecycle object {hold.subject.object_id}")
            partition_ids.add(process_partition)
        binding = request.binding_identity
        if binding is not None and binding.session_object_id not in staged_ids:
            session_route = self._routes.get_locked("session", binding.session_object_id)
            session_partition = self._session_partition_from_route(session_route)
            if session_partition is None:
                raise StateError(
                    f"Unknown target session lifecycle object {binding.session_object_id}"
                )
            partition_ids.add(session_partition)
        return tuple(sorted(partition_ids))

    def _validate_closed_transport_token(
        self,
        token: LifecycleClosedTransportAdmissionToken,
    ) -> None:
        """Require the exact token type and owning registry."""

        if type(token) is not LifecycleClosedTransportAdmissionToken:
            raise StateError("Closed-transport admission token has an invalid type")
        if token.registry_id != self._closed_transport_registry_id:
            raise StateError("Closed-transport admission token belongs to another registry")

    def _validate_closed_transport_token_against_canonical(
        self,
        token: LifecycleClosedTransportAdmissionToken,
        canonical_token: LifecycleClosedTransportAdmissionToken,
    ) -> None:
        """Require the exact retained owner-issued capability."""

        self._validate_closed_transport_token(token)
        if token is not canonical_token:
            raise StateError("Closed-transport admission token is not the retained capability")

    def _active_closed_transport_reservation_locked(
        self,
        token: LifecycleClosedTransportAdmissionToken,
    ) -> _ClosedTransportReservation:
        preparation_id = self._closed_transport_capability_locators.get(id(token))
        if preparation_id is None:
            self._validate_closed_transport_token(token)
            raise StateError("Closed-transport admission token is stale or consumed")
        active = self._closed_transport_reservations.get(preparation_id)
        if active is None or active.token is not token:
            self._closed_transport_capability_locators.pop(id(token), None)
            raise StateError("Closed-transport admission token is stale or consumed")
        try:
            self._validate_closed_transport_token_against_canonical(
                token,
                active.canonical_token,
            )
        except StateError:
            self._release_closed_transport_reservation_locked(active)
            raise
        return active

    def _release_closed_transport_reservation_locked(
        self,
        reservation: _ClosedTransportReservation,
    ) -> None:
        preparation_id = reservation.canonical_token.preparation_id
        active = self._closed_transport_reservations.pop(preparation_id, None)
        if active is not reservation:
            return
        if reservation.claimed:
            self._closed_transport_claimed_reservations -= 1
        self._closed_transport_capability_locators.pop(id(reservation.token), None)
        for key in reservation.keys:
            if self._closed_transport_reserved_keys.get(key) == preparation_id:
                self._closed_transport_reserved_keys.pop(key)
        if not self._closed_transport_reservations:
            self._closed_transport_reserved_keys.clear()
        self._closed_transport_preparation_condition.notify_all()

    def _discard_closed_transport_reservation_for_token(
        self,
        token: LifecycleClosedTransportAdmissionToken,
    ) -> None:
        """Best-effort cleanup keyed only by the unforgeable token object capability."""

        with self._gate.mutation(), self._closed_transport_preparation_lock:
            preparation_id = self._closed_transport_capability_locators.get(id(token))
            if preparation_id is None:
                return
            reservation = self._closed_transport_reservations.get(preparation_id)
            if reservation is not None and reservation.token is token:
                self._release_closed_transport_reservation_locked(reservation)

    def _reject_closed_transport_reservation_conflict_locked(
        self,
        keys: tuple[tuple[str, str], ...],
        *,
        reject_mutating: bool = True,
        allowed_service_owner: tuple[Literal["publication", "closure"], int] | None = None,
        allowed_action_cohort_owner: int | None = None,
    ) -> None:
        for key in keys:
            if key in self._closed_transport_reserved_keys:
                raise StateError(
                    f"Lifecycle {key[0]} {key[1]!r} has a prepared closed-transport publication"
                )
            service_owner = self._service_reserved_keys.get(key)
            if service_owner is not None and service_owner != allowed_service_owner:
                raise StateError(f"Lifecycle {key[0]} {key[1]!r} has a prepared service operation")
            action_owner = self._action_cohort_reserved_keys.get(key)
            if action_owner is not None and action_owner != allowed_action_cohort_owner:
                raise StateError(f"Lifecycle {key[0]} {key[1]!r} has a prepared action cohort")
            if reject_mutating and self._closed_transport_mutating_keys.get(key, 0):
                raise StateError(f"Lifecycle {key[0]} {key[1]!r} has an in-flight mutation")

    @contextmanager
    def _ordinary_closed_transport_mutation(
        self,
        keys: tuple[tuple[str, str], ...],
        *,
        allowed_service_owner: tuple[Literal["publication", "closure"], int] | None = None,
    ) -> Iterator[None]:
        """Claim related exact keys briefly without retaining the metadata lock."""

        normalized = tuple(dict.fromkeys(keys))
        with self._closed_transport_preparation_lock:
            self._reject_closed_transport_reservation_conflict_locked(
                normalized,
                reject_mutating=False,
                allowed_service_owner=allowed_service_owner,
            )
            for key in normalized:
                self._closed_transport_mutating_keys[key] = (
                    self._closed_transport_mutating_keys.get(key, 0) + 1
                )
        try:
            yield
        finally:
            with self._closed_transport_preparation_lock:
                for key in normalized:
                    remaining = self._closed_transport_mutating_keys[key] - 1
                    if remaining:
                        self._closed_transport_mutating_keys[key] = remaining
                    else:
                        self._closed_transport_mutating_keys.pop(key)
                self._closed_transport_preparation_condition.notify_all()

    @staticmethod
    def _action_cohort_exact_text(
        value: object,
        *,
        field_name: str,
        allow_empty: bool = True,
    ) -> str:
        if type(value) is not str:
            raise TypeError(f"Lifecycle action cohort {field_name} must be an exact string")
        if not allow_empty and not value:
            raise ValueError(f"Lifecycle action cohort {field_name} cannot be empty")
        return value

    @staticmethod
    def _action_cohort_exact_int(
        value: object,
        *,
        field_name: str,
        allow_none: bool = False,
    ) -> int | None:
        if value is None and allow_none:
            return None
        if type(value) is not int:
            raise TypeError(f"Lifecycle action cohort {field_name} must be an exact integer")
        if value < 0:
            raise ValueError(f"Lifecycle action cohort {field_name} must be non-negative")
        return value

    @staticmethod
    def _action_cohort_exact_datetime(
        value: object,
        *,
        field_name: str,
        allow_none: bool = False,
    ) -> datetime | None:
        if value is None and allow_none:
            return None
        if type(value) is not datetime or value.tzinfo is not UTC:
            raise TypeError(f"Lifecycle action cohort {field_name} must be an exact UTC datetime")
        return value

    @classmethod
    def _normalize_action_cohort_ref(cls, value: object) -> LifecycleEntityRef:
        if type(value) is not LifecycleEntityRef:
            raise TypeError("Lifecycle action cohort subjects must be exact entity references")
        return LifecycleEntityRef(
            kind=cls._action_cohort_exact_text(
                value.kind,
                field_name="subject kind",
                allow_empty=False,
            ),  # type: ignore[arg-type]
            object_id=cls._action_cohort_exact_text(
                value.object_id,
                field_name="subject object ID",
                allow_empty=False,
            ),
        )

    @classmethod
    def _normalize_action_cohort_session_identity(
        cls,
        value: object,
    ) -> SessionLifecycleIdentity:
        if type(value) is not SessionLifecycleIdentity:
            raise TypeError("Lifecycle action cohort session identity must be exact")
        session_id = cls._action_cohort_exact_int(
            value.session_id,
            field_name="session ID",
        )
        assert session_id is not None
        started_at = cls._action_cohort_exact_datetime(
            value.started_at,
            field_name="session start time",
        )
        assert started_at is not None
        return SessionLifecycleIdentity(
            hostname=cls._action_cohort_exact_text(
                value.hostname,
                field_name="session hostname",
                allow_empty=False,
            ),
            object_id=cls._action_cohort_exact_text(
                value.object_id,
                field_name="session object ID",
                allow_empty=False,
            ),
            logon_id=cls._action_cohort_exact_text(
                value.logon_id,
                field_name="session LogonID",
                allow_empty=False,
            ),
            principal=cls._action_cohort_exact_text(
                value.principal,
                field_name="session principal",
                allow_empty=False,
            ),
            session_kind=cls._action_cohort_exact_text(
                value.session_kind,
                field_name="session kind",
                allow_empty=False,
            ),
            started_at=started_at,
            session_id=session_id,
            logon_guid=cls._action_cohort_exact_text(
                value.logon_guid,
                field_name="session LogonGuid",
            ),
        )

    @classmethod
    def _normalize_action_cohort_process_identity(
        cls,
        value: object,
    ) -> ProcessLifecycleIdentity:
        if type(value) is not ProcessLifecycleIdentity:
            raise TypeError("Lifecycle action cohort process identity must be exact")
        pid = cls._action_cohort_exact_int(value.pid, field_name="process PID")
        assert pid is not None
        started_at = cls._action_cohort_exact_datetime(
            value.started_at,
            field_name="process start time",
        )
        assert started_at is not None
        return ProcessLifecycleIdentity(
            hostname=cls._action_cohort_exact_text(
                value.hostname,
                field_name="process hostname",
                allow_empty=False,
            ),
            object_id=cls._action_cohort_exact_text(
                value.object_id,
                field_name="process object ID",
                allow_empty=False,
            ),
            pid=pid,
            started_at=started_at,
            image=cls._action_cohort_exact_text(
                value.image,
                field_name="process image",
                allow_empty=False,
            ),
            parent_object_id=cls._action_cohort_exact_text(
                value.parent_object_id,
                field_name="parent process object ID",
            ),
            role=cls._action_cohort_exact_text(
                value.role,
                field_name="process role",
                allow_empty=False,
            ),
        )

    @classmethod
    def _normalize_action_cohort_process_token(
        cls,
        value: object,
    ) -> ProcessTokenIdentity:
        if type(value) is not ProcessTokenIdentity:
            raise TypeError("Lifecycle action cohort process token must be exact")
        session_id = cls._action_cohort_exact_int(
            value.session_id,
            field_name="token session ID",
            allow_none=True,
        )
        logon_type = cls._action_cohort_exact_int(
            value.logon_type,
            field_name="token logon type",
            allow_none=True,
        )
        return ProcessTokenIdentity(
            principal=cls._action_cohort_exact_text(
                value.principal,
                field_name="token principal",
                allow_empty=False,
            ),
            logon_id=cls._action_cohort_exact_text(
                value.logon_id,
                field_name="token LogonID",
            ),
            session_id=session_id,
            logon_type=logon_type,
            integrity_level=cls._action_cohort_exact_text(
                value.integrity_level,
                field_name="token integrity level",
            ),
        )

    @classmethod
    def _normalize_action_cohort_membership(
        cls,
        value: object,
    ) -> LifecycleMembership:
        if type(value) is not LifecycleMembership:
            raise TypeError("Lifecycle action cohort membership must be exact")
        return LifecycleMembership(
            owner_kind=cls._action_cohort_exact_text(
                value.owner_kind,
                field_name="membership owner kind",
                allow_empty=False,
            ),  # type: ignore[arg-type]
            owner_object_id=cls._action_cohort_exact_text(
                value.owner_object_id,
                field_name="membership owner object ID",
                allow_empty=False,
            ),
            session_object_id=cls._action_cohort_exact_text(
                value.session_object_id,
                field_name="membership session object ID",
            ),
        )

    @classmethod
    def _normalize_action_cohort_transition(cls, value: object) -> LifecycleTransition:
        if type(value) is not LifecycleTransition:
            raise TypeError("Lifecycle action cohort transition must be exact")
        canonical_time = cls._action_cohort_exact_datetime(
            value.canonical_time,
            field_name="transition time",
        )
        ordinal = cls._action_cohort_exact_int(
            value.transition_ordinal,
            field_name="transition ordinal",
        )
        assert canonical_time is not None and ordinal is not None
        return LifecycleTransition(
            transition_id=cls._action_cohort_exact_text(
                value.transition_id,
                field_name="transition ID",
                allow_empty=False,
            ),
            subject=cls._normalize_action_cohort_ref(value.subject),
            kind=cls._action_cohort_exact_text(
                value.kind,
                field_name="transition kind",
                allow_empty=False,
            ),  # type: ignore[arg-type]
            canonical_time=canonical_time,
            action_id=cls._action_cohort_exact_text(
                value.action_id,
                field_name="transition action ID",
                allow_empty=False,
            ),
            reason=cls._action_cohort_exact_text(
                value.reason,
                field_name="transition reason",
            ),
            transition_ordinal=ordinal,
        )

    @classmethod
    def _normalize_action_cohort_hold(cls, value: object) -> LifecycleHold:
        if type(value) is not LifecycleHold:
            raise TypeError("Lifecycle action cohort hold must be exact")
        acquired_at = cls._action_cohort_exact_datetime(
            value.acquired_at,
            field_name="hold acquisition time",
        )
        hold_until = cls._action_cohort_exact_datetime(
            value.hold_until,
            field_name="hold deadline",
        )
        ordinal = cls._action_cohort_exact_int(
            value.transition_ordinal,
            field_name="hold ordinal",
        )
        assert acquired_at is not None and hold_until is not None and ordinal is not None
        return LifecycleHold(
            hold_id=cls._action_cohort_exact_text(
                value.hold_id,
                field_name="hold ID",
                allow_empty=False,
            ),
            subject=cls._normalize_action_cohort_ref(value.subject),
            acquired_at=acquired_at,
            hold_until=hold_until,
            action_id=cls._action_cohort_exact_text(
                value.action_id,
                field_name="hold action ID",
                allow_empty=False,
            ),
            reason=cls._action_cohort_exact_text(
                value.reason,
                field_name="hold reason",
                allow_empty=False,
            ),
            transition_ordinal=ordinal,
        )

    @classmethod
    def _normalize_action_cohort_barrier(cls, value: object) -> LifecycleCloseBarrier:
        if type(value) is not LifecycleCloseBarrier:
            raise TypeError("Lifecycle action cohort close barrier must be exact")
        requested_at = cls._action_cohort_exact_datetime(
            value.requested_at,
            field_name="close request time",
        )
        assert requested_at is not None
        return LifecycleCloseBarrier(
            barrier_id=cls._action_cohort_exact_text(
                value.barrier_id,
                field_name="close barrier ID",
                allow_empty=False,
            ),
            subject=cls._normalize_action_cohort_ref(value.subject),
            requested_at=requested_at,
            authority=cls._action_cohort_exact_text(
                value.authority,
                field_name="close authority",
                allow_empty=False,
            ),  # type: ignore[arg-type]
            action_id=cls._action_cohort_exact_text(
                value.action_id,
                field_name="close action ID",
                allow_empty=False,
            ),
        )

    @classmethod
    def _normalize_action_cohort_ticket(cls, value: object) -> LifecycleClosureTicket:
        if type(value) is not LifecycleClosureTicket:
            raise TypeError("Lifecycle action cohort closure ticket must be exact")
        requested_at = cls._action_cohort_exact_datetime(
            value.requested_at,
            field_name="ticket request time",
        )
        effective_at = cls._action_cohort_exact_datetime(
            value.effective_at,
            field_name="ticket effective time",
        )
        assert requested_at is not None and effective_at is not None
        return LifecycleClosureTicket(
            ticket_id=cls._action_cohort_exact_text(
                value.ticket_id,
                field_name="closure ticket ID",
                allow_empty=False,
            ),
            barrier_id=cls._action_cohort_exact_text(
                value.barrier_id,
                field_name="ticket barrier ID",
                allow_empty=False,
            ),
            subject=cls._normalize_action_cohort_ref(value.subject),
            requested_at=requested_at,
            effective_at=effective_at,
            authority=cls._action_cohort_exact_text(
                value.authority,
                field_name="ticket authority",
                allow_empty=False,
            ),  # type: ignore[arg-type]
            action_id=cls._action_cohort_exact_text(
                value.action_id,
                field_name="ticket action ID",
                allow_empty=False,
            ),
        )

    @classmethod
    def _normalize_action_cohort_operation(
        cls,
        operation: object,
    ) -> LifecycleActionCohortOperation:
        if type(operation) is LifecycleSessionStartRequest:
            ordinal = cls._action_cohort_exact_int(
                operation.transition_ordinal,
                field_name="session start ordinal",
            )
            assert ordinal is not None
            return LifecycleSessionStartRequest(
                identity=cls._normalize_action_cohort_session_identity(operation.identity),
                action_id=cls._action_cohort_exact_text(
                    operation.action_id,
                    field_name="session start action ID",
                    allow_empty=False,
                ),
                transition_id=cls._action_cohort_exact_text(
                    operation.transition_id,
                    field_name="session start transition ID",
                    allow_empty=False,
                ),
                transition_ordinal=ordinal,
            )
        if type(operation) is LifecycleProcessStartRequest:
            ordinal = cls._action_cohort_exact_int(
                operation.transition_ordinal,
                field_name="process start ordinal",
            )
            assert ordinal is not None
            return LifecycleProcessStartRequest(
                identity=cls._normalize_action_cohort_process_identity(operation.identity),
                token=cls._normalize_action_cohort_process_token(operation.token),
                membership=cls._normalize_action_cohort_membership(operation.membership),
                action_id=cls._action_cohort_exact_text(
                    operation.action_id,
                    field_name="process start action ID",
                    allow_empty=False,
                ),
                transition_id=cls._action_cohort_exact_text(
                    operation.transition_id,
                    field_name="process start transition ID",
                    allow_empty=False,
                ),
                transition_ordinal=ordinal,
            )
        if type(operation) is LifecycleTransition:
            return cls._normalize_action_cohort_transition(operation)
        if type(operation) is LifecycleHold:
            return cls._normalize_action_cohort_hold(operation)
        if type(operation) is LifecycleSubjectClosureControl:
            return LifecycleSubjectClosureControl(
                barrier=cls._normalize_action_cohort_barrier(operation.barrier),
                ticket_id=cls._action_cohort_exact_text(
                    operation.ticket_id,
                    field_name="closure ticket ID",
                    allow_empty=False,
                ),
            )
        raise TypeError("Lifecycle action cohort contains an unsupported exact operation")

    @classmethod
    def _normalize_action_cohort_request(
        cls,
        request: object,
    ) -> LifecycleActionCohortRequest:
        """Copy one caller request only after recursively closing every scalar type."""

        if type(request) is not LifecycleActionCohortRequest:
            raise TypeError("Lifecycle action cohort preparation requires an exact request")
        state_publication_token = cls._action_cohort_exact_text(
            request.state_publication_token,
            field_name="State publication token",
            allow_empty=False,
        )
        operations = request.operations
        if type(operations) is not tuple or not operations:
            raise TypeError("Lifecycle action cohort operations must be an exact non-empty tuple")
        if len(operations) > _MAX_ACTION_COHORT_OPERATIONS_PER_REQUEST:
            raise ValueError(
                "Lifecycle action cohort operation capacity exceeded: "
                f"{len(operations)} > {_MAX_ACTION_COHORT_OPERATIONS_PER_REQUEST}"
            )
        return LifecycleActionCohortRequest(
            state_publication_token=state_publication_token,
            operations=tuple(cls._normalize_action_cohort_operation(item) for item in operations),
        )

    @staticmethod
    def _action_cohort_request_preimage(request: LifecycleActionCohortRequest) -> bytes:
        """Serialize only an already-normalized closed request."""

        return repr(request).encode("utf-8")

    @classmethod
    def _action_cohort_plan_digest(cls, request: LifecycleActionCohortRequest) -> str:
        """Return one deterministic digest over every normalized cohort input."""

        return sha256(cls._action_cohort_request_preimage(request)).hexdigest()

    @staticmethod
    def _action_cohort_operations_digest(request: LifecycleActionCohortRequest) -> str:
        """Identify exact lifecycle semantics independently of the opaque State token."""

        return sha256(repr(request.operations).encode("utf-8")).hexdigest()

    def _action_cohort_token_integrity(
        self,
        *,
        preparation_id: int,
        expected_watermark: datetime | None,
        plan_digest: str,
    ) -> str:
        watermark = "" if expected_watermark is None else expected_watermark.isoformat()
        return sha256(
            (
                "lifecycle-action-cohort-admission\0"
                f"{self._action_cohort_registry_id}\0{preparation_id}\0{watermark}\0{plan_digest}"
            ).encode()
        ).hexdigest()

    def _action_cohort_receipt_integrity(
        self,
        *,
        plan_digest: str,
        committed_digest: str,
    ) -> str:
        return sha256(
            (
                "lifecycle-action-cohort-receipt\0"
                f"{self._action_cohort_registry_id}\0{plan_digest}\0{committed_digest}"
            ).encode()
        ).hexdigest()

    @staticmethod
    def _action_cohort_operation_subject(
        operation: LifecycleActionCohortOperation,
    ) -> LifecycleEntityRef:
        if type(operation) in {LifecycleSessionStartRequest, LifecycleProcessStartRequest}:
            return operation.identity.ref
        if type(operation) in {LifecycleTransition, LifecycleHold}:
            return operation.subject
        assert type(operation) is LifecycleSubjectClosureControl
        return operation.barrier.subject

    def _action_cohort_static_reservation_keys(
        self,
        request: LifecycleActionCohortRequest,
    ) -> tuple[tuple[str, str], ...]:
        """Return exact declared keys before relationship expansion under locks."""

        keys: list[tuple[str, str]] = []
        for operation in request.operations:
            subject = self._action_cohort_operation_subject(operation)
            keys.append(self._closed_transport_subject_key(subject))
            if type(operation) is LifecycleSessionStartRequest:
                identity = operation.identity
                keys.extend(
                    (
                        ("transition", operation.transition_id),
                        (
                            "session_logon",
                            repr(
                                (
                                    identity.hostname.strip().casefold(),
                                    identity.logon_id.strip().casefold(),
                                )
                            ),
                        ),
                    )
                )
            elif type(operation) is LifecycleProcessStartRequest:
                identity = operation.identity
                keys.extend(
                    (
                        ("transition", operation.transition_id),
                        (
                            "process_pid",
                            repr((identity.hostname.strip().casefold(), identity.pid)),
                        ),
                    )
                )
                if identity.parent_object_id:
                    keys.append(
                        self._closed_transport_subject_key(
                            LifecycleEntityRef("process", identity.parent_object_id)
                        )
                    )
                if operation.membership.session_object_id:
                    keys.append(
                        self._closed_transport_subject_key(
                            LifecycleEntityRef(
                                "session",
                                operation.membership.session_object_id,
                            )
                        )
                    )
            elif type(operation) is LifecycleTransition:
                keys.append(("transition", operation.transition_id))
            elif type(operation) is LifecycleHold:
                keys.extend(
                    (
                        ("hold", operation.hold_id),
                        ("transition", f"{operation.hold_id}:acquired"),
                    )
                )
            else:
                assert type(operation) is LifecycleSubjectClosureControl
                barrier = operation.barrier
                keys.extend(
                    (
                        self._resource_lease_subject_key(barrier.subject),
                        ("barrier", barrier.barrier_id),
                        ("ticket", operation.ticket_id),
                        ("transition", f"{barrier.barrier_id}:requested"),
                        ("transition", f"{operation.ticket_id}:scheduled"),
                        ("transition", f"{operation.ticket_id}:closed"),
                    )
                )
        return tuple(dict.fromkeys(keys))

    def _action_cohort_route_keys(
        self,
        request: LifecycleActionCohortRequest,
    ) -> tuple[tuple[str, str], ...]:
        """Return every exact route shard used by validation and commit."""

        keys: list[tuple[str, str]] = []
        for operation in request.operations:
            subject = self._action_cohort_operation_subject(operation)
            keys.append((subject.kind, subject.object_id))
            if type(operation) is LifecycleSessionStartRequest:
                keys.append(("transition", operation.transition_id))
            elif type(operation) is LifecycleProcessStartRequest:
                keys.append(("transition", operation.transition_id))
                if operation.identity.parent_object_id:
                    keys.append(("process", operation.identity.parent_object_id))
                if operation.membership.session_object_id:
                    keys.append(("session", operation.membership.session_object_id))
            elif type(operation) is LifecycleTransition:
                keys.append(("transition", operation.transition_id))
            elif type(operation) is LifecycleHold:
                keys.extend(
                    (
                        ("hold", operation.hold_id),
                        ("transition", f"{operation.hold_id}:acquired"),
                    )
                )
            else:
                assert type(operation) is LifecycleSubjectClosureControl
                keys.extend(
                    (
                        ("barrier", operation.barrier.barrier_id),
                        ("ticket", operation.ticket_id),
                        ("transition", f"{operation.barrier.barrier_id}:requested"),
                        ("transition", f"{operation.ticket_id}:scheduled"),
                        ("transition", f"{operation.ticket_id}:closed"),
                    )
                )
        return tuple(dict.fromkeys(keys))

    def _action_cohort_partition_ids_locked(
        self,
        request: LifecycleActionCohortRequest,
    ) -> tuple[int, ...]:
        """Resolve every staged and live subject before sorted partition locking."""

        staged_partitions: dict[LifecycleEntityRef, int] = {}
        for operation in request.operations:
            if type(operation) in {LifecycleSessionStartRequest, LifecycleProcessStartRequest}:
                staged_partitions[operation.identity.ref] = self._partition_id(
                    operation.identity.hostname
                )
        partition_ids = set(staged_partitions.values())
        for operation in request.operations:
            subject = self._action_cohort_operation_subject(operation)
            partition_id = staged_partitions.get(subject)
            if partition_id is None:
                partition_id = self._subject_partition_locked(subject)
            partition_ids.add(partition_id)
            if type(operation) is not LifecycleProcessStartRequest:
                continue
            parent_id = operation.identity.parent_object_id
            parent_ref = LifecycleEntityRef("process", parent_id) if parent_id else None
            if parent_ref is not None and parent_ref not in staged_partitions:
                parent_partition = self._routes.get_locked("process", parent_id)
                if not isinstance(parent_partition, int):
                    raise StateError(f"Unknown parent process lifecycle object {parent_id}")
                partition_ids.add(parent_partition)
            session_id = operation.membership.session_object_id
            session_ref = LifecycleEntityRef("session", session_id) if session_id else None
            if session_ref is not None and session_ref not in staged_partitions:
                session_route = self._routes.get_locked("session", session_id)
                session_partition = self._session_partition_from_route(session_route)
                if session_partition is None:
                    raise StateError(f"Unknown session lifecycle object {session_id}")
                partition_ids.add(session_partition)
        return tuple(sorted(partition_ids))

    def _validate_action_cohort_token(
        self,
        token: LifecycleActionCohortAdmissionToken,
    ) -> LifecycleActionCohortAdmissionToken:
        """Require the exact capability type and owning registry."""

        if type(token) is not LifecycleActionCohortAdmissionToken:
            raise StateError("Lifecycle action-cohort token must have its exact public type")
        if token.registry_id != self._action_cohort_registry_id:
            raise StateError("Lifecycle action-cohort token belongs to another registry")
        return token

    @staticmethod
    def _action_cohort_token_matches_canonical(
        token: LifecycleActionCohortAdmissionToken,
        canonical: LifecycleActionCohortAdmissionToken,
    ) -> bool:
        del token, canonical
        return True

    def _active_action_cohort_reservation_locked(
        self,
        token: LifecycleActionCohortAdmissionToken,
    ) -> _ActionCohortReservation:
        preparation_id = self._action_cohort_capability_locators.get(id(token))
        if preparation_id is None:
            self._validate_action_cohort_token(token)
            raise StateError("Lifecycle action-cohort token is stale or consumed")
        active = self._action_cohort_reservations.get(preparation_id)
        if active is None or active.token_ref() is not token:
            self._action_cohort_capability_locators.pop(id(token), None)
            raise StateError("Lifecycle action-cohort token is stale or consumed")
        try:
            validated_token = self._validate_action_cohort_token(token)
            if not self._action_cohort_token_matches_canonical(
                validated_token,
                active.canonical_token,
            ):
                raise StateError("Lifecycle action-cohort token was mutated after preparation")
        except (
            AssertionError,
            AttributeError,
            RecursionError,
            StateError,
            TypeError,
            ValueError,
        ) as exc:
            primary = (
                exc
                if isinstance(exc, StateError)
                else StateError("Lifecycle action-cohort token is malformed")
            )
            _cleanup_required, cleanup_failures = self._cleanup_action_cohort_reservation_locked(
                active
            )
            self._add_action_cohort_cleanup_notes(primary, cleanup_failures)
            if primary is exc:
                raise
            raise primary from exc
        return active

    def _release_action_cohort_reservation_locked(
        self,
        reservation: _ActionCohortReservation,
        *,
        allow_committing: bool = False,
    ) -> bool:
        """Release one reservation through the ordinary injectable seam."""

        return self._release_action_cohort_reservation_state_locked(
            reservation,
            allow_committing=allow_committing,
        )

    def _release_action_cohort_reservation_state_locked(
        self,
        reservation: _ActionCohortReservation,
        *,
        allow_committing: bool = False,
    ) -> bool:
        """Release exact reservation state for owner-local cleanup reconciliation."""

        if reservation.committing and not allow_committing:
            return False
        preparation_id = reservation.canonical_token.preparation_id
        if self._action_cohort_reservations.get(preparation_id) is not reservation:
            return False
        if reservation.claimed:
            self._action_cohort_claimed_reservations -= 1
            reservation.claimed = False
        if reservation.committing:
            self._action_cohort_committing_reservations -= 1
            reservation.committing = False
        claimed_capability_id = reservation.claimed_capability_id
        if claimed_capability_id is not None:
            self._action_cohort_claimed_capabilities.pop(claimed_capability_id, None)
            reservation.claimed_capability_id = None
        certified_capability_id = reservation.certified_capability_id
        if certified_capability_id is not None:
            self._action_cohort_certified_authorizations.pop(certified_capability_id, None)
            reservation.certified_capability_id = None
        receipt_authority_id = reservation.receipt_authority_id
        if receipt_authority_id is not None:
            authority = self._action_cohort_receipt_authorities.pop(
                receipt_authority_id,
                None,
            )
            if authority is not None:
                if authority.committed:
                    self._action_cohort_committed_receipt_authorities -= 1
                else:
                    self._action_cohort_expected_receipt_authorities -= 1
            reservation.receipt_authority_id = None
        self._action_cohort_capability_locators.pop(reservation.token_id, None)
        if reservation.request_bytes:
            self._action_cohort_retained_request_bytes -= reservation.request_bytes
            reservation.request_bytes = 0
        if reservation.provenance_new:
            self._action_cohort_pending_provenance_insertions -= 1
            if reservation.provenance_eviction is not None:
                self._action_cohort_pending_provenance_evictions.discard(
                    reservation.provenance_eviction
                )
            reservation.provenance_new = False
            reservation.provenance_eviction = None
        elif reservation.retry_receipt is not None:
            remaining = self._action_cohort_provenance_pins[reservation.provenance_binding] - 1
            if remaining:
                self._action_cohort_provenance_pins[reservation.provenance_binding] = remaining
            else:
                self._action_cohort_provenance_pins.pop(reservation.provenance_binding)
            reservation.retry_receipt = None
        for key in reservation.keys:
            if self._action_cohort_reserved_keys.get(key) == preparation_id:
                self._action_cohort_reserved_keys.pop(key)
        reservation.composite_certified = False
        reservation.claim_thread_id = None
        reservation.commit_plan = None
        self._action_cohort_reservations.pop(preparation_id, None)
        if not self._action_cohort_reservations:
            self._action_cohort_reserved_keys.clear()
        self._closed_transport_preparation_condition.notify_all()
        return True

    def _prune_action_cohort_reservations_locked(self) -> int:
        """Release bounded unclaimed reservations with dead owners or stale watermarks."""

        released = 0
        for preparation_id in tuple(sorted(self._action_cohort_reservations)):
            reservation = self._action_cohort_reservations.get(preparation_id)
            if reservation is None or reservation.claimed or reservation.committing:
                continue
            owner_is_gone = reservation.token_ref() is None
            watermark_is_stale = reservation.canonical_token.expected_watermark != self._watermark
            if (owner_is_gone or watermark_is_stale) and (
                self._release_action_cohort_reservation_locked(reservation)
            ):
                released += 1
        return released

    def _reserve_action_cohort_provenance_locked(
        self,
        plan: _PreparedActionCohortCommitPlan,
    ) -> tuple[bool, tuple[str, str] | None, LifecycleActionCohortReceipt | None]:
        """Pre-reserve one retry pin or one bounded durable provenance insertion."""

        binding = (plan.token.request.state_publication_token, plan.token.plan_digest)
        if plan.retry_receipt is not None:
            if binding in self._action_cohort_pending_provenance_evictions:
                raise LifecycleActionCohortInProgressError(
                    "Exact lifecycle action-cohort retry provenance is reserved for bounded "
                    "eviction by another prepared cohort"
                )
            self._action_cohort_provenance_pins[binding] = (
                self._action_cohort_provenance_pins.get(binding, 0) + 1
            )
            return False, None, plan.retry_receipt

        if self._action_cohort_provenance_capacity <= 0:
            raise StateError(
                "Lifecycle action-cohort committed provenance capacity is zero; "
                "increase the configured capacity before preparing a new cohort"
            )
        effective_entries = (
            len(self._action_cohort_committed_provenance)
            + self._action_cohort_pending_provenance_insertions
            - len(self._action_cohort_pending_provenance_evictions)
        )
        eviction: tuple[str, str] | None = None
        if effective_entries >= self._action_cohort_provenance_capacity:
            eviction = next(
                (
                    candidate
                    for candidate in self._action_cohort_committed_provenance
                    if candidate not in self._action_cohort_provenance_pins
                    and candidate not in self._action_cohort_pending_provenance_evictions
                ),
                None,
            )
            if eviction is None:
                raise StateError(
                    "Lifecycle action-cohort committed provenance capacity is exhausted by "
                    "active exact retries; commit or cancel those retries before preparing "
                    "another cohort"
                )
            self._action_cohort_pending_provenance_evictions.add(eviction)
        self._action_cohort_pending_provenance_insertions += 1
        return True, eviction, None

    def _record_action_cohort_provenance_locked(
        self,
        reservation: _ActionCohortReservation,
        provenance: _CommittedActionCohortProvenance,
    ) -> None:
        """Apply one already-preflighted FIFO eviction and insert exact commit provenance."""

        eviction = reservation.provenance_eviction
        if eviction is not None:
            evicted = self._action_cohort_committed_provenance.pop(eviction, None)
            if (
                evicted is not None
                and self._action_cohort_provenance_by_operations.get(evicted.operations_digest)
                == eviction
            ):
                self._action_cohort_provenance_by_operations.pop(evicted.operations_digest)
        self._action_cohort_committed_provenance[reservation.provenance_binding] = provenance
        self._action_cohort_provenance_by_operations[reservation.operations_digest] = (
            reservation.provenance_binding
        )

    def _discard_action_cohort_reservation_for_token(
        self,
        token: LifecycleActionCohortAdmissionToken,
    ) -> bool:
        """Best-effort cleanup keyed only by the exact token object capability."""

        with self._gate.mutation(), self._closed_transport_preparation_lock:
            preparation_id = self._action_cohort_capability_locators.get(id(token))
            if preparation_id is None:
                return False
            reservation = self._action_cohort_reservations.get(preparation_id)
            if (
                reservation is not None
                and reservation.token_ref() is token
                and not reservation.committing
            ):
                return self._release_action_cohort_reservation_locked(reservation)
            return False

    @staticmethod
    def _add_action_cohort_cleanup_notes(
        primary: BaseException,
        failures: tuple[BaseException, ...],
    ) -> None:
        """Attach cleanup diagnostics without replacing the initiating exception."""

        for ordinal, failure in enumerate(failures, start=1):
            try:
                primary.add_note(
                    "Lifecycle action-cohort claim cleanup failure "
                    f"{ordinal}: {type(failure).__name__}"
                )
            except BaseException:
                continue

    def _cleanup_claimed_action_cohort_reservation(
        self,
        reservation: _ActionCohortReservation,
    ) -> tuple[bool, tuple[BaseException, ...]]:
        """Release one exact owner-local claim with bounded all-attempt fallback."""

        with self._gate.mutation(), self._closed_transport_preparation_lock:
            return self._cleanup_action_cohort_reservation_locked(reservation)

    def _cleanup_action_cohort_reservation_locked(
        self,
        reservation: _ActionCohortReservation,
    ) -> tuple[bool, tuple[BaseException, ...]]:
        """Reconcile one exact reservation while its owner locks are already held."""

        failures: list[BaseException] = []
        cleanup_required = False
        for attempt in range(3):
            try:
                preparation_id = reservation.canonical_token.preparation_id
                active = self._action_cohort_reservations.get(preparation_id)
                if active is not reservation:
                    return cleanup_required, tuple(failures)
                cleanup_required = True
                if reservation.committing:
                    failures.append(
                        StateError(
                            "Committing lifecycle action cohort requires primitive rollback "
                            "before claim cleanup"
                        )
                    )
                    return cleanup_required, tuple(failures)
                if attempt == 0:
                    released = self._release_action_cohort_reservation_locked(reservation)
                else:
                    released = self._release_action_cohort_reservation_state_locked(reservation)
                if released:
                    return cleanup_required, tuple(failures)
            except BaseException as exc:
                failures.append(exc)
        return cleanup_required, tuple(failures)

    def retry_claimed_action_cohort_cleanup(
        self,
        capability: PreparedLifecycleActionCohort,
    ) -> None:
        """Retry cleanup for an exact exhausted claim whose finalizer could not detach it."""

        with self._closed_transport_preparation_lock:
            locator = self._action_cohort_claimed_capabilities.get(id(capability))
            if locator is None or locator.capability_ref() is not capability:
                raise StateError(
                    "Lifecycle action cohort has no retryable exact claimed cleanup locator"
                )
            reservation = locator.reservation
        cleanup_required, failures = self._cleanup_claimed_action_cohort_reservation(reservation)
        with self._closed_transport_preparation_lock:
            cleanup_complete = (
                self._action_cohort_reservations.get(reservation.canonical_token.preparation_id)
                is not reservation
            )
        if cleanup_complete:
            return
        if failures:
            primary = failures[0]
            self._add_action_cohort_cleanup_notes(primary, failures[1:])
            raise primary
        if not cleanup_required:
            raise StateError("Lifecycle action cohort cleanup is already complete")

    def _action_cohort_existing_state_locked(
        self,
        subject: LifecycleEntityRef,
        *,
        partition_id: int,
    ) -> _ActionCohortSubjectState:
        """Snapshot one live or retained process/session while its partition is locked."""

        partition = self._partitions[partition_id]
        entry = partition._entry(subject)
        if entry is None:
            raise StateError(f"Unknown {subject.kind} lifecycle object {subject.object_id}")
        if subject.kind == "process":
            if not isinstance(entry, _ProcessEntry):
                raise StateError("Lifecycle action cohort resolved an incompatible process")
            parent_object_id = entry.identity.parent_object_id
            session_object_id = entry.membership.session_object_id
            process_role = entry.identity.role
        elif subject.kind == "session":
            if not isinstance(entry, _SessionEntry):
                raise StateError("Lifecycle action cohort resolved an incompatible session")
            parent_object_id = ""
            session_object_id = ""
            process_role = ""
        else:
            raise StateError("Lifecycle action cohorts support process or session subjects")
        return _ActionCohortSubjectState(
            subject=subject,
            partition_id=partition_id,
            started_at=partition._entry_started_at(entry),
            parent_object_id=parent_object_id,
            session_object_id=session_object_id,
            process_role=process_role,
            close_barrier=entry.close_barrier,
            closure_ticket=entry.closure_ticket,
            closed_at=entry.closed_at,
            latest_dependent_at=entry.state.latest_dependent_at,
            latest_hold_until=entry.state.latest_hold_until,
        )

    @staticmethod
    def _action_cohort_transition_for_start(
        operation: LifecycleSessionStartRequest | LifecycleProcessStartRequest,
    ) -> LifecycleTransition:
        return LifecycleTransition(
            transition_id=operation.transition_id,
            subject=operation.identity.ref,
            kind="started",
            canonical_time=operation.identity.started_at,
            action_id=operation.action_id,
            transition_ordinal=operation.transition_ordinal,
        )

    def _action_cohort_validate_global_transition_locked(
        self,
        transition: LifecycleTransition,
    ) -> LifecycleTransition | None:
        prior = self._routes.get_locked("transition", transition.transition_id)
        actual = self._transition_from_route(prior, transition.transition_id)
        if actual is not None and actual != transition:
            self._reject_exact_conflict("transition", transition.transition_id)
        if prior is not None and actual is None:
            self._reject_exact_conflict("transition", transition.transition_id)
        return actual

    def _action_cohort_validate_descendants_locked(
        self,
        state: _ActionCohortSubjectState,
        *,
        effective_at: datetime,
        states: dict[LifecycleEntityRef, _ActionCohortSubjectState],
        staged_children: dict[str, set[str]],
        staged_members: dict[str, set[str]],
        reservation_keys: list[tuple[str, str]],
    ) -> None:
        """Require every child/member relation to close first inside the cohort."""

        partition = self._partitions[state.partition_id]
        subject = state.subject
        if subject.kind == "process":
            aggregate = partition._children_by_parent.get(subject.object_id)
            related_ids = {
                binding.child_object_id
                for binding in partition._live_children.find_iter(
                    "parent",
                    subject.object_id,
                )
            }
            related_ids.update(staged_children.get(subject.object_id, ()))
            relationship = "child processes"
            external = partition._service_bindings_by_process.get(subject.object_id)
            if external is not None and external.blocks_close_at(effective_at):
                raise StateError(
                    f"Cannot close lifecycle {subject.object_id}: service bindings remain active"
                )
        else:
            aggregate = partition._members_by_session.get(subject.object_id)
            related_ids = {
                binding.process_object_id
                for binding in partition._live_session_members.find_iter(
                    "session",
                    subject.object_id,
                )
            }
            related_ids.update(staged_members.get(subject.object_id, ()))
            relationship = "session members"
            external = partition._transport_bindings_by_session.get(subject.object_id)
            if external is not None and external.blocks_close_at(effective_at):
                raise StateError(
                    f"Cannot close lifecycle {subject.object_id}: transport bindings remain active"
                )
        if aggregate is not None and (
            aggregate.latest_closed_at is not None and aggregate.latest_closed_at > effective_at
        ):
            raise StateError(
                f"Cannot close lifecycle {subject.object_id} before an existing {relationship} close"
            )
        for object_id in sorted(related_ids):
            child_ref = LifecycleEntityRef("process", object_id)
            reservation_keys.append(self._closed_transport_subject_key(child_ref))
            child = states.get(child_ref)
            if child is None:
                child = self._action_cohort_existing_state_locked(
                    child_ref,
                    partition_id=state.partition_id,
                )
                states[child_ref] = child
            if child.closed_at is None:
                raise StateError(
                    f"Cannot close lifecycle {subject.object_id}: {relationship} remain active"
                )
            if child.closed_at > effective_at:
                raise StateError(
                    f"Cannot close lifecycle {subject.object_id} before {relationship} close"
                )

    def _action_cohort_validate_durable_capacity_locked(
        self,
        state: _ActionCohortSubjectState,
    ) -> None:
        """Preflight the three durable control commits added by one closure."""

        partition = self._partitions[state.partition_id]
        entry = partition._entry(state.subject)
        if entry is None:
            existing_count = 1
        elif entry.state.commits is not None:
            existing_count = len(entry.state.commits)
        else:
            existing_count = len(
                {
                    (transition.action_id, transition.transition_ordinal)
                    for transition in entry.transitions
                    if transition.kind not in _STREAMED_TRANSITION_KINDS
                }
            )
        if existing_count + 3 > _MAX_DURABLE_COMMITS_PER_ENTITY:
            raise StateError(
                f"Lifecycle durable commit bound exceeded for {state.subject.object_id}"
            )

    def _prepare_action_cohort_commit_locked(
        self,
        token: LifecycleActionCohortAdmissionToken,
        *,
        partition_ids: tuple[int, ...],
    ) -> _PreparedActionCohortCommitPlan:
        """Validate every ordered operation without publishing canonical rows."""

        request = token.request
        admitted_sessions: dict[str, SessionLifecycleIdentity] = {}
        admitted_processes: dict[str, ProcessLifecycleIdentity] = {}
        states: dict[LifecycleEntityRef, _ActionCohortSubjectState] = {}
        staged_children: dict[str, set[str]] = {}
        staged_members: dict[str, set[str]] = {}
        reservation_keys = list(self._action_cohort_static_reservation_keys(request))
        prepared_operations: list[_PreparedActionCohortOperation] = []
        presence: list[bool] = []

        def state_for(subject: LifecycleEntityRef) -> _ActionCohortSubjectState:
            state = states.get(subject)
            if state is not None:
                return state
            partition_id = self._subject_partition_locked(subject)
            state = self._action_cohort_existing_state_locked(
                subject,
                partition_id=partition_id,
            )
            states[subject] = state
            return state

        for operation in request.operations:
            if type(operation) is LifecycleSessionStartRequest:
                identity = operation.identity
                transition = self._action_cohort_transition_for_start(operation)
                partition_id = self._partition_id(identity.hostname)
                prior_session = self._routes.get_locked("session", identity.object_id)
                prior_partition = self._session_partition_from_route(prior_session)
                if prior_partition is not None and prior_partition != partition_id:
                    raise StateError(
                        f"Session lifecycle object {identity.object_id} is already registered"
                    )
                if isinstance(prior_session, bytes):
                    if _decode_session_row(prior_session).object_id != identity.object_id:
                        raise StateError("Lifecycle session route semantic hash collision")
                elif isinstance(prior_session, int):
                    routed_partition, handle = self._decode_session_locator(prior_session)
                    snapshot = self._partitions[routed_partition].get_session_by_handle(handle)
                    if snapshot is None or snapshot.identity.object_id != identity.object_id:
                        raise StateError("Lifecycle session route semantic hash collision")
                prior_transition = self._action_cohort_validate_global_transition_locked(transition)
                prepared = self._partitions[partition_id]._prepare_session_registration_locked(
                    identity,
                    transition=transition,
                )
                already_present = prepared.existing is not None
                if already_present != (prior_partition is not None):
                    raise StateError("Lifecycle session retry lost its exact subject route")
                if already_present != (prior_transition is not None):
                    raise StateError("Lifecycle session retry lost its exact start transition")
                if already_present:
                    state = self._action_cohort_existing_state_locked(
                        identity.ref,
                        partition_id=partition_id,
                    )
                else:
                    state = _ActionCohortSubjectState(
                        subject=identity.ref,
                        partition_id=partition_id,
                        started_at=identity.started_at,
                    )
                states[identity.ref] = state
                admitted_sessions[identity.object_id] = identity
                prepared_operations.append(
                    _PreparedActionCohortOperation(
                        operation=operation,
                        partition_id=partition_id,
                        session_start=prepared,
                        session_registration=PreparedSessionRegistration(
                            _registry=self,
                            _partition_id=partition_id,
                            _prepared=prepared,
                            _prior_session_route=prior_session,
                        ),
                        prior_session_route=prior_session,
                        already_present=already_present,
                    )
                )
                presence.append(already_present)
                continue

            if type(operation) is LifecycleProcessStartRequest:
                identity = operation.identity
                transition = self._action_cohort_transition_for_start(operation)
                partition_id = self._partition_id(identity.hostname)
                prior_process = self._routes.get_locked("process", identity.object_id)
                if prior_process is not None and prior_process != partition_id:
                    raise StateError(
                        f"Process lifecycle object {identity.object_id} is already registered"
                    )
                prior_transition = self._action_cohort_validate_global_transition_locked(transition)
                prepared = self._partitions[partition_id]._prepare_process_registration_locked(
                    identity,
                    token=operation.token,
                    membership=operation.membership,
                    transition=transition,
                    staged_sessions=admitted_sessions,
                    staged_processes=admitted_processes,
                )
                already_present = prepared.existing is not None
                if already_present != (prior_process is not None):
                    raise StateError("Lifecycle process retry lost its exact subject route")
                if already_present != (prior_transition is not None):
                    raise StateError("Lifecycle process retry lost its exact start transition")
                if already_present:
                    state = self._action_cohort_existing_state_locked(
                        identity.ref,
                        partition_id=partition_id,
                    )
                else:
                    state = _ActionCohortSubjectState(
                        subject=identity.ref,
                        partition_id=partition_id,
                        started_at=identity.started_at,
                        parent_object_id=identity.parent_object_id,
                        session_object_id=operation.membership.session_object_id,
                        process_role=identity.role,
                    )
                    if identity.parent_object_id:
                        parent = state_for(LifecycleEntityRef("process", identity.parent_object_id))
                        if parent.closed_at is not None or parent.close_barrier is not None:
                            raise StateError("Lifecycle action cohort starts after parent closure")
                    if operation.membership.session_object_id:
                        session = state_for(
                            LifecycleEntityRef(
                                "session",
                                operation.membership.session_object_id,
                            )
                        )
                        if session.closed_at is not None or session.close_barrier is not None:
                            raise StateError("Lifecycle action cohort starts after session closure")
                states[identity.ref] = state
                admitted_processes[identity.object_id] = identity
                if identity.parent_object_id:
                    parent = state_for(LifecycleEntityRef("process", identity.parent_object_id))
                    if parent.process_role != "bootstrap_handoff":
                        staged_children.setdefault(identity.parent_object_id, set()).add(
                            identity.object_id
                        )
                if operation.membership.session_object_id:
                    staged_members.setdefault(
                        operation.membership.session_object_id,
                        set(),
                    ).add(identity.object_id)
                prepared_operations.append(
                    _PreparedActionCohortOperation(
                        operation=operation,
                        partition_id=partition_id,
                        process_start=prepared,
                        process_registration=PreparedProcessRegistration(
                            _registry=self,
                            _partition_id=partition_id,
                            _prepared=prepared,
                            _membership=operation.membership,
                        ),
                        already_present=already_present,
                    )
                )
                presence.append(already_present)
                continue

            subject = self._action_cohort_operation_subject(operation)
            state = state_for(subject)
            partition_id = state.partition_id
            partition = self._partitions[partition_id]
            entry = partition._entry(subject)

            if type(operation) is LifecycleTransition:
                prior = self._action_cohort_validate_global_transition_locked(operation)
                already_present = prior is not None
                if already_present:
                    if entry is None or not partition._entry_has_transition(entry, operation):
                        raise StateError("Lifecycle dependent retry lost exact subject state")
                else:
                    partition._reject_behind_watermark(
                        operation.canonical_time,
                        "dependent transition",
                    )
                    if operation.canonical_time < state.started_at:
                        raise StateError("Lifecycle dependent cannot precede its owning start")
                    if state.closed_at is not None and operation.canonical_time >= state.closed_at:
                        raise StateError("Lifecycle dependent cannot occur after closure")
                    if (
                        state.close_barrier is not None
                        and operation.canonical_time >= state.close_barrier.requested_at
                    ):
                        raise StateError("Lifecycle dependent cannot occur after its close barrier")
                    partition._validate_transition_claim(operation)
                    if (
                        state.latest_dependent_at is None
                        or operation.canonical_time > state.latest_dependent_at
                    ):
                        state.latest_dependent_at = operation.canonical_time
                prepared_operations.append(
                    _PreparedActionCohortOperation(
                        operation=operation,
                        partition_id=partition_id,
                        already_present=already_present,
                    )
                )
                presence.append(already_present)
                continue

            if type(operation) is LifecycleHold:
                transition = LifecycleTransition(
                    transition_id=f"{operation.hold_id}:acquired",
                    subject=operation.subject,
                    kind="hold_acquired",
                    canonical_time=operation.acquired_at,
                    action_id=operation.action_id,
                    reason=operation.reason,
                    transition_ordinal=operation.transition_ordinal,
                )
                prior_hold = self._routes.get_locked("hold", operation.hold_id)
                prior_transition = self._action_cohort_validate_global_transition_locked(transition)
                partition_hold = partition.hold(operation.hold_id)
                if prior_hold is not None:
                    if prior_hold != operation or prior_transition != transition:
                        self._reject_exact_conflict("hold", operation.hold_id)
                    if partition_hold != operation:
                        raise StateError("Lifecycle hold retry lost exact subject state")
                    already_present = True
                else:
                    if partition_hold is not None:
                        raise StateError("Lifecycle hold retry lost its exact global route")
                    if prior_transition is not None:
                        raise StateError("Partial lifecycle hold retry is not admissible")
                    already_present = False
                    partition._reject_behind_watermark(
                        operation.acquired_at,
                        "hold acquisition",
                    )
                    if operation.acquired_at < state.started_at:
                        raise StateError("Lifecycle hold cannot precede its owning start")
                    if state.close_barrier is not None or state.closed_at is not None:
                        raise StateError("Lifecycle hold cannot follow lifecycle closure")
                    partition._validate_transition_claim(transition)
                    if (
                        state.latest_dependent_at is None
                        or operation.acquired_at > state.latest_dependent_at
                    ):
                        state.latest_dependent_at = operation.acquired_at
                    if (
                        state.latest_hold_until is None
                        or operation.hold_until > state.latest_hold_until
                    ):
                        state.latest_hold_until = operation.hold_until
                prepared_operations.append(
                    _PreparedActionCohortOperation(
                        operation=operation,
                        partition_id=partition_id,
                        hold_transition=transition,
                        already_present=already_present,
                    )
                )
                presence.append(already_present)
                continue

            assert type(operation) is LifecycleSubjectClosureControl
            barrier = operation.barrier
            if entry is not None and entry.closed_at is not None:
                ticket = entry.closure_ticket
                if ticket is None:
                    raise StateError("Terminal lifecycle lost its exact closure ticket")
                expected = self._expected_subject_closure_transitions(
                    operation,
                    ticket.effective_at,
                )
                if (
                    entry.close_barrier != barrier
                    or ticket != expected[0]
                    or not partition._entry_has_transition(entry, expected[3])
                    or entry.closed_at != ticket.effective_at
                ):
                    raise StateError("Terminal action-cohort retry disagrees with exact closure")
                for kind, semantic_id, value in (
                    ("barrier", barrier.barrier_id, barrier),
                    ("ticket", operation.ticket_id, expected[0]),
                    ("transition", expected[1].transition_id, expected[1]),
                    ("transition", expected[2].transition_id, expected[2]),
                    ("transition", expected[3].transition_id, expected[3]),
                ):
                    prior = self._routes.get_locked(kind, semantic_id)
                    actual = (
                        self._transition_from_route(prior, semantic_id)
                        if kind == "transition"
                        else prior
                    )
                    if actual != value:
                        raise StateError("Terminal action-cohort retry lost exact control state")
                state.close_barrier = barrier
                state.closure_ticket = ticket
                state.closed_at = ticket.effective_at
                prepared_operations.append(
                    _PreparedActionCohortOperation(
                        operation=operation,
                        partition_id=partition_id,
                        closure_ticket=expected[0],
                        closure_transitions=expected[1:],
                        effective_at=ticket.effective_at,
                        already_present=True,
                    )
                )
                presence.append(True)
                continue
            if state.close_barrier is not None or state.closure_ticket is not None:
                raise StateError("Partial action-cohort terminal retry is not admissible")
            partition._reject_behind_watermark(barrier.requested_at, "close barrier")
            if barrier.requested_at < state.started_at:
                raise StateError("Lifecycle close precedes its start")
            if (
                state.latest_dependent_at is not None
                and state.latest_dependent_at >= barrier.requested_at
            ):
                raise StateError("Lifecycle close barrier precedes a dependent operation")
            latest_hold = state.latest_hold_until or barrier.requested_at
            latest_resource = partition._resource_lease_deadline_for(subject)
            latest_dependency = max(
                latest_hold,
                latest_resource or barrier.requested_at,
            )
            if barrier.authority == "authoritative" and latest_dependency > barrier.requested_at:
                raise StateError("Authoritative lifecycle close conflicts with a hold or lease")
            effective_at = max(barrier.requested_at, latest_dependency)
            self._action_cohort_validate_descendants_locked(
                state,
                effective_at=effective_at,
                states=states,
                staged_children=staged_children,
                staged_members=staged_members,
                reservation_keys=reservation_keys,
            )
            if subject.kind == "process":
                if state.parent_object_id:
                    reservation_keys.append(
                        self._closed_transport_subject_key(
                            LifecycleEntityRef("process", state.parent_object_id)
                        )
                    )
                if state.session_object_id:
                    reservation_keys.append(
                        self._closed_transport_subject_key(
                            LifecycleEntityRef("session", state.session_object_id)
                        )
                    )
            expected = self._expected_subject_closure_transitions(operation, effective_at)
            for kind, semantic_id, value in (
                ("barrier", barrier.barrier_id, barrier),
                ("ticket", operation.ticket_id, expected[0]),
                ("transition", expected[1].transition_id, expected[1]),
                ("transition", expected[2].transition_id, expected[2]),
                ("transition", expected[3].transition_id, expected[3]),
            ):
                prior = self._routes.get_locked(kind, semantic_id)
                actual = (
                    self._transition_from_route(prior, semantic_id)
                    if kind == "transition"
                    else prior
                )
                if prior is not None:
                    if actual != value:
                        self._reject_exact_conflict(kind, semantic_id)
                    raise StateError("Partial action-cohort terminal retry is not admissible")
            if entry is not None:
                partition._validate_barrier_claim(barrier)
                partition._validate_ticket_claim(expected[0])
                for transition in expected[1:]:
                    partition._validate_transition_claim(transition)
            self._action_cohort_validate_durable_capacity_locked(state)
            state.close_barrier = barrier
            state.closure_ticket = expected[0]
            state.closed_at = effective_at
            prepared_operations.append(
                _PreparedActionCohortOperation(
                    operation=operation,
                    partition_id=partition_id,
                    closure_ticket=expected[0],
                    closure_transitions=expected[1:],
                    effective_at=effective_at,
                )
            )
            presence.append(False)

        if any(presence) and not all(presence):
            raise StateError("Partial lifecycle action-cohort retry is not admissible")
        already_present = all(presence)
        receipt_request_preimage = self._action_cohort_request_preimage(request)
        operations_digest = self._action_cohort_operations_digest(request)
        binding = (request.state_publication_token, token.plan_digest)
        provenance_binding = self._action_cohort_provenance_by_operations.get(operations_digest)
        provenance = self._action_cohort_committed_provenance.get(binding)
        retry_receipt: LifecycleActionCohortReceipt | None = None
        if already_present:
            if (
                provenance_binding != binding
                or provenance is None
                or provenance.operations_digest != operations_digest
            ):
                raise StateError(
                    "Committed lifecycle action cohort has no matching original State/plan "
                    "provenance; exact retry cannot rebind existing lifecycle state"
                )
            retry_receipt = provenance.receipt
        elif provenance_binding is not None or provenance is not None:
            raise StateError(
                "Lifecycle action cohort State/plan provenance is already bound to another "
                "canonical operation set"
            )
        return _PreparedActionCohortCommitPlan(
            token=token,
            operations=tuple(prepared_operations),
            partition_ids=partition_ids,
            route_keys=self._action_cohort_route_keys(request),
            reservation_keys=tuple(dict.fromkeys(reservation_keys)),
            receipt_request_preimage=receipt_request_preimage,
            operations_digest=operations_digest,
            retry_receipt=retry_receipt,
            already_present=already_present,
        )

    def prepare_action_cohort(
        self,
        request: LifecycleActionCohortRequest,
    ) -> LifecycleActionCohortAdmissionToken:
        """Validate and reserve one ordered action cohort without canonical writes."""

        public_request = self._normalize_action_cohort_request(request)
        if len(public_request.operations) > self._action_cohort_operation_capacity:
            raise StateError(
                "Lifecycle action-cohort operation capacity exceeded: "
                f"{len(public_request.operations)} > "
                f"{self._action_cohort_operation_capacity}"
            )
        request_preimage = self._action_cohort_request_preimage(public_request)
        request_bytes = len(request_preimage)
        if request_bytes > self._action_cohort_request_byte_capacity:
            raise StateError(
                "Lifecycle action-cohort request-byte capacity exceeded: "
                f"{request_bytes} > {self._action_cohort_request_byte_capacity}"
            )
        static_keys = self._action_cohort_static_reservation_keys(public_request)
        route_keys = self._action_cohort_route_keys(public_request)
        with self._gate.mutation(), self._closed_transport_preparation_lock:
            self._prune_action_cohort_reservations_locked()
            if len(self._action_cohort_reservations) >= self._action_cohort_reservation_capacity:
                raise StateError(
                    "Lifecycle action-cohort reservation capacity is exhausted; commit, "
                    "cancel, or prune an unclaimed preparation before retrying"
                )
            if (
                self._action_cohort_retained_request_bytes + request_bytes
                > self._action_cohort_request_byte_capacity
            ):
                raise StateError(
                    "Lifecycle action-cohort retained request-byte capacity is exhausted; "
                    "commit, cancel, or prune an unclaimed preparation before retrying"
                )
            conflicts = {
                owner
                for key in static_keys
                if (owner := self._action_cohort_reserved_keys.get(key)) is not None
            }
            if conflicts and all(
                (active := self._action_cohort_reservations.get(preparation_id)) is not None
                and active.canonical_token.request == public_request
                for preparation_id in conflicts
            ):
                raise LifecycleActionCohortInProgressError(
                    "Exact lifecycle action cohort is already in progress"
                )
            self._reject_closed_transport_reservation_conflict_locked(static_keys)
            preparation_id = self._next_action_cohort_preparation_id
            expected_watermark = self._watermark
            plan_digest = sha256(request_preimage).hexdigest()
            token = LifecycleActionCohortAdmissionToken(
                request=public_request,
                registry_id=self._action_cohort_registry_id,
                preparation_id=preparation_id,
                expected_watermark=expected_watermark,
                plan_digest=plan_digest,
                _integrity=self._action_cohort_token_integrity(
                    preparation_id=preparation_id,
                    expected_watermark=expected_watermark,
                    plan_digest=plan_digest,
                ),
            )
            canonical_token = LifecycleActionCohortAdmissionToken(
                request=public_request,
                registry_id=token.registry_id,
                preparation_id=token.preparation_id,
                expected_watermark=token.expected_watermark,
                plan_digest=token.plan_digest,
                _integrity=token._integrity,
            )
            with self._routes.locked(route_keys):
                partition_ids = self._action_cohort_partition_ids_locked(public_request)
                with self._locked_partition_ids(partition_ids):
                    plan = self._prepare_action_cohort_commit_locked(
                        canonical_token,
                        partition_ids=partition_ids,
                    )
            reservation_keys = plan.reservation_keys
            self._reject_closed_transport_reservation_conflict_locked(reservation_keys)
            if (
                len(self._action_cohort_reserved_keys) + len(reservation_keys)
                > self._action_cohort_reserved_key_capacity
            ):
                raise StateError(
                    "Lifecycle action-cohort reserved-key capacity is exhausted; commit, "
                    "cancel, or prune an unclaimed preparation before retrying"
                )
            provenance_new, provenance_eviction, retry_receipt = (
                self._reserve_action_cohort_provenance_locked(plan)
            )
            provenance_binding = (
                public_request.state_publication_token,
                plan_digest,
            )
            self._next_action_cohort_preparation_id += 1
            reservation = _ActionCohortReservation(
                token_ref=ref(token),
                token_id=id(token),
                canonical_token=canonical_token,
                keys=reservation_keys,
                partition_ids=partition_ids,
                request_bytes=request_bytes,
                provenance_binding=provenance_binding,
                operations_digest=plan.operations_digest,
                provenance_new=provenance_new,
                provenance_eviction=provenance_eviction,
                retry_receipt=retry_receipt,
            )
            self._action_cohort_reservations[preparation_id] = reservation
            self._action_cohort_capability_locators[id(token)] = preparation_id
            self._action_cohort_retained_request_bytes += request_bytes
            for key in reservation_keys:
                self._action_cohort_reserved_keys[key] = preparation_id
            return token

    def prune_action_cohort_preparations(self) -> int:
        """Release stale or ownerless unclaimed action-cohort preparations."""

        with self._gate.mutation(), self._closed_transport_preparation_lock:
            return self._prune_action_cohort_reservations_locked()

    def cancel_action_cohort(self, token: LifecycleActionCohortAdmissionToken) -> None:
        """Cancel one unclaimed action-cohort reservation with zero canonical rows."""

        with self._gate.mutation(), self._closed_transport_preparation_lock:
            reservation = self._active_action_cohort_reservation_locked(token)
            if reservation.committing:
                raise StateError("Committing lifecycle action cohort cannot be cancelled")
            if reservation.claimed:
                raise StateError("Claimed lifecycle action cohort cannot cancel directly")
            self._release_action_cohort_reservation_locked(reservation)

    def authenticates_action_cohort_admission_token(
        self,
        token: object,
        *,
        request: LifecycleActionCohortRequest | None = None,
        state_publication_token: str | None = None,
    ) -> bool:
        """Totally authenticate one active cohort admission without consuming it."""

        if type(token) is not LifecycleActionCohortAdmissionToken:
            return False
        if request is not None and type(request) is not LifecycleActionCohortRequest:
            return False
        if state_publication_token is not None and type(state_publication_token) is not str:
            return False
        try:
            normalized_request = (
                None if request is None else self._normalize_action_cohort_request(request)
            )
        except (AttributeError, RecursionError, TypeError, ValueError):
            return False
        with self._closed_transport_preparation_lock:
            try:
                reservation = self._active_action_cohort_reservation_locked(token)
                canonical_request = reservation.canonical_token.request
                if normalized_request is not None and canonical_request != normalized_request:
                    return False
                return (
                    state_publication_token is None
                    or canonical_request.state_publication_token == state_publication_token
                )
            except (
                AssertionError,
                AttributeError,
                RecursionError,
                StateError,
                TypeError,
                ValueError,
            ):
                return False

    def action_cohort_preparation_census(
        self,
    ) -> LifecycleActionCohortPreparationCensus:
        """Return transient action-cohort capability counts in constant time."""

        with self._closed_transport_preparation_lock:
            reservations = len(self._action_cohort_reservations)
            return LifecycleActionCohortPreparationCensus(
                reservations=reservations,
                unclaimed_reservations=(reservations - self._action_cohort_claimed_reservations),
                claimed_reservations=self._action_cohort_claimed_reservations,
                committing_reservations=self._action_cohort_committing_reservations,
                reserved_keys=len(self._action_cohort_reserved_keys),
                capability_locators=len(self._action_cohort_capability_locators),
                claimed_capability_locators=len(self._action_cohort_claimed_capabilities),
                certified_authorization_locators=len(self._action_cohort_certified_authorizations),
                expected_receipt_authorities=(self._action_cohort_expected_receipt_authorities),
                committed_receipt_authorities=(self._action_cohort_committed_receipt_authorities),
                retained_request_bytes=self._action_cohort_retained_request_bytes,
                committed_provenance=len(self._action_cohort_committed_provenance),
                pending_provenance_insertions=(self._action_cohort_pending_provenance_insertions),
                pending_provenance_evictions=len(self._action_cohort_pending_provenance_evictions),
                operation_capacity_per_request=self._action_cohort_operation_capacity,
                reservation_capacity=self._action_cohort_reservation_capacity,
                reserved_key_capacity=self._action_cohort_reserved_key_capacity,
                request_byte_capacity=self._action_cohort_request_byte_capacity,
                committed_provenance_capacity=self._action_cohort_provenance_capacity,
                receipt_authority_capacity=self._action_cohort_receipt_authority_capacity,
            )

    def _prune_action_cohort_receipt_authorities_locked(self) -> int:
        """Drop dead committed receipt locators without traversing receipt values."""

        pruned = 0
        for receipt_id, authority in tuple(self._action_cohort_receipt_authorities.items()):
            if not authority.committed or authority.receipt_ref() is not None:
                continue
            if self._action_cohort_receipt_authorities.pop(receipt_id, None) is authority:
                self._action_cohort_committed_receipt_authorities -= 1
                pruned += 1
        return pruned

    def prune_action_cohort_receipt_authorities(self) -> int:
        """Prune dead exact committed-receipt authorities within their finite cap."""

        with self._closed_transport_preparation_lock:
            return self._prune_action_cohort_receipt_authorities_locked()

    def _register_action_cohort_expected_receipt_authority_locked(
        self,
        receipt: LifecycleActionCohortReceipt,
        reservation: _ActionCohortReservation,
    ) -> None:
        """Pre-register one exact expected receipt before exposing its claim."""

        self._prune_action_cohort_receipt_authorities_locked()
        receipt_id = id(receipt)
        prior = self._action_cohort_receipt_authorities.get(receipt_id)
        if prior is not None:
            raise StateError("Lifecycle action-cohort receipt authority identity is already in use")
        while (
            len(self._action_cohort_receipt_authorities)
            >= self._action_cohort_receipt_authority_capacity
        ):
            eviction_id = next(
                (
                    candidate_id
                    for candidate_id, candidate in self._action_cohort_receipt_authorities.items()
                    if candidate.committed
                ),
                None,
            )
            if eviction_id is None:
                raise StateError(
                    "Lifecycle action-cohort receipt authority capacity is exhausted by "
                    "active claims"
                )
            self._action_cohort_receipt_authorities.pop(eviction_id)
            self._action_cohort_committed_receipt_authorities -= 1
        self._action_cohort_receipt_authorities[receipt_id] = _ActionCohortReceiptAuthority(
            receipt_ref=ref(receipt),
            preparation_id=reservation.canonical_token.preparation_id,
            plan_digest=reservation.canonical_token.plan_digest,
            state_publication_token=(reservation.canonical_token.request.state_publication_token),
            request_id=id(receipt.request),
            results_id=id(receipt.operation_results),
            committed_digest=receipt.committed_digest,
            integrity=receipt._integrity,
        )
        self._action_cohort_expected_receipt_authorities += 1
        reservation.receipt_authority_id = receipt_id

    def _register_claimed_action_cohort_capability_locked(
        self,
        capability: PreparedLifecycleActionCohort,
        reservation: _ActionCohortReservation,
    ) -> None:
        """Bind one exact yielded wrapper to its registry-owned claimed reservation."""

        capability_id = id(capability)
        preparation_id = reservation.canonical_token.preparation_id
        if (
            self._action_cohort_reservations.get(preparation_id) is not reservation
            or not reservation.claimed
            or reservation.claim_exhausted
            or reservation.claim_thread_id != get_ident()
            or reservation.claimed_capability_id is not None
            or capability_id in self._action_cohort_claimed_capabilities
        ):
            raise StateError(
                "Lifecycle action-cohort claim cannot register its exact prepared capability"
            )
        self._action_cohort_claimed_capabilities[capability_id] = (
            _ActionCohortClaimedCapabilityLocator(
                capability_ref=ref(capability),
                reservation=reservation,
            )
        )
        reservation.claimed_capability_id = capability_id

    def _claimed_action_cohort_reservation_for_capability_locked(
        self,
        capability: PreparedLifecycleActionCohort,
    ) -> _ActionCohortReservation:
        """Resolve one active claim by exact registry-owned wrapper identity."""

        capability_id = id(capability)
        locator = self._action_cohort_claimed_capabilities.get(capability_id)
        if locator is None:
            raise StateError(
                "Lifecycle action cohort is not the exact registered prepared capability"
            )
        reservation = locator.reservation
        preparation_id = reservation.canonical_token.preparation_id
        if (
            locator.capability_ref() is not capability
            or reservation.claimed_capability_id != capability_id
            or self._action_cohort_reservations.get(preparation_id) is not reservation
            or not reservation.claimed
            or reservation.claim_exhausted
            or reservation.claim_thread_id != get_ident()
        ):
            raise StateError(
                "Lifecycle action cohort is not the exact registered prepared capability"
            )
        return reservation

    @contextmanager
    def claimed_action_cohort(
        self,
        token: LifecycleActionCohortAdmissionToken,
    ) -> Iterator[PreparedLifecycleActionCohort]:
        """Short-claim one token, then yield without retaining registry locks."""

        with self._gate.mutation(), self._closed_transport_preparation_lock:
            reservation = self._active_action_cohort_reservation_locked(token)
            canonical_token = reservation.canonical_token
            if reservation.claimed:
                raise StateError("Lifecycle action-cohort token is already claimed")
            if self._watermark != canonical_token.expected_watermark:
                primary = StateError(
                    "Lifecycle action-cohort admission is stale after watermark advance"
                )
                _cleanup_required, cleanup_failures = (
                    self._cleanup_action_cohort_reservation_locked(reservation)
                )
                self._add_action_cohort_cleanup_notes(primary, cleanup_failures)
                raise primary
            route_keys = self._action_cohort_route_keys(canonical_token.request)
            try:
                with self._routes.locked(route_keys):
                    partition_ids = self._action_cohort_partition_ids_locked(
                        canonical_token.request
                    )
                    if partition_ids != reservation.partition_ids:
                        raise StateError("Lifecycle action-cohort partition ownership changed")
                    with self._locked_partition_ids(partition_ids):
                        commit_plan = self._prepare_action_cohort_commit_locked(
                            canonical_token,
                            partition_ids=partition_ids,
                        )
                        self._prepare_action_cohort_expected_receipts_locked(commit_plan)
                if commit_plan.reservation_keys != reservation.keys:
                    raise StateError("Lifecycle action-cohort relationship ownership changed")
                if (
                    commit_plan.operations_digest != reservation.operations_digest
                    or reservation.provenance_new == commit_plan.already_present
                    or commit_plan.retry_receipt is not reservation.retry_receipt
                ):
                    raise StateError("Lifecycle action-cohort provenance changed before claim")
                validated_token = self._validate_action_cohort_token(token)
                if not self._action_cohort_token_matches_canonical(
                    validated_token,
                    canonical_token,
                ):
                    raise StateError("Lifecycle action-cohort token was mutated after preparation")
            except BaseException as primary:
                _cleanup_required, cleanup_failures = (
                    self._cleanup_action_cohort_reservation_locked(reservation)
                )
                self._add_action_cohort_cleanup_notes(primary, cleanup_failures)
                raise
            reservation.commit_plan = commit_plan
            reservation.claimed = True
            claim_thread_id = get_ident()
            reservation.claim_thread_id = claim_thread_id
            self._action_cohort_claimed_reservations += 1

        expected_receipt = commit_plan.expected_receipt
        if expected_receipt is None:
            primary = StateError("Claimed lifecycle action cohort lost its expected receipt")
            _cleanup_required, cleanup_failures = self._cleanup_claimed_action_cohort_reservation(
                reservation
            )
            self._add_action_cohort_cleanup_notes(primary, cleanup_failures)
            raise primary
        capability = PreparedLifecycleActionCohort(
            self,
            token,
            expected_receipt,
            claim_thread_id=claim_thread_id,
        )
        try:
            with self._gate.mutation(), self._closed_transport_preparation_lock:
                self._register_action_cohort_expected_receipt_authority_locked(
                    expected_receipt,
                    reservation,
                )
                self._register_claimed_action_cohort_capability_locked(
                    capability,
                    reservation,
                )
        except BaseException as primary:
            _cleanup_required, cleanup_failures = self._cleanup_claimed_action_cohort_reservation(
                reservation
            )
            self._add_action_cohort_cleanup_notes(primary, cleanup_failures)
            reservation.claim_exhausted = True
            object.__setattr__(capability, "_active", False)
            raise
        try:
            yield capability
        except BaseException as primary:
            _cleanup_required, cleanup_failures = self._cleanup_claimed_action_cohort_reservation(
                reservation
            )
            self._add_action_cohort_cleanup_notes(primary, cleanup_failures)
            raise
        else:
            cleanup_required, cleanup_failures = self._cleanup_claimed_action_cohort_reservation(
                reservation
            )
            if cleanup_required:
                primary = StateError(
                    "Claimed lifecycle action cohort exited without commit_no_fail"
                )
                self._add_action_cohort_cleanup_notes(primary, cleanup_failures)
                raise primary
        finally:
            reservation.claim_exhausted = True
            object.__setattr__(capability, "_active", False)

    def _cancel_claimed_action_cohort(
        self,
        token: LifecycleActionCohortAdmissionToken,
    ) -> None:
        """Release one claimed cohort after its enclosing composite aborts."""

        with self._gate.mutation(), self._closed_transport_preparation_lock:
            reservation = self._active_action_cohort_reservation_locked(token)
            if not reservation.claimed:
                raise StateError("Lifecycle action-cohort token is not claimed")
            if reservation.committing:
                raise StateError("Committing lifecycle action cohort cannot be cancelled")
            self._release_action_cohort_reservation_locked(reservation)

    @classmethod
    def _normalize_action_cohort_process_snapshot(
        cls,
        value: object,
    ) -> ProcessLifecycleSnapshot:
        if type(value) is not ProcessLifecycleSnapshot:
            raise TypeError("Lifecycle action cohort process result must be an exact snapshot")
        if type(value.transitions) is not tuple or type(value.holds) is not tuple:
            raise TypeError("Lifecycle action cohort process result collections must be tuples")
        close_barrier = (
            None
            if value.close_barrier is None
            else cls._normalize_action_cohort_barrier(value.close_barrier)
        )
        closure_ticket = (
            None
            if value.closure_ticket is None
            else cls._normalize_action_cohort_ticket(value.closure_ticket)
        )
        closed_at = cls._action_cohort_exact_datetime(
            value.closed_at,
            field_name="process result close time",
            allow_none=True,
        )
        latest_dependent_at = cls._action_cohort_exact_datetime(
            value.latest_dependent_at,
            field_name="process result latest dependent time",
            allow_none=True,
        )
        latest_hold_until = cls._action_cohort_exact_datetime(
            value.latest_hold_until,
            field_name="process result latest hold time",
            allow_none=True,
        )
        counts = tuple(
            cls._action_cohort_exact_int(item, field_name=label)
            for item, label in (
                (value.transition_count, "process result transition count"),
                (
                    value.compacted_transition_count,
                    "process result compacted transition count",
                ),
                (value.hold_count, "process result hold count"),
                (value.compacted_hold_count, "process result compacted hold count"),
            )
        )
        assert all(item is not None for item in counts)
        return ProcessLifecycleSnapshot(
            identity=cls._normalize_action_cohort_process_identity(value.identity),
            token=cls._normalize_action_cohort_process_token(value.token),
            membership=cls._normalize_action_cohort_membership(value.membership),
            transitions=tuple(
                cls._normalize_action_cohort_transition(item) for item in value.transitions
            ),
            holds=tuple(cls._normalize_action_cohort_hold(item) for item in value.holds),
            close_barrier=close_barrier,
            closure_ticket=closure_ticket,
            closed_at=closed_at,
            transition_count=counts[0],  # type: ignore[arg-type]
            compacted_transition_count=counts[1],  # type: ignore[arg-type]
            transition_ledger_digest=cls._action_cohort_exact_text(
                value.transition_ledger_digest,
                field_name="process result transition ledger digest",
            ),
            hold_count=counts[2],  # type: ignore[arg-type]
            compacted_hold_count=counts[3],  # type: ignore[arg-type]
            hold_ledger_digest=cls._action_cohort_exact_text(
                value.hold_ledger_digest,
                field_name="process result hold ledger digest",
            ),
            latest_dependent_at=latest_dependent_at,
            latest_hold_until=latest_hold_until,
        )

    @classmethod
    def _normalize_action_cohort_session_snapshot(
        cls,
        value: object,
    ) -> SessionLifecycleSnapshot:
        if type(value) is not SessionLifecycleSnapshot:
            raise TypeError("Lifecycle action cohort session result must be an exact snapshot")
        if type(value.transitions) is not tuple or type(value.holds) is not tuple:
            raise TypeError("Lifecycle action cohort session result collections must be tuples")
        close_barrier = (
            None
            if value.close_barrier is None
            else cls._normalize_action_cohort_barrier(value.close_barrier)
        )
        closure_ticket = (
            None
            if value.closure_ticket is None
            else cls._normalize_action_cohort_ticket(value.closure_ticket)
        )
        closed_at = cls._action_cohort_exact_datetime(
            value.closed_at,
            field_name="session result close time",
            allow_none=True,
        )
        latest_dependent_at = cls._action_cohort_exact_datetime(
            value.latest_dependent_at,
            field_name="session result latest dependent time",
            allow_none=True,
        )
        latest_hold_until = cls._action_cohort_exact_datetime(
            value.latest_hold_until,
            field_name="session result latest hold time",
            allow_none=True,
        )
        counts = tuple(
            cls._action_cohort_exact_int(item, field_name=label)
            for item, label in (
                (value.transition_count, "session result transition count"),
                (
                    value.compacted_transition_count,
                    "session result compacted transition count",
                ),
                (value.hold_count, "session result hold count"),
                (value.compacted_hold_count, "session result compacted hold count"),
            )
        )
        assert all(item is not None for item in counts)
        return SessionLifecycleSnapshot(
            identity=cls._normalize_action_cohort_session_identity(value.identity),
            transitions=tuple(
                cls._normalize_action_cohort_transition(item) for item in value.transitions
            ),
            holds=tuple(cls._normalize_action_cohort_hold(item) for item in value.holds),
            close_barrier=close_barrier,
            closure_ticket=closure_ticket,
            closed_at=closed_at,
            transition_count=counts[0],  # type: ignore[arg-type]
            compacted_transition_count=counts[1],  # type: ignore[arg-type]
            transition_ledger_digest=cls._action_cohort_exact_text(
                value.transition_ledger_digest,
                field_name="session result transition ledger digest",
            ),
            hold_count=counts[2],  # type: ignore[arg-type]
            compacted_hold_count=counts[3],  # type: ignore[arg-type]
            hold_ledger_digest=cls._action_cohort_exact_text(
                value.hold_ledger_digest,
                field_name="session result hold ledger digest",
            ),
            latest_dependent_at=latest_dependent_at,
            latest_hold_until=latest_hold_until,
        )

    @classmethod
    def _normalize_action_cohort_results(
        cls,
        request: LifecycleActionCohortRequest,
        results: object,
    ) -> tuple[LifecycleActionCohortOperationResult, ...]:
        if type(results) is not tuple or len(results) != len(request.operations):
            raise TypeError(
                "Lifecycle action cohort results must be an exact operation-aligned tuple"
            )
        normalized: list[LifecycleActionCohortOperationResult] = []
        for operation, result in zip(request.operations, results, strict=True):
            if type(operation) is LifecycleSessionStartRequest:
                normalized.append(cls._normalize_action_cohort_session_snapshot(result))
            elif type(operation) is LifecycleProcessStartRequest:
                normalized.append(cls._normalize_action_cohort_process_snapshot(result))
            elif type(operation) is LifecycleTransition:
                normalized.append(cls._normalize_action_cohort_transition(result))
            elif type(operation) is LifecycleHold:
                normalized.append(cls._normalize_action_cohort_hold(result))
            elif operation.barrier.subject.kind == "process":
                normalized.append(cls._normalize_action_cohort_process_snapshot(result))
            else:
                normalized.append(cls._normalize_action_cohort_session_snapshot(result))
        return tuple(normalized)

    @staticmethod
    def _action_cohort_result_matches_operation(
        operation: LifecycleActionCohortOperation,
        result: object,
    ) -> bool:
        if type(operation) is LifecycleSessionStartRequest:
            return type(result) is SessionLifecycleSnapshot and (
                result.identity == operation.identity
            )
        if type(operation) is LifecycleProcessStartRequest:
            return (
                type(result) is ProcessLifecycleSnapshot and result.identity == operation.identity
            )
        if type(operation) is LifecycleTransition:
            return type(result) is LifecycleTransition and result == operation
        if type(operation) is LifecycleHold:
            return type(result) is LifecycleHold and result == operation
        assert type(operation) is LifecycleSubjectClosureControl
        if operation.barrier.subject.kind == "process":
            if type(result) is not ProcessLifecycleSnapshot:
                return False
        elif type(result) is not SessionLifecycleSnapshot:
            return False
        return (
            result.identity.ref == operation.barrier.subject
            and result.close_barrier == operation.barrier
            and result.closure_ticket is not None
            and result.closure_ticket.ticket_id == operation.ticket_id
            and result.closed_at == result.closure_ticket.effective_at
        )

    @classmethod
    def _action_cohort_results_match_request(
        cls,
        request: LifecycleActionCohortRequest,
        results: tuple[LifecycleActionCohortOperationResult, ...],
    ) -> bool:
        return len(request.operations) == len(results) and all(
            cls._action_cohort_result_matches_operation(operation, result)
            for operation, result in zip(request.operations, results, strict=True)
        )

    @staticmethod
    def _action_cohort_committed_digest(
        request_preimage: bytes,
        results: tuple[LifecycleActionCohortOperationResult, ...],
    ) -> str:
        return sha256(
            request_preimage + b"\0lifecycle-action-cohort-results\0" + str(len(results)).encode()
        ).hexdigest()

    def _action_cohort_expected_transition_snapshot(
        self,
        snapshot: ProcessLifecycleSnapshot | SessionLifecycleSnapshot,
        transition: LifecycleTransition,
    ) -> ProcessLifecycleSnapshot | SessionLifecycleSnapshot:
        """Project one already-admitted transition into an immutable result snapshot."""

        transitions = sorted(
            (*snapshot.transitions, transition),
            key=lambda item: item.order_key,
        )
        if len(transitions) > self._snapshot_history_limit:
            transitions = transitions[-self._snapshot_history_limit :]
        visible = tuple(
            item
            for item in transitions
            if self._ledger_floor is None or item.canonical_time > self._ledger_floor
        )
        transition_count = snapshot.transition_count + 1
        transition_digest = int(snapshot.transition_ledger_digest or "0", 16)
        transition_digest ^= _transition_digest_value(transition)
        latest_dependent_at = snapshot.latest_dependent_at
        if transition.kind in _STREAMED_TRANSITION_KINDS and (
            latest_dependent_at is None or transition.canonical_time > latest_dependent_at
        ):
            latest_dependent_at = transition.canonical_time
        return replace(
            snapshot,
            transitions=visible,
            transition_count=transition_count,
            compacted_transition_count=transition_count - len(visible),
            transition_ledger_digest=f"{transition_digest:064x}",
            latest_dependent_at=latest_dependent_at,
        )

    def _action_cohort_expected_hold_snapshot(
        self,
        snapshot: ProcessLifecycleSnapshot | SessionLifecycleSnapshot,
        hold: LifecycleHold,
    ) -> ProcessLifecycleSnapshot | SessionLifecycleSnapshot:
        """Project one already-admitted hold into an immutable result snapshot."""

        holds = sorted(
            (*snapshot.holds, hold),
            key=lambda item: (
                item.acquired_at,
                item.action_id,
                item.transition_ordinal,
                item.hold_id,
            ),
        )
        if len(holds) > self._snapshot_history_limit:
            holds = holds[-self._snapshot_history_limit :]
        visible = tuple(
            item
            for item in holds
            if self._ledger_floor is None or item.acquired_at > self._ledger_floor
        )
        hold_count = snapshot.hold_count + 1
        hold_digest = int(snapshot.hold_ledger_digest or "0", 16)
        hold_digest ^= _LifecyclePartition._hold_digest(hold)
        latest_hold_until = snapshot.latest_hold_until
        if latest_hold_until is None or hold.hold_until > latest_hold_until:
            latest_hold_until = hold.hold_until
        projected = replace(
            snapshot,
            holds=visible,
            hold_count=hold_count,
            compacted_hold_count=hold_count - len(visible),
            hold_ledger_digest=f"{hold_digest:064x}",
            latest_hold_until=latest_hold_until,
        )
        transition = LifecycleTransition(
            transition_id=f"{hold.hold_id}:acquired",
            subject=hold.subject,
            kind="hold_acquired",
            canonical_time=hold.acquired_at,
            action_id=hold.action_id,
            reason=hold.reason,
            transition_ordinal=hold.transition_ordinal,
        )
        return self._action_cohort_expected_transition_snapshot(projected, transition)

    @staticmethod
    def _action_cohort_exact_session_snapshot(
        snapshot: SessionLifecycleSnapshotView,
    ) -> SessionLifecycleSnapshot:
        """Materialize one internal packed session view as an exact public snapshot."""

        if type(snapshot) is SessionLifecycleSnapshot:
            return snapshot
        if type(snapshot) is _PackedSessionSnapshot:
            return snapshot._materialized()
        raise StateError("Lifecycle action cohort resolved an incompatible session snapshot")

    def _action_cohort_expected_results_locked(
        self,
        plan: _PreparedActionCohortCommitPlan,
    ) -> tuple[LifecycleActionCohortOperationResult, ...]:
        """Build exact final results from the claim-time simulated operation state."""

        snapshots: dict[
            LifecycleEntityRef,
            ProcessLifecycleSnapshot | SessionLifecycleSnapshot,
        ] = {}

        def snapshot_for(
            prepared: _PreparedActionCohortOperation,
        ) -> ProcessLifecycleSnapshot | SessionLifecycleSnapshot:
            operation = prepared.operation
            subject = self._action_cohort_operation_subject(operation)
            snapshot = snapshots.get(subject)
            if snapshot is not None:
                return snapshot
            partition = self._partitions[prepared.partition_id]
            if subject.kind == "process":
                process = partition.get_process(subject.object_id)
                if process is None:
                    raise StateError(
                        "Lifecycle action cohort lost a process during receipt projection"
                    )
                snapshot = process
            else:
                session = partition.get_session(subject.object_id)
                if session is None:
                    raise StateError(
                        "Lifecycle action cohort lost a session during receipt projection"
                    )
                snapshot = self._action_cohort_exact_session_snapshot(session)
            snapshots[subject] = snapshot
            return snapshot

        for prepared in plan.operations:
            operation = prepared.operation
            subject = self._action_cohort_operation_subject(operation)
            if type(operation) is LifecycleSessionStartRequest:
                session_start = prepared.session_start
                if session_start is None:
                    raise StateError("Lifecycle action cohort lost a prepared session start")
                snapshots[subject] = self._action_cohort_exact_session_snapshot(
                    session_start.snapshot
                )
                continue
            if type(operation) is LifecycleProcessStartRequest:
                process_start = prepared.process_start
                if process_start is None:
                    raise StateError("Lifecycle action cohort lost a prepared process start")
                snapshots[subject] = process_start.snapshot
                continue

            snapshot = snapshot_for(prepared)
            if type(operation) is LifecycleTransition:
                snapshots[subject] = self._action_cohort_expected_transition_snapshot(
                    snapshot,
                    operation,
                )
                continue
            if type(operation) is LifecycleHold:
                snapshots[subject] = self._action_cohort_expected_hold_snapshot(
                    snapshot,
                    operation,
                )
                continue

            ticket = prepared.closure_ticket
            closure_transitions = prepared.closure_transitions
            if ticket is None or closure_transitions is None:
                raise StateError("Lifecycle action cohort lost prepared closure results")
            requested, scheduled, closed = closure_transitions
            projected = replace(
                snapshot,
                close_barrier=operation.barrier,
                closure_ticket=ticket,
                closed_at=ticket.effective_at,
            )
            for transition in (requested, scheduled, closed):
                projected = self._action_cohort_expected_transition_snapshot(
                    projected,
                    transition,
                )
            snapshots[subject] = projected

        raw_results: list[LifecycleActionCohortOperationResult] = []
        for prepared in plan.operations:
            operation = prepared.operation
            if type(operation) in {LifecycleTransition, LifecycleHold}:
                raw_results.append(operation)
            else:
                raw_results.append(snapshots[self._action_cohort_operation_subject(operation)])
        return self._normalize_action_cohort_results(
            plan.token.request,
            tuple(raw_results),
        )

    def _prepare_action_cohort_expected_receipts_locked(
        self,
        plan: _PreparedActionCohortCommitPlan,
    ) -> None:
        """Freeze caller and private provenance receipts before any canonical primitive."""

        request = plan.token.request
        if plan.already_present:
            if plan.retry_receipt is None:
                raise StateError("Exact lifecycle action-cohort retry lost its retained receipt")
            expected_receipt = deepcopy(plan.retry_receipt)
            terminal_receipt_template = deepcopy(plan.retry_receipt)
            provenance_receipt = None
        else:
            results = self._action_cohort_expected_results_locked(plan)
            committed_digest = self._action_cohort_committed_digest(
                plan.receipt_request_preimage,
                results,
            )
            canonical_receipt = LifecycleActionCohortReceipt(
                request=request,
                operation_results=results,
                registry_id=self._action_cohort_registry_id,
                plan_digest=plan.token.plan_digest,
                committed_digest=committed_digest,
                _integrity=self._action_cohort_receipt_integrity(
                    plan_digest=plan.token.plan_digest,
                    committed_digest=committed_digest,
                ),
            )
            expected_receipt = deepcopy(canonical_receipt)
            terminal_receipt_template = deepcopy(canonical_receipt)
            provenance_receipt = deepcopy(canonical_receipt)
        if not self._authenticates_action_cohort_receipt_contents(
            expected_receipt,
            request=request,
            state_publication_token=request.state_publication_token,
        ):
            raise StateError("Lifecycle action-cohort expected receipt failed authentication")
        if not self._authenticates_action_cohort_receipt_contents(
            terminal_receipt_template,
            request=request,
            state_publication_token=request.state_publication_token,
        ):
            raise StateError(
                "Lifecycle action-cohort terminal receipt template failed authentication"
            )
        if (
            provenance_receipt is not None
            and not self._authenticates_action_cohort_receipt_contents(
                provenance_receipt,
                request=request,
                state_publication_token=request.state_publication_token,
            )
        ):
            raise StateError("Lifecycle action-cohort provenance receipt failed authentication")
        plan.expected_receipt = expected_receipt
        plan.terminal_receipt_template = terminal_receipt_template
        plan.provenance_receipt = provenance_receipt
        plan.provenance_record = (
            None
            if provenance_receipt is None
            else _CommittedActionCohortProvenance(
                binding=(request.state_publication_token, plan.token.plan_digest),
                operations_digest=plan.operations_digest,
                receipt=provenance_receipt,
            )
        )

    def _authenticates_action_cohort_receipt_contents(
        self,
        receipt: object,
        *,
        request: LifecycleActionCohortRequest | None = None,
        state_publication_token: str | None = None,
    ) -> bool:
        """Validate the lightweight shape of an internally issued receipt."""

        if type(receipt) is not LifecycleActionCohortReceipt:
            return False
        if state_publication_token is not None and type(state_publication_token) is not str:
            return False
        if receipt.registry_id != self._action_cohort_registry_id:
            return False
        if request is not None and receipt.request is not request and receipt.request != request:
            return False
        return (
            state_publication_token is None
            or receipt.request.state_publication_token == state_publication_token
        )

    def authenticates_expected_action_cohort_receipt(
        self,
        receipt: object,
        *,
        state_publication_token: str | None = None,
    ) -> bool:
        """Authenticate one exact active claim receipt without traversing caller graphs."""

        if type(receipt) is not LifecycleActionCohortReceipt:
            return False
        if state_publication_token is not None and type(state_publication_token) is not str:
            return False
        try:
            registry_id = receipt.registry_id
            plan_digest = receipt.plan_digest
            receipt_request = receipt.request
            operation_results = receipt.operation_results
            committed_digest = receipt.committed_digest
            integrity = receipt._integrity
        except (AttributeError, TypeError):
            return False
        if (
            type(registry_id) is not str
            or type(plan_digest) is not str
            or type(receipt_request) is not LifecycleActionCohortRequest
            or type(operation_results) is not tuple
            or type(committed_digest) is not str
            or type(integrity) is not str
        ):
            return False
        with self._closed_transport_preparation_lock:
            authority = self._action_cohort_receipt_authorities.get(id(receipt))
            if (
                authority is None
                or authority.receipt_ref() is not receipt
                or authority.committed
                or authority.preparation_id not in self._action_cohort_reservations
            ):
                return False
            reservation = self._action_cohort_reservations[authority.preparation_id]
            commit_plan = reservation.commit_plan
            if (
                reservation.receipt_authority_id != id(receipt)
                or not reservation.claimed
                or reservation.claim_exhausted
                or reservation.committing
                or reservation.claim_thread_id != get_ident()
                or commit_plan is None
                or commit_plan.expected_receipt is not receipt
                or authority.plan_digest != reservation.canonical_token.plan_digest
                or registry_id != self._action_cohort_registry_id
                or plan_digest != authority.plan_digest
                or id(receipt_request) != authority.request_id
                or id(operation_results) != authority.results_id
                or committed_digest != authority.committed_digest
                or integrity != authority.integrity
            ):
                return False
            return bool(
                state_publication_token is None
                or state_publication_token == authority.state_publication_token
            )

    def authenticates_action_cohort_receipt(
        self,
        receipt: object,
        *,
        request: LifecycleActionCohortRequest | None = None,
        state_publication_token: str | None = None,
    ) -> bool:
        """Authenticate one exact committed receipt under bounded owner authority."""

        if type(receipt) is not LifecycleActionCohortReceipt:
            return False
        with self._closed_transport_preparation_lock:
            authority = self._action_cohort_receipt_authorities.get(id(receipt))
            if (
                authority is None
                or authority.receipt_ref() is not receipt
                or not authority.committed
            ):
                return False
            return self._authenticates_action_cohort_receipt_contents(
                receipt,
                request=request,
                state_publication_token=state_publication_token,
            )

    def _authorize_action_cohort_commit_locked(
        self,
        capability: PreparedLifecycleActionCohort,
        token: LifecycleActionCohortAdmissionToken,
        *,
        expected_receipt: LifecycleActionCohortReceipt,
        for_composite: bool,
    ) -> _ActionCohortCommitAuthorization:
        """Complete every fallible commit check before a trusted primitive tail."""

        claimed_reservation = self._claimed_action_cohort_reservation_for_capability_locked(
            capability
        )
        if for_composite:
            reservation = claimed_reservation
        else:
            reservation = self._active_action_cohort_reservation_locked(token)
            if reservation is not claimed_reservation:
                raise StateError(
                    "Lifecycle action-cohort token does not belong to its exact prepared capability"
                )
        canonical_token = reservation.canonical_token
        commit_plan = reservation.commit_plan
        if not reservation.claimed or commit_plan is None:
            raise StateError("Lifecycle action-cohort token is not claimed")
        if reservation.claim_thread_id != get_ident():
            raise StateError("Lifecycle action cohort must commit on its claiming thread")
        if reservation.committing:
            raise StateError("Lifecycle action cohort is already committing")
        if reservation.composite_certified:
            raise StateError("Lifecycle action cohort is already composite-certified")
        if not for_composite and self._watermark != canonical_token.expected_watermark:
            raise StateError("Lifecycle action-cohort admission is stale after watermark advance")
        if expected_receipt is not commit_plan.expected_receipt:
            raise StateError("Lifecycle action-cohort expected receipt changed before commit")
        if (
            commit_plan.token is not canonical_token
            or commit_plan.partition_ids != reservation.partition_ids
            or commit_plan.reservation_keys != reservation.keys
            or commit_plan.operations_digest != reservation.operations_digest
        ):
            raise StateError("Lifecycle action-cohort claimed commit plan changed before commit")
        if not self.authenticates_expected_action_cohort_receipt(expected_receipt):
            raise StateError("Lifecycle action-cohort expected receipt failed authentication")
        if not for_composite:
            request = canonical_token.request
            if not self._authenticates_action_cohort_receipt_contents(
                expected_receipt,
                request=request,
                state_publication_token=request.state_publication_token,
            ):
                raise StateError("Lifecycle action-cohort expected receipt failed authentication")

        receipt_authority = self._action_cohort_receipt_authorities.get(id(expected_receipt))
        if (
            receipt_authority is None
            or receipt_authority.receipt_ref() is not expected_receipt
            or receipt_authority.committed
            or reservation.receipt_authority_id != id(expected_receipt)
        ):
            raise StateError("Lifecycle action-cohort expected receipt authority is not active")

        provenance = commit_plan.provenance_record
        if reservation.provenance_new:
            provenance_receipt = commit_plan.provenance_receipt
            if (
                provenance is None
                or provenance_receipt is None
                or provenance.binding != reservation.provenance_binding
                or provenance.operations_digest != reservation.operations_digest
                or provenance.receipt is not provenance_receipt
            ):
                raise StateError("Lifecycle action-cohort provenance changed before commit")
        elif provenance is not None or commit_plan.provenance_receipt is not None:
            raise StateError("Lifecycle action-cohort retry retained unexpected provenance")

        authorization = _ActionCohortCommitAuthorization(
            reservation=reservation,
            commit_plan=commit_plan,
            expected_receipt=expected_receipt,
            receipt_authority=receipt_authority,
            provenance_record=provenance,
        )
        if for_composite:
            reservation.composite_certified = True
        return authorization

    def _certify_claimed_action_cohort(
        self,
        capability: PreparedLifecycleActionCohort,
        token: LifecycleActionCohortAdmissionToken,
        *,
        expected_receipt: LifecycleActionCohortReceipt,
    ) -> None:
        """Authenticate and retain one exact capability's composite authorization."""

        with self._gate.mutation(), self._closed_transport_preparation_lock:
            authorization = self._authorize_action_cohort_commit_locked(
                capability,
                token,
                expected_receipt=expected_receipt,
                for_composite=True,
            )
            capability_id = id(capability)
            reservation = authorization.reservation
            if (
                reservation.certified_capability_id is not None
                or capability_id in self._action_cohort_certified_authorizations
            ):
                reservation.composite_certified = False
                raise StateError("Prepared lifecycle action cohort is already composite-certified")
            self._action_cohort_certified_authorizations[capability_id] = (
                _ActionCohortCertifiedAuthorizationLocator(
                    capability_ref=ref(capability),
                    authorization=authorization,
                )
            )
            reservation.certified_capability_id = capability_id

    def _consume_certified_action_cohort_locked(
        self,
        capability: PreparedLifecycleActionCohort,
    ) -> _ActionCohortCommitAuthorization | None:
        """Consume one registry-owned authorization by exact capability identity."""

        claimed_reservation = self._claimed_action_cohort_reservation_for_capability_locked(
            capability
        )
        capability_id = id(capability)
        locator = self._action_cohort_certified_authorizations.get(capability_id)
        if locator is None:
            return None
        authorization = locator.authorization
        reservation = authorization.reservation
        commit_plan = authorization.commit_plan
        if (
            locator.capability_ref() is not capability
            or reservation is not claimed_reservation
            or reservation.certified_capability_id != capability_id
            or not reservation.composite_certified
            or reservation.claim_thread_id != get_ident()
            or reservation.committing
            or reservation.commit_plan is not commit_plan
            or commit_plan.expected_receipt is not authorization.expected_receipt
            or reservation.receipt_authority_id != id(authorization.expected_receipt)
            or self._action_cohort_receipt_authorities.get(id(authorization.expected_receipt))
            is not authorization.receipt_authority
            or authorization.receipt_authority.committed
        ):
            raise StateError(
                "Lifecycle action-cohort certified authorization no longer matches its exact "
                "prepared capability"
            )
        self._action_cohort_certified_authorizations.pop(capability_id)
        reservation.certified_capability_id = None
        return authorization

    def _commit_action_cohort_closure_locked(
        self,
        prepared: _PreparedActionCohortOperation,
    ) -> None:
        """Publish one prebuilt process/session barrier, ticket, and close."""

        operation = prepared.operation
        assert type(operation) is LifecycleSubjectClosureControl
        effective_at = prepared.effective_at
        ticket = prepared.closure_ticket
        transitions = prepared.closure_transitions
        assert effective_at is not None and ticket is not None and transitions is not None

        partition = self._partitions[prepared.partition_id]
        subject = operation.barrier.subject
        entry = partition._entry(subject)
        assert entry is not None
        state = partition._ensure_full_state(entry)
        state.close_barrier = operation.barrier
        state.closure_ticket = ticket
        partition._barriers[operation.barrier.barrier_id] = operation.barrier
        partition._tickets[ticket.ticket_id] = ticket
        requested, scheduled, closed = transitions
        partition._append_transition(entry, requested, claim_validated=True)
        partition._append_transition(entry, scheduled, claim_validated=True)
        state.closed_at = effective_at
        partition._append_transition(entry, closed, claim_validated=True)
        if subject.kind == "process":
            assert isinstance(entry, _ProcessEntry)
            partition._record_process_closed(entry, effective_at)
            partition._live_processes -= 1
        else:
            assert subject.kind == "session"
            partition._live_sessions -= 1
        partition._schedule_retention(subject, entry)

        self._routes.invalidate_subject_snapshot_locked(operation.barrier.subject)
        self._routes.set_locked("barrier", operation.barrier.barrier_id, operation.barrier)
        self._routes.set_locked("ticket", operation.ticket_id, ticket)
        for transition in transitions:
            self._routes.set_locked("transition", transition.transition_id, transition)
        self._promote_session_route_locked(
            operation.barrier.subject,
            prepared.partition_id,
        )

    def _commit_action_cohort_primitives_locked(
        self,
        plan: _PreparedActionCohortCommitPlan,
    ) -> None:
        """Apply only primitive writes covered by the claimed cohort admission."""

        if plan.already_present:
            return

        for prepared in plan.operations:
            operation = prepared.operation
            partition = self._partitions[prepared.partition_id]
            if type(operation) is LifecycleSessionStartRequest:
                registration = prepared.session_registration
                assert registration is not None
                registration.commit()
            elif type(operation) is LifecycleProcessStartRequest:
                registration = prepared.process_registration
                assert registration is not None
                registration.commit()
            elif type(operation) is LifecycleTransition:
                self._routes.invalidate_subject_snapshot_locked(operation.subject)
                entry = partition._entry(operation.subject)
                assert entry is not None
                partition._append_transition(
                    entry,
                    operation,
                    claim_validated=True,
                )
                self._routes.set_locked("transition", operation.transition_id, operation)
                self._promote_session_route_locked(
                    operation.subject,
                    prepared.partition_id,
                )
            elif type(operation) is LifecycleHold:
                transition = prepared.hold_transition
                assert transition is not None
                self._routes.invalidate_subject_snapshot_locked(operation.subject)
                entry = partition._entry(operation.subject)
                assert entry is not None
                partition._append_hold(entry, operation)
                partition._append_transition(entry, transition, claim_validated=True)
                self._routes.set_locked("hold", operation.hold_id, operation)
                self._routes.set_locked("transition", transition.transition_id, transition)
                self._promote_session_route_locked(
                    operation.subject,
                    prepared.partition_id,
                )
            else:
                self._commit_action_cohort_closure_locked(prepared)

    def _begin_authorized_action_cohort_commit_locked(
        self,
        authorization: _ActionCohortCommitAuthorization,
    ) -> None:
        """Mark one already-authorized reservation as committing without revalidation."""

        self._restore_action_cohort_terminal_receipt_locked(authorization)
        authorization.reservation.committing = True
        self._action_cohort_committing_reservations += 1

    @staticmethod
    def _restore_action_cohort_terminal_receipt_locked(
        authorization: _ActionCohortCommitAuthorization,
    ) -> None:
        """Restore the exact exposed object from a claim-private closed template."""

        template = authorization.commit_plan.terminal_receipt_template
        if template is None:
            raise StateError("Lifecycle action-cohort terminal receipt template is unavailable")
        receipt = authorization.expected_receipt
        object.__setattr__(receipt, "request", template.request)
        object.__setattr__(receipt, "operation_results", template.operation_results)
        object.__setattr__(receipt, "registry_id", template.registry_id)
        object.__setattr__(receipt, "plan_digest", template.plan_digest)
        object.__setattr__(receipt, "committed_digest", template.committed_digest)
        object.__setattr__(receipt, "_integrity", template._integrity)
        receipt_authority = authorization.receipt_authority
        receipt_authority.request_id = id(template.request)
        receipt_authority.results_id = id(template.operation_results)
        receipt_authority.plan_digest = template.plan_digest
        receipt_authority.state_publication_token = template.request.state_publication_token
        receipt_authority.committed_digest = template.committed_digest
        receipt_authority.integrity = template._integrity

    def _commit_action_cohort_receipt_authority_locked(
        self,
        authorization: _ActionCohortCommitAuthorization,
    ) -> None:
        """Flip one prevalidated exact receipt authority without caller traversal."""

        authorization.receipt_authority.committed = True
        self._action_cohort_expected_receipt_authorities -= 1
        self._action_cohort_committed_receipt_authorities += 1
        authorization.reservation.receipt_authority_id = None

    def _publish_authorized_action_cohort(
        self,
        authorization: _ActionCohortCommitAuthorization,
    ) -> LifecycleActionCohortReceipt:
        """Apply trusted canonical primitives and consume their retained reservation."""

        reservation = authorization.reservation
        commit_plan = authorization.commit_plan
        with self._routes.locked(commit_plan.route_keys):
            with self._locked_partition_ids(reservation.partition_ids):
                self._commit_action_cohort_primitives_locked(commit_plan)
        with self._closed_transport_preparation_lock:
            provenance = authorization.provenance_record
            if provenance is not None:
                self._record_action_cohort_provenance_locked(reservation, provenance)
            self._commit_action_cohort_receipt_authority_locked(authorization)
            self._release_action_cohort_reservation_locked(
                reservation,
                allow_committing=True,
            )
        return authorization.expected_receipt

    def _commit_claimed_action_cohort(
        self,
        capability: PreparedLifecycleActionCohort,
        token: LifecycleActionCohortAdmissionToken,
        *,
        expected_receipt: LifecycleActionCohortReceipt,
    ) -> LifecycleActionCohortReceipt:
        """Fully validate and commit one standalone claimed cohort exactly once."""

        with self._gate.mutation():
            with self._closed_transport_preparation_lock:
                authorization = self._authorize_action_cohort_commit_locked(
                    capability,
                    token,
                    expected_receipt=expected_receipt,
                    for_composite=False,
                )
                self._begin_authorized_action_cohort_commit_locked(authorization)
            return self._publish_authorized_action_cohort(authorization)

    def _commit_prepared_action_cohort(
        self,
        capability: PreparedLifecycleActionCohort,
        *,
        token: LifecycleActionCohortAdmissionToken,
        expected_receipt: LifecycleActionCohortReceipt,
    ) -> LifecycleActionCohortReceipt:
        """Commit an exact prepared capability through its registry-owned authorization."""

        with self._gate.mutation():
            with self._closed_transport_preparation_lock:
                authorization = self._consume_certified_action_cohort_locked(capability)
                if authorization is None:
                    authorization = self._authorize_action_cohort_commit_locked(
                        capability,
                        token,
                        expected_receipt=expected_receipt,
                        for_composite=False,
                    )
                self._begin_authorized_action_cohort_commit_locked(authorization)
            return self._publish_authorized_action_cohort(authorization)

    def _commit_certified_action_cohort(
        self,
        capability: PreparedLifecycleActionCohort,
    ) -> LifecycleActionCohortReceipt:
        """Commit only a registry-located exact composite-certified capability."""

        with self._gate.mutation():
            with self._closed_transport_preparation_lock:
                authorization = self._consume_certified_action_cohort_locked(capability)
                if authorization is None:
                    raise StateError(
                        "Lifecycle action-cohort certified authorization is not registered for "
                        "this exact prepared capability"
                    )
                self._begin_authorized_action_cohort_commit_locked(authorization)
            return self._publish_authorized_action_cohort(authorization)

    def prepare_closed_transport_publication(
        self,
        request: LifecycleClosedTransportPublicationRequest,
    ) -> LifecycleClosedTransportAdmissionToken:
        """Validate and reserve one all-or-none closed transport without rows."""

        if type(request) is not LifecycleClosedTransportPublicationRequest:
            raise TypeError("Closed-transport publication requires its exact frozen request")
        # Production adapters construct this recursively frozen request and transfer it
        # directly into the one-shot registry capability. Rebuilding the full dataclass
        # graph adds no isolation at this trusted ownership boundary.
        public_request = request
        reservation_keys = self._closed_transport_reservation_keys(public_request)
        route_keys = self._closed_transport_route_keys(public_request)
        with self._gate.mutation(), self._closed_transport_preparation_lock:
            conflicting_ids = {
                owner
                for key in reservation_keys
                if (owner := self._closed_transport_reserved_keys.get(key)) is not None
            }
            if conflicting_ids and all(
                (active := self._closed_transport_reservations.get(preparation_id)) is not None
                and active.canonical_token.request == public_request
                for preparation_id in conflicting_ids
            ):
                raise LifecycleClosedTransportPublicationInProgressError(
                    "Exact closed-transport publication is already in progress"
                )
            self._reject_closed_transport_reservation_conflict_locked(reservation_keys)
            preparation_id = self._next_closed_transport_preparation_id
            expected_watermark = self._watermark
            plan_digest = self._closed_transport_plan_digest(public_request)
            token = LifecycleClosedTransportAdmissionToken(
                request=public_request,
                registry_id=self._closed_transport_registry_id,
                preparation_id=preparation_id,
                expected_watermark=expected_watermark,
                plan_digest=plan_digest,
                _integrity=self._closed_transport_token_integrity(
                    preparation_id=preparation_id,
                    expected_watermark=expected_watermark,
                    plan_digest=plan_digest,
                ),
            )
            canonical_token = token
            with self._routes.locked(route_keys):
                partition_ids = self._closed_transport_partition_ids_locked(public_request)
                with self._locked_partition_ids(partition_ids):
                    self._prepare_closed_transport_commit_locked(canonical_token)
            self._next_closed_transport_preparation_id += 1
            reservation = _ClosedTransportReservation(
                token=token,
                canonical_token=canonical_token,
                keys=reservation_keys,
            )
            self._closed_transport_reservations[preparation_id] = reservation
            self._closed_transport_capability_locators[id(token)] = preparation_id
            for key in reservation_keys:
                self._closed_transport_reserved_keys[key] = preparation_id
            return token

    def wait_for_closed_transport_publication(
        self,
        request: LifecycleClosedTransportPublicationRequest,
    ) -> None:
        """Wait for an exact compatibility publication without retaining registry locks."""

        with self._closed_transport_preparation_condition:
            while any(
                reservation.canonical_token.request == request
                for reservation in self._closed_transport_reservations.values()
            ):
                self._closed_transport_preparation_condition.wait()

    def cancel_closed_transport_publication(
        self,
        token: LifecycleClosedTransportAdmissionToken,
    ) -> None:
        """Cancel one unclaimed reservation with zero canonical lifecycle rows."""

        with self._gate.mutation(), self._closed_transport_preparation_lock:
            reservation = self._active_closed_transport_reservation_locked(token)
            if reservation.claimed:
                raise StateError("Claimed closed-transport publication cannot cancel directly")
            self._release_closed_transport_reservation_locked(reservation)

    def authenticates_closed_transport_admission_token(
        self,
        token: object,
        *,
        request: LifecycleClosedTransportPublicationRequest | None = None,
        start_plan_tokens: tuple[str, ...] = (),
    ) -> bool:
        """Authenticate one admission proof without claiming or consuming it."""

        if not isinstance(token, LifecycleClosedTransportAdmissionToken):
            return False
        with self._closed_transport_preparation_lock:
            try:
                reservation = self._active_closed_transport_reservation_locked(token)
            except StateError:
                return False
            canonical_request = reservation.canonical_token.request
            if request is not None and canonical_request != request:
                return False
            return not start_plan_tokens or canonical_request.start_plan_tokens == start_plan_tokens

    def closed_transport_preparation_census(
        self,
    ) -> LifecycleClosedTransportPreparationCensus:
        """Return transient capability counts without scanning lifecycle rows."""

        with self._closed_transport_preparation_lock:
            return LifecycleClosedTransportPreparationCensus(
                reservations=len(self._closed_transport_reservations),
                claimed_reservations=self._closed_transport_claimed_reservations,
                reserved_keys=len(self._closed_transport_reserved_keys),
                capability_locators=len(self._closed_transport_capability_locators),
            )

    @contextmanager
    def claimed_closed_transport_publication(
        self,
        token: LifecycleClosedTransportAdmissionToken,
    ) -> Iterator[PreparedLifecycleClosedTransportPublication]:
        """Short-claim a token, then yield without retaining registry locks."""

        with self._gate.mutation(), self._closed_transport_preparation_lock:
            reservation = self._active_closed_transport_reservation_locked(token)
            canonical_token = reservation.canonical_token
            canonical_request = canonical_token.request
            if reservation.claimed:
                raise StateError("Closed-transport admission token is already claimed")
            if self._watermark != canonical_token.expected_watermark:
                raise StateError("Closed-transport admission is stale after watermark advance")
            route_keys = self._closed_transport_route_keys(canonical_request)
            try:
                with self._routes.locked(route_keys):
                    partition_ids = self._closed_transport_partition_ids_locked(canonical_request)
                    with self._locked_partition_ids(partition_ids):
                        reservation.commit_plan = self._prepare_closed_transport_commit_locked(
                            canonical_token
                        )
                self._validate_closed_transport_token_against_canonical(
                    token,
                    canonical_token,
                )
            except BaseException:
                self._release_closed_transport_reservation_locked(reservation)
                raise
            reservation.claimed = True
            reservation.claim_thread_id = get_ident()
            self._closed_transport_claimed_reservations += 1

        capability = PreparedLifecycleClosedTransportPublication(self, token)
        try:
            yield capability
        except BaseException:
            if not capability.committed:
                self._discard_closed_transport_reservation_for_token(token)
            raise
        else:
            if not capability.committed:
                self._discard_closed_transport_reservation_for_token(token)
                raise StateError(
                    "Claimed closed-transport publication exited without commit_no_fail"
                )
        finally:
            capability._close()

    def _cancel_claimed_closed_transport_publication(
        self,
        token: LifecycleClosedTransportAdmissionToken,
    ) -> None:
        """Release one claimed token after its enclosing composite aborts."""

        with self._gate.mutation(), self._closed_transport_preparation_lock:
            reservation = self._active_closed_transport_reservation_locked(token)
            if not reservation.claimed:
                raise StateError("Closed-transport admission token is not claimed")
            self._release_closed_transport_reservation_locked(reservation)

    def authenticates_closed_transport_publication_receipt(
        self,
        receipt: object,
        *,
        request: LifecycleClosedTransportPublicationRequest | None = None,
        start_plan_tokens: tuple[str, ...] = (),
    ) -> bool:
        """Recognize one exact owner-issued committed receipt."""

        if not isinstance(receipt, LifecycleClosedTransportPublicationReceipt):
            return False
        with self._closed_transport_preparation_lock:
            if self._closed_transport_receipts.get(id(receipt)) is not receipt:
                return False
            if (
                request is not None
                and receipt.request is not request
                and receipt.request != request
            ):
                return False
            return not start_plan_tokens or receipt.start_plan_tokens == start_plan_tokens

    @staticmethod
    def _closed_transport_committed_digest(
        request: LifecycleClosedTransportPublicationRequest,
        transport: TransportLifecycleSnapshot,
        binding: TransportSessionBindingSnapshot | None,
        session_snapshots: tuple[SessionLifecycleSnapshotView, ...],
        process_snapshots: tuple[ProcessLifecycleSnapshot, ...],
        process_holds: tuple[LifecycleHold, ...],
    ) -> str:
        del binding, session_snapshots, process_snapshots, process_holds
        return sha256(
            f"closed-transport-committed:{request.identity.object_id}:{transport.closed_at}".encode()
        ).hexdigest()

    def _prepare_closed_transport_starts_locked(
        self,
        request: LifecycleClosedTransportPublicationRequest,
    ) -> tuple[
        tuple[tuple[int, _PreparedSessionPartitionStart, object | None], ...],
        tuple[tuple[int, _PreparedProcessPartitionStart, LifecycleMembership], ...],
    ]:
        """Validate the complete external session/process batch without rows."""

        session_requests = tuple(
            member.request
            for member in request.start_members
            if isinstance(member.request, LifecycleSessionStartRequest)
        )
        process_requests = tuple(
            member.request
            for member in request.start_members
            if isinstance(member.request, LifecycleProcessStartRequest)
        )
        session_groups = [
            (item.identity.hostname, item.identity.logon_id) for item in session_requests
        ]
        process_groups = [(item.identity.hostname, item.identity.pid) for item in process_requests]
        transition_ids = [item.transition_id for item in (*session_requests, *process_requests)]
        if len(set(session_groups)) != len(session_groups):
            raise StateError("Closed-transport batch contains overlapping session LogonIDs")
        if len(set(process_groups)) != len(process_groups):
            raise StateError("Closed-transport batch contains overlapping process PIDs")
        if len(set(transition_ids)) != len(transition_ids):
            raise StateError("Closed-transport batch contains a duplicate transition ID")

        staged_sessions = {item.identity.object_id: item.identity for item in session_requests}
        staged_processes = {item.identity.object_id: item.identity for item in process_requests}
        prepared_sessions: list[tuple[int, _PreparedSessionPartitionStart, object | None]] = []
        for item in session_requests:
            identity = item.identity
            transition = LifecycleTransition(
                transition_id=item.transition_id,
                subject=identity.ref,
                kind="started",
                canonical_time=identity.started_at,
                action_id=item.action_id,
                transition_ordinal=item.transition_ordinal,
            )
            partition_id = self._partition_id(identity.hostname)
            prior_session = self._routes.get_locked("session", identity.object_id)
            prior_partition = self._session_partition_from_route(prior_session)
            if prior_partition is not None and prior_partition != partition_id:
                raise StateError(
                    f"Session lifecycle object {identity.object_id} is already registered"
                )
            if isinstance(prior_session, bytes):
                if _decode_session_row(prior_session).object_id != identity.object_id:
                    raise StateError("Lifecycle session route semantic hash collision")
            elif isinstance(prior_session, int):
                routed_partition, handle = self._decode_session_locator(prior_session)
                prior_snapshot = self._partitions[routed_partition].get_session_by_handle(handle)
                if (
                    prior_snapshot is None
                    or prior_snapshot.identity.object_id != identity.object_id
                ):
                    raise StateError("Lifecycle session route semantic hash collision")
            prior_transition = self._routes.get_locked("transition", item.transition_id)
            if (
                prior_transition is not None
                and self._transition_from_route(prior_transition, item.transition_id) != transition
            ):
                self._reject_exact_conflict("transition", item.transition_id)
            prepared = self._partitions[partition_id]._prepare_session_registration_locked(
                identity,
                transition=transition,
            )
            prepared_sessions.append((partition_id, prepared, prior_session))

        prepared_processes: list[
            tuple[int, _PreparedProcessPartitionStart, LifecycleMembership]
        ] = []
        admitted_processes: set[str] = set()
        for item in process_requests:
            identity = item.identity
            parent_id = identity.parent_object_id
            if parent_id and parent_id in staged_processes and parent_id not in admitted_processes:
                raise StateError(
                    f"Closed-transport staged process parent {parent_id} must precede child"
                )
            transition = LifecycleTransition(
                transition_id=item.transition_id,
                subject=identity.ref,
                kind="started",
                canonical_time=identity.started_at,
                action_id=item.action_id,
                transition_ordinal=item.transition_ordinal,
            )
            partition_id = self._partition_id(identity.hostname)
            prior_process = self._routes.get_locked("process", identity.object_id)
            if prior_process is not None and prior_process != partition_id:
                raise StateError(
                    f"Process lifecycle object {identity.object_id} is already registered"
                )
            prior_transition = self._routes.get_locked("transition", item.transition_id)
            if (
                prior_transition is not None
                and self._transition_from_route(prior_transition, item.transition_id) != transition
            ):
                self._reject_exact_conflict("transition", item.transition_id)
            if parent_id and parent_id not in staged_processes:
                parent_partition = self._routes.get_locked("process", parent_id)
                if parent_partition != partition_id:
                    if parent_partition is None:
                        raise StateError(f"Unknown parent process lifecycle object {parent_id}")
                    raise StateError(
                        f"Process lifecycle {identity.object_id} cannot use a cross-host parent"
                    )
            session_id = item.membership.session_object_id
            if session_id and session_id not in staged_sessions:
                session_route = self._routes.get_locked("session", session_id)
                session_partition = self._session_partition_from_route(session_route)
                if session_partition != partition_id:
                    if session_partition is None:
                        raise StateError(f"Unknown session lifecycle object {session_id}")
                    raise StateError(
                        f"Process lifecycle {identity.object_id} cannot use cross-host "
                        "session membership"
                    )
            prepared = self._partitions[partition_id]._prepare_process_registration_locked(
                identity,
                token=item.token,
                membership=item.membership,
                transition=transition,
                staged_sessions=staged_sessions,
                staged_processes=staged_processes,
            )
            prepared_processes.append((partition_id, prepared, item.membership))
            admitted_processes.add(identity.object_id)
        return tuple(prepared_sessions), tuple(prepared_processes)

    def _prepare_closed_transport_entity_locked(
        self,
        request: LifecycleClosedTransportPublicationRequest,
    ) -> tuple[int, _PreparedTransportPartitionStart, object | None]:
        """Validate exact object/ID/UID/tuple ownership without publication."""

        identity = request.identity
        transition = LifecycleTransition(
            transition_id=request.start_transition_id,
            subject=identity.ref,
            kind="started",
            canonical_time=identity.opened_at,
            action_id=request.start_action_id,
            transition_ordinal=request.start_transition_ordinal,
        )
        partition_id = self._partition_id(identity.hostname)
        prior_transport = self._routes.get_locked("transport", identity.object_id)
        if prior_transport is not None:
            if not isinstance(prior_transport, int):
                self._reject_exact_conflict("transport", identity.object_id)
            prior_partition, prior_handle = self._decode_session_locator(prior_transport)
            prior_snapshot = self._partitions[prior_partition].get_transport_by_handle(prior_handle)
            if (
                prior_partition != partition_id
                or prior_snapshot is None
                or prior_snapshot.identity != identity
            ):
                raise StateError(
                    f"Transport lifecycle object {identity.object_id} has immutable identity drift"
                )
        for kind, semantic_id in (
            ("transport_id", identity.transport_id),
            ("transport_uid", identity.zeek_uid),
        ):
            prior_locator = self._routes.get_locked(kind, semantic_id)
            if prior_locator is None:
                continue
            if not isinstance(prior_locator, int):
                self._reject_exact_conflict(kind, semantic_id)
            prior_partition, prior_handle = self._decode_session_locator(prior_locator)
            prior_snapshot = self._partitions[prior_partition].get_transport_by_handle(prior_handle)
            if prior_snapshot is None or prior_snapshot.identity != identity:
                self._reject_exact_conflict(kind, semantic_id)
        prior_transition = self._routes.get_locked("transition", request.start_transition_id)
        if (
            prior_transition is not None
            and self._transition_from_route(prior_transition, request.start_transition_id)
            != transition
        ):
            self._reject_exact_conflict("transition", request.start_transition_id)
        prepared = self._partitions[partition_id]._prepare_transport_registration_locked(
            identity,
            transition=transition,
        )
        return partition_id, prepared, prior_transport

    def _prepare_closed_transport_holds_locked(
        self,
        request: LifecycleClosedTransportPublicationRequest,
        processes: tuple[tuple[int, _PreparedProcessPartitionStart, LifecycleMembership], ...],
    ) -> tuple[tuple[int, LifecycleHold, bool], ...]:
        """Validate exact process holds against existing or staged process authority."""

        staged = {
            prepared.entry.identity.object_id: (partition_id, prepared)
            for partition_id, prepared, _membership in processes
        }
        commit_keys: set[tuple[str, str, int]] = set()
        prepared_holds: list[tuple[int, LifecycleHold, bool]] = []
        for hold in request.process_holds:
            commit_key = (
                hold.subject.object_id,
                hold.action_id,
                hold.transition_ordinal,
            )
            if commit_key in commit_keys:
                raise StateError("Closed-transport process holds repeat an action commit identity")
            commit_keys.add(commit_key)
            transition = LifecycleTransition(
                transition_id=f"{hold.hold_id}:acquired",
                subject=hold.subject,
                kind="hold_acquired",
                canonical_time=hold.acquired_at,
                action_id=hold.action_id,
                reason=hold.reason,
                transition_ordinal=hold.transition_ordinal,
            )
            prior_hold = self._routes.get_locked("hold", hold.hold_id)
            prior_transition = self._routes.get_locked("transition", transition.transition_id)
            if prior_hold is not None:
                if (
                    prior_hold == hold
                    and self._transition_from_route(
                        prior_transition,
                        transition.transition_id,
                    )
                    == transition
                ):
                    prior_partition = self._routes.get_locked(
                        "process",
                        hold.subject.object_id,
                    )
                    if not isinstance(prior_partition, int):
                        raise StateError("Retained process hold lost its exact subject route")
                    prepared_holds.append((prior_partition, hold, True))
                    continue
                self._reject_exact_conflict("hold", hold.hold_id)
            if prior_transition is not None:
                if (
                    self._transition_from_route(prior_transition, transition.transition_id)
                    != transition
                ):
                    self._reject_exact_conflict("transition", transition.transition_id)
                raise StateError(
                    f"Lifecycle transition {transition.transition_id} is already registered"
                )

            staged_process = staged.get(hold.subject.object_id)
            if staged_process is not None:
                partition_id, prepared_process = staged_process
                identity = prepared_process.entry.identity
                if hold.acquired_at < identity.started_at:
                    raise StateError("Lifecycle hold acquisition precedes staged process start")
                if prepared_process.existing is not None:
                    entry = prepared_process.existing
                    if entry.closed_at is not None:
                        raise StateError("Cannot add a hold to a closed process lifecycle")
                    if entry.close_barrier is not None:
                        raise StateError("Cannot add a hold after a process close barrier")
                    self._partitions[partition_id]._validate_dependent_time(
                        entry,
                        hold.acquired_at,
                    )
            else:
                prior_partition = self._routes.get_locked(
                    "process",
                    hold.subject.object_id,
                )
                if not isinstance(prior_partition, int):
                    raise StateError(f"Unknown process lifecycle object {hold.subject.object_id}")
                partition_id = prior_partition
                entry = self._partitions[partition_id]._processes.get(hold.subject.object_id)
                if entry is None:
                    raise StateError(f"Unknown process lifecycle object {hold.subject.object_id}")
                if entry.closed_at is not None:
                    raise StateError("Cannot add a hold to a closed process lifecycle")
                if entry.close_barrier is not None:
                    raise StateError("Cannot add a hold after a process close barrier")
                self._partitions[partition_id]._validate_dependent_time(
                    entry,
                    hold.acquired_at,
                )
            partition = self._partitions[partition_id]
            partition._reject_behind_watermark(hold.acquired_at, "hold acquisition")
            partition._validate_transition_claim(transition)
            prepared_holds.append((partition_id, hold, False))
        return tuple(prepared_holds)

    def _expected_closed_transport_control(
        self,
        request: LifecycleClosedTransportPublicationRequest,
    ) -> tuple[
        LifecycleClosureTicket,
        LifecycleTransition,
        LifecycleTransition,
        LifecycleTransition,
    ]:
        barrier = request.barrier
        ticket = LifecycleClosureTicket(
            ticket_id=request.ticket_id,
            barrier_id=barrier.barrier_id,
            subject=barrier.subject,
            requested_at=barrier.requested_at,
            effective_at=request.identity.close_deadline,
            authority=barrier.authority,
            action_id=barrier.action_id,
        )
        requested = LifecycleTransition(
            transition_id=f"{barrier.barrier_id}:requested",
            subject=barrier.subject,
            kind="close_requested",
            canonical_time=barrier.requested_at,
            action_id=barrier.action_id,
            transition_ordinal=0,
        )
        scheduled = LifecycleTransition(
            transition_id=f"{ticket.ticket_id}:scheduled",
            subject=barrier.subject,
            kind="close_scheduled",
            canonical_time=ticket.effective_at,
            action_id=barrier.action_id,
            transition_ordinal=1,
        )
        closed = LifecycleTransition(
            transition_id=f"{ticket.ticket_id}:closed",
            subject=barrier.subject,
            kind="closed",
            canonical_time=ticket.effective_at,
            action_id=barrier.action_id,
            transition_ordinal=2,
        )
        return ticket, requested, scheduled, closed

    def _validate_closed_transport_control_locked(
        self,
        request: LifecycleClosedTransportPublicationRequest,
        prepared: _PreparedTransportPartitionStart,
        binding: TransportSessionBindingSnapshot | None,
    ) -> bool:
        """Validate barrier/ticket/terminal writes and return terminal idempotence."""

        ticket, requested, scheduled, closed = self._expected_closed_transport_control(request)
        partition = self._partitions[self._partition_id(request.identity.hostname)]
        entry = prepared.existing
        if entry is not None and entry.closed_at is not None:
            if (
                entry.identity == request.identity
                and entry.closed_at == request.identity.close_deadline
                and entry.close_barrier == request.barrier
                and entry.closure_ticket == ticket
                and partition._entry_has_transition(entry, closed)
                and (
                    request.binding_identity is None
                    or (
                        binding is not None
                        and binding.identity == request.binding_identity
                        and binding.closed_at == request.identity.close_deadline
                        and binding.close_action_id == request.binding_close_action_id
                        and binding.close_transition_ordinal
                        == request.binding_close_transition_ordinal
                    )
                )
            ):
                return True
            raise StateError("Transport lifecycle retry disagrees with its terminal close")
        if entry is not None:
            if entry.close_barrier is not None and entry.close_barrier != request.barrier:
                raise StateError("Transport lifecycle already accepted a different close barrier")
            if entry.closure_ticket is not None and entry.closure_ticket != ticket:
                raise StateError("Transport lifecycle already resolved a different close ticket")
            latest = entry.state.latest_dependent_at
            if latest is not None and latest >= request.identity.close_deadline:
                raise StateError("Transport close barrier precedes an existing dependent")
            latest_hold = entry.state.latest_hold_until
            if latest_hold is not None and latest_hold > request.identity.close_deadline:
                raise StateError("Transport lifecycle hold extends beyond canonical close")
            active_after_close = entry.active_binding_count
            if binding is not None and binding.closed_at is None:
                active_after_close -= 1
            if active_after_close:
                raise StateError("Transport lifecycle has another active session binding")
        for kind, semantic_id, expected in (
            ("barrier", request.barrier.barrier_id, request.barrier),
            ("ticket", request.ticket_id, ticket),
            ("transition", requested.transition_id, requested),
            ("transition", scheduled.transition_id, scheduled),
            ("transition", closed.transition_id, closed),
        ):
            prior = self._routes.get_locked(kind, semantic_id)
            actual = (
                self._transition_from_route(prior, semantic_id) if kind == "transition" else prior
            )
            if actual is not None and actual != expected:
                self._reject_exact_conflict(kind, semantic_id)
        return False

    def _prepare_closed_transport_binding_locked(
        self,
        request: LifecycleClosedTransportPublicationRequest,
        sessions: tuple[tuple[int, _PreparedSessionPartitionStart, object | None], ...],
        transport_partition_id: int,
        transport: _PreparedTransportPartitionStart,
    ) -> tuple[TransportSessionBindingSnapshot | None, int | None]:
        """Validate the optional cross-host binding and its terminal relation."""

        identity = request.binding_identity
        if identity is None:
            return None, None
        staged_sessions = {
            prepared.identity.object_id: (partition_id, prepared)
            for partition_id, prepared, _route in sessions
        }
        staged = staged_sessions.get(identity.session_object_id)
        if staged is None:
            session_route = self._routes.get_locked("session", identity.session_object_id)
            session_partition_id = self._session_partition_from_route(session_route)
            if session_partition_id is None:
                raise StateError(
                    f"Unknown target session lifecycle object {identity.session_object_id}"
                )
        else:
            session_partition_id, prepared_session = staged
            session_identity = prepared_session.identity
            if session_identity.object_id != identity.session_object_id:
                raise StateError("Transport binding target differs from staged session")

        prior_route = self._routes.get_locked(
            "transport_session_binding",
            identity.binding_id,
        )
        if prior_route is not None and prior_route != transport_partition_id:
            self._reject_exact_conflict("transport_session_binding", identity.binding_id)
        transport_partition = self._partitions[transport_partition_id]
        current = transport_partition.transport_session_binding(identity.binding_id)
        if current is not None:
            if current.identity != identity:
                self._reject_exact_conflict("transport_session_binding", identity.binding_id)
            if current.closed_at is not None:
                if (
                    current.closed_at != request.identity.close_deadline
                    or current.close_action_id != request.binding_close_action_id
                    or current.close_transition_ordinal != request.binding_close_transition_ordinal
                ):
                    raise StateError(
                        f"Transport/session binding {identity.binding_id} is already closed"
                    )
                return current, session_partition_id

        if staged is None:
            self._partitions[session_partition_id]._validate_session_transport_binding_locked(
                identity
            )
        else:
            _session_partition_id, prepared_session = staged
            if identity.bound_at < prepared_session.identity.started_at:
                raise StateError("Transport/session binding precedes the staged session")
            if prepared_session.existing is not None:
                self._partitions[session_partition_id]._validate_session_transport_binding_locked(
                    identity
                )

        if current is not None:
            transport_partition._validate_transport_session_binding_close_locked(
                identity,
                request.identity.close_deadline,
            )
            self._partitions[session_partition_id]._validate_session_transport_binding_close_locked(
                identity
            )
            return current, session_partition_id

        if prior_route is not None:
            self._reject_exact_conflict("transport_session_binding", identity.binding_id)
        if transport.existing is not None:
            transport_partition._validate_transport_session_binding_locked(identity)
        else:
            if identity.bound_at < request.identity.opened_at:
                raise StateError("Transport/session binding precedes the staged transport")
            if identity.bound_at >= request.identity.close_deadline:
                raise StateError(
                    "Transport/session binding must start before transport close deadline"
                )
        return None, session_partition_id

    def _prepare_closed_transport_commit_locked(
        self,
        token: LifecycleClosedTransportAdmissionToken,
    ) -> _PreparedClosedTransportCommitPlan:
        """Validate every expected row while route and sorted partition locks are held."""

        request = token.request
        sessions, processes = self._prepare_closed_transport_starts_locked(request)
        process_holds = self._prepare_closed_transport_holds_locked(request, processes)
        transport_partition_id, transport, prior_transport_route = (
            self._prepare_closed_transport_entity_locked(request)
        )
        binding, session_partition_id = self._prepare_closed_transport_binding_locked(
            request,
            sessions,
            transport_partition_id,
            transport,
        )
        already_terminal = self._validate_closed_transport_control_locked(
            request,
            transport,
            binding,
        )
        if already_terminal and any(
            prepared.existing is None for _partition_id, prepared, _route in sessions
        ):
            raise StateError("Terminal transport retry cannot introduce a new staged session")
        if already_terminal and any(
            prepared.existing is None for _partition_id, prepared, _membership in processes
        ):
            raise StateError("Terminal transport retry cannot introduce new staged processes")
        if already_terminal and any(
            not already_present for _partition_id, _hold, already_present in process_holds
        ):
            raise StateError("Terminal transport retry cannot introduce new process holds")
        if already_terminal and request.binding_identity is not None:
            if binding is None or binding.closed_at != request.identity.close_deadline:
                raise StateError(
                    "Terminal transport retry requires its exact closed session binding"
                )
        return _PreparedClosedTransportCommitPlan(
            token=token,
            sessions=sessions,
            processes=processes,
            process_holds=process_holds,
            transport_partition_id=transport_partition_id,
            transport=transport,
            prior_transport_route=prior_transport_route,
            binding=binding,
            session_partition_id=session_partition_id,
            already_terminal=already_terminal,
        )

    def _commit_closed_transport_primitives_locked(
        self,
        plan: _PreparedClosedTransportCommitPlan,
    ) -> LifecycleClosedTransportPublicationReceipt:
        """Apply only writes already validated by the claimed admission."""

        request = plan.token.request
        session_results: list[SessionLifecycleSnapshotView] = []
        for partition_id, prepared, prior_route in plan.sessions:
            ticket = PreparedSessionRegistration(
                _registry=self,
                _partition_id=partition_id,
                _prepared=prepared,
                _prior_session_route=prior_route,
            )
            session_results.append(ticket.commit())
        process_results: list[ProcessLifecycleSnapshot] = []
        for partition_id, prepared, membership in plan.processes:
            ticket = PreparedProcessRegistration(
                _registry=self,
                _partition_id=partition_id,
                _prepared=prepared,
                _membership=membership,
            )
            process_results.append(ticket.commit())

        hold_results: list[LifecycleHold] = []
        for partition_id, hold, already_present in plan.process_holds:
            if already_present:
                result = hold
            else:
                result = self._partitions[partition_id].add_hold(hold)
                transition = LifecycleTransition(
                    transition_id=f"{hold.hold_id}:acquired",
                    subject=hold.subject,
                    kind="hold_acquired",
                    canonical_time=hold.acquired_at,
                    action_id=hold.action_id,
                    reason=hold.reason,
                    transition_ordinal=hold.transition_ordinal,
                )
                self._routes.set_locked("hold", hold.hold_id, result)
                self._routes.set_locked("transition", transition.transition_id, transition)
            hold_results.append(result)
        if plan.processes:
            process_results = [
                self._partitions[partition_id]._process_snapshot(prepared.entry)
                for partition_id, prepared, _membership in plan.processes
            ]

        transport_partition = self._partitions[plan.transport_partition_id]
        transport_snapshot, handle = transport_partition._commit_prepared_transport_locked(
            plan.transport
        )
        locator = self._session_locator(plan.transport_partition_id, handle)
        self._routes.set_locked("transport", request.identity.object_id, locator)
        self._routes.set_locked("transport_id", request.identity.transport_id, locator)
        self._routes.set_locked("transport_uid", request.identity.zeek_uid, locator)
        self._routes.set_locked(
            "transition",
            request.start_transition_id,
            self._start_transition_locator(
                plan.transport_partition_id,
                handle,
                _TRANSPORT_START_TAG,
            ),
        )

        binding_snapshot = plan.binding
        binding_identity = request.binding_identity
        if binding_identity is not None:
            assert plan.session_partition_id is not None
            session_partition = self._partitions[plan.session_partition_id]
            if binding_snapshot is None:
                binding_snapshot = transport_partition._register_transport_session_binding_locked(
                    binding_identity
                )
                session_partition._register_session_transport_binding_locked(binding_identity)
                self._routes.set_locked(
                    "transport_session_binding",
                    binding_identity.binding_id,
                    plan.transport_partition_id,
                )
            if binding_snapshot.closed_at is None:
                binding_snapshot = transport_partition._close_transport_session_binding_locked(
                    binding_identity.binding_id,
                    expected_identity=binding_identity,
                    closed_at=request.identity.close_deadline,
                    action_id=request.binding_close_action_id,
                    transition_ordinal=request.binding_close_transition_ordinal,
                )
                session_partition._close_session_transport_binding_locked(
                    binding_identity,
                    request.identity.close_deadline,
                )

        barrier = request.barrier
        ticket = transport_partition.request_close(barrier, ticket_id=request.ticket_id)
        expected_ticket, requested, scheduled, closed_transition = (
            self._expected_closed_transport_control(request)
        )
        if ticket != expected_ticket:
            raise StateError("Prepared transport close ticket changed during primitive commit")
        self._routes.set_locked("barrier", barrier.barrier_id, barrier)
        self._routes.set_locked("ticket", request.ticket_id, ticket)
        self._routes.set_locked("transition", requested.transition_id, requested)
        self._routes.set_locked("transition", scheduled.transition_id, scheduled)
        closed = transport_partition.close(request.ticket_id)
        if not isinstance(closed, TransportLifecycleSnapshot):
            raise StateError("Prepared transport close returned an incompatible lifecycle")
        self._routes.set_locked(
            "transition",
            closed_transition.transition_id,
            closed_transition,
        )
        self._routes.cache_snapshot_locked("transport", request.identity.object_id, closed)
        committed_digest = self._closed_transport_committed_digest(
            request,
            closed,
            binding_snapshot,
            tuple(session_results),
            tuple(process_results),
            tuple(hold_results),
        )
        return LifecycleClosedTransportPublicationReceipt(
            request=request,
            transport=closed,
            binding=binding_snapshot,
            session_snapshots=tuple(session_results),
            process_snapshots=tuple(process_results),
            process_holds=tuple(hold_results),
            registry_id=self._closed_transport_registry_id,
            plan_digest=plan.token.plan_digest,
            committed_digest=committed_digest,
            _integrity=self._closed_transport_receipt_integrity(
                plan_digest=plan.token.plan_digest,
                committed_digest=committed_digest,
            ),
        )

    def _commit_claimed_closed_transport_publication(
        self,
        token: LifecycleClosedTransportAdmissionToken,
    ) -> LifecycleClosedTransportPublicationReceipt:
        """Commit one claimed token under sorted locks and consume it once."""

        with self._gate.mutation():
            with self._closed_transport_preparation_lock:
                reservation = self._active_closed_transport_reservation_locked(token)
                canonical_token = reservation.canonical_token
                canonical_request = canonical_token.request
                if not reservation.claimed or reservation.commit_plan is None:
                    raise StateError("Closed-transport admission token is not claimed")
                if reservation.claim_thread_id != get_ident():
                    raise StateError(
                        "Closed-transport publication must commit on its claiming thread"
                    )
                if self._watermark != canonical_token.expected_watermark:
                    raise StateError("Closed-transport admission is stale after watermark advance")
                commit_plan = reservation.commit_plan
            route_keys = self._closed_transport_route_keys(canonical_request)
            with self._routes.locked(route_keys):
                partition_ids = self._closed_transport_partition_ids_locked(canonical_request)
                with self._locked_partition_ids(partition_ids):
                    self._validate_closed_transport_token_against_canonical(
                        token,
                        canonical_token,
                    )
                    receipt = self._commit_closed_transport_primitives_locked(commit_plan)
            with self._closed_transport_preparation_lock:
                active = self._closed_transport_reservations.get(canonical_token.preparation_id)
                if active is not reservation:
                    raise StateError("Closed-transport admission token was consumed during commit")
                self._release_closed_transport_reservation_locked(reservation)
                self._closed_transport_receipts[id(receipt)] = receipt
            return receipt

    @contextmanager
    def prepare_start_batch(
        self,
        *,
        sessions: tuple[LifecycleSessionStartRequest, ...] = (),
        processes: tuple[LifecycleProcessStartRequest, ...] = (),
        service_publication: PreparedLifecycleServicePublication | None = None,
    ) -> Iterator[PreparedLifecycleStartBatch]:
        """Validate an all-or-none start batch under one globally sorted lock set."""

        service_token: LifecycleServiceAdmissionToken | None = None
        service_owner: tuple[Literal["publication", "closure"], int] | None = None
        if service_publication is not None:
            if service_publication._registry is not self:
                raise StateError("Prepared service publication belongs to another registry")
            if not service_publication._active or service_publication.committed:
                raise StateError("Prepared service publication is not active")
            service_token = service_publication._token
            with self._closed_transport_preparation_lock:
                reservation = self._active_service_publication_reservation_locked(service_token)
                if not reservation.claimed or reservation.claim_thread_id != get_ident():
                    raise StateError("Service publication is not claimed by this start thread")
                self._validate_service_staged_process_requests(service_token, processes)
                service_owner = ("publication", service_token.preparation_id)

        session_transitions = tuple(
            LifecycleTransition(
                transition_id=request.transition_id,
                subject=request.identity.ref,
                kind="started",
                canonical_time=request.identity.started_at,
                action_id=request.action_id,
                transition_ordinal=request.transition_ordinal,
            )
            for request in sessions
        )
        process_transitions = tuple(
            LifecycleTransition(
                transition_id=request.transition_id,
                subject=request.identity.ref,
                kind="started",
                canonical_time=request.identity.started_at,
                action_id=request.action_id,
                transition_ordinal=request.transition_ordinal,
            )
            for request in processes
        )
        session_ids = [request.identity.object_id for request in sessions]
        process_ids = [request.identity.object_id for request in processes]
        transition_ids = [
            transition.transition_id for transition in (*session_transitions, *process_transitions)
        ]
        if len(set(session_ids)) != len(session_ids):
            raise StateError("Lifecycle start batch contains a duplicate session object")
        if len(set(process_ids)) != len(process_ids):
            raise StateError("Lifecycle start batch contains a duplicate process object")
        if len(set(transition_ids)) != len(transition_ids):
            raise StateError("Lifecycle start batch contains a duplicate transition ID")
        session_groups = [
            (request.identity.hostname, request.identity.logon_id) for request in sessions
        ]
        process_groups = [
            (request.identity.hostname, request.identity.pid) for request in processes
        ]
        if len(set(session_groups)) != len(session_groups):
            raise StateError("Lifecycle start batch contains overlapping session LogonIDs")
        if len(set(process_groups)) != len(process_groups):
            raise StateError("Lifecycle start batch contains overlapping process PIDs")

        route_keys: list[tuple[str, str]] = []
        partition_ids: list[int] = []
        for request, transition in zip(sessions, session_transitions, strict=True):
            route_keys.extend(
                (("session", request.identity.object_id), ("transition", transition.transition_id))
            )
            partition_ids.append(self._partition_id(request.identity.hostname))
        for request, transition in zip(processes, process_transitions, strict=True):
            route_keys.extend(
                (("process", request.identity.object_id), ("transition", transition.transition_id))
            )
            if request.identity.parent_object_id:
                route_keys.append(("process", request.identity.parent_object_id))
            if request.membership.session_object_id:
                route_keys.append(("session", request.membership.session_object_id))
            partition_ids.append(self._partition_id(request.identity.hostname))
        if service_token is not None:
            route_keys.extend(self._service_publication_route_keys(service_token.request))
            partition_ids.append(self._partition_id(service_token.request.identity.hostname))

        mutation_keys: list[tuple[str, str]] = []
        for request, transition in zip(sessions, session_transitions, strict=True):
            mutation_keys.extend(
                (
                    self._closed_transport_subject_key(request.identity.ref),
                    ("transition", transition.transition_id),
                    (
                        "session_logon",
                        repr(
                            (
                                request.identity.hostname.strip().casefold(),
                                request.identity.logon_id.strip().casefold(),
                            )
                        ),
                    ),
                )
            )
        for request, transition in zip(processes, process_transitions, strict=True):
            mutation_keys.extend(
                (
                    self._closed_transport_subject_key(request.identity.ref),
                    ("transition", transition.transition_id),
                    (
                        "process_pid",
                        repr(
                            (
                                request.identity.hostname.strip().casefold(),
                                request.identity.pid,
                            )
                        ),
                    ),
                )
            )
            if request.identity.parent_object_id:
                mutation_keys.append(
                    self._closed_transport_subject_key(
                        LifecycleEntityRef("process", request.identity.parent_object_id)
                    )
                )
            if request.membership.session_object_id:
                mutation_keys.append(
                    self._closed_transport_subject_key(
                        LifecycleEntityRef("session", request.membership.session_object_id)
                    )
                )

        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(
                tuple(mutation_keys),
                allowed_service_owner=service_owner,
            ),
            self._routes.locked(tuple(route_keys)),
            self._locked_partition_ids(tuple(partition_ids)),
        ):
            prepared_sessions: list[tuple[int, _PreparedSessionPartitionStart, object | None]] = []
            staged_sessions = {request.identity.object_id: request.identity for request in sessions}
            for request, transition in zip(sessions, session_transitions, strict=True):
                identity = request.identity
                partition_id = self._partition_id(identity.hostname)
                prior_session = self._routes.get_locked("session", identity.object_id)
                prior_transition = self._routes.get_locked("transition", transition.transition_id)
                prior_partition = self._session_partition_from_route(prior_session)
                if prior_partition is not None and prior_partition != partition_id:
                    raise StateError(
                        f"Session lifecycle object {identity.object_id} is already registered"
                    )
                if isinstance(prior_session, bytes):
                    if _decode_session_row(prior_session).object_id != identity.object_id:
                        raise StateError("Lifecycle session route semantic hash collision")
                elif isinstance(prior_session, int):
                    routed_partition, handle = self._decode_session_locator(prior_session)
                    prior_snapshot = self._partitions[routed_partition].get_session_by_handle(
                        handle
                    )
                    if (
                        prior_snapshot is None
                        or prior_snapshot.identity.object_id != identity.object_id
                    ):
                        raise StateError("Lifecycle session route semantic hash collision")
                if (
                    prior_transition is not None
                    and self._transition_from_route(prior_transition, transition.transition_id)
                    != transition
                ):
                    self._reject_exact_conflict("transition", transition.transition_id)
                prepared = self._partitions[partition_id]._prepare_session_registration_locked(
                    identity, transition=transition
                )
                prepared_sessions.append((partition_id, prepared, prior_session))

            staged_processes = {
                request.identity.object_id: request.identity for request in processes
            }
            pending = list(zip(processes, process_transitions, strict=True))
            ordered: list[tuple[LifecycleProcessStartRequest, LifecycleTransition]] = []
            admitted_ids: set[str] = set()
            while pending:
                ready = [
                    item
                    for item in pending
                    if not item[0].identity.parent_object_id
                    or item[0].identity.parent_object_id not in staged_processes
                    or item[0].identity.parent_object_id in admitted_ids
                ]
                if not ready:
                    raise StateError("Lifecycle start batch contains a process-parent cycle")
                ready.sort(
                    key=lambda item: (
                        item[0].identity.started_at,
                        item[0].action_id,
                        item[0].transition_ordinal,
                        item[0].identity.object_id,
                    )
                )
                for item in ready:
                    pending.remove(item)
                    ordered.append(item)
                    admitted_ids.add(item[0].identity.object_id)

            prepared_processes: list[
                tuple[int, _PreparedProcessPartitionStart, LifecycleMembership]
            ] = []
            for request, transition in ordered:
                identity = request.identity
                partition_id = self._partition_id(identity.hostname)
                prior_process = self._routes.get_locked("process", identity.object_id)
                prior_transition = self._routes.get_locked("transition", transition.transition_id)
                if prior_process is not None and prior_process != partition_id:
                    raise StateError(
                        f"Process lifecycle object {identity.object_id} is already registered"
                    )
                if (
                    prior_transition is not None
                    and self._transition_from_route(prior_transition, transition.transition_id)
                    != transition
                ):
                    self._reject_exact_conflict("transition", transition.transition_id)
                if identity.parent_object_id:
                    parent_partition = self._routes.get_locked("process", identity.parent_object_id)
                    if parent_partition is not None and parent_partition != partition_id:
                        raise StateError(
                            f"Process lifecycle {identity.object_id} cannot use a cross-host parent"
                        )
                if request.membership.session_object_id:
                    session_route = self._routes.get_locked(
                        "session", request.membership.session_object_id
                    )
                    session_partition = self._session_partition_from_route(session_route)
                    if session_partition is not None and session_partition != partition_id:
                        raise StateError(
                            f"Process lifecycle {identity.object_id} cannot use cross-host "
                            "session membership"
                        )
                prepared = self._partitions[partition_id]._prepare_process_registration_locked(
                    identity,
                    token=request.token,
                    membership=request.membership,
                    transition=transition,
                    staged_sessions=staged_sessions,
                    staged_processes=staged_processes,
                )
                prepared_processes.append((partition_id, prepared, request.membership))

            service_plan = (
                None
                if service_token is None
                else self._prepare_service_commit_locked(service_token)
            )

            ticket = PreparedLifecycleStartBatch(
                _registry=self,
                _sessions=tuple(prepared_sessions),
                _processes=tuple(prepared_processes),
                _service_publication=service_publication,
                _service_plan=service_plan,
            )
            try:
                yield ticket
            finally:
                ticket._active = False

    @staticmethod
    def _service_plan_digest(
        request: LifecycleServicePublicationRequest | LifecycleServiceProcessClosureRequest,
    ) -> str:
        """Return one deterministic digest over a frozen service operation."""

        return sha256(repr(request).encode("utf-8")).hexdigest()

    @staticmethod
    def _service_watermark_text(watermark: datetime | None) -> str:
        return "" if watermark is None else watermark.isoformat()

    def _service_token_integrity(
        self,
        *,
        kind: Literal["publication", "closure"],
        preparation_id: int,
        expected_watermark: datetime | None,
        plan_digest: str,
    ) -> str:
        return sha256(
            (
                f"lifecycle-service-{kind}-admission\0{self._service_registry_id}\0"
                f"{preparation_id}\0{self._service_watermark_text(expected_watermark)}\0"
                f"{plan_digest}"
            ).encode()
        ).hexdigest()

    def _service_receipt_integrity(
        self,
        *,
        kind: Literal["publication", "closure"],
        plan_digest: str,
        committed_digest: str,
    ) -> str:
        return sha256(
            (
                f"lifecycle-service-{kind}-receipt\0{self._service_registry_id}\0"
                f"{plan_digest}\0{committed_digest}"
            ).encode()
        ).hexdigest()

    def _service_publication_reservation_keys(
        self,
        request: LifecycleServicePublicationRequest,
    ) -> tuple[tuple[str, str], ...]:
        identity = request.identity
        keys: list[tuple[str, str]] = [
            self._closed_transport_subject_key(identity.ref),
            ("transition", request.transition_id),
            ("service_logical", repr(request.logical_identity.host_logical_key)),
            ("service_instance", repr(identity.host_instance_key)),
        ]
        if identity.parent_service_object_id:
            keys.append(
                self._closed_transport_subject_key(
                    LifecycleEntityRef("service", identity.parent_service_object_id)
                )
            )
        for binding in request.process_bindings:
            keys.extend(
                (
                    self._closed_transport_subject_key(
                        LifecycleEntityRef("process", binding.process_object_id)
                    ),
                    ("service_process_binding", binding.binding_id),
                )
            )
        for member in request.staged_process_bindings:
            start = member.process_start
            keys.extend(
                (
                    ("transition", start.transition_id),
                    (
                        "process_pid",
                        repr(
                            (
                                start.identity.hostname.strip().casefold(),
                                start.identity.pid,
                            )
                        ),
                    ),
                )
            )
            if start.identity.parent_object_id:
                keys.append(
                    self._closed_transport_subject_key(
                        LifecycleEntityRef("process", start.identity.parent_object_id)
                    )
                )
            if start.membership.session_object_id:
                keys.append(
                    self._closed_transport_subject_key(
                        LifecycleEntityRef("session", start.membership.session_object_id)
                    )
                )
        return tuple(dict.fromkeys(keys))

    def _service_publication_route_keys(
        self,
        request: LifecycleServicePublicationRequest,
    ) -> tuple[tuple[str, str], ...]:
        identity = request.identity
        keys: list[tuple[str, str]] = [
            ("service", identity.object_id),
            ("transition", request.transition_id),
        ]
        if identity.parent_service_object_id:
            keys.append(("service", identity.parent_service_object_id))
        for binding in request.process_bindings:
            keys.extend(
                (
                    ("process", binding.process_object_id),
                    ("service_process_binding", binding.binding_id),
                )
            )
        for member in request.staged_process_bindings:
            start = member.process_start
            keys.append(("transition", start.transition_id))
            if start.identity.parent_object_id:
                keys.append(("process", start.identity.parent_object_id))
            if start.membership.session_object_id:
                keys.append(("session", start.membership.session_object_id))
        return tuple(dict.fromkeys(keys))

    def _validate_service_publication_token(
        self,
        token: LifecycleServiceAdmissionToken,
    ) -> None:
        if type(token) is not LifecycleServiceAdmissionToken:
            raise StateError("Service admission token has an invalid type")
        if token.registry_id != self._service_registry_id:
            raise StateError("Service admission token belongs to another registry")

    def _active_service_publication_reservation_locked(
        self,
        token: LifecycleServiceAdmissionToken,
    ) -> _ServicePublicationReservation:
        locator = self._service_capability_locators.get(id(token))
        if locator is None:
            self._validate_service_publication_token(token)
            raise StateError("Service admission token is stale or consumed")
        kind, preparation_id = locator
        active = self._service_publication_reservations.get(preparation_id)
        if kind != "publication" or active is None or active.token is not token:
            self._service_capability_locators.pop(id(token), None)
            raise StateError("Service admission token is stale or consumed")
        try:
            self._validate_service_publication_token(token)
        except StateError:
            self._release_service_publication_reservation_locked(active)
            raise
        return active

    def _release_service_keys_locked(
        self,
        *,
        family: Literal["publication", "closure"],
        preparation_id: int,
        token: object,
        keys: tuple[tuple[str, str], ...],
    ) -> None:
        self._service_capability_locators.pop(id(token), None)
        owner = (family, preparation_id)
        for key in keys:
            if self._service_reserved_keys.get(key) == owner:
                self._service_reserved_keys.pop(key)
        self._closed_transport_preparation_condition.notify_all()

    def _release_service_publication_reservation_locked(
        self,
        reservation: _ServicePublicationReservation,
    ) -> None:
        preparation_id = reservation.canonical_token.preparation_id
        if self._service_publication_reservations.pop(preparation_id, None) is not reservation:
            return
        if reservation.claimed:
            self._service_claimed_publications -= 1
        self._release_service_keys_locked(
            family="publication",
            preparation_id=preparation_id,
            token=reservation.token,
            keys=reservation.keys,
        )

    def _reject_service_reservation_conflict_locked(
        self,
        keys: tuple[tuple[str, str], ...],
    ) -> None:
        self._reject_closed_transport_reservation_conflict_locked(keys)

    @staticmethod
    def _validate_service_staged_process_requests(
        token: LifecycleServiceAdmissionToken,
        processes: tuple[LifecycleProcessStartRequest, ...],
    ) -> None:
        """Require every service-staged process to be in the exact start batch."""

        members = token.request.staged_process_bindings
        if not members:
            raise StateError("Composite service publication has no staged process binding")
        processes_by_id = {request.identity.object_id: request for request in processes}
        staged_ids: set[str] = set()
        ordered_requests: list[LifecycleProcessStartRequest] = []
        for member in members:
            object_id = member.process_start.identity.object_id
            if object_id in staged_ids:
                raise StateError("Composite service publication repeats a staged process")
            staged_ids.add(object_id)
            if processes_by_id.get(object_id) != member.process_start:
                raise StateError("Composite service staged process start does not match")
            ordered_requests.append(member.process_start)
        in_batch_order = [
            request for request in processes if request.identity.object_id in staged_ids
        ]
        if in_batch_order != ordered_requests:
            raise StateError("Composite service staged process order does not match")

    def _prepare_service_commit_locked(
        self,
        token: LifecycleServiceAdmissionToken,
    ) -> _PreparedServiceCommitPlan:
        request = token.request
        identity = request.identity
        staged_processes = {
            member.process_start.identity.object_id: member.process_start.identity
            for member in request.staged_process_bindings
        }
        for member in request.staged_process_bindings:
            start = member.process_start
            process_identity = start.identity
            process_partition_id = self._partition_id(process_identity.hostname)
            prior_process = self._routes.get_locked("process", process_identity.object_id)
            if prior_process is not None and prior_process != process_partition_id:
                raise StateError(
                    f"Process lifecycle object {process_identity.object_id} is already registered"
                )
            process_transition = LifecycleTransition(
                transition_id=start.transition_id,
                subject=process_identity.ref,
                kind="started",
                canonical_time=process_identity.started_at,
                action_id=start.action_id,
                transition_ordinal=start.transition_ordinal,
            )
            prior_transition = self._routes.get_locked(
                "transition",
                process_transition.transition_id,
            )
            if (
                prior_transition is not None
                and self._transition_from_route(
                    prior_transition,
                    process_transition.transition_id,
                )
                != process_transition
            ):
                self._reject_exact_conflict(
                    "transition",
                    process_transition.transition_id,
                )
            self._partitions[process_partition_id]._prepare_process_registration_locked(
                process_identity,
                token=start.token,
                membership=start.membership,
                transition=process_transition,
                staged_processes=staged_processes,
            )
        transition = LifecycleTransition(
            transition_id=request.transition_id,
            subject=identity.ref,
            kind="started",
            canonical_time=identity.started_at,
            action_id=request.action_id,
            transition_ordinal=request.transition_ordinal,
        )
        partition_id = self._partition_id(identity.hostname)
        prior_service = self._routes.get_locked("service", identity.object_id)
        if prior_service is not None:
            if not isinstance(prior_service, int):
                self._reject_exact_conflict("service", identity.object_id)
            prior_partition, prior_handle = self._decode_session_locator(prior_service)
            prior_snapshot = self._partitions[prior_partition].get_service_by_handle(prior_handle)
            if (
                prior_partition != partition_id
                or prior_snapshot is None
                or prior_snapshot.identity.object_id != identity.object_id
            ):
                self._reject_exact_conflict("service", identity.object_id)
        prior_transition = self._routes.get_locked("transition", transition.transition_id)
        if (
            prior_transition is not None
            and self._transition_from_route(prior_transition, transition.transition_id)
            != transition
        ):
            self._reject_exact_conflict("transition", transition.transition_id)
        if identity.parent_service_object_id:
            parent_partition = self._subject_partition_locked(
                LifecycleEntityRef("service", identity.parent_service_object_id)
            )
            if parent_partition != partition_id:
                raise StateError("Service instances cannot use a cross-host parent")
        partition = self._partitions[partition_id]
        prepared_service = partition._prepare_service_registration_locked(
            request.logical_identity,
            identity,
            transition=transition,
        )
        staged_by_binding = {
            member.binding_id: member for member in request.staged_process_bindings
        }
        prepared_bindings: list[_PreparedServiceProcessBinding] = []
        for binding in request.process_bindings:
            staged_member = staged_by_binding.get(binding.binding_id)
            process_partition = (
                self._partition_id(staged_member.process_start.identity.hostname)
                if staged_member is not None
                else self._subject_partition_locked(
                    LifecycleEntityRef("process", binding.process_object_id)
                )
            )
            if process_partition != partition_id:
                raise StateError("Service/process bindings cannot cross host partitions")
            prior_binding = self._routes.get_locked("service_process_binding", binding.binding_id)
            if prior_binding is not None and prior_binding != partition_id:
                self._reject_exact_conflict("service_process_binding", binding.binding_id)
            prepared_binding = partition._prepare_service_process_binding_locked(
                binding,
                staged_service=identity,
                staged_process=(
                    None if staged_member is None else staged_member.process_start.identity
                ),
            )
            if (
                prepared_binding.existing is not None
                and prepared_binding.existing.closed_at is not None
            ):
                raise StateError(f"Service/process binding {binding.binding_id} is already closed")
            prepared_bindings.append(prepared_binding)
        return _PreparedServiceCommitPlan(
            token=token,
            partition_id=partition_id,
            service=prepared_service,
            bindings=tuple(prepared_bindings),
        )

    def prepare_service_publication(
        self,
        request: LifecycleServicePublicationRequest,
    ) -> LifecycleServiceAdmissionToken:
        """Validate and reserve one service publication without canonical rows."""

        public_request = deepcopy(request)
        reservation_keys = self._service_publication_reservation_keys(public_request)
        route_keys = self._service_publication_route_keys(public_request)
        with self._gate.mutation(), self._closed_transport_preparation_lock:
            conflicts = {
                owner
                for key in reservation_keys
                if (owner := self._service_reserved_keys.get(key)) is not None
            }
            if conflicts and all(
                family == "publication"
                and (active := self._service_publication_reservations.get(preparation_id))
                is not None
                and active.canonical_token.request == public_request
                for family, preparation_id in conflicts
            ):
                raise LifecycleServicePublicationInProgressError(
                    "Exact service publication is already in progress"
                )
            self._reject_service_reservation_conflict_locked(reservation_keys)
            preparation_id = self._next_service_preparation_id
            expected_watermark = self._watermark
            plan_digest = self._service_plan_digest(public_request)
            token = LifecycleServiceAdmissionToken(
                request=public_request,
                registry_id=self._service_registry_id,
                preparation_id=preparation_id,
                expected_watermark=expected_watermark,
                plan_digest=plan_digest,
                _integrity=self._service_token_integrity(
                    kind="publication",
                    preparation_id=preparation_id,
                    expected_watermark=expected_watermark,
                    plan_digest=plan_digest,
                ),
            )
            canonical_token = deepcopy(token)
            partition_id = self._partition_id(public_request.identity.hostname)
            with self._routes.locked(route_keys), self._locked_partition_ids((partition_id,)):
                self._prepare_service_commit_locked(canonical_token)
            self._next_service_preparation_id += 1
            reservation = _ServicePublicationReservation(
                token=token,
                canonical_token=canonical_token,
                keys=reservation_keys,
            )
            self._service_publication_reservations[preparation_id] = reservation
            self._service_capability_locators[id(token)] = ("publication", preparation_id)
            for key in reservation_keys:
                self._service_reserved_keys[key] = ("publication", preparation_id)
            return token

    def wait_for_service_publication(self, request: LifecycleServicePublicationRequest) -> None:
        """Wait for an exact compatibility publication without retaining registry locks."""

        with self._closed_transport_preparation_condition:
            while any(
                item.canonical_token.request == request
                for item in self._service_publication_reservations.values()
            ):
                self._closed_transport_preparation_condition.wait()

    def cancel_service_publication(self, token: LifecycleServiceAdmissionToken) -> None:
        """Cancel one unclaimed service reservation with zero canonical rows."""

        with self._gate.mutation(), self._closed_transport_preparation_lock:
            reservation = self._active_service_publication_reservation_locked(token)
            if reservation.claimed:
                raise StateError("Claimed service publication cannot cancel directly")
            self._release_service_publication_reservation_locked(reservation)

    def authenticates_service_admission_token(
        self,
        token: object,
        *,
        request: LifecycleServicePublicationRequest | None = None,
    ) -> bool:
        """Authenticate one active service admission token without consuming it."""

        if not isinstance(token, LifecycleServiceAdmissionToken):
            return False
        with self._closed_transport_preparation_lock:
            try:
                reservation = self._active_service_publication_reservation_locked(token)
            except StateError:
                return False
            return request is None or reservation.canonical_token.request == request

    @contextmanager
    def claimed_service_publication(
        self,
        token: LifecycleServiceAdmissionToken,
    ) -> Iterator[PreparedLifecycleServicePublication]:
        """Short-claim a token, then yield without retaining registry locks."""

        with self._gate.mutation(), self._closed_transport_preparation_lock:
            reservation = self._active_service_publication_reservation_locked(token)
            canonical_token = reservation.canonical_token
            if reservation.claimed:
                raise StateError("Service admission token is already claimed")
            if self._watermark != canonical_token.expected_watermark:
                self._release_service_publication_reservation_locked(reservation)
                raise StateError("Service admission is stale after watermark advance")
            route_keys = self._service_publication_route_keys(canonical_token.request)
            partition_id = self._partition_id(canonical_token.request.identity.hostname)
            try:
                with self._routes.locked(route_keys), self._locked_partition_ids((partition_id,)):
                    reservation.commit_plan = self._prepare_service_commit_locked(canonical_token)
                self._validate_service_publication_token(token)
            except BaseException:
                self._release_service_publication_reservation_locked(reservation)
                raise
            reservation.claimed = True
            reservation.claim_thread_id = get_ident()
            self._service_claimed_publications += 1
        capability = PreparedLifecycleServicePublication(self, token)
        try:
            yield capability
        except BaseException:
            if not capability.committed:
                with self._gate.mutation(), self._closed_transport_preparation_lock:
                    locator = self._service_capability_locators.get(id(token))
                    if locator == ("publication", token.preparation_id):
                        active = self._service_publication_reservations.get(token.preparation_id)
                        if active is not None and active.token is token:
                            self._release_service_publication_reservation_locked(active)
            raise
        else:
            if not capability.committed:
                with self._gate.mutation(), self._closed_transport_preparation_lock:
                    locator = self._service_capability_locators.get(id(token))
                    if locator == ("publication", token.preparation_id):
                        active = self._service_publication_reservations.get(token.preparation_id)
                        if active is not None and active.token is token:
                            self._release_service_publication_reservation_locked(active)
                raise StateError("Claimed service publication exited without commit_no_fail")
        finally:
            if capability.committed:
                with self._gate.mutation(), self._closed_transport_preparation_lock:
                    locator = self._service_capability_locators.get(id(token))
                    if locator == ("publication", token.preparation_id):
                        active = self._service_publication_reservations.get(token.preparation_id)
                        if active is not None and active.token is token:
                            self._release_service_publication_reservation_locked(active)
            capability._close()

    def _commit_service_primitives_locked(
        self,
        plan: _PreparedServiceCommitPlan,
        *,
        staged_processes: tuple[ProcessLifecycleSnapshot, ...] = (),
    ) -> LifecycleServicePublicationReceipt:
        request = plan.token.request
        staged_by_id = {item.identity.object_id: item for item in staged_processes}
        ordered_processes = tuple(
            staged_by_id[member.process_start.identity.object_id]
            for member in request.staged_process_bindings
            if member.process_start.identity.object_id in staged_by_id
        )
        if len(ordered_processes) != len(request.staged_process_bindings):
            raise AssertionError("Service commit is missing a staged process result")
        start_plan_tokens = tuple(
            member.state_publication_token for member in request.staged_process_bindings
        )
        partition = self._partitions[plan.partition_id]
        service, handle = partition._commit_prepared_service_locked(plan.service)
        locator = self._session_locator(plan.partition_id, handle)
        self._routes.set_locked("service", request.identity.object_id, locator)
        self._routes.set_locked(
            "transition",
            request.transition_id,
            self._start_transition_locator(plan.partition_id, handle, _SERVICE_START_TAG),
        )
        bindings: list[ServiceProcessBindingSnapshot] = []
        for prepared in plan.bindings:
            snapshot = partition._commit_prepared_service_process_binding_locked(prepared)
            self._routes.set_locked(
                "service_process_binding", snapshot.identity.binding_id, plan.partition_id
            )
            bindings.append(snapshot)
        self._routes.cache_snapshot_locked("service", request.identity.object_id, service)
        binding_results = tuple(bindings)
        committed_digest = sha256(
            repr(
                (
                    request,
                    service,
                    binding_results,
                    ordered_processes,
                    start_plan_tokens,
                )
            ).encode()
        ).hexdigest()
        receipt = LifecycleServicePublicationReceipt(
            request=request,
            service=service,
            bindings=binding_results,
            processes=ordered_processes,
            start_plan_tokens=start_plan_tokens,
            registry_id=self._service_registry_id,
            plan_digest=plan.token.plan_digest,
            committed_digest=committed_digest,
            _integrity=self._service_receipt_integrity(
                kind="publication",
                plan_digest=plan.token.plan_digest,
                committed_digest=committed_digest,
            ),
        )
        self._service_publication_receipts[id(receipt)] = receipt
        return receipt

    def _commit_claimed_service_publication(
        self,
        token: LifecycleServiceAdmissionToken,
    ) -> LifecycleServicePublicationReceipt:
        """Commit one claimed service token under sorted locks and consume it once."""

        if token.request.staged_process_bindings:
            raise StateError(
                "Staged service process publication requires a combined lifecycle start ticket"
            )

        with self._gate.mutation():
            with self._closed_transport_preparation_lock:
                reservation = self._active_service_publication_reservation_locked(token)
                canonical_token = reservation.canonical_token
                if not reservation.claimed or reservation.commit_plan is None:
                    raise StateError("Service admission token is not claimed")
                if reservation.claim_thread_id != get_ident():
                    raise StateError("Service publication must commit on its claiming thread")
                if self._watermark != canonical_token.expected_watermark:
                    raise StateError("Service admission is stale after watermark advance")
                commit_plan = reservation.commit_plan
            route_keys = self._service_publication_route_keys(canonical_token.request)
            with (
                self._routes.locked(route_keys),
                self._locked_partition_ids((commit_plan.partition_id,)),
            ):
                self._validate_service_publication_token(token)
                receipt = self._commit_service_primitives_locked(commit_plan)
            with self._closed_transport_preparation_lock:
                active = self._service_publication_reservations.get(token.preparation_id)
                if active is not reservation:
                    raise StateError("Service admission token was consumed during commit")
                self._release_service_publication_reservation_locked(reservation)
            return receipt

    def authenticates_service_publication_receipt(
        self,
        receipt: object,
        *,
        request: LifecycleServicePublicationRequest | None = None,
    ) -> bool:
        """Authenticate one service publication receipt and optional exact request."""

        if not isinstance(receipt, LifecycleServicePublicationReceipt):
            return False
        if self._service_publication_receipts.get(id(receipt)) is not receipt:
            return False
        return request is None or receipt.request is request or receipt.request == request

    def service_preparation_census(self) -> LifecycleServicePreparationCensus:
        """Return transient service capability counts without scanning canonical rows."""

        with self._closed_transport_preparation_lock:
            return LifecycleServicePreparationCensus(
                publication_reservations=len(self._service_publication_reservations),
                closure_reservations=len(self._service_closure_reservations),
                claimed_publications=self._service_claimed_publications,
                claimed_closures=self._service_claimed_closures,
                reserved_keys=len(self._service_reserved_keys),
                capability_locators=len(self._service_capability_locators),
            )

    def _service_closure_reservation_keys(
        self,
        request: LifecycleServiceProcessClosureRequest,
    ) -> tuple[tuple[str, str], ...]:
        keys: list[tuple[str, str]] = []
        for item in request.binding_closures:
            keys.extend(
                (
                    ("service_process_binding", item.identity.binding_id),
                    self._closed_transport_subject_key(
                        LifecycleEntityRef("service", item.identity.service_object_id)
                    ),
                    self._closed_transport_subject_key(
                        LifecycleEntityRef("process", item.identity.process_object_id)
                    ),
                )
            )
        for item in (*request.process_closures, *request.service_closures):
            barrier = item.barrier
            keys.extend(
                (
                    self._closed_transport_subject_key(barrier.subject),
                    self._resource_lease_subject_key(barrier.subject),
                    ("barrier", barrier.barrier_id),
                    ("ticket", item.ticket_id),
                    ("transition", f"{barrier.barrier_id}:requested"),
                    ("transition", f"{item.ticket_id}:scheduled"),
                    ("transition", f"{item.ticket_id}:closed"),
                )
            )
        return tuple(dict.fromkeys(keys))

    def _service_closure_route_keys(
        self,
        request: LifecycleServiceProcessClosureRequest,
    ) -> tuple[tuple[str, str], ...]:
        keys: list[tuple[str, str]] = []
        for item in request.binding_closures:
            keys.extend(
                (
                    ("service_process_binding", item.identity.binding_id),
                    ("service", item.identity.service_object_id),
                    ("process", item.identity.process_object_id),
                )
            )
        for item in (*request.process_closures, *request.service_closures):
            barrier = item.barrier
            keys.extend(
                (
                    (barrier.subject.kind, barrier.subject.object_id),
                    ("barrier", barrier.barrier_id),
                    ("ticket", item.ticket_id),
                    ("transition", f"{barrier.barrier_id}:requested"),
                    ("transition", f"{item.ticket_id}:scheduled"),
                    ("transition", f"{item.ticket_id}:closed"),
                )
            )
        return tuple(dict.fromkeys(keys))

    def _service_closure_partition_ids_locked(
        self,
        request: LifecycleServiceProcessClosureRequest,
    ) -> tuple[int, ...]:
        partition_ids: set[int] = set()
        for item in request.binding_closures:
            partition_id = self._routes.get_locked(
                "service_process_binding", item.identity.binding_id
            )
            if not isinstance(partition_id, int):
                raise StateError(f"Unknown service/process binding {item.identity.binding_id}")
            partition_ids.add(partition_id)
        for item in (*request.process_closures, *request.service_closures):
            partition_ids.add(self._subject_partition_locked(item.barrier.subject))
        return tuple(sorted(partition_ids))

    def _validate_service_closure_token(
        self,
        token: LifecycleServiceClosureAdmissionToken,
    ) -> None:
        if type(token) is not LifecycleServiceClosureAdmissionToken:
            raise StateError("Service closure token has an invalid type")
        if token.registry_id != self._service_registry_id:
            raise StateError("Service closure token belongs to another registry")

    def _active_service_closure_reservation_locked(
        self,
        token: LifecycleServiceClosureAdmissionToken,
    ) -> _ServiceClosureReservation:
        locator = self._service_capability_locators.get(id(token))
        if locator is None:
            self._validate_service_closure_token(token)
            raise StateError("Service closure token is stale or consumed")
        kind, preparation_id = locator
        active = self._service_closure_reservations.get(preparation_id)
        if kind != "closure" or active is None or active.token is not token:
            self._service_capability_locators.pop(id(token), None)
            raise StateError("Service closure token is stale or consumed")
        try:
            self._validate_service_closure_token(token)
        except StateError:
            self._release_service_closure_reservation_locked(active)
            raise
        return active

    def _release_service_closure_reservation_locked(
        self,
        reservation: _ServiceClosureReservation,
    ) -> None:
        preparation_id = reservation.canonical_token.preparation_id
        if self._service_closure_reservations.pop(preparation_id, None) is not reservation:
            return
        if reservation.claimed:
            self._service_claimed_closures -= 1
        self._release_service_keys_locked(
            family="closure",
            preparation_id=preparation_id,
            token=reservation.token,
            keys=reservation.keys,
        )

    @staticmethod
    def _expected_subject_closure_transitions(
        control: LifecycleSubjectClosureControl,
        effective_at: datetime,
    ) -> tuple[
        LifecycleClosureTicket, LifecycleTransition, LifecycleTransition, LifecycleTransition
    ]:
        barrier = control.barrier
        ticket = LifecycleClosureTicket(
            ticket_id=control.ticket_id,
            barrier_id=barrier.barrier_id,
            subject=barrier.subject,
            requested_at=barrier.requested_at,
            effective_at=effective_at,
            authority=barrier.authority,
            action_id=barrier.action_id,
        )
        return (
            ticket,
            LifecycleTransition(
                transition_id=f"{barrier.barrier_id}:requested",
                subject=barrier.subject,
                kind="close_requested",
                canonical_time=barrier.requested_at,
                action_id=barrier.action_id,
                transition_ordinal=0,
            ),
            LifecycleTransition(
                transition_id=f"{control.ticket_id}:scheduled",
                subject=barrier.subject,
                kind="close_scheduled",
                canonical_time=effective_at,
                action_id=barrier.action_id,
                transition_ordinal=1,
            ),
            LifecycleTransition(
                transition_id=f"{control.ticket_id}:closed",
                subject=barrier.subject,
                kind="closed",
                canonical_time=effective_at,
                action_id=barrier.action_id,
                transition_ordinal=2,
            ),
        )

    def _active_service_binding_ids_locked(
        self,
        partition_id: int,
        *,
        kind: Literal["process", "service"],
        object_id: str,
    ) -> tuple[str, ...]:
        partition = self._partitions[partition_id]
        cursor: int | None = None
        binding_ids: list[str] = []
        while True:
            page, cursor = partition.service_process_binding_page(
                process_object_id=object_id if kind == "process" else "",
                service_object_id=object_id if kind == "service" else "",
                after_handle=cursor,
                limit=_PRIMARY_COMPACTION_PAGE,
            )
            binding_ids.extend(item.identity.binding_id for item in page)
            if cursor is None:
                return tuple(binding_ids)

    def _validate_planned_subject_dependents_locked(
        self,
        *,
        partition_id: int,
        subject: LifecycleEntityRef,
        effective_at: datetime,
        planned_binding_closures: tuple[LifecycleServiceProcessBindingClosure, ...],
    ) -> None:
        partition = self._partitions[partition_id]
        active_ids = set(
            self._active_service_binding_ids_locked(
                partition_id,
                kind=subject.kind,
                object_id=subject.object_id,
            )
        )
        included = {
            item.identity.binding_id
            for item in planned_binding_closures
            if (
                item.identity.process_object_id
                if subject.kind == "process"
                else item.identity.service_object_id
            )
            == subject.object_id
        }
        missing = active_ids - included
        if missing:
            raise StateError(
                f"Process close must include every active service binding; missing "
                f"{sorted(missing)!r}"
                if subject.kind == "process"
                else f"Service close must include every active process binding; missing "
                f"{sorted(missing)!r}"
            )
        planned_times = [
            item.closed_at
            for item in planned_binding_closures
            if item.identity.binding_id in active_ids
        ]
        if planned_times and max(planned_times) > effective_at:
            raise StateError("Service/process binding closes after its owning lifecycle")
        if subject.kind == "process":
            aggregate = partition._children_by_parent.get(subject.object_id)
            relationship = "child processes"
        else:
            aggregate = partition._service_children_by_parent.get(subject.object_id)
            relationship = "child service instances"
        if aggregate is not None and aggregate.blocks_close_at(effective_at):
            raise StateError(
                f"Cannot close lifecycle {subject.object_id} at {effective_at.isoformat()}: "
                f"{relationship} remain active"
            )

    def _validate_subject_closure_control_locked(
        self,
        control: LifecycleSubjectClosureControl,
        *,
        partition_id: int,
        planned_binding_closures: tuple[LifecycleServiceProcessBindingClosure, ...],
    ) -> bool:
        partition = self._partitions[partition_id]
        subject = control.barrier.subject
        entry = (
            partition._processes.get(subject.object_id)
            if subject.kind == "process"
            else partition._services.get(subject.object_id)
        )
        if entry is None:
            raise StateError(f"Unknown {subject.kind} lifecycle object {subject.object_id}")
        if entry.closed_at is not None:
            ticket = entry.closure_ticket
            if ticket is None:
                raise StateError("Terminal lifecycle lost its exact closure ticket")
            expected = self._expected_subject_closure_transitions(control, ticket.effective_at)
            if (
                entry.close_barrier != control.barrier
                or ticket != expected[0]
                or not partition._entry_has_transition(entry, expected[3])
                or entry.closed_at != ticket.effective_at
            ):
                raise StateError("Terminal service/process retry disagrees with exact closure")
            for kind, semantic_id, value in (
                ("barrier", control.barrier.barrier_id, control.barrier),
                ("ticket", control.ticket_id, expected[0]),
                ("transition", expected[1].transition_id, expected[1]),
                ("transition", expected[2].transition_id, expected[2]),
                ("transition", expected[3].transition_id, expected[3]),
            ):
                prior = self._routes.get_locked(kind, semantic_id)
                actual = (
                    self._transition_from_route(prior, semantic_id)
                    if kind == "transition"
                    else prior
                )
                if actual != value:
                    raise StateError("Terminal service/process retry lost exact control state")
            return True
        if entry.close_barrier is not None or entry.closure_ticket is not None:
            raise StateError("Partial service/process terminal retry is not admissible")
        barrier = control.barrier
        partition._reject_behind_watermark(barrier.requested_at, "close barrier")
        if barrier.requested_at < partition._entry_started_at(entry):
            raise StateError("Lifecycle close precedes its start")
        latest_dependent = entry.state.latest_dependent_at
        if latest_dependent is not None and latest_dependent >= barrier.requested_at:
            raise StateError("Lifecycle close barrier precedes an existing dependent")
        latest_hold = entry.state.latest_hold_until or barrier.requested_at
        latest_resource = partition._resource_lease_deadline_for(subject)
        latest_dependency = max(latest_hold, latest_resource or barrier.requested_at)
        if barrier.authority == "authoritative" and latest_dependency > barrier.requested_at:
            raise StateError(
                "Authoritative lifecycle close conflicts with a hold or resource lease"
            )
        effective_at = max(barrier.requested_at, latest_dependency)
        self._validate_planned_subject_dependents_locked(
            partition_id=partition_id,
            subject=subject,
            effective_at=effective_at,
            planned_binding_closures=planned_binding_closures,
        )
        expected = self._expected_subject_closure_transitions(control, effective_at)
        for kind, semantic_id, value in (
            ("barrier", barrier.barrier_id, barrier),
            ("ticket", control.ticket_id, expected[0]),
            ("transition", expected[1].transition_id, expected[1]),
            ("transition", expected[2].transition_id, expected[2]),
            ("transition", expected[3].transition_id, expected[3]),
        ):
            prior = self._routes.get_locked(kind, semantic_id)
            actual = (
                self._transition_from_route(prior, semantic_id) if kind == "transition" else prior
            )
            if actual is not None:
                if actual != value:
                    self._reject_exact_conflict(kind, semantic_id)
                raise StateError("Partial service/process terminal retry is not admissible")
        return False

    def _prepare_service_closure_commit_locked(
        self,
        token: LifecycleServiceClosureAdmissionToken,
    ) -> _PreparedServiceClosureCommitPlan:
        request = token.request
        terminal: list[bool] = []
        for item in request.binding_closures:
            partition_id = self._routes.get_locked(
                "service_process_binding", item.identity.binding_id
            )
            if not isinstance(partition_id, int):
                raise StateError(f"Unknown service/process binding {item.identity.binding_id}")
            current = self._partitions[partition_id].service_process_binding(
                item.identity.binding_id
            )
            if current is None or current.identity != item.identity:
                raise StateError(
                    f"Service/process binding {item.identity.binding_id} identity changed"
                )
            if current.closed_at is None:
                self._partitions[partition_id]._reject_behind_watermark(
                    item.closed_at, "service/process binding close"
                )
                terminal.append(False)
            elif (
                current.closed_at == item.closed_at
                and current.close_action_id == item.action_id
                and current.close_transition_ordinal == item.transition_ordinal
            ):
                terminal.append(True)
            else:
                raise StateError(
                    f"Service/process binding {item.identity.binding_id} is already closed"
                )
        for item in request.process_closures:
            partition_id = self._subject_partition_locked(item.barrier.subject)
            terminal.append(
                self._validate_subject_closure_control_locked(
                    item,
                    partition_id=partition_id,
                    planned_binding_closures=request.binding_closures,
                )
            )
        for item in request.service_closures:
            partition_id = self._subject_partition_locked(item.barrier.subject)
            terminal.append(
                self._validate_subject_closure_control_locked(
                    item,
                    partition_id=partition_id,
                    planned_binding_closures=request.binding_closures,
                )
            )
        if any(terminal) and not all(terminal):
            raise StateError("Partial service/process terminal retry cannot heal missing relations")
        return _PreparedServiceClosureCommitPlan(
            token=token,
            already_terminal=all(terminal),
        )

    def prepare_service_process_closure(
        self,
        request: LifecycleServiceProcessClosureRequest,
    ) -> LifecycleServiceClosureAdmissionToken:
        """Validate and reserve binding-first service closure without mutation."""

        public_request = deepcopy(request)
        reservation_keys = self._service_closure_reservation_keys(public_request)
        route_keys = self._service_closure_route_keys(public_request)
        with self._gate.mutation(), self._closed_transport_preparation_lock:
            conflicts = {
                owner
                for key in reservation_keys
                if (owner := self._service_reserved_keys.get(key)) is not None
            }
            if conflicts and all(
                family == "closure"
                and (active := self._service_closure_reservations.get(preparation_id)) is not None
                and active.canonical_token.request == public_request
                for family, preparation_id in conflicts
            ):
                raise LifecycleServicePublicationInProgressError(
                    "Exact service/process closure is already in progress"
                )
            self._reject_service_reservation_conflict_locked(reservation_keys)
            preparation_id = self._next_service_preparation_id
            expected_watermark = self._watermark
            plan_digest = self._service_plan_digest(public_request)
            token = LifecycleServiceClosureAdmissionToken(
                request=public_request,
                registry_id=self._service_registry_id,
                preparation_id=preparation_id,
                expected_watermark=expected_watermark,
                plan_digest=plan_digest,
                _integrity=self._service_token_integrity(
                    kind="closure",
                    preparation_id=preparation_id,
                    expected_watermark=expected_watermark,
                    plan_digest=plan_digest,
                ),
            )
            canonical_token = deepcopy(token)
            with self._routes.locked(route_keys):
                partition_ids = self._service_closure_partition_ids_locked(public_request)
                with self._locked_partition_ids(partition_ids):
                    self._prepare_service_closure_commit_locked(canonical_token)
            self._next_service_preparation_id += 1
            reservation = _ServiceClosureReservation(
                token=token,
                canonical_token=canonical_token,
                keys=reservation_keys,
            )
            self._service_closure_reservations[preparation_id] = reservation
            self._service_capability_locators[id(token)] = ("closure", preparation_id)
            for key in reservation_keys:
                self._service_reserved_keys[key] = ("closure", preparation_id)
            return token

    def cancel_service_process_closure(
        self,
        token: LifecycleServiceClosureAdmissionToken,
    ) -> None:
        """Cancel one unclaimed service/process closure reservation."""

        with self._gate.mutation(), self._closed_transport_preparation_lock:
            reservation = self._active_service_closure_reservation_locked(token)
            if reservation.claimed:
                raise StateError("Claimed service/process closure cannot cancel directly")
            self._release_service_closure_reservation_locked(reservation)

    def authenticates_service_closure_admission_token(
        self,
        token: object,
        *,
        request: LifecycleServiceProcessClosureRequest | None = None,
    ) -> bool:
        """Authenticate one active service closure token without consuming it."""

        if not isinstance(token, LifecycleServiceClosureAdmissionToken):
            return False
        with self._closed_transport_preparation_lock:
            try:
                reservation = self._active_service_closure_reservation_locked(token)
            except StateError:
                return False
            return request is None or reservation.canonical_token.request == request

    @contextmanager
    def claimed_service_process_closure(
        self,
        token: LifecycleServiceClosureAdmissionToken,
    ) -> Iterator[PreparedLifecycleServiceProcessClosure]:
        """Short-claim a closure token, then yield without retaining registry locks."""

        with self._gate.mutation(), self._closed_transport_preparation_lock:
            reservation = self._active_service_closure_reservation_locked(token)
            canonical_token = reservation.canonical_token
            if reservation.claimed:
                raise StateError("Service closure token is already claimed")
            if self._watermark != canonical_token.expected_watermark:
                self._release_service_closure_reservation_locked(reservation)
                raise StateError("Service closure admission is stale after watermark advance")
            route_keys = self._service_closure_route_keys(canonical_token.request)
            try:
                with self._routes.locked(route_keys):
                    partition_ids = self._service_closure_partition_ids_locked(
                        canonical_token.request
                    )
                    with self._locked_partition_ids(partition_ids):
                        reservation.commit_plan = self._prepare_service_closure_commit_locked(
                            canonical_token
                        )
                self._validate_service_closure_token(token)
            except BaseException:
                self._release_service_closure_reservation_locked(reservation)
                raise
            reservation.claimed = True
            reservation.claim_thread_id = get_ident()
            self._service_claimed_closures += 1
        capability = PreparedLifecycleServiceProcessClosure(self, token)
        try:
            yield capability
        except BaseException:
            if not capability.committed:
                with self._gate.mutation(), self._closed_transport_preparation_lock:
                    locator = self._service_capability_locators.get(id(token))
                    if locator == ("closure", token.preparation_id):
                        active = self._service_closure_reservations.get(token.preparation_id)
                        if active is not None and active.token is token:
                            self._release_service_closure_reservation_locked(active)
            raise
        else:
            if not capability.committed:
                with self._gate.mutation(), self._closed_transport_preparation_lock:
                    locator = self._service_capability_locators.get(id(token))
                    if locator == ("closure", token.preparation_id):
                        active = self._service_closure_reservations.get(token.preparation_id)
                        if active is not None and active.token is token:
                            self._release_service_closure_reservation_locked(active)
                raise StateError("Claimed service/process closure exited without commit_no_fail")
        finally:
            capability._close()

    def _commit_subject_closure_locked(
        self,
        control: LifecycleSubjectClosureControl,
        partition_id: int,
    ) -> ProcessLifecycleSnapshot | ServiceInstanceLifecycleSnapshot:
        partition = self._partitions[partition_id]
        ticket = partition.request_close(control.barrier, ticket_id=control.ticket_id)
        expected = self._expected_subject_closure_transitions(control, ticket.effective_at)
        self._routes.set_locked("barrier", control.barrier.barrier_id, control.barrier)
        self._routes.set_locked("ticket", control.ticket_id, ticket)
        self._routes.set_locked("transition", expected[1].transition_id, expected[1])
        self._routes.set_locked("transition", expected[2].transition_id, expected[2])
        snapshot = partition.close(control.ticket_id)
        if not isinstance(snapshot, (ProcessLifecycleSnapshot, ServiceInstanceLifecycleSnapshot)):
            raise StateError("Prepared service closure returned an incompatible lifecycle")
        self._routes.set_locked("transition", expected[3].transition_id, expected[3])
        if isinstance(snapshot, ServiceInstanceLifecycleSnapshot):
            self._routes.cache_snapshot_locked("service", snapshot.identity.object_id, snapshot)
        return snapshot

    def _service_closure_receipt_locked(
        self,
        plan: _PreparedServiceClosureCommitPlan,
    ) -> LifecycleServiceProcessClosureReceipt:
        request = plan.token.request
        bindings: list[ServiceProcessBindingSnapshot] = []
        processes: list[ProcessLifecycleSnapshot] = []
        services: list[ServiceInstanceLifecycleSnapshot] = []
        if not plan.already_terminal:
            for item in request.binding_closures:
                partition_id = self._routes.get_locked(
                    "service_process_binding", item.identity.binding_id
                )
                assert isinstance(partition_id, int)
                bindings.append(
                    self._partitions[partition_id].close_service_process_binding(
                        item.identity.binding_id,
                        expected_identity=item.identity,
                        closed_at=item.closed_at,
                        action_id=item.action_id,
                        transition_ordinal=item.transition_ordinal,
                    )
                )
            for item in request.process_closures:
                partition_id = self._subject_partition_locked(item.barrier.subject)
                result = self._commit_subject_closure_locked(item, partition_id)
                assert isinstance(result, ProcessLifecycleSnapshot)
                processes.append(result)
            for item in request.service_closures:
                partition_id = self._subject_partition_locked(item.barrier.subject)
                result = self._commit_subject_closure_locked(item, partition_id)
                assert isinstance(result, ServiceInstanceLifecycleSnapshot)
                services.append(result)
        else:
            for item in request.binding_closures:
                partition_id = self._routes.get_locked(
                    "service_process_binding", item.identity.binding_id
                )
                assert isinstance(partition_id, int)
                snapshot = self._partitions[partition_id].service_process_binding(
                    item.identity.binding_id
                )
                assert snapshot is not None
                bindings.append(snapshot)
            for item in request.process_closures:
                partition_id = self._subject_partition_locked(item.barrier.subject)
                snapshot = self._partitions[partition_id].get_process(
                    item.barrier.subject.object_id
                )
                assert snapshot is not None
                processes.append(snapshot)
            for item in request.service_closures:
                partition_id = self._subject_partition_locked(item.barrier.subject)
                snapshot = self._partitions[partition_id].get_service_instance(
                    item.barrier.subject.object_id
                )
                assert snapshot is not None
                services.append(snapshot)
        binding_results = tuple(bindings)
        process_results = tuple(processes)
        service_results = tuple(services)
        committed_digest = sha256(
            repr((request, binding_results, process_results, service_results)).encode()
        ).hexdigest()
        receipt = LifecycleServiceProcessClosureReceipt(
            request=request,
            bindings=binding_results,
            processes=process_results,
            services=service_results,
            registry_id=self._service_registry_id,
            plan_digest=plan.token.plan_digest,
            committed_digest=committed_digest,
            _integrity=self._service_receipt_integrity(
                kind="closure",
                plan_digest=plan.token.plan_digest,
                committed_digest=committed_digest,
            ),
        )
        self._service_closure_receipts[id(receipt)] = receipt
        return receipt

    def _commit_claimed_service_closure(
        self,
        token: LifecycleServiceClosureAdmissionToken,
    ) -> LifecycleServiceProcessClosureReceipt:
        """Commit one claimed service closure under sorted locks and consume it once."""

        with self._gate.mutation():
            with self._closed_transport_preparation_lock:
                reservation = self._active_service_closure_reservation_locked(token)
                canonical_token = reservation.canonical_token
                if not reservation.claimed or reservation.commit_plan is None:
                    raise StateError("Service closure token is not claimed")
                if reservation.claim_thread_id != get_ident():
                    raise StateError("Service closure must commit on its claiming thread")
                if self._watermark != canonical_token.expected_watermark:
                    raise StateError("Service closure admission is stale after watermark advance")
                commit_plan = reservation.commit_plan
            route_keys = self._service_closure_route_keys(canonical_token.request)
            with self._routes.locked(route_keys):
                partition_ids = self._service_closure_partition_ids_locked(canonical_token.request)
                with self._locked_partition_ids(partition_ids):
                    self._validate_service_closure_token(token)
                    receipt = self._service_closure_receipt_locked(commit_plan)
            with self._closed_transport_preparation_lock:
                active = self._service_closure_reservations.get(token.preparation_id)
                if active is not reservation:
                    raise StateError("Service closure token was consumed during commit")
                self._release_service_closure_reservation_locked(reservation)
            return receipt

    def authenticates_service_process_closure_receipt(
        self,
        receipt: object,
        *,
        request: LifecycleServiceProcessClosureRequest | None = None,
    ) -> bool:
        """Authenticate one service closure receipt and optional exact request."""

        if not isinstance(receipt, LifecycleServiceProcessClosureReceipt):
            return False
        if self._service_closure_receipts.get(id(receipt)) is not receipt:
            return False
        return request is None or receipt.request is request or receipt.request == request

    @contextmanager
    def prepare_session_registration(
        self,
        identity: SessionLifecycleIdentity,
        *,
        action_id: str,
        transition_id: str,
        transition_ordinal: int = 0,
    ) -> Iterator[PreparedSessionRegistration]:
        """Validate one session start and retain every authority lock until exit."""

        transition = LifecycleTransition(
            transition_id=transition_id,
            subject=identity.ref,
            kind="started",
            canonical_time=identity.started_at,
            action_id=action_id,
            transition_ordinal=transition_ordinal,
        )
        partition_id = self._partition_id(identity.hostname)
        keys = (("session", identity.object_id), ("transition", transition_id))
        mutation_keys = (
            self._closed_transport_subject_key(identity.ref),
            ("transition", transition_id),
            (
                "session_logon",
                repr((identity.hostname.strip().casefold(), identity.logon_id.strip().casefold())),
            ),
        )
        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(mutation_keys),
            self._routes.locked(keys),
            self._locked_partition_ids((partition_id,)),
        ):
            prior_session = self._routes.get_locked("session", identity.object_id)
            prior_transition = self._routes.get_locked("transition", transition_id)
            prior_partition = self._session_partition_from_route(prior_session)
            if prior_partition is not None and prior_partition != partition_id:
                raise StateError(
                    f"Session lifecycle object {identity.object_id} is already registered"
                )
            if isinstance(prior_session, bytes):
                prior_object_id = _decode_session_row(prior_session).object_id
                if prior_object_id != identity.object_id:
                    raise StateError("Lifecycle session route semantic hash collision")
            elif isinstance(prior_session, int):
                prior_partition_id, prior_handle = self._decode_session_locator(prior_session)
                prior_snapshot = self._partitions[prior_partition_id].get_session_by_handle(
                    prior_handle
                )
                if (
                    prior_snapshot is None
                    or prior_snapshot.identity.object_id != identity.object_id
                ):
                    raise StateError("Lifecycle session route semantic hash collision")
            if (
                prior_transition is not None
                and self._transition_from_route(prior_transition, transition_id) != transition
            ):
                self._reject_exact_conflict("transition", transition_id)
            partition = self._partitions[partition_id]
            prepared = partition._prepare_session_registration_locked(
                identity,
                transition=transition,
            )
            ticket = PreparedSessionRegistration(
                _registry=self,
                _partition_id=partition_id,
                _prepared=prepared,
                _prior_session_route=prior_session,
            )
            try:
                yield ticket
            finally:
                ticket._active = False

    def register_session(
        self,
        identity: SessionLifecycleIdentity,
        *,
        action_id: str,
        transition_id: str,
        transition_ordinal: int = 0,
    ) -> SessionLifecycleSnapshotView:
        """Register one immutable session in its stable host partition."""

        with self.prepare_session_registration(
            identity,
            action_id=action_id,
            transition_id=transition_id,
            transition_ordinal=transition_ordinal,
        ) as ticket:
            return ticket.commit()

    @contextmanager
    def prepare_process_registration(
        self,
        identity: ProcessLifecycleIdentity,
        *,
        token: ProcessTokenIdentity,
        membership: LifecycleMembership,
        action_id: str,
        transition_id: str,
        transition_ordinal: int = 0,
    ) -> Iterator[PreparedProcessRegistration]:
        """Validate one process start and retain every authority lock until exit."""

        transition = LifecycleTransition(
            transition_id=transition_id,
            subject=identity.ref,
            kind="started",
            canonical_time=identity.started_at,
            action_id=action_id,
            transition_ordinal=transition_ordinal,
        )
        partition_id = self._partition_id(identity.hostname)
        key_list = [("process", identity.object_id), ("transition", transition_id)]
        if identity.parent_object_id:
            key_list.append(("process", identity.parent_object_id))
        if membership.session_object_id:
            key_list.append(("session", membership.session_object_id))
        keys = tuple(key_list)
        mutation_keys = [
            self._closed_transport_subject_key(identity.ref),
            ("transition", transition_id),
            (
                "process_pid",
                repr((identity.hostname.strip().casefold(), identity.pid)),
            ),
        ]
        if identity.parent_object_id:
            mutation_keys.append(
                self._closed_transport_subject_key(
                    LifecycleEntityRef("process", identity.parent_object_id)
                )
            )
        if membership.session_object_id:
            mutation_keys.append(
                self._closed_transport_subject_key(
                    LifecycleEntityRef("session", membership.session_object_id)
                )
            )
        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(tuple(mutation_keys)),
            self._routes.locked(keys),
            self._locked_partition_ids((partition_id,)),
        ):
            prior_process = self._routes.get_locked("process", identity.object_id)
            prior_transition = self._routes.get_locked("transition", transition_id)
            if prior_process is not None and prior_process != partition_id:
                raise StateError(
                    f"Process lifecycle object {identity.object_id} is already registered"
                )
            if (
                prior_transition is not None
                and self._transition_from_route(prior_transition, transition_id) != transition
            ):
                self._reject_exact_conflict("transition", transition_id)
            if identity.parent_object_id:
                parent_partition = self._routes.get_locked("process", identity.parent_object_id)
                if parent_partition is not None and parent_partition != partition_id:
                    raise StateError(
                        f"Process lifecycle {identity.object_id} cannot use a cross-host parent"
                    )
            if membership.session_object_id:
                session_route = self._routes.get_locked("session", membership.session_object_id)
                session_partition = self._session_partition_from_route(session_route)
                if session_partition is not None and session_partition != partition_id:
                    raise StateError(
                        f"Process lifecycle {identity.object_id} cannot use cross-host "
                        "session membership"
                    )
            prepared = self._partitions[partition_id]._prepare_process_registration_locked(
                identity,
                token=token,
                membership=membership,
                transition=transition,
            )
            ticket = PreparedProcessRegistration(
                _registry=self,
                _partition_id=partition_id,
                _prepared=prepared,
                _membership=membership,
            )
            try:
                yield ticket
            finally:
                ticket._active = False

    def register_process(
        self,
        identity: ProcessLifecycleIdentity,
        *,
        token: ProcessTokenIdentity,
        membership: LifecycleMembership,
        action_id: str,
        transition_id: str,
        transition_ordinal: int = 0,
    ) -> ProcessLifecycleSnapshot:
        """Register one immutable process in its stable host partition."""

        with self.prepare_process_registration(
            identity,
            token=token,
            membership=membership,
            action_id=action_id,
            transition_id=transition_id,
            transition_ordinal=transition_ordinal,
        ) as ticket:
            return ticket.commit()

    @staticmethod
    def _service_logical_route_id(hostname: str, logical_service_id: str) -> str:
        return f"{hostname.strip().casefold()}\0{logical_service_id.strip().casefold()}"

    @staticmethod
    def _service_instance_route_id(
        hostname: str,
        boot_id: str,
        logical_service_id: str,
        instance_id: str,
    ) -> str:
        return "\0".join(
            (
                hostname.strip().casefold(),
                boot_id,
                logical_service_id.strip().casefold(),
                instance_id,
            )
        )

    def register_service_instance(
        self,
        logical_identity: LogicalServiceIdentity,
        identity: ServiceInstanceLifecycleIdentity,
        *,
        action_id: str,
        transition_id: str,
        transition_ordinal: int = 0,
    ) -> ServiceInstanceLifecycleSnapshot:
        """Register one service instance under global exact identity authority."""

        transition = LifecycleTransition(
            transition_id=transition_id,
            subject=identity.ref,
            kind="started",
            canonical_time=identity.started_at,
            action_id=action_id,
            transition_ordinal=transition_ordinal,
        )
        partition_id = self._partition_id(identity.hostname)
        keys = [
            ("service", identity.object_id),
            ("transition", transition_id),
        ]
        mutation_keys = [
            self._closed_transport_subject_key(identity.ref),
            ("transition", transition_id),
            ("service_logical", repr(logical_identity.host_logical_key)),
            ("service_instance", repr(identity.host_instance_key)),
        ]
        if identity.parent_service_object_id:
            keys.append(("service", identity.parent_service_object_id))
            mutation_keys.append(
                self._closed_transport_subject_key(
                    LifecycleEntityRef("service", identity.parent_service_object_id)
                )
            )
        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(tuple(mutation_keys)),
            self._routes.locked(tuple(keys)),
        ):
            prior = self._routes.get_locked("service", identity.object_id)
            if prior is not None:
                if not isinstance(prior, int):
                    self._reject_exact_conflict("service", identity.object_id)
                prior_partition, prior_handle = self._decode_session_locator(prior)
                prior_snapshot = self._partitions[prior_partition].get_service_by_handle(
                    prior_handle
                )
                if (
                    prior_snapshot is None
                    or prior_snapshot.identity.object_id != identity.object_id
                ):
                    self._reject_exact_conflict("service", identity.object_id)
            if identity.parent_service_object_id:
                parent_route = self._routes.get_locked("service", identity.parent_service_object_id)
                parent_partition = self._session_partition_from_route(parent_route)
                if parent_partition is not None and parent_partition != partition_id:
                    raise StateError("Service instances cannot use a cross-host parent")
            prior_transition = self._routes.get_locked("transition", transition_id)
            if (
                prior_transition is not None
                and self._transition_from_route(prior_transition, transition_id) != transition
            ):
                self._reject_exact_conflict("transition", transition_id)
            snapshot, handle = self._partitions[partition_id].register_service_instance(
                logical_identity,
                identity,
                action_id=action_id,
                transition_id=transition_id,
                transition_ordinal=transition_ordinal,
            )
            self._routes.set_locked(
                "service",
                identity.object_id,
                self._session_locator(partition_id, handle),
            )
            self._routes.set_locked(
                "transition",
                transition_id,
                self._start_transition_locator(partition_id, handle, _SERVICE_START_TAG),
            )
            self._routes.cache_snapshot_locked("service", identity.object_id, snapshot)
            return snapshot

    def register_transport(
        self,
        identity: TransportLifecycleIdentity,
        *,
        action_id: str,
        transition_id: str,
        transition_ordinal: int = 0,
    ) -> TransportLifecycleSnapshot:
        """Register one frozen network-plan transport under exact global IDs."""

        transition = LifecycleTransition(
            transition_id=transition_id,
            subject=identity.ref,
            kind="started",
            canonical_time=identity.opened_at,
            action_id=action_id,
            transition_ordinal=transition_ordinal,
        )
        partition_id = self._partition_id(identity.hostname)
        keys = (
            ("transport", identity.object_id),
            ("transport_id", identity.transport_id),
            ("transport_uid", identity.zeek_uid),
            ("transition", transition_id),
        )
        mutation_keys = (
            self._closed_transport_subject_key(identity.ref),
            ("transport_id", identity.transport_id),
            ("transport_uid", identity.zeek_uid),
            self._closed_transport_tuple_key(identity),
            ("transition", transition_id),
        )
        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(mutation_keys),
            self._routes.locked(keys),
        ):
            prior = self._routes.get_locked("transport", identity.object_id)
            if prior is not None:
                if not isinstance(prior, int):
                    self._reject_exact_conflict("transport", identity.object_id)
                prior_partition, prior_handle = self._decode_session_locator(prior)
                prior_snapshot = self._partitions[prior_partition].get_transport_by_handle(
                    prior_handle
                )
                if (
                    prior_snapshot is None
                    or prior_snapshot.identity.object_id != identity.object_id
                ):
                    self._reject_exact_conflict("transport", identity.object_id)
            for kind, semantic_id in (
                ("transport_id", identity.transport_id),
                ("transport_uid", identity.zeek_uid),
            ):
                prior_locator = self._routes.get_locked(kind, semantic_id)
                if prior_locator is not None:
                    if not isinstance(prior_locator, int):
                        self._reject_exact_conflict(kind, semantic_id)
                    prior_partition, prior_handle = self._decode_session_locator(prior_locator)
                    prior_snapshot = self._partitions[prior_partition].get_transport_by_handle(
                        prior_handle
                    )
                    if (
                        prior_snapshot is None
                        or prior_snapshot.identity.object_id != identity.object_id
                    ):
                        self._reject_exact_conflict(kind, semantic_id)
            prior_transition = self._routes.get_locked("transition", transition_id)
            if (
                prior_transition is not None
                and self._transition_from_route(prior_transition, transition_id) != transition
            ):
                self._reject_exact_conflict("transition", transition_id)
            snapshot, handle = self._partitions[partition_id].register_transport(
                identity,
                action_id=action_id,
                transition_id=transition_id,
                transition_ordinal=transition_ordinal,
            )
            locator = self._session_locator(partition_id, handle)
            self._routes.set_locked("transport", identity.object_id, locator)
            self._routes.set_locked("transport_id", identity.transport_id, locator)
            self._routes.set_locked("transport_uid", identity.zeek_uid, locator)
            self._routes.set_locked(
                "transition",
                transition_id,
                self._start_transition_locator(partition_id, handle, _TRANSPORT_START_TAG),
            )
            self._routes.cache_snapshot_locked("transport", identity.object_id, snapshot)
            return snapshot

    def _partition_for_entity(self, kind: str, object_id: str) -> _LifecyclePartition | None:
        value = self._routes.get(kind, object_id)
        if not isinstance(value, int):
            return None
        partition_id = (
            self._decode_session_locator(value)[0]
            if kind in {"session", "service", "transport"}
            else value
        )
        return self._partitions[partition_id]

    def get_process(self, object_id: str) -> ProcessLifecycleSnapshot | None:
        """Return a process through one exact route shard."""

        partition = self._partition_for_entity("process", object_id)
        return None if partition is None else partition.get_process(object_id)

    def get_session(self, object_id: str) -> SessionLifecycleSnapshotView | None:
        """Return a session through one exact route shard."""

        route = self._routes.get("session", object_id)
        if isinstance(route, bytes):
            return _PackedSessionSnapshot(route, self._ledger_floor)
        if isinstance(route, int):
            partition_id, handle = self._decode_session_locator(route)
            return self._partitions[partition_id].get_session_by_handle(handle)
        return None

    def get_service_instance(self, object_id: str) -> ServiceInstanceLifecycleSnapshot | None:
        """Return one service instance through its exact object route."""

        locator, cached = self._routes.get_entity_with_cached_snapshot("service", object_id)
        if isinstance(cached, ServiceInstanceLifecycleSnapshot):
            return cached
        if not isinstance(locator, int):
            return None
        partition_id, handle = self._decode_session_locator(locator)
        snapshot = self._partitions[partition_id].get_service_by_handle(handle)
        if snapshot is None or snapshot.identity.object_id != object_id:
            return None
        with self._routes.locked((("service", object_id),)):
            self._routes.cache_snapshot_locked("service", object_id, snapshot)
        return snapshot

    def get_transport(self, object_id: str) -> TransportLifecycleSnapshot | None:
        """Return one canonical transport through its exact object route."""

        locator, cached = self._routes.get_entity_with_cached_snapshot("transport", object_id)
        if isinstance(cached, TransportLifecycleSnapshot):
            return cached
        if not isinstance(locator, int):
            return None
        partition_id, handle = self._decode_session_locator(locator)
        snapshot = self._partitions[partition_id].get_transport_by_handle(handle)
        if snapshot is None or snapshot.identity.object_id != object_id:
            return None
        with self._routes.locked((("transport", object_id),)):
            self._routes.cache_snapshot_locked("transport", object_id, snapshot)
        return snapshot

    def service_instance_at(
        self,
        object_id: str,
        canonical_time: datetime,
    ) -> ServiceInstanceLifecycleSnapshot | None:
        """Resolve one exact service instance at explicit canonical time."""

        partition = self._partition_for_entity("service", object_id)
        return (
            None if partition is None else partition.service_instance_at(object_id, canonical_time)
        )

    def service_for_logical_at(
        self,
        hostname: str,
        logical_service_id: str,
        canonical_time: datetime,
    ) -> ServiceInstanceLifecycleSnapshot | None:
        """Resolve the active host/logical service instance temporally."""

        return self._partitions[self._partition_id(hostname)].service_for_logical_at(
            hostname,
            logical_service_id,
            canonical_time,
        )

    def service_for_instance_key(
        self,
        hostname: str,
        boot_id: str,
        logical_service_id: str,
        instance_id: str,
    ) -> ServiceInstanceLifecycleSnapshot | None:
        """Resolve one exact boot-scoped service instance key."""

        return self._partitions[self._partition_id(hostname)].service_for_instance_key(
            hostname,
            boot_id,
            logical_service_id,
            instance_id,
        )

    def transport_at(
        self,
        object_id: str,
        canonical_time: datetime,
    ) -> TransportLifecycleSnapshot | None:
        """Resolve one exact transport at explicit canonical time."""

        partition = self._partition_for_entity("transport", object_id)
        return None if partition is None else partition.transport_at(object_id, canonical_time)

    def transport_for_transport_id(self, transport_id: str) -> TransportLifecycleSnapshot | None:
        """Resolve one transport through the canonical network-plan ID route."""

        locator = self._routes.get("transport_id", transport_id)
        if not isinstance(locator, int):
            return None
        partition_id, handle = self._decode_session_locator(locator)
        snapshot = self._partitions[partition_id].get_transport_by_handle(
            handle,
            count_candidate=True,
        )
        if snapshot is None or snapshot.identity.transport_id != transport_id:
            return None
        return snapshot

    def transport_for_uid(self, zeek_uid: str) -> TransportLifecycleSnapshot | None:
        """Resolve one transport through its canonical network-plan UID route."""

        locator = self._routes.get("transport_uid", zeek_uid)
        if not isinstance(locator, int):
            return None
        partition_id, handle = self._decode_session_locator(locator)
        snapshot = self._partitions[partition_id].get_transport_by_handle(
            handle,
            count_candidate=True,
        )
        if snapshot is None or snapshot.identity.zeek_uid != zeek_uid:
            return None
        return snapshot

    def transport_for_tuple_at(
        self,
        hostname: str,
        tuple_key: tuple[str, int, str, int, str],
        canonical_time: datetime,
    ) -> TransportLifecycleSnapshot | None:
        """Resolve a reused tuple in its explicit lifecycle-authority partition."""

        return self._partitions[self._partition_id(hostname)].transport_for_tuple_at(
            tuple_key,
            canonical_time,
        )

    def bind_service_process(
        self,
        identity: ServiceProcessBindingIdentity,
    ) -> ServiceProcessBindingSnapshot:
        """Bind a service instance to a same-host process under exact ID authority."""

        keys = (
            ("service", identity.service_object_id),
            ("process", identity.process_object_id),
            ("service_process_binding", identity.binding_id),
        )
        mutation_keys = (
            self._closed_transport_subject_key(
                LifecycleEntityRef("service", identity.service_object_id)
            ),
            self._closed_transport_subject_key(
                LifecycleEntityRef("process", identity.process_object_id)
            ),
            ("service_process_binding", identity.binding_id),
        )
        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(mutation_keys),
            self._routes.locked(keys),
        ):
            service_partition = self._subject_partition_locked(
                LifecycleEntityRef("service", identity.service_object_id)
            )
            process_partition = self._subject_partition_locked(
                LifecycleEntityRef("process", identity.process_object_id)
            )
            if service_partition != process_partition:
                raise StateError("Service/process bindings cannot cross host partitions")
            prior = self._routes.get_locked("service_process_binding", identity.binding_id)
            if prior is not None and prior != service_partition:
                self._reject_exact_conflict("service_process_binding", identity.binding_id)
            result = self._partitions[service_partition].bind_service_process(identity)
            self._routes.set_locked(
                "service_process_binding", identity.binding_id, service_partition
            )
            return result

    def service_process_binding(
        self,
        binding_id: str,
    ) -> ServiceProcessBindingSnapshot | None:
        """Return one routed service/process relation by exact identity."""

        partition_id = self._routes.get("service_process_binding", binding_id)
        if not isinstance(partition_id, int):
            return None
        return self._partitions[partition_id].service_process_binding(binding_id)

    def close_service_process_binding(
        self,
        binding_id: str,
        *,
        expected_identity: ServiceProcessBindingIdentity,
        closed_at: datetime,
        action_id: str,
        transition_ordinal: int = 0,
    ) -> ServiceProcessBindingSnapshot:
        """Close one exact service/process ownership relation."""

        key = ("service_process_binding", binding_id)
        mutation_keys = (
            self._closed_transport_subject_key(
                LifecycleEntityRef("service", expected_identity.service_object_id)
            ),
            self._closed_transport_subject_key(
                LifecycleEntityRef("process", expected_identity.process_object_id)
            ),
            key,
        )
        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(mutation_keys),
            self._routes.locked((key,)),
        ):
            partition_id = self._routes.get_locked(*key)
            if not isinstance(partition_id, int):
                raise StateError(f"Unknown service/process binding {binding_id}")
            return self._partitions[partition_id].close_service_process_binding(
                binding_id,
                expected_identity=expected_identity,
                closed_at=closed_at,
                action_id=action_id,
                transition_ordinal=transition_ordinal,
            )

    def bind_transport_session(
        self,
        identity: TransportSessionBindingIdentity,
    ) -> TransportSessionBindingSnapshot:
        """Atomically bind a transport to an exact possibly cross-host session."""

        keys = (
            ("transport", identity.transport_object_id),
            ("session", identity.session_object_id),
            ("transport_session_binding", identity.binding_id),
        )
        mutation_keys = (
            self._closed_transport_subject_key(
                LifecycleEntityRef("transport", identity.transport_object_id)
            ),
            self._closed_transport_subject_key(
                LifecycleEntityRef("session", identity.session_object_id)
            ),
            ("transport_session_binding", identity.binding_id),
        )
        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(mutation_keys),
            self._routes.locked(keys),
        ):
            transport_partition_id = self._subject_partition_locked(
                LifecycleEntityRef("transport", identity.transport_object_id)
            )
            session_partition_id = self._subject_partition_locked(
                LifecycleEntityRef("session", identity.session_object_id)
            )
            prior = self._routes.get_locked("transport_session_binding", identity.binding_id)
            if prior is not None:
                if not isinstance(prior, int) or prior != transport_partition_id:
                    self._reject_exact_conflict("transport_session_binding", identity.binding_id)
                current = self._partitions[transport_partition_id].transport_session_binding(
                    identity.binding_id
                )
                if current is not None and current.identity == identity:
                    return current
                self._reject_exact_conflict("transport_session_binding", identity.binding_id)
            transport_partition = self._partitions[transport_partition_id]
            session_partition = self._partitions[session_partition_id]
            self._routes.invalidate_snapshot_locked(
                "transport",
                identity.transport_object_id,
            )
            with self._locked_partition_ids((transport_partition_id, session_partition_id)):
                transport_partition._validate_transport_session_binding_locked(identity)
                session_partition._validate_session_transport_binding_locked(identity)
                result = transport_partition._register_transport_session_binding_locked(identity)
                session_partition._register_session_transport_binding_locked(identity)
            self._routes.set_locked(
                "transport_session_binding",
                identity.binding_id,
                transport_partition_id,
            )
            return result

    def transport_session_binding(
        self,
        binding_id: str,
    ) -> TransportSessionBindingSnapshot | None:
        """Return one routed transport/session relation by exact identity."""

        partition_id = self._routes.get("transport_session_binding", binding_id)
        if not isinstance(partition_id, int):
            return None
        return self._partitions[partition_id].transport_session_binding(binding_id)

    def close_transport_session_binding(
        self,
        binding_id: str,
        *,
        expected_identity: TransportSessionBindingIdentity,
        closed_at: datetime,
        action_id: str,
        transition_ordinal: int = 0,
    ) -> TransportSessionBindingSnapshot:
        """Atomically close a cross-host binding on both exact owner partitions."""

        if not action_id:
            raise ValueError("Transport/session binding closure requires an action_id")
        if transition_ordinal < 0:
            raise ValueError("Transport/session binding closure ordinal must be non-negative")
        at = ensure_utc(closed_at)
        key = ("transport_session_binding", binding_id)
        transport_key = ("transport", expected_identity.transport_object_id)
        mutation_keys = (
            self._closed_transport_subject_key(
                LifecycleEntityRef("transport", expected_identity.transport_object_id)
            ),
            self._closed_transport_subject_key(
                LifecycleEntityRef("session", expected_identity.session_object_id)
            ),
            ("transport_session_binding", binding_id),
        )
        with self._gate.mutation(), self._ordinary_closed_transport_mutation(mutation_keys):
            transport_partition_id = self._routes.get(*key)
            if not isinstance(transport_partition_id, int):
                raise StateError(f"Unknown transport/session binding {binding_id}")
            transport_partition = self._partitions[transport_partition_id]
            current = transport_partition.transport_session_binding(binding_id)
            if current is None:
                raise StateError(f"Unknown transport/session binding {binding_id}")
            if current.identity != expected_identity:
                raise StateError(
                    f"Transport/session binding {binding_id} identity changed before close"
                )
            if current.closed_at is not None:
                with self._routes.locked((key, transport_key)):
                    if self._routes.get_locked(*key) != transport_partition_id:
                        raise StateError(
                            f"Transport/session binding {binding_id} route changed before close"
                        )
                    self._routes.invalidate_snapshot_locked(*transport_key)
                    with self._locked_partition_ids((transport_partition_id,)):
                        return transport_partition._close_transport_session_binding_locked(
                            binding_id,
                            expected_identity=expected_identity,
                            closed_at=at,
                            action_id=action_id,
                            transition_ordinal=transition_ordinal,
                        )
            session_key = ("session", expected_identity.session_object_id)
            with self._routes.locked((key, session_key, transport_key)):
                if self._routes.get_locked(*key) != transport_partition_id:
                    raise StateError(
                        f"Transport/session binding {binding_id} route changed before close"
                    )
                session_route = self._routes.get_locked(*session_key)
                session_partition_id = self._session_partition_from_route(session_route)
                if session_partition_id is None:
                    raise StateError("Transport/session binding session route disappeared")
                session_partition = self._partitions[session_partition_id]
                self._routes.invalidate_snapshot_locked(*transport_key)
                with self._locked_partition_ids((transport_partition_id, session_partition_id)):
                    transport_partition._validate_transport_session_binding_close_locked(
                        expected_identity,
                        at,
                    )
                    session_partition._validate_session_transport_binding_close_locked(
                        expected_identity
                    )
                    result = transport_partition._close_transport_session_binding_locked(
                        binding_id,
                        expected_identity=expected_identity,
                        closed_at=at,
                        action_id=action_id,
                        transition_ordinal=transition_ordinal,
                    )
                    session_partition._close_session_transport_binding_locked(
                        result.identity,
                        at,
                    )
                return result

    def transport_binding_page(
        self,
        transport_object_id: str,
        *,
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[TransportSessionBindingSnapshot, ...], int | None]:
        """Return a bounded page of active bindings for one exact transport."""

        partition = self._partition_for_entity("transport", transport_object_id)
        if partition is None:
            return (), None
        return partition.transport_binding_page(
            transport_object_id,
            after_handle=after_handle,
            limit=limit,
        )

    def live_child_service_page(
        self,
        parent_service_object_id: str,
        *,
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[ServiceInstanceLifecycleSnapshot, ...], int | None]:
        """Return one bounded exact page of live child service instances."""

        partition = self._partition_for_entity("service", parent_service_object_id)
        if partition is None:
            return (), None
        return partition.live_child_service_page(
            parent_service_object_id,
            after_handle=after_handle,
            limit=limit,
        )

    def service_process_binding_page(
        self,
        *,
        service_object_id: str = "",
        process_object_id: str = "",
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[ServiceProcessBindingSnapshot, ...], int | None]:
        """Return one routed service/process ownership page."""

        if bool(service_object_id) == bool(process_object_id):
            raise ValueError("Specify exactly one service or process object for binding pages")
        kind = "service" if service_object_id else "process"
        object_id = service_object_id or process_object_id
        partition = self._partition_for_entity(kind, object_id)
        if partition is None:
            return (), None
        return partition.service_process_binding_page(
            service_object_id=service_object_id,
            process_object_id=process_object_id,
            after_handle=after_handle,
            limit=limit,
        )

    def service_child_close_deadline(self, service_object_id: str) -> datetime | None:
        """Return one routed service's exact child close aggregate."""

        partition = self._partition_for_entity("service", service_object_id)
        return (
            None if partition is None else partition.service_child_close_deadline(service_object_id)
        )

    def service_process_close_deadline(self, service_object_id: str) -> datetime | None:
        """Return one routed service's exact process-unbind aggregate."""

        partition = self._partition_for_entity("service", service_object_id)
        return (
            None
            if partition is None
            else partition.service_process_close_deadline(service_object_id)
        )

    def session_transport_close_deadline(self, session_object_id: str) -> datetime | None:
        """Return one routed session's exact transport-unbind aggregate."""

        route = self._routes.get("session", session_object_id)
        partition_id = self._session_partition_from_route(route)
        return (
            None
            if partition_id is None
            else self._partitions[partition_id].session_transport_close_deadline(session_object_id)
        )

    def session_transport_binding_page(
        self,
        session_object_id: str,
        *,
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[TransportSessionBindingSnapshot, ...], int | None]:
        """Return a bounded cross-host page of active bindings for one session."""

        route = self._routes.get("session", session_object_id)
        partition_id = self._session_partition_from_route(route)
        if partition_id is None:
            return (), None
        binding_ids, cursor = self._partitions[partition_id].session_transport_binding_id_page(
            session_object_id,
            after_handle=after_handle,
            limit=limit,
        )
        bindings = tuple(
            binding
            for binding_id in binding_ids
            if (binding := self.transport_session_binding(binding_id)) is not None
            and binding.closed_at is None
        )
        return bindings, cursor

    def session_member_close_deadline(self, session_object_id: str) -> datetime | None:
        """Return the O(1) aggregate deadline after all session members close."""

        route = self._routes.get("session", session_object_id)
        if isinstance(route, bytes):
            return None
        if not isinstance(route, int):
            return None
        partition_id, _handle = self._decode_session_locator(route)
        return self._partitions[partition_id].session_member_close_deadline(session_object_id)

    def live_child_process_page(
        self,
        parent_object_id: str,
        *,
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[ProcessLifecycleSnapshot, ...], int | None]:
        """Return one bounded page of exact live children for a routed parent."""

        partition = self._partition_for_entity("process", parent_object_id)
        if partition is None:
            return (), None
        return partition.live_child_process_page(
            parent_object_id,
            after_handle=after_handle,
            limit=limit,
        )

    def live_session_member_process_page(
        self,
        session_object_id: str,
        *,
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[ProcessLifecycleSnapshot, ...], int | None]:
        """Return one bounded exact page of live members for a routed session."""

        route = self._routes.get("session", session_object_id)
        if not isinstance(route, int):
            return (), None
        partition_id, _handle = self._decode_session_locator(route)
        return self._partitions[partition_id].live_session_member_process_page(
            session_object_id,
            after_handle=after_handle,
            limit=limit,
        )

    def process_child_close_deadline(self, process_object_id: str) -> datetime | None:
        """Return the O(1) latest exact child close after all children close."""

        partition = self._partition_for_entity("process", process_object_id)
        if partition is None:
            return None
        return partition.process_child_close_deadline(process_object_id)

    def process_latest_closed_child_at(self, process_object_id: str) -> datetime | None:
        """Return the routed parent's O(1) latest retained direct-child close."""

        partition = self._partition_for_entity("process", process_object_id)
        if partition is None:
            return None
        return partition.process_latest_closed_child_at(process_object_id)

    def session_latest_closed_member_at(self, session_object_id: str) -> datetime | None:
        """Return the routed session's O(1) latest retained member close."""

        route = self._routes.get("session", session_object_id)
        if not isinstance(route, int):
            return None
        partition_id, _handle = self._decode_session_locator(route)
        return self._partitions[partition_id].session_latest_closed_member_at(session_object_id)

    def resource_lease_deadline(self, subject: LifecycleEntityRef) -> datetime | None:
        """Return one routed subject's O(1) cached resource-lease deadline."""

        partition = self._partition_for_entity(subject.kind, subject.object_id)
        if partition is None:
            return None
        return partition.resource_lease_deadline(subject)

    def process_at(
        self,
        object_id: str,
        canonical_time: datetime,
    ) -> ProcessLifecycleSnapshot | None:
        """Resolve one exact process at explicit canonical time."""

        partition = self._partition_for_entity("process", object_id)
        return None if partition is None else partition.process_at(object_id, canonical_time)

    def session_at(
        self,
        object_id: str,
        canonical_time: datetime,
    ) -> SessionLifecycleSnapshotView | None:
        """Resolve one exact session at explicit canonical time."""

        route = self._routes.get("session", object_id)
        if isinstance(route, bytes):
            at = ensure_utc(canonical_time)
            if at < _session_started_at_from_row(route):
                return None
            return _PackedSessionSnapshot(route, self._ledger_floor)
        if isinstance(route, int):
            partition_id, handle = self._decode_session_locator(route)
            return self._partitions[partition_id].session_at_by_handle(handle, canonical_time)
        return None

    def process_for_pid_at(
        self,
        hostname: str,
        pid: int,
        canonical_time: datetime,
    ) -> ProcessLifecycleSnapshot | None:
        """Resolve PID reuse directly through its stable host partition."""

        return self._partitions[self._partition_id(hostname)].process_for_pid_at(
            hostname,
            pid,
            canonical_time,
        )

    def session_for_logon_at(
        self,
        hostname: str,
        logon_id: str,
        canonical_time: datetime,
    ) -> SessionLifecycleSnapshotView | None:
        """Resolve LogonID reuse directly through its stable host partition."""

        return self._partitions[self._partition_id(hostname)].session_for_logon_at(
            hostname,
            logon_id,
            canonical_time,
        )

    def transition(self, transition_id: str) -> LifecycleTransition | None:
        """Return one exact globally claimed transition."""

        value = self._routes.get("transition", transition_id)
        return self._transition_from_route(value, transition_id)

    def hold(self, hold_id: str) -> LifecycleHold | None:
        """Return one exact globally claimed hold."""

        value = self._routes.get("hold", hold_id)
        return value if isinstance(value, LifecycleHold) else None

    def close_barrier(self, barrier_id: str) -> LifecycleCloseBarrier | None:
        """Return one exact globally claimed close barrier."""

        value = self._routes.get("barrier", barrier_id)
        return value if isinstance(value, LifecycleCloseBarrier) else None

    def closure_ticket(self, ticket_id: str) -> LifecycleClosureTicket | None:
        """Return one exact globally claimed closure ticket."""

        value = self._routes.get("ticket", ticket_id)
        return value if isinstance(value, LifecycleClosureTicket) else None

    def record_dependent(
        self,
        subject: LifecycleEntityRef,
        *,
        transition_id: str,
        canonical_time: datetime,
        action_id: str,
        reason: str = "",
        transition_ordinal: int = 0,
    ) -> LifecycleTransition:
        """Append one dependent transition under exact global ID authority."""

        transition = LifecycleTransition(
            transition_id=transition_id,
            subject=subject,
            kind="dependent",
            canonical_time=canonical_time,
            action_id=action_id,
            reason=reason,
            transition_ordinal=transition_ordinal,
        )
        keys = ((self._entity_kind(subject), subject.object_id), ("transition", transition_id))
        mutation_keys = (
            self._closed_transport_subject_key(subject),
            ("transition", transition_id),
        )
        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(mutation_keys),
            self._routes.locked(keys),
        ):
            partition_id = self._subject_partition_locked(subject)
            existing = self._routes.get_locked("transition", transition_id)
            if existing is not None:
                if self._transition_from_route(existing, transition_id) == transition:
                    return transition
                self._reject_exact_conflict("transition", transition_id)
            self._routes.invalidate_subject_snapshot_locked(subject)
            result = self._partitions[partition_id].record_dependent(
                subject,
                transition_id=transition_id,
                canonical_time=canonical_time,
                action_id=action_id,
                reason=reason,
                transition_ordinal=transition_ordinal,
            )
            self._routes.set_locked("transition", transition_id, result)
            self._promote_session_route_locked(subject, partition_id)
            return result

    def add_hold(self, hold: LifecycleHold) -> LifecycleHold:
        """Append one typed hold with globally exact hold/transition claims."""

        transition = LifecycleTransition(
            transition_id=f"{hold.hold_id}:acquired",
            subject=hold.subject,
            kind="hold_acquired",
            canonical_time=hold.acquired_at,
            action_id=hold.action_id,
            reason=hold.reason,
            transition_ordinal=hold.transition_ordinal,
        )
        keys = (
            (self._entity_kind(hold.subject), hold.subject.object_id),
            ("hold", hold.hold_id),
            ("transition", transition.transition_id),
        )
        mutation_keys = (
            self._closed_transport_subject_key(hold.subject),
            ("transition", transition.transition_id),
        )
        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(mutation_keys),
            self._routes.locked(keys),
        ):
            partition_id = self._subject_partition_locked(hold.subject)
            prior_hold = self._routes.get_locked("hold", hold.hold_id)
            prior_transition = self._routes.get_locked("transition", transition.transition_id)
            if prior_hold is not None:
                if (
                    prior_hold == hold
                    and self._transition_from_route(prior_transition, transition.transition_id)
                    == transition
                ):
                    return hold
                self._reject_exact_conflict("hold", hold.hold_id)
            if (
                prior_transition is not None
                and self._transition_from_route(prior_transition, transition.transition_id)
                != transition
            ):
                self._reject_exact_conflict("transition", transition.transition_id)
            self._routes.invalidate_subject_snapshot_locked(hold.subject)
            result = self._partitions[partition_id].add_hold(hold)
            self._routes.set_locked("hold", hold.hold_id, result)
            self._routes.set_locked("transition", transition.transition_id, transition)
            self._promote_session_route_locked(hold.subject, partition_id)
            return result

    def request_close(
        self,
        barrier: LifecycleCloseBarrier,
        *,
        ticket_id: str,
    ) -> LifecycleClosureTicket:
        """Accept one immutable close barrier and globally exact ticket."""

        requested_id = f"{barrier.barrier_id}:requested"
        scheduled_id = f"{ticket_id}:scheduled"
        keys = (
            (self._entity_kind(barrier.subject), barrier.subject.object_id),
            ("barrier", barrier.barrier_id),
            ("ticket", ticket_id),
            ("transition", requested_id),
            ("transition", scheduled_id),
        )
        mutation_keys = (
            self._closed_transport_subject_key(barrier.subject),
            ("barrier", barrier.barrier_id),
            ("ticket", ticket_id),
            ("transition", requested_id),
            ("transition", scheduled_id),
        )
        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(mutation_keys),
            self._routes.locked(keys),
        ):
            partition_id = self._subject_partition_locked(barrier.subject)
            prior_barrier = self._routes.get_locked("barrier", barrier.barrier_id)
            if prior_barrier is not None and prior_barrier != barrier:
                self._reject_exact_conflict("barrier", barrier.barrier_id)
            prior_ticket = self._routes.get_locked("ticket", ticket_id)
            if prior_ticket is not None and not isinstance(prior_ticket, LifecycleClosureTicket):
                self._reject_exact_conflict("ticket", ticket_id)
            self._routes.invalidate_subject_snapshot_locked(barrier.subject)
            ticket = self._partitions[partition_id].request_close(
                barrier,
                ticket_id=ticket_id,
            )
            requested = LifecycleTransition(
                transition_id=requested_id,
                subject=barrier.subject,
                kind="close_requested",
                canonical_time=barrier.requested_at,
                action_id=barrier.action_id,
                transition_ordinal=0,
            )
            scheduled = LifecycleTransition(
                transition_id=scheduled_id,
                subject=barrier.subject,
                kind="close_scheduled",
                canonical_time=ticket.effective_at,
                action_id=barrier.action_id,
                transition_ordinal=1,
            )
            for transition in (requested, scheduled):
                prior = self._routes.get_locked("transition", transition.transition_id)
                if (
                    prior is not None
                    and self._transition_from_route(prior, transition.transition_id) != transition
                ):
                    self._reject_exact_conflict("transition", transition.transition_id)
            self._routes.set_locked("barrier", barrier.barrier_id, barrier)
            self._routes.set_locked("ticket", ticket_id, ticket)
            self._routes.set_locked("transition", requested_id, requested)
            self._routes.set_locked("transition", scheduled_id, scheduled)
            self._promote_session_route_locked(barrier.subject, partition_id)
            return ticket

    def close(
        self,
        ticket_id: str,
    ) -> (
        ProcessLifecycleSnapshot
        | SessionLifecycleSnapshotView
        | ServiceInstanceLifecycleSnapshot
        | TransportLifecycleSnapshot
    ):
        """Close one ticket without globally serializing unrelated hosts."""

        with self._gate.mutation():
            ticket_value = self._routes.get("ticket", ticket_id)
            if not isinstance(ticket_value, LifecycleClosureTicket):
                raise StateError(f"Unknown lifecycle closure ticket {ticket_id}")
            ticket = ticket_value
            transition = LifecycleTransition(
                transition_id=f"{ticket.ticket_id}:closed",
                subject=ticket.subject,
                kind="closed",
                canonical_time=ticket.effective_at,
                action_id=ticket.action_id,
                transition_ordinal=2,
            )
            keys = (
                (self._entity_kind(ticket.subject), ticket.subject.object_id),
                ("ticket", ticket_id),
                ("transition", transition.transition_id),
            )
            mutation_keys = (
                self._closed_transport_subject_key(ticket.subject),
                ("ticket", ticket_id),
                ("transition", transition.transition_id),
            )
            with self._ordinary_closed_transport_mutation(mutation_keys), self._routes.locked(keys):
                if self._routes.get_locked("ticket", ticket_id) != ticket:
                    raise StateError(f"Unknown lifecycle closure ticket {ticket_id}")
                partition_id = self._subject_partition_locked(ticket.subject)
                prior = self._routes.get_locked("transition", transition.transition_id)
                if (
                    prior is not None
                    and self._transition_from_route(prior, transition.transition_id) != transition
                ):
                    self._reject_exact_conflict("transition", transition.transition_id)
                self._routes.invalidate_subject_snapshot_locked(ticket.subject)
                snapshot = self._partitions[partition_id].close(ticket_id)
                self._routes.set_locked("transition", transition.transition_id, transition)
                self._promote_session_route_locked(ticket.subject, partition_id)
                return snapshot

    def add_retention_lease(self, lease: LifecycleRetentionLease) -> LifecycleRetentionLease:
        """Add one bounded reference lease under exact global identity."""

        keys = (
            (self._entity_kind(lease.subject), lease.subject.object_id),
            ("lease", lease.lease_id),
        )
        with self._gate.mutation(), self._routes.locked(keys):
            partition_id = self._subject_partition_locked(lease.subject)
            prior = self._routes.get_locked("lease", lease.lease_id)
            if prior is not None:
                if prior == lease:
                    return lease
                self._reject_exact_conflict("lease", lease.lease_id)
            result = self._partitions[partition_id].add_retention_lease(lease)
            self._routes.set_locked("lease", lease.lease_id, result)
            return result

    def release_retention_lease(self, lease_id: str) -> bool:
        """Release one exact bounded lease."""

        with self._gate.mutation():
            lease_value = self._routes.get("lease", lease_id)
            if not isinstance(lease_value, LifecycleRetentionLease):
                return False
            lease = lease_value
            keys = (
                (self._entity_kind(lease.subject), lease.subject.object_id),
                ("lease", lease_id),
            )
            with self._routes.locked(keys):
                if self._routes.get_locked("lease", lease_id) != lease:
                    return False
                partition_id = self._subject_partition_locked(lease.subject)
                released = self._partitions[partition_id].release_retention_lease(lease_id)
                if released:
                    self._routes.remove_locked("lease", lease_id)
                return released

    def acquire_foreground_lease(
        self,
        lease: LifecycleForegroundLease,
    ) -> LifecycleForegroundLease:
        """Acquire one exact session foreground resource."""

        keys = (
            ("session", lease.session_object_id),
            ("process", lease.process_object_id),
            ("foreground_lease", lease.lease_id),
        )
        mutation_keys = tuple(
            self._resource_lease_subject_key(subject)
            for subject in _LifecyclePartition._resource_lease_subjects(lease)
        )
        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(mutation_keys),
            self._routes.locked(keys),
        ):
            partition_id = self._resource_partition_locked(
                hostname=lease.hostname,
                session_object_id=lease.session_object_id,
                process_object_id=lease.process_object_id,
            )
            prior_partition = self._routes.get_locked("foreground_lease", lease.lease_id)
            if isinstance(prior_partition, int):
                prior = self._partitions[prior_partition].foreground_lease(lease.lease_id)
                if prior == lease:
                    return lease
                if prior is None:
                    self._routes.remove_locked("foreground_lease", lease.lease_id)
                else:
                    self._reject_exact_conflict("foreground_lease", lease.lease_id)
            result = self._partitions[partition_id].acquire_foreground_lease(lease)
            self._routes.set_locked("foreground_lease", lease.lease_id, partition_id)
            return result

    def foreground_lease(self, lease_id: str) -> LifecycleForegroundLease | None:
        """Return one foreground lease by exact global lease identity."""

        partition_id = self._routes.get("foreground_lease", lease_id)
        if not isinstance(partition_id, int):
            return None
        return self._partitions[partition_id].foreground_lease(lease_id)

    def foreground_lease_for(
        self,
        hostname: str,
        principal: str,
        session_object_id: str,
        process_object_id: str,
    ) -> LifecycleForegroundLease | None:
        """Return the lease for one exact session-member shell resource key."""

        key: LifecycleForegroundLeaseKey = (
            hostname.strip().casefold(),
            principal.strip().casefold(),
            session_object_id,
            process_object_id,
        )
        session_route = self._routes.get("session", session_object_id)
        partition_id = self._session_partition_from_route(session_route)
        if partition_id is None:
            return None
        return self._partitions[partition_id].foreground_lease_for(key)

    def renew_foreground_lease(
        self,
        lease_id: str,
        *,
        expected_lease_until: datetime,
        lease_until: datetime,
        canonical_time: datetime,
        action_id: str,
        concurrency_group_id: str | None = None,
        transition_ordinal: int = 0,
    ) -> LifecycleForegroundLease:
        """CAS-renew one exact foreground lease."""

        key = ("foreground_lease", lease_id)
        current = self.foreground_lease(lease_id)
        mutation_keys = tuple(
            self._resource_lease_subject_key(subject)
            for subject in (
                () if current is None else _LifecyclePartition._resource_lease_subjects(current)
            )
        )
        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(mutation_keys),
            self._routes.locked((key,)),
        ):
            partition_id = self._routes.get_locked(*key)
            if not isinstance(partition_id, int):
                raise StateError(f"Unknown lifecycle foreground lease {lease_id}")
            return self._partitions[partition_id].renew_foreground_lease(
                lease_id,
                expected_lease_until=expected_lease_until,
                lease_until=lease_until,
                canonical_time=canonical_time,
                action_id=action_id,
                concurrency_group_id=concurrency_group_id,
                transition_ordinal=transition_ordinal,
            )

    def release_foreground_lease(
        self,
        lease_id: str,
        *,
        released_at: datetime,
        action_id: str,
        transition_ordinal: int = 0,
    ) -> bool:
        """Release one exact foreground lease."""

        key = ("foreground_lease", lease_id)
        current = self.foreground_lease(lease_id)
        mutation_keys = tuple(
            self._resource_lease_subject_key(subject)
            for subject in (
                () if current is None else _LifecyclePartition._resource_lease_subjects(current)
            )
        )
        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(mutation_keys),
            self._routes.locked((key,)),
        ):
            partition_id = self._routes.get_locked(*key)
            if not isinstance(partition_id, int):
                return False
            released = self._partitions[partition_id].release_foreground_lease(
                lease_id,
                released_at=released_at,
                action_id=action_id,
                transition_ordinal=transition_ordinal,
            )
            if released:
                self._routes.remove_locked(*key)
            return released

    def acquire_singleton_lease(
        self,
        lease: LifecycleSingletonLease,
    ) -> LifecycleSingletonLease:
        """Acquire one exact non-overlapping singleton interval."""

        keys_list = [
            ("session", lease.session_object_id),
            ("singleton_lease", lease.lease_id),
        ]
        if lease.process_object_id:
            keys_list.append(("process", lease.process_object_id))
        keys = tuple(keys_list)
        mutation_keys = tuple(
            self._resource_lease_subject_key(subject)
            for subject in _LifecyclePartition._resource_lease_subjects(lease)
        )
        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(mutation_keys),
            self._routes.locked(keys),
        ):
            partition_id = self._resource_partition_locked(
                hostname=lease.hostname,
                session_object_id=lease.session_object_id,
                process_object_id=lease.process_object_id,
            )
            prior_partition = self._routes.get_locked("singleton_lease", lease.lease_id)
            if isinstance(prior_partition, int):
                prior = self._partitions[prior_partition].singleton_lease(lease.lease_id)
                if prior == lease:
                    return lease
                if prior is None:
                    self._routes.remove_locked("singleton_lease", lease.lease_id)
                else:
                    self._reject_exact_conflict("singleton_lease", lease.lease_id)
            result = self._partitions[partition_id].acquire_singleton_lease(lease)
            self._routes.set_locked("singleton_lease", lease.lease_id, partition_id)
            return result

    def singleton_lease(self, lease_id: str) -> LifecycleSingletonLease | None:
        """Return one singleton lease by exact global lease identity."""

        partition_id = self._routes.get("singleton_lease", lease_id)
        if not isinstance(partition_id, int):
            return None
        return self._partitions[partition_id].singleton_lease(lease_id)

    def singleton_lease_for(
        self,
        hostname: str,
        principal: str,
        session_object_id: str,
        logon_id: str,
        canonical_image: str,
        canonical_time: datetime,
    ) -> LifecycleSingletonLease | None:
        """Resolve one exact singleton resource at explicit canonical time."""

        key: LifecycleSingletonLeaseKey = (
            hostname.strip().casefold(),
            principal.strip().casefold(),
            session_object_id,
            logon_id.strip().casefold(),
            canonical_image.strip().replace("\\", "/").casefold(),
        )
        session_route = self._routes.get("session", session_object_id)
        partition_id = self._session_partition_from_route(session_route)
        if partition_id is None:
            return None
        return self._partitions[partition_id].singleton_lease_for(key, canonical_time)

    def singleton_lease_for_process(
        self,
        process_object_id: str,
    ) -> LifecycleSingletonLease | None:
        """Return the exact live singleton lease bound to one process object."""

        process_route = self._routes.get("process", process_object_id)
        if not isinstance(process_route, int):
            return None
        return self._partitions[process_route].singleton_lease_for_process(process_object_id)

    def bind_singleton_lease(
        self,
        lease_id: str,
        *,
        process_object_id: str,
        canonical_time: datetime,
        action_id: str,
        transition_ordinal: int = 0,
    ) -> LifecycleSingletonLease:
        """Bind a pre-allocation singleton claim to an exact process object."""

        keys = (("singleton_lease", lease_id), ("process", process_object_id))
        current = self.singleton_lease(lease_id)
        subjects = (
            [] if current is None else list(_LifecyclePartition._resource_lease_subjects(current))
        )
        subjects.append(LifecycleEntityRef("process", process_object_id))
        mutation_keys = tuple(
            self._resource_lease_subject_key(subject) for subject in dict.fromkeys(subjects)
        )
        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(mutation_keys),
            self._routes.locked(keys),
        ):
            partition_id = self._routes.get_locked("singleton_lease", lease_id)
            process_partition = self._routes.get_locked("process", process_object_id)
            if not isinstance(partition_id, int):
                raise StateError(f"Unknown lifecycle singleton lease {lease_id}")
            if process_partition != partition_id:
                raise StateError(
                    f"Lifecycle singleton lease {lease_id} cannot bind unknown/cross-host "
                    f"process {process_object_id}"
                )
            return self._partitions[partition_id].bind_singleton_lease(
                lease_id,
                process_object_id=process_object_id,
                canonical_time=canonical_time,
                action_id=action_id,
                transition_ordinal=transition_ordinal,
            )

    def renew_singleton_lease(
        self,
        lease_id: str,
        *,
        expected_lease_until: datetime,
        lease_until: datetime,
        canonical_time: datetime,
        action_id: str,
        transition_ordinal: int = 0,
    ) -> LifecycleSingletonLease:
        """CAS-renew one exact singleton lease."""

        key = ("singleton_lease", lease_id)
        current = self.singleton_lease(lease_id)
        mutation_keys = tuple(
            self._resource_lease_subject_key(subject)
            for subject in (
                () if current is None else _LifecyclePartition._resource_lease_subjects(current)
            )
        )
        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(mutation_keys),
            self._routes.locked((key,)),
        ):
            partition_id = self._routes.get_locked(*key)
            if not isinstance(partition_id, int):
                raise StateError(f"Unknown lifecycle singleton lease {lease_id}")
            return self._partitions[partition_id].renew_singleton_lease(
                lease_id,
                expected_lease_until=expected_lease_until,
                lease_until=lease_until,
                canonical_time=canonical_time,
                action_id=action_id,
                transition_ordinal=transition_ordinal,
            )

    def release_singleton_lease(
        self,
        lease_id: str,
        *,
        released_at: datetime,
        action_id: str,
        transition_ordinal: int = 0,
    ) -> bool:
        """Release one exact singleton lease."""

        key = ("singleton_lease", lease_id)
        current = self.singleton_lease(lease_id)
        mutation_keys = tuple(
            self._resource_lease_subject_key(subject)
            for subject in (
                () if current is None else _LifecyclePartition._resource_lease_subjects(current)
            )
        )
        with (
            self._gate.mutation(),
            self._ordinary_closed_transport_mutation(mutation_keys),
            self._routes.locked((key,)),
        ):
            partition_id = self._routes.get_locked(*key)
            if not isinstance(partition_id, int):
                return False
            released = self._partitions[partition_id].release_singleton_lease(
                lease_id,
                released_at=released_at,
                action_id=action_id,
                transition_ordinal=transition_ordinal,
            )
            if released:
                self._routes.remove_locked(*key)
            return released

    def retention_deadline(self, subject: LifecycleEntityRef) -> datetime | None:
        """Return one closed identity's exact bounded eviction deadline."""

        key = (self._entity_kind(subject), subject.object_id)
        with self._routes.locked((key,)):
            route = self._routes.get_locked(*key)
            if subject.kind in {"service", "transport"} and isinstance(route, int):
                partition_id, handle = self._decode_session_locator(route)
                return self._partitions[partition_id].retention_deadline_by_handle(
                    subject.kind,
                    handle,
                )
            partition_id = self._subject_partition_locked(subject)
            return self._partitions[partition_id].retention_deadline(subject)

    def advance_watermark(self, cutoff: datetime) -> tuple[LifecycleEntityRef, ...]:
        """Seal canonical time and stream bounded retention/ledger compaction."""

        canonical_cutoff = ensure_utc(cutoff)
        with self._gate.watermark():
            with self._closed_transport_preparation_lock:
                if any(
                    reservation.claimed
                    and canonical_cutoff != reservation.canonical_token.expected_watermark
                    for reservation in self._closed_transport_reservations.values()
                ):
                    raise StateError(
                        "Lifecycle watermark cannot move while a claimed closed-transport "
                        "publication fences the prior watermark"
                    )
                claimed_service_tokens = (
                    *(
                        reservation
                        for reservation in self._service_publication_reservations.values()
                    ),
                    *(reservation for reservation in self._service_closure_reservations.values()),
                )
                if any(
                    reservation.claimed
                    and canonical_cutoff != reservation.canonical_token.expected_watermark
                    for reservation in claimed_service_tokens
                ):
                    raise StateError(
                        "Lifecycle watermark cannot move while a claimed service operation "
                        "fences the prior watermark"
                    )
                if any(
                    reservation.claimed
                    and canonical_cutoff != reservation.canonical_token.expected_watermark
                    for reservation in self._action_cohort_reservations.values()
                ):
                    raise StateError(
                        "Lifecycle watermark cannot move while a claimed action cohort "
                        "fences the prior watermark"
                    )
            if self._watermark is not None and canonical_cutoff < self._watermark:
                raise StateError(
                    f"Lifecycle watermark cannot move backward: "
                    f"{canonical_cutoff.isoformat()} < {self._watermark.isoformat()}"
                )
            evicted: list[LifecycleEntityRef] = []
            removals: list[tuple[str, str]] = []
            for partition in self._partitions:
                evicted.extend(partition.advance_watermark(canonical_cutoff))
                removals.extend(partition.drain_route_removals())
            self._routes.remove_many(tuple(removals))
            self._routes.compact(max_entries=_PRIMARY_COMPACTION_PAGE)
            ledger_floor = canonical_cutoff - self._ledger_detail_retention
            if self._ledger_floor is None or ledger_floor > self._ledger_floor:
                self._ledger_floor = ledger_floor
            self._watermark = canonical_cutoff
            with self._closed_transport_preparation_lock:
                self._prune_action_cohort_reservations_locked()
            evicted.sort(key=lambda subject: (subject.kind, subject.object_id))
            return tuple(evicted)

    def stats(self) -> LifecycleRegistryStats:
        """Return a fixed-shard structural census without entry scans."""

        partition_stats = tuple(partition.stats() for partition in self._partitions)
        routes = self._routes.metrics()
        counts = routes.counts
        maximum_shard_entries = max(
            (
                stat.process_entries
                + stat.session_entries
                + stat.service_instance_entries
                + stat.transport_entries
                for stat in partition_stats
            ),
            default=0,
        )
        ledger_floors = [
            stat.ledger_floor for stat in partition_stats if stat.ledger_floor is not None
        ]
        primary_map_backing_bytes = (
            sum(stat.primary_map_backing_bytes for stat in partition_stats)
            + routes.primary_map_backing_bytes
        )
        estimated_index_bytes = (
            sum(stat.estimated_index_bytes for stat in partition_stats) + routes.estimated_bytes
        )
        return LifecycleRegistryStats(
            process_entries=sum(stat.process_entries for stat in partition_stats),
            session_entries=sum(stat.session_entries for stat in partition_stats),
            live_processes=sum(stat.live_processes for stat in partition_stats),
            live_sessions=sum(stat.live_sessions for stat in partition_stats),
            retained_processes=sum(stat.retained_processes for stat in partition_stats),
            retained_sessions=sum(stat.retained_sessions for stat in partition_stats),
            transitions=counts["transition"],
            holds=counts["hold"],
            close_barriers=counts["barrier"],
            closure_tickets=counts["ticket"],
            retention_leases=counts["lease"],
            evicted_processes=sum(stat.evicted_processes for stat in partition_stats),
            evicted_sessions=sum(stat.evicted_sessions for stat in partition_stats),
            high_water_processes=sum(stat.high_water_processes for stat in partition_stats),
            high_water_sessions=sum(stat.high_water_sessions for stat in partition_stats),
            watermark=self._watermark,
            process_index_backing_entries=sum(
                stat.process_index_backing_entries for stat in partition_stats
            ),
            session_index_backing_entries=sum(
                stat.session_index_backing_entries for stat in partition_stats
            ),
            process_temporal_live_entries=sum(
                stat.process_temporal_live_entries for stat in partition_stats
            ),
            process_temporal_backing_entries=sum(
                stat.process_temporal_backing_entries for stat in partition_stats
            ),
            process_temporal_groups=sum(stat.process_temporal_groups for stat in partition_stats),
            session_temporal_live_entries=sum(
                stat.session_temporal_live_entries for stat in partition_stats
            ),
            session_temporal_backing_entries=sum(
                stat.session_temporal_backing_entries for stat in partition_stats
            ),
            session_temporal_groups=sum(stat.session_temporal_groups for stat in partition_stats),
            temporal_stale_entries=sum(stat.temporal_stale_entries for stat in partition_stats),
            retention_deadline_entries=sum(
                stat.retention_deadline_entries for stat in partition_stats
            ),
            retention_deadline_backing_entries=sum(
                stat.retention_deadline_backing_entries for stat in partition_stats
            ),
            lease_deadline_backing_entries=sum(
                stat.lease_deadline_backing_entries for stat in partition_stats
            ),
            lookup_candidates_inspected=sum(
                stat.lookup_candidates_inspected for stat in partition_stats
            )
            + routes.lookup_candidates_inspected,
            estimated_bytes=(
                sum(stat.estimated_bytes for stat in partition_stats)
                + routes.estimated_bytes
                + routes.snapshot_cache_estimated_bytes
            ),
            estimated_index_bytes=estimated_index_bytes,
            detailed_transition_entries=counts["transition"],
            detailed_hold_entries=counts["hold"],
            compacted_transition_entries=sum(
                stat.compacted_transition_entries for stat in partition_stats
            ),
            compacted_hold_entries=sum(stat.compacted_hold_entries for stat in partition_stats),
            ledger_floor=max(ledger_floors) if ledger_floors else None,
            ledger_temporal_backing_entries=sum(
                stat.ledger_temporal_backing_entries for stat in partition_stats
            ),
            ledger_compaction_pending=any(
                stat.ledger_compaction_pending for stat in partition_stats
            ),
            ledger_commit_map_entries=sum(
                stat.ledger_commit_map_entries for stat in partition_stats
            ),
            ledger_commit_map_backing_bytes=sum(
                stat.ledger_commit_map_backing_bytes for stat in partition_stats
            ),
            lifecycle_shards_allocated=self._shard_count,
            lifecycle_shard_count=self._shard_count,
            maximum_shard_entries=maximum_shard_entries,
            primary_map_backing_bytes=primary_map_backing_bytes,
            primary_compaction_pending=(
                routes.compaction_pending
                or any(stat.primary_compaction_pending for stat in partition_stats)
            ),
            primary_compaction_work=(
                routes.compaction_work
                + sum(stat.primary_compaction_work for stat in partition_stats)
            ),
            route_entries=sum(counts.values()),
            route_map_backing_bytes=routes.primary_map_backing_bytes,
            route_compaction_pending=routes.compaction_pending,
            route_compaction_work=routes.compaction_work,
            foreground_leases=sum(stat.foreground_leases for stat in partition_stats),
            singleton_leases=sum(stat.singleton_leases for stat in partition_stats),
            resource_lease_deadline_entries=sum(
                stat.resource_lease_deadline_entries for stat in partition_stats
            ),
            resource_lease_deadline_backing_entries=sum(
                stat.resource_lease_deadline_backing_entries for stat in partition_stats
            ),
            resource_lease_subjects=sum(stat.resource_lease_subjects for stat in partition_stats),
            resource_lease_subject_bindings=sum(
                stat.resource_lease_subject_bindings for stat in partition_stats
            ),
            resource_lease_deadline_candidates_inspected=sum(
                stat.resource_lease_deadline_candidates_inspected for stat in partition_stats
            ),
            resource_lease_max_subject_bindings=max(
                (stat.resource_lease_max_subject_bindings for stat in partition_stats),
                default=0,
            ),
            retention_lease_subjects=sum(stat.retention_lease_subjects for stat in partition_stats),
            retention_lease_subject_bindings=sum(
                stat.retention_lease_subject_bindings for stat in partition_stats
            ),
            retention_lease_deadline_candidates_inspected=sum(
                stat.retention_lease_deadline_candidates_inspected for stat in partition_stats
            ),
            retention_lease_max_subject_bindings=max(
                (stat.retention_lease_max_subject_bindings for stat in partition_stats),
                default=0,
            ),
            singleton_lease_temporal_live_entries=sum(
                stat.singleton_lease_temporal_live_entries for stat in partition_stats
            ),
            singleton_lease_temporal_backing_entries=sum(
                stat.singleton_lease_temporal_backing_entries for stat in partition_stats
            ),
            singleton_lease_temporal_groups=sum(
                stat.singleton_lease_temporal_groups for stat in partition_stats
            ),
            logical_service_entries=sum(stat.logical_service_entries for stat in partition_stats),
            service_instance_entries=sum(stat.service_instance_entries for stat in partition_stats),
            live_service_instances=sum(stat.live_service_instances for stat in partition_stats),
            retained_service_instances=sum(
                stat.retained_service_instances for stat in partition_stats
            ),
            transport_entries=sum(stat.transport_entries for stat in partition_stats),
            live_transports=sum(stat.live_transports for stat in partition_stats),
            retained_transports=sum(stat.retained_transports for stat in partition_stats),
            service_process_bindings=sum(stat.service_process_bindings for stat in partition_stats),
            active_service_process_bindings=sum(
                stat.active_service_process_bindings for stat in partition_stats
            ),
            transport_session_bindings=sum(
                stat.transport_session_bindings for stat in partition_stats
            ),
            active_transport_session_bindings=sum(
                stat.active_transport_session_bindings for stat in partition_stats
            ),
            service_index_backing_entries=sum(
                stat.service_index_backing_entries for stat in partition_stats
            ),
            transport_index_backing_entries=sum(
                stat.transport_index_backing_entries for stat in partition_stats
            ),
            binding_index_backing_entries=sum(
                stat.binding_index_backing_entries for stat in partition_stats
            ),
            service_temporal_live_entries=sum(
                stat.service_temporal_live_entries for stat in partition_stats
            ),
            service_temporal_backing_entries=sum(
                stat.service_temporal_backing_entries for stat in partition_stats
            ),
            service_temporal_groups=sum(stat.service_temporal_groups for stat in partition_stats),
            transport_temporal_live_entries=sum(
                stat.transport_temporal_live_entries for stat in partition_stats
            ),
            transport_temporal_backing_entries=sum(
                stat.transport_temporal_backing_entries for stat in partition_stats
            ),
            transport_temporal_groups=sum(
                stat.transport_temporal_groups for stat in partition_stats
            ),
            service_retention_deadline_entries=sum(
                stat.service_retention_deadline_entries for stat in partition_stats
            ),
            transport_retention_deadline_entries=sum(
                stat.transport_retention_deadline_entries for stat in partition_stats
            ),
            service_evictions=sum(stat.service_evictions for stat in partition_stats),
            transport_evictions=sum(stat.transport_evictions for stat in partition_stats),
            binding_evictions=sum(stat.binding_evictions for stat in partition_stats),
            decoded_snapshot_cache_entries=routes.snapshot_cache_entries,
            decoded_snapshot_cache_capacity=routes.snapshot_cache_capacity,
            decoded_snapshot_cache_estimated_bytes=routes.snapshot_cache_estimated_bytes,
        )

    def census(self) -> LifecycleRegistryStats:
        """Return the public structural census used by scale probes."""

        return self.stats()
