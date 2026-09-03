"""Bounded semantic checkpoint head for canonical network runtime state."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.generation.network_runtime import (
    NetworkRuntimePointFamily,
    NetworkTransactionRuntime,
    NetworkTransportLease,
    _canonical_ip,
    _canonical_key,
    _canonical_value,
    _IndexedExpiryHeap,
    _IndexedTransportDeadlineHeap,
    _network_transport_occurrence_stable_id,
    _point_key_order,
    _PointSlot,
    _transport_lease_digest_value,
    _TransportLeaseRecord,
)

from .errors import CheckpointCorruptionError
from .owner_inventory import (
    NETWORK_TRANSACTION_RUNTIME_CHECKPOINT_FIELDS,
    assert_complete_owner_inventory,
    assert_transient_owner_state_empty,
)
from .packed import dumps, loads
from .participants import ParticipantSeal
from .state_values import decode_state_value, encode_state_value
from .store import HeadDraft

_SCHEMA_VERSION = "1"
_MAX_TIME = datetime.max.replace(tzinfo=UTC)


class _NetworkRuntimeHead(BaseModel):
    """Validated envelope for bounded points, leases, and freshness rows."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    window_start: object
    window_end: object
    tombstone_retention: object
    watermark: object
    next_preparation_id: int = Field(gt=0)
    next_point_ordinal: int = Field(gt=0)
    next_transport_ordinal: int = Field(gt=0)
    points: list[list[object]] = Field(default_factory=list)
    transports: list[list[object]] = Field(default_factory=list)
    freshness: list[list[object]] = Field(default_factory=list)
    state_digest: str


def _datetime(value: object, *, field_name: str) -> datetime:
    decoded = decode_state_value(value)
    if type(decoded) is not datetime or decoded.tzinfo is not UTC:
        raise CheckpointCorruptionError(
            f"network runtime checkpoint {field_name} must be an exact UTC datetime"
        )
    return decoded


def _transport_key(value: object) -> tuple[str, int, str, int, str]:
    if (
        type(value) is not tuple
        or len(value) != 5
        or type(value[0]) is not str
        or not value[0]
        or type(value[1]) is not int
        or not 1 <= value[1] <= 65_535
        or type(value[2]) is not str
        or not value[2]
        or type(value[3]) is not int
        or not 0 <= value[3] <= 65_535
        or value[4] not in {"tcp", "udp"}
    ):
        raise CheckpointCorruptionError("network runtime checkpoint transport key is invalid")
    src_ip, src_port, dst_ip, dst_port, protocol = value
    if (
        _canonical_ip(src_ip, field_name="checkpoint transport source IP") != src_ip
        or _canonical_ip(dst_ip, field_name="checkpoint transport destination IP") != dst_ip
    ):
        raise CheckpointCorruptionError("network runtime checkpoint transport key is not canonical")
    return src_ip, src_port, dst_ip, dst_port, protocol


def _capture_points(runtime: NetworkTransactionRuntime) -> list[list[object]]:
    return [
        [
            family.value,
            encode_state_value(key),
            slot.generation,
            encode_state_value(slot.value),
            encode_state_value(slot.expires_at),
            encode_state_value(slot.tombstone_until),
            slot.ordinal,
        ]
        for (family, key), slot in sorted(
            runtime._points.items(), key=lambda row: _point_key_order(row[0])
        )
    ]


def _capture_transports(runtime: NetworkTransactionRuntime) -> list[list[object]]:
    deadlines = {
        occurrence_id: (deadline, ordinal)
        for deadline, ordinal, occurrence_id in runtime._transport_lease_deadlines._entries
    }
    if set(deadlines) != set(runtime._transport_records_by_occurrence):
        raise RuntimeError("network runtime transport deadline authority diverged")
    rows: list[list[object]] = []
    for occurrence_id, record in sorted(runtime._transport_records_by_occurrence.items()):
        if not record.committed or record.lease.occurrence_stable_id != occurrence_id:
            raise RuntimeError("network runtime retained a non-committed transport")
        deadline, ordinal = deadlines[occurrence_id]
        lease = record.lease
        rows.append(
            [
                lease.intent_stable_id,
                lease.src_ip,
                lease.src_port,
                lease.dst_ip,
                lease.dst_port,
                lease.protocol,
                encode_state_value(lease.opened_at),
                encode_state_value(lease.closed_at),
                lease.occurrence_stable_id,
                lease.automatic,
                record.preparation_id,
                record.candidate_inspections,
                record.adaptive_reuse,
                encode_state_value(deadline),
                ordinal,
            ]
        )
    return rows


def _capture_freshness(runtime: NetworkTransactionRuntime) -> list[list[object]]:
    deadlines = {
        key: (deadline, ordinal)
        for deadline, ordinal, key in runtime._transport_freshness_deadlines._entries
    }
    if set(deadlines) != set(runtime._transport_freshness):
        raise RuntimeError("network runtime freshness deadline authority diverged")
    return [
        [
            encode_state_value(key),
            encode_state_value(seen_at),
            encode_state_value(deadlines[key][0]),
            deadlines[key][1],
        ]
        for key, seen_at in sorted(runtime._transport_freshness.items())
    ]


def _restore_points(
    runtime: NetworkTransactionRuntime, rows: object, *, watermark: datetime
) -> None:
    if type(rows) is not list:
        raise CheckpointCorruptionError("network runtime checkpoint point table is invalid")
    ordinals: set[int] = set()
    for row in rows:
        if (
            type(row) is not list
            or len(row) != 7
            or type(row[0]) is not str
            or type(row[2]) is not int
            or row[2] <= 0
            or type(row[6]) is not int
            or row[6] <= 0
            or row[6] in ordinals
        ):
            raise CheckpointCorruptionError("network runtime checkpoint point row is invalid")
        try:
            family = NetworkRuntimePointFamily(row[0])
            key = _canonical_key(decode_state_value(row[1]))  # type: ignore[arg-type]
            value = decode_state_value(row[3])
            expires_at = _datetime(row[4], field_name="point expiry")
            tombstone_until_value = decode_state_value(row[5])
        except (TypeError, ValueError) as error:
            raise CheckpointCorruptionError(
                "network runtime checkpoint point row is invalid"
            ) from error
        if tombstone_until_value is not None and (
            type(tombstone_until_value) is not datetime or tombstone_until_value.tzinfo is not UTC
        ):
            raise CheckpointCorruptionError("network runtime checkpoint tombstone is invalid")
        point_key = (family, key)
        if point_key in runtime._points:
            raise CheckpointCorruptionError("network runtime checkpoint point is duplicated")
        if tombstone_until_value is None:
            try:
                value = _canonical_value(value)
            except ValueError as error:
                raise CheckpointCorruptionError(
                    "network runtime checkpoint point value is invalid"
                ) from error
            if expires_at <= watermark:
                raise CheckpointCorruptionError(
                    "network runtime checkpoint live point predates its watermark"
                )
            runtime._live_points += 1
        else:
            if value is not None or expires_at != _MAX_TIME or tombstone_until_value <= watermark:
                raise CheckpointCorruptionError("network runtime checkpoint tombstone is invalid")
            runtime._tombstone_points += 1
        slot = _PointSlot(row[2], value, expires_at, tombstone_until_value, row[6])
        runtime._points[point_key] = slot
        runtime._point_state_xor ^= runtime._point_slot_state_component(point_key, slot)
        deadline = expires_at if tombstone_until_value is None else tombstone_until_value
        if deadline != _MAX_TIME:
            kind = "live" if tombstone_until_value is None else "tombstone"
            runtime._expiry_heap.replace(
                point_key,
                (deadline, slot.ordinal, family, key, slot.generation, kind),
            )
        ordinals.add(slot.ordinal)
    if ordinals and runtime._next_point_ordinal <= max(ordinals):
        raise CheckpointCorruptionError("network runtime checkpoint point allocator regressed")


def _restore_transports(
    runtime: NetworkTransactionRuntime,
    rows: object,
    *,
    watermark: datetime,
) -> None:
    if type(rows) is not list:
        raise CheckpointCorruptionError("network runtime checkpoint transport table is invalid")
    seen_deadline_ordinals: set[int] = set()
    for row in rows:
        if (
            type(row) is not list
            or len(row) != 15
            or type(row[0]) is not str
            or not row[0]
            or type(row[1]) is not str
            or type(row[2]) is not int
            or not 1 <= row[2] <= 65_535
            or type(row[3]) is not str
            or type(row[4]) is not int
            or not 0 <= row[4] <= 65_535
            or row[5] not in {"tcp", "udp"}
            or type(row[8]) is not str
            or not row[8]
            or type(row[9]) is not bool
            or type(row[10]) is not int
            or row[10] <= 0
            or type(row[11]) is not int
            or row[11] < 0
            or type(row[12]) is not bool
            or type(row[14]) is not int
            or row[14] <= 0
            or row[14] in seen_deadline_ordinals
        ):
            raise CheckpointCorruptionError("network runtime checkpoint transport row is invalid")
        tuple_key = _transport_key((row[1], row[2], row[3], row[4], row[5]))
        opened_at = _datetime(row[6], field_name="transport opening")
        closed_at = _datetime(row[7], field_name="transport closing")
        deadline = _datetime(row[13], field_name="transport deadline")
        if (
            opened_at < runtime._window_start
            or closed_at < opened_at
            or closed_at > runtime._window_end
            or deadline != closed_at
            or deadline <= watermark
            or row[8] in runtime._transport_records_by_occurrence
            or row[8]
            != _network_transport_occurrence_stable_id(
                row[0],
                src_ip=tuple_key[0],
                src_port=tuple_key[1],
                dst_ip=tuple_key[2],
                dst_port=tuple_key[3],
                protocol=tuple_key[4],
                opened_at=opened_at,
            )
        ):
            raise CheckpointCorruptionError("network runtime checkpoint transport row is invalid")
        lease = NetworkTransportLease(
            intent_stable_id=row[0],
            src_ip=row[1],
            src_port=row[2],
            dst_ip=row[3],
            dst_port=row[4],
            protocol=row[5],
            opened_at=opened_at,
            closed_at=closed_at,
            occurrence_stable_id=row[8],
            automatic=row[9],
        )
        record = _TransportLeaseRecord(
            lease=lease,
            preparation_id=row[10],
            candidate_inspections=row[11],
            adaptive_reuse=row[12],
            committed=True,
        )
        if not runtime._transport_interval_available_locked(tuple_key, opened_at, closed_at):
            raise CheckpointCorruptionError("network runtime checkpoint transports overlap")
        runtime._insert_transport_record_locked(record)
        runtime._transport_lease_deadlines.replace(
            lease.occurrence_stable_id,
            (deadline, row[14], lease.occurrence_stable_id),
        )
        runtime._transport_state_xor ^= runtime._state_component(
            "network-transport-lease-v1",
            _transport_lease_digest_value(lease),
        )
        runtime._live_transport_leases += 1
        seen_deadline_ordinals.add(row[14])
    if seen_deadline_ordinals and runtime._next_transport_ordinal <= max(seen_deadline_ordinals):
        raise CheckpointCorruptionError("network runtime checkpoint transport allocator regressed")


def _restore_freshness(
    runtime: NetworkTransactionRuntime,
    rows: object,
    *,
    watermark: datetime,
) -> None:
    if type(rows) is not list:
        raise CheckpointCorruptionError("network runtime checkpoint freshness table is invalid")
    seen_ordinals: set[int] = set()
    for row in rows:
        if type(row) is not list or len(row) != 4 or type(row[3]) is not int or row[3] <= 0:
            raise CheckpointCorruptionError("network runtime checkpoint freshness row is invalid")
        key = _transport_key(decode_state_value(row[0]))
        seen_at = _datetime(row[1], field_name="freshness observation")
        deadline = _datetime(row[2], field_name="freshness deadline")
        if (
            key in runtime._transport_freshness
            or deadline <= watermark
            or deadline < seen_at
            or not runtime._window_start <= seen_at <= runtime._window_end
            or row[3] in seen_ordinals
        ):
            raise CheckpointCorruptionError("network runtime checkpoint freshness row is invalid")
        runtime._transport_freshness[key] = seen_at
        runtime._transport_freshness_deadlines.replace(key, (deadline, row[3], key))
        runtime._transport_state_xor ^= runtime._state_component(
            "network-transport-freshness-v1",
            (key, seen_at),
        )
        seen_ordinals.add(row[3])
    if seen_ordinals and runtime._next_transport_ordinal <= max(seen_ordinals):
        raise CheckpointCorruptionError("network runtime checkpoint freshness allocator regressed")


class NetworkTransactionRuntimeParticipant:
    """Persist bounded network points and committed transport authority."""

    checkpoint_owner = "network-runtime"
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = NETWORK_TRANSACTION_RUNTIME_CHECKPOINT_FIELDS

    def __init__(self, runtime: NetworkTransactionRuntime) -> None:
        self.runtime = runtime

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture bounded semantic rows after rejecting in-flight capabilities."""

        del sequence
        assert_complete_owner_inventory(
            self.runtime,
            self.checkpoint_state_fields,
            owner_name="NetworkTransactionRuntime",
        )
        with self.runtime._lock:
            assert_transient_owner_state_empty(
                self.runtime,
                self.checkpoint_state_fields,
                owner_name="NetworkTransactionRuntime",
            )
            document = _NetworkRuntimeHead(
                schema_version=self.checkpoint_schema_version,
                window_start=encode_state_value(self.runtime._window_start),
                window_end=encode_state_value(self.runtime._window_end),
                tombstone_retention=encode_state_value(self.runtime._tombstone_retention),
                watermark=encode_state_value(self.runtime._watermark),
                next_preparation_id=self.runtime._next_preparation_id,
                next_point_ordinal=self.runtime._next_point_ordinal,
                next_transport_ordinal=self.runtime._next_transport_ordinal,
                points=_capture_points(self.runtime),
                transports=_capture_transports(self.runtime),
                freshness=_capture_freshness(self.runtime),
                state_digest=self.runtime._state_digest_locked(),
            )
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(document.model_dump(mode="python")),
            )
        )

    def checkpoint_committed(self, sequence: int) -> None:
        """The bounded network head owns no delta watermark."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """The bounded network head owns no prepared publication state."""

        del sequence

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore bounded authority and rebuild all network indexes and hashes."""

        if segments:
            raise CheckpointCorruptionError("network runtime checkpoint has unexpected segments")
        try:
            document = _NetworkRuntimeHead.model_validate(loads(head))
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError("network runtime checkpoint head is invalid") from error
        if document.schema_version != self.checkpoint_schema_version:
            raise CheckpointCorruptionError("network runtime checkpoint schema is unsupported")
        window_start = _datetime(document.window_start, field_name="window start")
        window_end = _datetime(document.window_end, field_name="window end")
        tombstone_retention = decode_state_value(document.tombstone_retention)
        watermark = _datetime(document.watermark, field_name="watermark")
        if (
            window_start != self.runtime._window_start
            or window_end != self.runtime._window_end
            or tombstone_retention != self.runtime._tombstone_retention
            or not window_start <= watermark <= window_end
        ):
            raise CheckpointCorruptionError("network runtime checkpoint configuration changed")
        with self.runtime._lock:
            if (
                self.runtime._points
                or self.runtime._transport_records_by_occurrence
                or self.runtime._transport_freshness
            ):
                raise ValueError("network runtime checkpoint hydration requires a fresh runtime")
            self.runtime._watermark = watermark
            self.runtime._next_preparation_id = document.next_preparation_id
            self.runtime._next_point_ordinal = document.next_point_ordinal
            self.runtime._next_transport_ordinal = document.next_transport_ordinal
            self.runtime._expiry_heap = _IndexedExpiryHeap()
            self.runtime._transport_lease_deadlines = _IndexedTransportDeadlineHeap()
            self.runtime._transport_freshness_deadlines = _IndexedTransportDeadlineHeap()
            self.runtime._point_state_xor = 0
            self.runtime._transport_state_xor = 0
            self.runtime._live_points = 0
            self.runtime._tombstone_points = 0
            self.runtime._live_transport_leases = 0
            _restore_points(self.runtime, document.points, watermark=watermark)
            _restore_transports(self.runtime, document.transports, watermark=watermark)
            _restore_freshness(self.runtime, document.freshness, watermark=watermark)
            preparation_ids = {
                record.preparation_id
                for record in self.runtime._transport_records_by_occurrence.values()
            }
            if preparation_ids and self.runtime._next_preparation_id <= max(preparation_ids):
                raise CheckpointCorruptionError(
                    "network runtime checkpoint preparation allocator regressed"
                )
            self.runtime._last_result = None
            self.runtime._transport_candidate_inspections = 0
            self.runtime._peak_transport_bucket_occupancy = max(
                (len(bucket) for bucket in self.runtime._transport_buckets.values()),
                default=0,
            )
            self.runtime._adaptive_transport_reuses = 0
            self.runtime._transport_exhaustions = 0
            if self.runtime._state_digest_locked() != document.state_digest:
                raise CheckpointCorruptionError("network runtime checkpoint state digest changed")


__all__ = ["NetworkTransactionRuntimeParticipant"]
