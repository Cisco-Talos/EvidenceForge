"""Bounded packed checkpoint head for runtime local artifact versions."""

from __future__ import annotations

import math
import struct
import zlib
from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.events.content_identity import (
    FileContentIdentity,
    LocalArtifactBinaryIdentity,
    LocalArtifactIdentity,
    LocalArtifactVersionRecord,
    PeVersionInfo,
)
from evidenceforge.generation.deployment_registry import (
    LocalArtifactVersionRegistry,
    _pack_artifact_payload,
    _unpack_artifact_payload,
)
from evidenceforge.models.exceptions import StateError

from .errors import CheckpointCorruptionError
from .owner_inventory import (
    LOCAL_ARTIFACT_DEADLINE_CHECKPOINT_FIELDS,
    LOCAL_ARTIFACT_PACKED_STORE_CHECKPOINT_FIELDS,
    LOCAL_ARTIFACT_REGISTRY_CHECKPOINT_FIELDS,
    LOCAL_ARTIFACT_ROUTE_CHECKPOINT_FIELDS,
    LOCAL_ARTIFACT_SHARD_CHECKPOINT_FIELDS,
    REFERENCE_LEASE_INDEX_CHECKPOINT_FIELDS,
    assert_complete_owner_inventory,
    assert_transient_owner_state_empty,
)
from .packed import dumps, loads
from .participants import ParticipantSeal
from .state_values import decode_state_value, encode_state_value
from .store import HeadDraft

_SCHEMA_VERSION = "1"
_ROW_WIDTH = 9
_ALLOCATOR_ROW_WIDTH = 3


class _ArtifactRegistryHead(BaseModel):
    """Validated envelope for retained local artifact versions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    capacity: int = Field(gt=0)
    retention: object
    prepared_byte_capacity: int = Field(gt=0)
    shard_count: int = Field(gt=0)
    watermark: object | None
    eviction_cursor: int = Field(ge=0)
    next_reservation_id: int = Field(gt=0)
    allocators: list[list[object]] = Field(default_factory=list)
    records: list[list[object]] = Field(default_factory=list)


def _decode_record(platform: str, payload: bytes) -> LocalArtifactVersionRecord:
    try:
        values = _unpack_artifact_payload(payload)
        if len(values) != 13:
            raise ValueError("packed artifact row width changed")
        content_values = values[11]
        if type(content_values) is not list or len(content_values) != 5:
            raise ValueError("packed artifact content row is invalid")
        content = FileContentIdentity(
            file_object_id=content_values[0],
            version=content_values[1],
            size_bytes=content_values[2],
            mime_type=content_values[3],
            seed_ref=content_values[4],
        )
        artifact = LocalArtifactIdentity(
            hostname=values[0],
            principal=values[1],
            platform=platform,
            user_profile_id=values[2],
            application_profile_id=values[3],
            application_id=values[4],
            family=values[5],
            source_object_id=values[6],
            native_path=values[7],
            content_id=values[8],
            slot=values[9],
            version=values[10],
        )
        binary_values = values[12]
        binary = None
        if binary_values is not None:
            if type(binary_values) is not list or len(binary_values) != 3:
                raise ValueError("packed artifact binary row is invalid")
            version_values = binary_values[2]
            version_info = None
            if version_values is not None:
                if type(version_values) is not list or len(version_values) != 5:
                    raise ValueError("packed artifact version-info row is invalid")
                version_info = PeVersionInfo(
                    file_version=version_values[0],
                    description=version_values[1],
                    product=version_values[2],
                    company=version_values[3],
                    original_filename=version_values[4],
                )
            binary = LocalArtifactBinaryIdentity(
                artifact_version_id=artifact.artifact_version_id,
                content_id=content.content_id,
                digests=content.digests,
                platform=artifact.platform,
                architecture=binary_values[0],
                artifact_name=binary_values[1],
                pe_version_info=version_info,
            )
        record = LocalArtifactVersionRecord(artifact=artifact, content=content, binary=binary)
        if _pack_artifact_payload(artifact, record) != payload:
            raise ValueError("packed artifact row is not canonical")
        return record
    except (
        IndexError,
        KeyError,
        StateError,
        TypeError,
        UnicodeDecodeError,
        ValueError,
        struct.error,
        zlib.error,
    ) as error:
        raise CheckpointCorruptionError("local artifact checkpoint record is invalid") from error


def _capture_rows(
    registry: LocalArtifactVersionRegistry,
) -> tuple[list[list[object]], list[list[object]]]:
    rows: list[list[object]] = []
    allocators: list[list[object]] = []
    for route in registry._routes:
        assert_complete_owner_inventory(
            route,
            LOCAL_ARTIFACT_ROUTE_CHECKPOINT_FIELDS,
            owner_name="LocalArtifactRoute",
        )
    for shard in registry._shards:
        shard_live_versions: set[str] = set()
        live_handles: set[int] = set()
        assert_complete_owner_inventory(
            shard,
            LOCAL_ARTIFACT_SHARD_CHECKPOINT_FIELDS,
            owner_name=f"LocalArtifactShard[{shard.shard_id}]",
        )
        assert_complete_owner_inventory(
            shard.store,
            LOCAL_ARTIFACT_PACKED_STORE_CHECKPOINT_FIELDS,
            owner_name=f"PackedArtifactStore[{shard.shard_id}]",
        )
        assert_complete_owner_inventory(
            shard.deadlines,
            LOCAL_ARTIFACT_DEADLINE_CHECKPOINT_FIELDS,
            owner_name=f"ArtifactDeadlines[{shard.shard_id}]",
        )
        assert_complete_owner_inventory(
            shard.leases,
            REFERENCE_LEASE_INDEX_CHECKPOINT_FIELDS,
            owner_name=f"ArtifactLeases[{shard.shard_id}]",
        )
        if any(shard.store._reserved) or any(shard.store._release_pending):
            raise RuntimeError("local artifact checkpoint retains a reserved packed handle")
        leases_by_version: dict[str, list[list[object]]] = {}
        for version_id, owner, deadline, order in shard.leases.checkpoint_records():
            leases_by_version.setdefault(version_id, []).append([owner, deadline, order])
        for handle in range(shard.store._next_handle):
            if not shard.store.is_live_handle(handle):
                continue
            payload = shard.store._payload(handle)
            record = shard.store.get_record_by_handle(handle)
            if record is None or _pack_artifact_payload(record.artifact, record) != payload:
                raise RuntimeError("local artifact checkpoint packed record diverged")
            version_id = record.artifact.artifact_version_id
            shard_live_versions.add(version_id)
            live_handles.add(handle)
            deadline = shard.deadlines.deadline(handle)
            pending = version_id in shard.pending_expiry
            if (deadline is None) != pending:
                raise RuntimeError("local artifact checkpoint retention authority diverged")
            rows.append(
                [
                    version_id,
                    shard.shard_id,
                    handle,
                    record.artifact.platform,
                    payload,
                    deadline,
                    0 if deadline is None else int(shard.deadlines._orders[handle]),
                    pending,
                    leases_by_version.pop(version_id, []),
                ]
            )
        free_handles = [
            int(shard.store._free_handles[index]) for index in range(shard.store._free_handle_count)
        ]
        expected_free = set(range(shard.store._next_handle)) - live_handles
        if (
            leases_by_version
            or not shard.pending_expiry <= shard_live_versions
            or any(not shard.leases.is_leased(version_id) for version_id in shard.pending_expiry)
            or shard.deadlines._live != len(shard_live_versions - shard.pending_expiry)
            or len(free_handles) != len(set(free_handles))
            or set(free_handles) != expected_free
        ):
            raise RuntimeError("local artifact checkpoint lease authority diverged")
        allocators.append([shard.shard_id, shard.store._next_handle, free_handles])
    rows.sort(key=lambda row: row[0])
    if len(rows) != registry._live_count:
        raise RuntimeError("local artifact checkpoint live count diverged")
    return rows, allocators


def _validated_lease_rows(value: object) -> list[tuple[str, float, int]]:
    if type(value) is not list:
        raise CheckpointCorruptionError("local artifact checkpoint leases are invalid")
    rows: list[tuple[str, float, int]] = []
    seen: set[str] = set()
    prior_order = -1
    for row in value:
        if (
            type(row) is not list
            or len(row) != 3
            or type(row[0]) is not str
            or not row[0]
            or type(row[1]) not in {int, float}
            or type(row[2]) is not int
            or row[2] <= prior_order
            or row[0] in seen
        ):
            raise CheckpointCorruptionError("local artifact checkpoint leases are invalid")
        seen.add(row[0])
        prior_order = row[2]
        rows.append((row[0], float(row[1]), row[2]))
    return rows


def _restore_row(
    registry: LocalArtifactVersionRegistry,
    row: object,
    lease_rows: dict[int, list[tuple[str, str, float, int]]],
) -> tuple[int, int]:
    if (
        type(row) is not list
        or len(row) != _ROW_WIDTH
        or type(row[0]) is not str
        or not row[0]
        or type(row[1]) is not int
        or not 0 <= row[1] < registry._shard_count
        or type(row[2]) is not int
        or row[2] < 0
        or type(row[3]) is not str
        or type(row[4]) is not bytes
        or (row[5] is not None and type(row[5]) not in {int, float})
        or type(row[6]) is not int
        or type(row[7]) is not bool
    ):
        raise CheckpointCorruptionError("local artifact checkpoint row is invalid")
    record = _decode_record(row[3], row[4])
    version_id = record.artifact.artifact_version_id
    deadline = None if row[5] is None else float(row[5])
    if (
        version_id != row[0]
        or (deadline is not None and not math.isfinite(deadline))
        or (deadline is None) != row[7]
        or (deadline is None and row[6] != 0)
        or (deadline is not None and row[6] <= 0)
    ):
        raise CheckpointCorruptionError("local artifact checkpoint retention row is invalid")
    leases = _validated_lease_rows(row[8])
    shard = registry._shards[row[1]]
    if registry._existing_locator(version_id) is not None:
        raise CheckpointCorruptionError("local artifact checkpoint version is duplicated")
    handle = row[2]
    try:
        shard.store.insert_reserved(handle, record.artifact, record, packed_payload=row[4])
        shard.store.consume_reserved_handle(handle)
    except (IndexError, StateError, ValueError) as error:
        raise CheckpointCorruptionError(
            "local artifact checkpoint packed handle is invalid"
        ) from error
    registry._set_route(version_id, shard.shard_id, handle)
    if deadline is not None:
        shard.deadlines.set(handle, deadline)
        shard.deadlines._orders[handle] = row[6]
    else:
        shard.pending_expiry.add(version_id)
    lease_rows[shard.shard_id].extend(
        (version_id, owner, lease_deadline, order) for owner, lease_deadline, order in leases
    )
    shard.mutation_version += 1
    registry._live_count += 1
    return shard.shard_id, row[6]


def _prepare_allocators(
    registry: LocalArtifactVersionRegistry,
    allocators: object,
    records: list[list[object]],
) -> list[list[int]]:
    if type(allocators) is not list or len(allocators) != registry._shard_count:
        raise CheckpointCorruptionError("local artifact checkpoint allocators are invalid")
    live_handles: dict[int, set[int]] = {shard.shard_id: set() for shard in registry._shards}
    for row in records:
        if (
            type(row) is not list
            or len(row) != _ROW_WIDTH
            or type(row[1]) is not int
            or type(row[2]) is not int
            or row[1] not in live_handles
            or row[2] in live_handles[row[1]]
        ):
            raise CheckpointCorruptionError("local artifact checkpoint handles are invalid")
        live_handles[row[1]].add(row[2])
    free_by_shard: list[list[int]] = []
    for expected_shard_id, allocator in enumerate(allocators):
        if (
            type(allocator) is not list
            or len(allocator) != _ALLOCATOR_ROW_WIDTH
            or allocator[0] != expected_shard_id
            or type(allocator[1]) is not int
            or type(allocator[2]) is not list
        ):
            raise CheckpointCorruptionError("local artifact checkpoint allocator row is invalid")
        shard = registry._shards[expected_shard_id]
        next_handle = allocator[1]
        free_handles = allocator[2]
        if (
            not 0 <= next_handle <= len(shard.store._active)
            or any(type(handle) is not int for handle in free_handles)
            or len(free_handles) != len(set(free_handles))
            or any(not 0 <= handle < next_handle for handle in free_handles)
            or any(handle >= next_handle for handle in live_handles[expected_shard_id])
            or set(free_handles) != set(range(next_handle)) - live_handles[expected_shard_id]
        ):
            raise CheckpointCorruptionError(
                "local artifact checkpoint allocator topology is invalid"
            )
        shard.store._next_handle = next_handle
        for handle in range(next_handle):
            shard.store._reserved[handle] = 1
        free_by_shard.append(free_handles)
    return free_by_shard


def _finish_allocators(
    registry: LocalArtifactVersionRegistry,
    free_by_shard: list[list[int]],
) -> None:
    for shard, free_handles in zip(registry._shards, free_by_shard, strict=True):
        for position, handle in enumerate(free_handles):
            shard.store._reserved[handle] = 0
            shard.store._free_handles[position] = handle
            shard.store._free_handle_positions[handle] = position
        shard.store._free_handle_count = len(free_handles)


class LocalArtifactVersionRegistryParticipant:
    """Persist live runtime artifact payloads, deadlines, and owner leases."""

    checkpoint_owner = "local-artifacts"
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = LOCAL_ARTIFACT_REGISTRY_CHECKPOINT_FIELDS

    def __init__(self, registry: LocalArtifactVersionRegistry) -> None:
        self.registry = registry

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture the bounded live registry after rejecting prepared publications."""

        del sequence
        assert_complete_owner_inventory(
            self.registry,
            self.checkpoint_state_fields,
            owner_name="LocalArtifactVersionRegistry",
        )
        with (
            self.registry._gate.watermark(),
            self.registry._capacity_lock,
            self.registry._all_shards_locked(),
        ):
            assert_transient_owner_state_empty(
                self.registry,
                self.checkpoint_state_fields,
                owner_name="LocalArtifactVersionRegistry",
            )
            if any(self.registry._prepared_counts):
                raise RuntimeError("local artifact checkpoint retains prepared shard counts")
            records, allocators = _capture_rows(self.registry)
            document = _ArtifactRegistryHead(
                schema_version=self.checkpoint_schema_version,
                capacity=self.registry._capacity,
                retention=encode_state_value(self.registry._retention),
                prepared_byte_capacity=self.registry._prepared_byte_capacity,
                shard_count=self.registry._shard_count,
                watermark=(
                    None
                    if self.registry._watermark is None
                    else encode_state_value(self.registry._watermark)
                ),
                eviction_cursor=self.registry._eviction_cursor,
                next_reservation_id=self.registry._next_reservation_id,
                allocators=allocators,
                records=records,
            )
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(document.model_dump(mode="python")),
            )
        )

    def checkpoint_committed(self, sequence: int) -> None:
        """The bounded artifact head owns no incremental mutation tail."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """The bounded artifact head owns no prepared publication state."""

        del sequence

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Hydrate live rows into a fresh registry and rebuild packed indexes."""

        if segments:
            raise CheckpointCorruptionError("local artifact checkpoint has unexpected segments")
        try:
            document = _ArtifactRegistryHead.model_validate(loads(head))
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError("local artifact checkpoint head is invalid") from error
        retention = decode_state_value(document.retention)
        watermark = None if document.watermark is None else decode_state_value(document.watermark)
        if (
            document.schema_version != self.checkpoint_schema_version
            or document.capacity != self.registry._capacity
            or type(retention) is not timedelta
            or retention != self.registry._retention
            or document.prepared_byte_capacity != self.registry._prepared_byte_capacity
            or document.shard_count != self.registry._shard_count
            or document.eviction_cursor >= self.registry._shard_count
            or (
                watermark is not None
                and (type(watermark) is not datetime or watermark.utcoffset() != timedelta(0))
            )
        ):
            raise CheckpointCorruptionError("local artifact checkpoint configuration changed")
        if self.registry._live_count or any(shard.store for shard in self.registry._shards):
            raise ValueError("local artifact checkpoint hydration requires a fresh registry")
        self.registry._watermark = watermark
        self.registry._eviction_cursor = document.eviction_cursor
        self.registry._next_reservation_id = document.next_reservation_id
        lease_rows: dict[int, list[tuple[str, str, float, int]]] = {
            shard.shard_id: [] for shard in self.registry._shards
        }
        maximum_orders = [0] * self.registry._shard_count
        deadline_orders: list[set[int]] = [set() for _ in range(self.registry._shard_count)]
        prior_version = ""
        for row in document.records:
            if (
                type(row) is not list
                or not row
                or type(row[0]) is not str
                or row[0] <= prior_version
            ):
                raise CheckpointCorruptionError("local artifact checkpoint rows are not ordered")
            prior_version = row[0]
        free_by_shard = _prepare_allocators(
            self.registry,
            document.allocators,
            document.records,
        )
        for row in document.records:
            shard_id, order = _restore_row(self.registry, row, lease_rows)
            if order and order in deadline_orders[shard_id]:
                raise CheckpointCorruptionError(
                    "local artifact checkpoint deadline order is duplicated"
                )
            deadline_orders[shard_id].add(order)
            maximum_orders[shard_id] = max(maximum_orders[shard_id], order)
        _finish_allocators(self.registry, free_by_shard)
        for shard in self.registry._shards:
            try:
                shard.leases.restore_checkpoint_records(
                    tuple(sorted(lease_rows[shard.shard_id], key=lambda row: row[3]))
                )
            except (TypeError, ValueError) as error:
                raise CheckpointCorruptionError(
                    "local artifact checkpoint lease table is invalid"
                ) from error
            shard.deadlines._order_counter = maximum_orders[shard.shard_id]
            shard.deadlines.compact(force=True)
            if any(not shard.leases.is_leased(version_id) for version_id in shard.pending_expiry):
                raise CheckpointCorruptionError(
                    "local artifact pending expiry has no retained lease"
                )
        self.registry._high_water_mark = self.registry._live_count


__all__ = ["LocalArtifactVersionRegistryParticipant"]
