"""Bounded semantic checkpoint head for process-adjacent runtime caches."""

from __future__ import annotations

import math
from collections.abc import Hashable
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.generation.process_runtime_cache import (
    ProcessRuntimeCacheCheckpoint,
    ProcessRuntimeCacheCheckpointFamily,
    ProductionProcessRuntimeCaches,
)

from .errors import CheckpointCorruptionError
from .owner_inventory import (
    BOUNDED_RUNTIME_CACHE_CHECKPOINT_FIELDS,
    PROCESS_RUNTIME_CACHE_BUNDLE_CHECKPOINT_FIELDS,
    PROCESS_RUNTIME_REVERSE_CHECKPOINT_FIELDS,
    assert_complete_owner_inventory,
)
from .packed import dumps, loads
from .participants import ParticipantSeal
from .state_values import decode_state_value, encode_state_value
from .store import HeadDraft

_SCHEMA_VERSION = "1"
_FAMILY_ROW_WIDTH = 3
_CACHE_ROW_WIDTH = 3
_REVERSE_ROW_WIDTH = 3


class _ProcessRuntimeHead(BaseModel):
    """Validated envelope for fixed process-runtime cache families."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    families: list[list[object]] = Field(default_factory=list)
    reverse_routes: list[list[object]] = Field(default_factory=list)


def _capture_families(checkpoint: ProcessRuntimeCacheCheckpoint) -> list[list[object]]:
    return [
        [
            family.name,
            encode_state_value(family.watermark),
            [
                [encode_state_value(key), encode_state_value(value), deadline]
                for key, value, deadline in family.records
            ],
        ]
        for family in checkpoint.families
    ]


def _capture_reverse_routes(checkpoint: ProcessRuntimeCacheCheckpoint) -> list[list[object]]:
    return [
        [
            encode_state_value(process_key),
            cache_name,
            encode_state_value(cache_key),
        ]
        for process_key, cache_name, cache_key in checkpoint.reverse_routes
    ]


def _watermark(value: object) -> datetime | None:
    decoded = decode_state_value(value)
    if decoded is None:
        return None
    if type(decoded) is not datetime or decoded.tzinfo is not UTC:
        raise CheckpointCorruptionError(
            "process-runtime checkpoint watermark must be an exact UTC datetime"
        )
    return decoded


def _hashable(value: object, *, field_name: str) -> Hashable:
    try:
        hash(value)
    except TypeError as error:
        raise CheckpointCorruptionError(
            f"process-runtime checkpoint {field_name} is unhashable"
        ) from error
    return value  # type: ignore[return-value]


def _decode_families(value: object) -> tuple[ProcessRuntimeCacheCheckpointFamily, ...]:
    if type(value) is not list:
        raise CheckpointCorruptionError("process-runtime checkpoint family table is invalid")
    families: list[ProcessRuntimeCacheCheckpointFamily] = []
    seen_names: set[str] = set()
    for family_row in value:
        if (
            type(family_row) is not list
            or len(family_row) != _FAMILY_ROW_WIDTH
            or type(family_row[0]) is not str
            or not family_row[0]
            or family_row[0] in seen_names
            or type(family_row[2]) is not list
        ):
            raise CheckpointCorruptionError("process-runtime checkpoint family row is invalid")
        name = family_row[0]
        seen_names.add(name)
        watermark = _watermark(family_row[1])
        records: list[tuple[Hashable, object, float]] = []
        seen_keys: set[Hashable] = set()
        for record_row in family_row[2]:
            if (
                type(record_row) is not list
                or len(record_row) != _CACHE_ROW_WIDTH
                or type(record_row[2]) is not float
                or not math.isfinite(record_row[2])
            ):
                raise CheckpointCorruptionError("process-runtime checkpoint cache row is invalid")
            key = _hashable(
                decode_state_value(record_row[0]),
                field_name="cache key",
            )
            if key in seen_keys:
                raise CheckpointCorruptionError(
                    "process-runtime checkpoint cache key is duplicated"
                )
            seen_keys.add(key)
            records.append((key, decode_state_value(record_row[1]), record_row[2]))
        families.append(
            ProcessRuntimeCacheCheckpointFamily(
                name=name,
                watermark=watermark,
                records=tuple(records),
            )
        )
    return tuple(families)


def _process_key(value: object) -> tuple[str, int, datetime | None]:
    decoded = decode_state_value(value)
    if (
        type(decoded) is not tuple
        or len(decoded) != 3
        or type(decoded[0]) is not str
        or not decoded[0]
        or type(decoded[1]) is not int
        or decoded[1] <= 0
        or (
            decoded[2] is not None
            and (type(decoded[2]) is not datetime or decoded[2].tzinfo is not UTC)
        )
    ):
        raise CheckpointCorruptionError("process-runtime checkpoint reverse process key is invalid")
    return decoded


def _decode_reverse_routes(
    value: object,
) -> tuple[tuple[tuple[str, int, datetime | None], str, Hashable], ...]:
    if type(value) is not list:
        raise CheckpointCorruptionError("process-runtime checkpoint reverse-route table is invalid")
    routes: list[tuple[tuple[str, int, datetime | None], str, Hashable]] = []
    seen: set[tuple[tuple[str, int, datetime | None], str, Hashable]] = set()
    for row in value:
        if (
            type(row) is not list
            or len(row) != _REVERSE_ROW_WIDTH
            or type(row[1]) is not str
            or not row[1]
        ):
            raise CheckpointCorruptionError(
                "process-runtime checkpoint reverse-route row is invalid"
            )
        process_key = _process_key(row[0])
        cache_key = _hashable(
            decode_state_value(row[2]),
            field_name="reverse cache key",
        )
        route = (process_key, row[1], cache_key)
        if route in seen:
            raise CheckpointCorruptionError(
                "process-runtime checkpoint reverse route is duplicated"
            )
        seen.add(route)
        routes.append(route)
    return tuple(routes)


class ProcessRuntimeCachesParticipant:
    """Persist bounded process cache rows once and rebuild all alias indexes."""

    checkpoint_owner = "process-runtime-caches"
    checkpoint_restore_priority = 40
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = PROCESS_RUNTIME_CACHE_BUNDLE_CHECKPOINT_FIELDS

    def __init__(self, caches: ProductionProcessRuntimeCaches) -> None:
        self.caches = caches

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture visible semantic rows without compact-store or expiry backing."""

        del sequence
        assert_complete_owner_inventory(
            self.caches,
            self.checkpoint_state_fields,
            owner_name="ProductionProcessRuntimeCaches",
        )
        for name, cache in self.caches.items():
            assert_complete_owner_inventory(
                cache,
                BOUNDED_RUNTIME_CACHE_CHECKPOINT_FIELDS,
                owner_name=f"BoundedRuntimeCache[{name}]",
            )
        assert_complete_owner_inventory(
            self.caches._reverse,
            PROCESS_RUNTIME_REVERSE_CHECKPOINT_FIELDS,
            owner_name="ProcessRuntimeReverseIndex",
        )
        checkpoint = self.caches.checkpoint_records()
        document = _ProcessRuntimeHead(
            schema_version=self.checkpoint_schema_version,
            families=_capture_families(checkpoint),
            reverse_routes=_capture_reverse_routes(checkpoint),
        )
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(document.model_dump(mode="python")),
            )
        )

    def checkpoint_committed(self, sequence: int) -> None:
        """The bounded process-cache head owns no delta watermark."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """The bounded process-cache head owns no prepared publication state."""

        del sequence

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore cache rows and exact reverse routes into a fresh bundle."""

        if segments:
            raise CheckpointCorruptionError("process-runtime checkpoint has unexpected segments")
        try:
            document = _ProcessRuntimeHead.model_validate(loads(head))
            if document.schema_version != self.checkpoint_schema_version:
                raise CheckpointCorruptionError("process-runtime checkpoint schema version changed")
            checkpoint = ProcessRuntimeCacheCheckpoint(
                families=_decode_families(document.families),
                reverse_routes=_decode_reverse_routes(document.reverse_routes),
            )
            self.caches.restore_checkpoint_records(checkpoint)
        except CheckpointCorruptionError:
            raise
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError("process-runtime checkpoint head is invalid") from error


__all__ = ["ProcessRuntimeCachesParticipant"]
