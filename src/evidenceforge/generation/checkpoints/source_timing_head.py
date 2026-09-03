"""Bounded live-head checkpoint participant for source-native timing indexes."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.generation.source_timing import SourceTimingPlanner, _SourceTimingCache

from .errors import CheckpointCorruptionError
from .owner_inventory import (
    SOURCE_TIMING_PLANNER_CHECKPOINT_FIELDS,
    assert_transient_owner_state_empty,
)
from .packed import dumps, loads
from .participants import ParticipantSeal
from .state_values import decode_state_value, encode_state_value
from .store import HeadDraft

_SCHEMA_VERSION = "1"


class _SourceTimingHead(BaseModel):
    """Small validated envelope around explicitly encoded cache rows."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    watermark: str | None = None
    families: dict[str, list[object]] = Field(default_factory=dict)


def _decode_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise CheckpointCorruptionError("source timing checkpoint watermark is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CheckpointCorruptionError("source timing checkpoint watermark lacks an offset")
    return parsed


def _capture_cache(cache: _SourceTimingCache) -> list[object]:
    rows = [
        [encode_state_value(key), encode_state_value(value), deadline]
        for key, value, deadline in cache._cache.checkpoint_records()
    ]
    rows.sort(key=dumps)
    return rows


def _restore_cache(
    cache: _SourceTimingCache,
    rows: object,
    *,
    watermark: datetime | None,
    family: str,
) -> None:
    if type(rows) is not list:
        raise CheckpointCorruptionError(f"source timing checkpoint family {family!r} is invalid")
    decoded: list[tuple[object, object, float]] = []
    for row in rows:
        if type(row) is not list or len(row) != 3 or type(row[2]) not in {int, float}:
            raise CheckpointCorruptionError(
                f"source timing checkpoint family {family!r} row is invalid"
            )
        decoded.append(
            (
                decode_state_value(row[0]),
                decode_state_value(row[1]),
                float(row[2]),
            )
        )
    try:
        cache._cache.restore_checkpoint_records(tuple(decoded), watermark=watermark)
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError(
            f"source timing checkpoint family {family!r} row is invalid"
        ) from error
    cache._mutation_version = len(decoded)


class SourceTimingPlannerParticipant:
    """Persist only bounded cross-event source-timing facts."""

    checkpoint_owner = "source-timing"
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = SOURCE_TIMING_PLANNER_CHECKPOINT_FIELDS

    def __init__(self, planner: SourceTimingPlanner) -> None:
        self.planner = planner

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture visible cache rows after rejecting in-flight timing authority."""

        del sequence
        assert_transient_owner_state_empty(
            self.planner,
            self.checkpoint_state_fields,
            owner_name="SourceTimingPlanner",
        )
        families = {name: _capture_cache(cache) for name, cache in self.planner._bounded_indexes()}
        head = _SourceTimingHead(
            schema_version=self.checkpoint_schema_version,
            watermark=(
                None if self.planner._watermark is None else self.planner._watermark.isoformat()
            ),
            families=families,
        )
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(head.model_dump(mode="python")),
            )
        )

    def checkpoint_committed(self, sequence: int) -> None:
        """A bounded head has no participant-local delta watermark."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """A bounded head has no prepared mutable publication state."""

        del sequence

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore bounded semantic indexes into a freshly constructed planner."""

        if segments:
            raise CheckpointCorruptionError("source timing checkpoint has unexpected segments")
        try:
            document = _SourceTimingHead.model_validate(loads(head))
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError("source timing checkpoint head is invalid") from error
        if document.schema_version != self.checkpoint_schema_version:
            raise CheckpointCorruptionError("source timing checkpoint schema is unsupported")
        expected = {name for name, _cache in self.planner._bounded_indexes()}
        if set(document.families) != expected:
            raise CheckpointCorruptionError("source timing checkpoint family set changed")
        assert_transient_owner_state_empty(
            self.planner,
            self.checkpoint_state_fields,
            owner_name="SourceTimingPlanner",
        )
        watermark = _decode_time(document.watermark)
        for name, cache in self.planner._bounded_indexes():
            _restore_cache(
                cache,
                document.families[name],
                watermark=watermark,
                family=name,
            )
        self.planner._watermark = watermark
