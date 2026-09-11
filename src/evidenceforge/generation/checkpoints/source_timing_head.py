"""Bounded live-head checkpoint participant for source-native timing indexes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

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
from .store import HeadDraft, SegmentDraft

_SCHEMA_VERSION = "3"


class _SourceTimingHead(BaseModel):
    """Bounded live pointer state for incremental source-timing segments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    watermark: str | None = None
    segment_count: int = Field(ge=1)


class _SourceTimingSegment(BaseModel):
    """One initial base or ordered coalesced delta across timing families."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    kind: Literal["base", "delta"]
    families: dict[str, list[object]] = Field(default_factory=dict)


_TimingMutation = tuple[Literal["set", "pop"], object | None, float | None]


@dataclass(frozen=True)
class _PreparedTimingDelta:
    sequence: int
    pending: dict[str, dict[object, _TimingMutation]]
    seal: ParticipantSeal
    initial: bool


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
    with cache._lock:
        rows = [
            [encode_state_value(key), encode_state_value(value), deadline]
            for key, value, deadline in cache._cache.checkpoint_records()
        ]
    rows.sort(key=dumps)
    return rows


def _encode_mutations(mutations: dict[object, _TimingMutation]) -> list[object]:
    rows = [
        [
            kind,
            encode_state_value(key),
            None if kind == "pop" else encode_state_value(value),
            deadline,
        ]
        for key, (kind, value, deadline) in mutations.items()
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


def _apply_mutations(cache: _SourceTimingCache, rows: object, *, family: str) -> None:
    if type(rows) is not list:
        raise CheckpointCorruptionError(f"source timing checkpoint family {family!r} is invalid")
    for row in rows:
        if type(row) is not list or len(row) != 4 or row[0] not in {"set", "pop"}:
            raise CheckpointCorruptionError(
                f"source timing checkpoint family {family!r} mutation is invalid"
            )
        kind, encoded_key, encoded_value, deadline = row
        key = decode_state_value(encoded_key)
        if kind == "pop":
            if encoded_value is not None or deadline is not None:
                raise CheckpointCorruptionError(
                    f"source timing checkpoint family {family!r} pop is invalid"
                )
            cache._cache.pop(key, None)
        else:
            if type(deadline) not in {int, float}:
                raise CheckpointCorruptionError(
                    f"source timing checkpoint family {family!r} deadline is invalid"
                )
            cache._cache.set(
                key,
                decode_state_value(encoded_value),
                deadline=float(deadline),
            )
        cache._mutation_version += 1


class SourceTimingPlannerParticipant:
    """Persist only bounded cross-event source-timing facts."""

    checkpoint_owner = "source-timing"
    checkpoint_restore_priority = 20
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = SOURCE_TIMING_PLANNER_CHECKPOINT_FIELDS

    def __init__(self, planner: SourceTimingPlanner) -> None:
        self.planner = planner
        self._pending: dict[str, dict[object, _TimingMutation]] = {
            name: {} for name, _cache in planner._bounded_indexes()
        }
        self._prepared: _PreparedTimingDelta | None = None
        self._committed = False
        self._segment_count = 0
        for name, cache in planner._bounded_indexes():
            if cache._checkpoint_recorder is not None:
                raise RuntimeError(f"source timing family {name!r} already has a checkpoint owner")

            def record(
                kind: str,
                key: object,
                value: object | None,
                deadline: float | None,
                *,
                family: str = name,
            ) -> None:
                if kind not in {"set", "pop"}:
                    raise RuntimeError("source timing checkpoint mutation kind is invalid")
                self._pending[family][key] = (kind, value, deadline)  # type: ignore[assignment]

            cache._checkpoint_recorder = record

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture visible state or coalesced changes under the planner mutation lane."""

        with self.planner._preparation_lock:
            assert_transient_owner_state_empty(
                self.planner,
                self.checkpoint_state_fields,
                owner_name="SourceTimingPlanner",
            )
            if self._prepared is not None:
                if self._prepared.sequence != sequence:
                    raise RuntimeError(
                        "source timing participant already prepared another sequence"
                    )
                return self._prepared.seal
            initial = not self._committed
            pending = {name: dict(rows) for name, rows in self._pending.items()}
            if initial:
                families = {
                    name: _capture_cache(cache) for name, cache in self.planner._bounded_indexes()
                }
            else:
                families = {name: _encode_mutations(rows) for name, rows in pending.items() if rows}
            segments = (
                (
                    SegmentDraft(
                        owner=self.checkpoint_owner,
                        schema_version=self.checkpoint_schema_version,
                        payload=dumps(
                            _SourceTimingSegment(
                                schema_version=self.checkpoint_schema_version,
                                kind="base" if initial else "delta",
                                families=families,
                            ).model_dump(mode="python")
                        ),
                        record_count=sum(len(rows) for rows in families.values()),
                        compression="zlib-1",
                    ),
                )
                if initial or families
                else ()
            )
            head = _SourceTimingHead(
                schema_version=self.checkpoint_schema_version,
                watermark=(
                    None if self.planner._watermark is None else self.planner._watermark.isoformat()
                ),
                segment_count=self._segment_count + len(segments),
            )
            seal = ParticipantSeal(
                head=HeadDraft(
                    owner=self.checkpoint_owner,
                    schema_version=self.checkpoint_schema_version,
                    payload=dumps(head.model_dump(mode="python")),
                ),
                segments=segments,
            )
            self._prepared = _PreparedTimingDelta(
                sequence=sequence,
                pending=pending,
                seal=seal,
                initial=initial,
            )
            return seal

    def checkpoint_committed(self, sequence: int) -> None:
        """Advance each coalesced family watermark after durable publication."""

        with self.planner._preparation_lock:
            prepared = self._prepared
            if prepared is None or prepared.sequence != sequence:
                raise RuntimeError("source timing commit does not match its prepared sequence")
            for family, records in prepared.pending.items():
                current = self._pending[family]
                for key, mutation in records.items():
                    if current.get(key) == mutation:
                        current.pop(key)
            self._segment_count += len(prepared.seal.segments)
            self._committed = True
            self._prepared = None

    def checkpoint_aborted(self, sequence: int) -> None:
        """Retain every coalesced mutation after failed publication."""

        with self.planner._preparation_lock:
            if self._prepared is None or self._prepared.sequence != sequence:
                raise RuntimeError("source timing abort does not match its prepared sequence")
            self._prepared = None

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore bounded semantic indexes into a freshly constructed planner."""

        try:
            document = _SourceTimingHead.model_validate(loads(head))
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError("source timing checkpoint head is invalid") from error
        if document.schema_version != self.checkpoint_schema_version:
            raise CheckpointCorruptionError("source timing checkpoint schema is unsupported")
        if len(segments) != document.segment_count:
            raise CheckpointCorruptionError("source timing checkpoint segment count changed")
        expected = {name for name, _cache in self.planner._bounded_indexes()}
        assert_transient_owner_state_empty(
            self.planner,
            self.checkpoint_state_fields,
            owner_name="SourceTimingPlanner",
        )
        watermark = _decode_time(document.watermark)
        for index, payload in enumerate(segments):
            try:
                segment = _SourceTimingSegment.model_validate(loads(payload))
            except (TypeError, ValueError, ValidationError) as error:
                raise CheckpointCorruptionError(
                    "source timing checkpoint segment is invalid"
                ) from error
            if segment.schema_version != self.checkpoint_schema_version:
                raise CheckpointCorruptionError("source timing checkpoint schema is unsupported")
            if (index == 0) != (segment.kind == "base"):
                raise CheckpointCorruptionError("source timing checkpoint segment order is invalid")
            if not set(segment.families).issubset(expected) or (
                index == 0 and set(segment.families) != expected
            ):
                raise CheckpointCorruptionError("source timing checkpoint family set changed")
            for name, cache in self.planner._bounded_indexes():
                rows = segment.families.get(name, [])
                if segment.kind == "base":
                    _restore_cache(cache, rows, watermark=None, family=name)
                elif rows:
                    _apply_mutations(cache, rows, family=name)
        self.planner._watermark = watermark
        with self.planner._preparation_lock:
            self._pending = {name: {} for name in expected}
            self._segment_count = len(segments)
            self._committed = True
            self._prepared = None
