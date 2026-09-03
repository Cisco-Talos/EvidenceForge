"""Bounded semantic checkpoint head for timing audit state."""

from __future__ import annotations

import sys
from collections import Counter

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.generation.timing.runtime import (
    TimingRuntime,
    _BoundedRelationshipCounter,
    _RelationshipCounterSlot,
)

from .errors import CheckpointCorruptionError
from .owner_inventory import (
    SOURCE_CLOCK_REGISTRY_CHECKPOINT_FIELDS,
    TIMING_AUDIT_CHECKPOINT_FIELDS,
    TIMING_RELATIONSHIP_COUNTER_CHECKPOINT_FIELDS,
    TIMING_RUNTIME_CHECKPOINT_FIELDS,
    assert_complete_owner_inventory,
    assert_transient_owner_state_empty,
)
from .packed import dumps, loads
from .participants import ParticipantSeal
from .store import HeadDraft

_SCHEMA_VERSION = "1"
_COUNTER_NAMES = ("sample", "repair", "saturation", "fallback")


class _TimingRuntimeHead(BaseModel):
    """Validated envelope for exact bounded audit buckets."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    mutation_version: int = Field(ge=0)
    counter_capacity: int = Field(gt=0)
    counters: dict[str, list[list[object]]]
    distribution_counts: list[list[object]] = Field(default_factory=list)


def _counter_rows(counter: _BoundedRelationshipCounter) -> list[list[object]]:
    assert_complete_owner_inventory(
        counter,
        TIMING_RELATIONSHIP_COUNTER_CHECKPOINT_FIELDS,
        owner_name="timing-relationship-counter",
    )
    return [
        [slot_id, slot.label, slot.count, slot.collided]
        for slot_id, slot in sorted(counter._slots.items())
    ]


def _decode_counter(
    rows: object,
    *,
    capacity: int,
) -> _BoundedRelationshipCounter:
    if type(rows) is not list or len(rows) > capacity:
        raise CheckpointCorruptionError("timing checkpoint counter table is invalid")
    counter = _BoundedRelationshipCounter(capacity)
    for row in rows:
        if (
            type(row) is not list
            or len(row) != 4
            or type(row[0]) is not int
            or not 0 <= row[0] < capacity
            or row[0] in counter._slots
            or type(row[1]) is not str
            or not row[1]
            or type(row[2]) is not int
            or row[2] <= 0
            or type(row[3]) is not bool
        ):
            raise CheckpointCorruptionError("timing checkpoint counter row is invalid")
        slot = _RelationshipCounterSlot(label=row[1], count=row[2], collided=row[3])
        counter._slots[row[0]] = slot
        counter._total += row[2]
        counter._estimated_slot_bytes += (
            sys.getsizeof(row[0]) + sys.getsizeof(slot) + sys.getsizeof(row[1])
        )
    return counter


def _decode_distributions(rows: object) -> Counter[str]:
    if type(rows) is not list:
        raise CheckpointCorruptionError("timing checkpoint distribution table is invalid")
    result: Counter[str] = Counter()
    for row in rows:
        if (
            type(row) is not list
            or len(row) != 2
            or type(row[0]) is not str
            or not row[0]
            or row[0] in result
            or type(row[1]) is not int
            or row[1] <= 0
        ):
            raise CheckpointCorruptionError("timing checkpoint distribution row is invalid")
        result[row[0]] = row[1]
    return result


class TimingRuntimeParticipant:
    """Persist timing audit semantics and rebuild deterministic clock caches."""

    checkpoint_owner = "timing-runtime"
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = TIMING_RUNTIME_CHECKPOINT_FIELDS

    def __init__(self, runtime: TimingRuntime) -> None:
        self.runtime = runtime

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture exact audit slots after rejecting a retained owner claim."""

        del sequence
        assert_transient_owner_state_empty(
            self.runtime,
            self.checkpoint_state_fields,
            owner_name="TimingRuntime",
        )
        assert_complete_owner_inventory(
            self.runtime.audit,
            TIMING_AUDIT_CHECKPOINT_FIELDS,
            owner_name="TimingAudit",
        )
        assert_complete_owner_inventory(
            self.runtime.clocks,
            SOURCE_CLOCK_REGISTRY_CHECKPOINT_FIELDS,
            owner_name="SourceClockRegistry",
        )
        audit = self.runtime.audit
        with audit._lock:
            counter_values = (
                audit._sample_counts,
                audit._repair_counts,
                audit._saturation_counts,
                audit._fallback_counts,
            )
            capacities = {counter._capacity for counter in counter_values}
            if len(capacities) != 1:
                raise RuntimeError("timing audit counters have inconsistent capacities")
            document = _TimingRuntimeHead(
                schema_version=self.checkpoint_schema_version,
                mutation_version=audit._mutation_version,
                counter_capacity=capacities.pop(),
                counters={
                    name: _counter_rows(counter)
                    for name, counter in zip(_COUNTER_NAMES, counter_values, strict=True)
                },
                distribution_counts=[
                    [name, count] for name, count in sorted(audit._distribution_counts.items())
                ],
            )
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(document.model_dump(mode="python")),
            )
        )

    def checkpoint_committed(self, sequence: int) -> None:
        """The bounded timing head owns no delta watermark."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """The bounded timing head owns no prepared publication state."""

        del sequence

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore audit buckets and clear deterministic source-clock caches."""

        if segments:
            raise CheckpointCorruptionError("timing checkpoint has unexpected segments")
        try:
            document = _TimingRuntimeHead.model_validate(loads(head))
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError("timing checkpoint head is invalid") from error
        if document.schema_version != self.checkpoint_schema_version:
            raise CheckpointCorruptionError("timing checkpoint schema is unsupported")
        if set(document.counters) != set(_COUNTER_NAMES):
            raise CheckpointCorruptionError("timing checkpoint counter families changed")
        decoded = {
            name: _decode_counter(document.counters[name], capacity=document.counter_capacity)
            for name in _COUNTER_NAMES
        }
        audit = self.runtime.audit
        with audit._lock:
            audit._sample_counts = decoded["sample"]
            audit._repair_counts = decoded["repair"]
            audit._saturation_counts = decoded["saturation"]
            audit._fallback_counts = decoded["fallback"]
            audit._distribution_counts = _decode_distributions(document.distribution_counts)
            audit._mutation_version = document.mutation_version
        clocks = self.runtime.clocks
        with clocks._lock:
            clocks._states.clear()
            clocks._cache_entry_estimated_bytes = 0
            clocks._high_water_mark = 0
            clocks._lookup_count = 0
            clocks._cache_hit_count = 0
            clocks._cache_miss_count = 0
            clocks._eviction_count = 0
            clocks._mutation_version = 0
