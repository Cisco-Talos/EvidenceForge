"""Bounded semantic checkpoint head for authored-intent execution evidence."""

from __future__ import annotations

from collections import Counter
from heapq import heapify

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.generation.intent_ledger import (
    IntentExecutionLedger,
    _CompactIdentityAggregate,
    _IntentExecutionAggregate,
)

from .errors import CheckpointCorruptionError
from .owner_inventory import (
    INTENT_EXECUTION_LEDGER_CHECKPOINT_FIELDS,
    assert_transient_owner_state_empty,
)
from .packed import dumps, loads
from .participants import ParticipantSeal
from .store import HeadDraft

_SCHEMA_VERSION = "1"
_DIGEST_LIMIT = 1 << 256


class _IntentLedgerHead(BaseModel):
    """Validated outer envelope for fixed-shape intent aggregates."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    identity_sample_limit: int = Field(gt=0)
    hot_identity_capacity: int = Field(gt=0)
    watermark_us: int | None = None
    aggregates: list[list[object]] = Field(default_factory=list)
    hot_identities: list[list[object]] = Field(default_factory=list)


def _identity_row(aggregate: _CompactIdentityAggregate) -> list[object]:
    return [
        aggregate.reference_count,
        aggregate.digest_xor,
        aggregate.digest_sum,
        [[identity, digest] for identity, digest in sorted(aggregate.sample.items())],
    ]


def _decode_identity(row: object, sample_limit: int) -> _CompactIdentityAggregate:
    if type(row) is not list or len(row) != 4:
        raise CheckpointCorruptionError("intent checkpoint identity aggregate is invalid")
    reference_count, digest_xor, digest_sum, samples = row
    if (
        type(reference_count) is not int
        or reference_count < 0
        or type(digest_xor) is not int
        or not 0 <= digest_xor < _DIGEST_LIMIT
        or type(digest_sum) is not int
        or not 0 <= digest_sum < _DIGEST_LIMIT
        or type(samples) is not list
        or len(samples) > sample_limit
    ):
        raise CheckpointCorruptionError("intent checkpoint identity aggregate is invalid")
    decoded = _CompactIdentityAggregate(sample_limit)
    decoded.reference_count = reference_count
    decoded.digest_xor = digest_xor
    decoded.digest_sum = digest_sum
    for sample in samples:
        if (
            type(sample) is not list
            or len(sample) != 2
            or type(sample[0]) is not str
            or not sample[0]
            or type(sample[1]) is not bytes
            or len(sample[1]) != 32
            or sample[0] in decoded.sample
        ):
            raise CheckpointCorruptionError("intent checkpoint identity sample is invalid")
        decoded.sample[sample[0]] = sample[1]
    if reference_count < len(decoded.sample):
        raise CheckpointCorruptionError("intent checkpoint identity count is invalid")
    return decoded


def _aggregate_row(intent_id: str, aggregate: _IntentExecutionAggregate) -> list[object]:
    return [
        intent_id,
        aggregate.planned,
        aggregate.duplicate_occurrence_count,
        _identity_row(aggregate.action_ids),
        _identity_row(aggregate.occurrence_ids),
        [
            [source, status, count]
            for (source, status), count in sorted(aggregate.source_counts.items())
        ],
        [[hour, count] for hour, count in sorted(aggregate.occurrence_hour_counts.items())],
    ]


def _positive_counter_rows(rows: object, *, key_width: int) -> Counter[object]:
    if type(rows) is not list:
        raise CheckpointCorruptionError("intent checkpoint counter table is invalid")
    result: Counter[object] = Counter()
    for row in rows:
        if type(row) is not list or len(row) != key_width + 1:
            raise CheckpointCorruptionError("intent checkpoint counter row is invalid")
        values = row[:-1]
        count = row[-1]
        if type(count) is not int or count <= 0:
            raise CheckpointCorruptionError("intent checkpoint counter value is invalid")
        if key_width == 1:
            if type(values[0]) is not int:
                raise CheckpointCorruptionError("intent checkpoint hour key is invalid")
            key: object = values[0]
        else:
            if any(type(value) is not str or not value for value in values):
                raise CheckpointCorruptionError("intent checkpoint source key is invalid")
            key = tuple(values)
        if key in result:
            raise CheckpointCorruptionError("intent checkpoint counter key is duplicated")
        result[key] = count
    return result


def _decode_aggregates(
    rows: object,
    sample_limit: int,
) -> dict[str, _IntentExecutionAggregate]:
    if type(rows) is not list:
        raise CheckpointCorruptionError("intent checkpoint aggregate table is invalid")
    result: dict[str, _IntentExecutionAggregate] = {}
    for row in rows:
        if type(row) is not list or len(row) != 7:
            raise CheckpointCorruptionError("intent checkpoint aggregate row is invalid")
        intent_id, planned, duplicates, action_ids, occurrence_ids, sources, hours = row
        if (
            type(intent_id) is not str
            or not intent_id
            or intent_id in result
            or type(planned) is not bool
            or type(duplicates) is not int
            or duplicates < 0
        ):
            raise CheckpointCorruptionError("intent checkpoint aggregate row is invalid")
        aggregate = _IntentExecutionAggregate(sample_limit)
        aggregate.planned = planned
        aggregate.duplicate_occurrence_count = duplicates
        aggregate.action_ids = _decode_identity(action_ids, sample_limit)
        aggregate.occurrence_ids = _decode_identity(occurrence_ids, sample_limit)
        aggregate.source_counts = _positive_counter_rows(sources, key_width=2)  # type: ignore[assignment]
        aggregate.occurrence_hour_counts = _positive_counter_rows(hours, key_width=1)  # type: ignore[assignment]
        result[intent_id] = aggregate
    return result


def _decode_hot_identities(
    rows: object,
    capacity: int,
) -> dict[tuple[str, str, str], int]:
    if type(rows) is not list or len(rows) > capacity:
        raise CheckpointCorruptionError("intent checkpoint hot identity table is invalid")
    result: dict[tuple[str, str, str], int] = {}
    for row in rows:
        if (
            type(row) is not list
            or len(row) != 4
            or any(type(value) is not str or not value for value in row[:3])
            or type(row[3]) is not int
        ):
            raise CheckpointCorruptionError("intent checkpoint hot identity row is invalid")
        key = (row[0], row[1], row[2])
        if key in result:
            raise CheckpointCorruptionError("intent checkpoint hot identity is duplicated")
        result[key] = row[3]
    return result


class IntentExecutionLedgerParticipant:
    """Capture bounded reconciliation aggregates and rebuild transient batch authority."""

    checkpoint_owner = "intent-execution-ledger"
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = INTENT_EXECUTION_LEDGER_CHECKPOINT_FIELDS

    def __init__(self, ledger: IntentExecutionLedger) -> None:
        self.ledger = ledger

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture one stable bounded head while no prepared batch is retained."""

        del sequence
        assert_transient_owner_state_empty(
            self.ledger,
            self.checkpoint_state_fields,
            owner_name="IntentExecutionLedger",
        )
        with self.ledger._lock:
            document = _IntentLedgerHead(
                schema_version=self.checkpoint_schema_version,
                identity_sample_limit=self.ledger._identity_sample_limit,
                hot_identity_capacity=self.ledger._hot_identity_capacity,
                watermark_us=self.ledger._watermark_us,
                aggregates=[
                    _aggregate_row(intent_id, aggregate)
                    for intent_id, aggregate in sorted(self.ledger._aggregates.items())
                ],
                hot_identities=[
                    [*key, timestamp]
                    for key, timestamp in sorted(self.ledger._hot_identities.items())
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
        """The bounded head owns no incremental publication watermark."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """The bounded head owns no prepared publication state."""

        del sequence

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore execution evidence into a fresh ledger and rebuild its heap."""

        if segments:
            raise CheckpointCorruptionError("intent checkpoint has unexpected segments")
        try:
            document = _IntentLedgerHead.model_validate(loads(head))
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError("intent checkpoint head is invalid") from error
        if document.schema_version != self.checkpoint_schema_version:
            raise CheckpointCorruptionError("intent checkpoint schema is unsupported")
        if (
            document.identity_sample_limit != self.ledger._identity_sample_limit
            or document.hot_identity_capacity != self.ledger._hot_identity_capacity
        ):
            raise CheckpointCorruptionError("intent checkpoint capacity configuration changed")
        aggregates = _decode_aggregates(document.aggregates, document.identity_sample_limit)
        hot_identities = _decode_hot_identities(
            document.hot_identities,
            document.hot_identity_capacity,
        )
        if document.watermark_us is None and hot_identities:
            raise CheckpointCorruptionError("intent checkpoint hot identities lack a watermark")
        if document.watermark_us is not None and any(
            timestamp > document.watermark_us for timestamp in hot_identities.values()
        ):
            raise CheckpointCorruptionError("intent checkpoint hot identity exceeds its watermark")
        with self.ledger._lock:
            self.ledger._aggregates = aggregates
            self.ledger._hot_identities = hot_identities
            self.ledger._hot_identity_heap = [
                (timestamp, key) for key, timestamp in hot_identities.items()
            ]
            heapify(self.ledger._hot_identity_heap)
            self.ledger._watermark_us = document.watermark_us
