# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Independent authored-intent ledger for future ground-truth reconciliation."""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from heapq import heappop, heappush
from threading import RLock
from typing import TYPE_CHECKING

from pydantic import BaseModel

from evidenceforge.events.contracts import SemanticOccurrenceKey
from evidenceforge.utils.rng import stable_uuid

if TYPE_CHECKING:
    from evidenceforge.models.scenario import Scenario


class IntentSection(StrEnum):
    """Authored narrative section that owns one intent."""

    STORYLINE = "storyline"
    RED_HERRING = "red_herring"


@dataclass(frozen=True, slots=True)
class AuthoredIntent:
    """One immutable typed event specification captured before planning."""

    intent_id: str
    section: IntentSection
    step_id: str
    event_type: str
    semantic_instance_key: str
    authored_time: str
    actor: str
    system: str
    activity: str


@dataclass(frozen=True, slots=True)
class IntentReconciliation:
    """Comparison between independent authored intent and planned intent references."""

    expected_intent_ids: frozenset[str]
    planned_intent_ids: frozenset[str]
    missing_intent_ids: frozenset[str]
    unexpected_intent_ids: frozenset[str]

    @property
    def complete(self) -> bool:
        """Return whether planning accounts for every and only authored intent."""

        return not self.missing_intent_ids and not self.unexpected_intent_ids


@dataclass(frozen=True, slots=True)
class AuthoredIntentLedger:
    """Frozen authored oracle retained independently from generated occurrences."""

    scenario_name: str
    intents: tuple[AuthoredIntent, ...]

    @classmethod
    def from_scenario(cls, scenario: Scenario) -> AuthoredIntentLedger:
        """Capture typed storyline and red-herring intent without consulting generation output."""

        intents: list[AuthoredIntent] = []
        duplicate_counts: Counter[tuple[IntentSection, str, str]] = Counter()
        sections = (
            (IntentSection.STORYLINE, scenario.storyline or []),
            (IntentSection.RED_HERRING, scenario.red_herrings or []),
        )
        for section, steps in sections:
            for step in steps:
                for spec in step.events:
                    fingerprint = _semantic_spec_fingerprint(spec)
                    peer_key = (section, step.id, fingerprint)
                    peer_ordinal = duplicate_counts[peer_key]
                    duplicate_counts[peer_key] += 1
                    semantic_instance_key = f"{fingerprint}:{peer_ordinal}"
                    intents.append(
                        AuthoredIntent(
                            intent_id=stable_uuid(
                                "authored-intent",
                                scenario.name,
                                section.value,
                                step.id,
                                semantic_instance_key,
                            ),
                            section=section,
                            step_id=step.id,
                            event_type=spec.type,
                            semantic_instance_key=semantic_instance_key,
                            authored_time=step.time,
                            actor=step.actor,
                            system=step.system,
                            activity=step.activity,
                        )
                    )
        return cls(scenario_name=scenario.name, intents=tuple(intents))

    @property
    def intent_ids(self) -> frozenset[str]:
        """Return all authored intent IDs."""

        return frozenset(intent.intent_id for intent in self.intents)

    def reconcile(self, planned_intent_ids: Iterable[str]) -> IntentReconciliation:
        """Compare authored intent with the IDs acknowledged by an action planner."""

        expected = self.intent_ids
        planned = frozenset(planned_intent_ids)
        return IntentReconciliation(
            expected_intent_ids=expected,
            planned_intent_ids=planned,
            missing_intent_ids=expected - planned,
            unexpected_intent_ids=planned - expected,
        )

    def intent_at(
        self,
        section: IntentSection,
        step_id: str,
        event_index: int,
    ) -> AuthoredIntent:
        """Return the authored intent at one typed step-relative position."""

        matches = tuple(
            intent
            for intent in self.intents
            if intent.section == section and intent.step_id == step_id
        )
        try:
            return matches[event_index]
        except IndexError as exc:
            raise KeyError(
                f"No authored intent for {section.value} step {step_id!r} event {event_index}"
            ) from exc


@dataclass(frozen=True, slots=True)
class IntentSourceObservation:
    """One source-observation counter attached to an authored intent."""

    source: str
    status: str
    count: int


@dataclass(frozen=True, slots=True)
class IntentWindowCount:
    """Bounded bucket-aligned occurrence count at one reporting horizon."""

    window: str
    count: int


@dataclass(frozen=True, slots=True)
class IntentExecutionSnapshot:
    """Immutable bounded execution evidence for one authored intent.

    ``action_ids`` and ``occurrence_ids`` are deterministic diagnostic samples,
    never complete duration-wide identity sets.  Counts and commutative digests
    are the authoritative reconciliation values.
    """

    intent_id: str
    planned: bool
    action_ids: tuple[str, ...]
    occurrence_ids: tuple[str, ...]
    action_reference_count: int
    occurrence_reference_count: int
    action_digest: str
    occurrence_digest: str
    duplicate_occurrence_count: int
    window_occurrences: tuple[IntentWindowCount, ...]
    source_observations: tuple[IntentSourceObservation, ...]

    @property
    def source_status(self) -> dict[str, dict[str, int]]:
        """Return source observations in the ground-truth manifest shape."""

        result: dict[str, dict[str, int]] = {}
        for observation in self.source_observations:
            result.setdefault(observation.source, {})[observation.status] = observation.count
        return result

    @property
    def occurrence_window_counts(self) -> dict[str, int]:
        """Return bucket-aligned occurrence counts for the fixed reporting horizons."""

        return {window.window: window.count for window in self.window_occurrences}


@dataclass(frozen=True, slots=True)
class IntentExecutionLedgerDiagnostics:
    """Bounded-retention diagnostics used by million-occurrence scale probes."""

    watermark: datetime | None
    aggregate_intent_count: int
    hot_identity_count: int
    hot_identity_capacity: int
    hot_horizon_seconds: int
    window_bucket_count: int
    window_bucket_capacity: int
    source_aggregate_count: int
    sample_identity_count: int
    retained_candidate_count: int
    retained_bytes: int


_IDENTITY_SAMPLE_LIMIT = 8
_HOT_IDENTITY_CAPACITY = 65_536
_HOT_IDENTITY_HORIZON = timedelta(days=7)
_WINDOW_HORIZON_HOURS = 30 * 24
_WINDOWS: tuple[tuple[str, int], ...] = (("24h", 24), ("7d", 7 * 24), ("30d", 30 * 24))
_DIGEST_MODULUS = 1 << 256


@dataclass(slots=True)
class _CompactIdentityAggregate:
    """Order-independent count/digest plus a fixed-size deterministic sample."""

    sample_limit: int
    reference_count: int = 0
    digest_xor: int = 0
    digest_sum: int = 0
    sample: dict[str, bytes] = field(default_factory=dict)

    def record(self, identity: str) -> None:
        encoded_digest = self.sample.get(identity)
        if encoded_digest is None:
            encoded_digest = hashlib.sha256(identity.encode("utf-8")).digest()
        digest_value = int.from_bytes(encoded_digest, "big")
        self.reference_count += 1
        self.digest_xor ^= digest_value
        self.digest_sum = (self.digest_sum + digest_value) % _DIGEST_MODULUS
        if identity in self.sample:
            return
        candidate_rank = (encoded_digest, identity)
        if len(self.sample) < self.sample_limit:
            self.sample[identity] = encoded_digest
            return
        worst_identity, worst_digest = max(
            self.sample.items(),
            key=lambda item: (item[1], item[0]),
        )
        if candidate_rank < (worst_digest, worst_identity):
            del self.sample[worst_identity]
            self.sample[identity] = encoded_digest

    @property
    def digest(self) -> str:
        payload = (
            f"intent-identities-v1:{self.reference_count}:"
            f"{self.digest_xor:064x}:{self.digest_sum:064x}"
        )
        return hashlib.sha256(payload.encode("ascii")).hexdigest()

    @property
    def sampled_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self.sample))


@dataclass(slots=True)
class _IntentExecutionAggregate:
    """Fixed-shape mutable aggregate for one authored or unexpected intent."""

    sample_limit: int
    planned: bool = False
    duplicate_occurrence_count: int = 0
    action_ids: _CompactIdentityAggregate = field(init=False)
    occurrence_ids: _CompactIdentityAggregate = field(init=False)
    source_counts: Counter[tuple[str, str]] = field(default_factory=Counter)
    occurrence_hour_counts: Counter[int] = field(default_factory=Counter)

    def __post_init__(self) -> None:
        self.action_ids = _CompactIdentityAggregate(self.sample_limit)
        self.occurrence_ids = _CompactIdentityAggregate(self.sample_limit)


class IntentExecutionLedger:
    """Thread-safe bounded recorder for authored-intent reconciliation.

    Lifetime execution truth is retained as counts and commutative digests.  A
    global exact-ID cache exists only for the seven-day hot horizon and is also
    capacity bounded, so one high-volume intent cannot grow memory with run
    duration.  Thirty days of hourly occurrence counters support fixed 24h/7d/
    30d reporting windows without retaining individual timestamps.
    """

    def __init__(
        self,
        authored: AuthoredIntentLedger,
        *,
        hot_identity_capacity: int = _HOT_IDENTITY_CAPACITY,
        identity_sample_limit: int = _IDENTITY_SAMPLE_LIMIT,
    ):
        if hot_identity_capacity <= 0:
            raise ValueError("hot_identity_capacity must be positive")
        if identity_sample_limit <= 0:
            raise ValueError("identity_sample_limit must be positive")
        self._authored = authored
        self._authored_ids = authored.intent_ids
        self._aggregates: dict[str, _IntentExecutionAggregate] = {}
        self._hot_identity_capacity = hot_identity_capacity
        self._identity_sample_limit = identity_sample_limit
        self._hot_identities: dict[tuple[str, str, str], int] = {}
        self._hot_identity_heap: list[tuple[int, tuple[str, str, str]]] = []
        self._watermark_us: int | None = None
        self._lock = RLock()

    def _aggregate(self, intent_id: str) -> _IntentExecutionAggregate:
        aggregate = self._aggregates.get(intent_id)
        if aggregate is None:
            aggregate = _IntentExecutionAggregate(self._identity_sample_limit)
            self._aggregates[intent_id] = aggregate
        return aggregate

    def mark_planned(self, intent_id: str) -> None:
        """Record that execution entered the planner path for one authored intent."""

        with self._lock:
            self._aggregate(intent_id).planned = True

    def record_occurrence(
        self,
        intent_id: str,
        occurrence_key: SemanticOccurrenceKey,
        timestamp: datetime | None = None,
    ) -> None:
        """Record one occurrence into bounded aggregates and the exact hot cache."""

        with self._lock:
            timestamp_us = self._advance_watermark_locked(timestamp)
            aggregate = self._aggregate(intent_id)
            aggregate.action_ids.record(occurrence_key.action_id)
            aggregate.occurrence_ids.record(occurrence_key.occurrence_id)
            if self._touch_hot_identity_locked(
                (intent_id, "occurrence", occurrence_key.occurrence_id),
                timestamp_us,
            ):
                aggregate.duplicate_occurrence_count += 1
            if timestamp is not None:
                occurrence_hour = timestamp_us // 3_600_000_000
                minimum_hour = self._minimum_retained_hour_locked()
                if minimum_hour is None or occurrence_hour >= minimum_hour:
                    aggregate.occurrence_hour_counts[occurrence_hour] += 1

    def record_observation(
        self,
        intent_id: str,
        source: str,
        status: str,
        timestamp: datetime | None = None,
    ) -> None:
        """Record one source decision for an authored intent."""

        with self._lock:
            self._advance_watermark_locked(timestamp)
            self._aggregate(intent_id).source_counts[(source, status)] += 1

    def advance_watermark(self, watermark: datetime) -> None:
        """Advance exact-ID and window retention without recording an occurrence."""

        with self._lock:
            self._advance_watermark_locked(watermark)

    def snapshot(self) -> tuple[IntentExecutionSnapshot, ...]:
        """Freeze bounded evidence in stable authored-intent order."""

        with self._lock:
            known_ids = [intent.intent_id for intent in self._authored.intents]
            unexpected_ids = sorted(set(self._aggregates) - self._authored_ids)
            intent_ids = [*known_ids, *unexpected_ids]
            snapshots = []
            for intent_id in intent_ids:
                aggregate = self._aggregates.get(intent_id) or _IntentExecutionAggregate(
                    self._identity_sample_limit
                )
                observations = tuple(
                    IntentSourceObservation(source=source, status=status, count=count)
                    for (source, status), count in sorted(aggregate.source_counts.items())
                )
                window_occurrences = tuple(
                    IntentWindowCount(
                        window=label,
                        count=self._window_count_locked(aggregate, hours),
                    )
                    for label, hours in _WINDOWS
                )
                snapshots.append(
                    IntentExecutionSnapshot(
                        intent_id=intent_id,
                        planned=aggregate.planned,
                        action_ids=aggregate.action_ids.sampled_ids,
                        occurrence_ids=aggregate.occurrence_ids.sampled_ids,
                        action_reference_count=aggregate.action_ids.reference_count,
                        occurrence_reference_count=aggregate.occurrence_ids.reference_count,
                        action_digest=aggregate.action_ids.digest,
                        occurrence_digest=aggregate.occurrence_ids.digest,
                        duplicate_occurrence_count=aggregate.duplicate_occurrence_count,
                        window_occurrences=window_occurrences,
                        source_observations=observations,
                    )
                )
            return tuple(snapshots)

    def reconcile(self) -> IntentReconciliation:
        """Compare the current planned set with the independent authored oracle."""

        with self._lock:
            return self._authored.reconcile(
                intent_id for intent_id, aggregate in self._aggregates.items() if aggregate.planned
            )

    def diagnostics(self) -> IntentExecutionLedgerDiagnostics:
        """Return retained-candidate and byte counts without exposing hot identities."""

        with self._lock:
            window_bucket_count = sum(
                len(aggregate.occurrence_hour_counts) for aggregate in self._aggregates.values()
            )
            source_aggregate_count = sum(
                len(aggregate.source_counts) for aggregate in self._aggregates.values()
            )
            sample_identity_count = sum(
                len(aggregate.action_ids.sample) + len(aggregate.occurrence_ids.sample)
                for aggregate in self._aggregates.values()
            )
            retained_candidate_count = (
                len(self._aggregates)
                + len(self._hot_identities)
                + window_bucket_count
                + source_aggregate_count
                + sample_identity_count
            )
            return IntentExecutionLedgerDiagnostics(
                watermark=self._watermark_datetime_locked(),
                aggregate_intent_count=len(self._aggregates),
                hot_identity_count=len(self._hot_identities),
                hot_identity_capacity=self._hot_identity_capacity,
                hot_horizon_seconds=int(_HOT_IDENTITY_HORIZON.total_seconds()),
                window_bucket_count=window_bucket_count,
                window_bucket_capacity=len(self._aggregates) * _WINDOW_HORIZON_HOURS,
                source_aggregate_count=source_aggregate_count,
                sample_identity_count=sample_identity_count,
                retained_candidate_count=retained_candidate_count,
                retained_bytes=self._retained_bytes_locked(),
            )

    def _advance_watermark_locked(self, timestamp: datetime | None) -> int:
        timestamp_us = (
            _datetime_to_epoch_us(timestamp)
            if timestamp is not None
            else (self._watermark_us if self._watermark_us is not None else 0)
        )
        if self._watermark_us is None or timestamp_us > self._watermark_us:
            self._watermark_us = timestamp_us
            self._expire_hot_identities_locked()
            self._expire_window_buckets_locked()
        return timestamp_us

    def _touch_hot_identity_locked(
        self,
        key: tuple[str, str, str],
        timestamp_us: int,
    ) -> bool:
        if key in self._hot_identities:
            return True
        if self._watermark_us is not None:
            horizon_us = int(_HOT_IDENTITY_HORIZON.total_seconds() * 1_000_000)
            if timestamp_us < self._watermark_us - horizon_us:
                return False
        self._hot_identities[key] = timestamp_us
        heappush(self._hot_identity_heap, (timestamp_us, key))
        while len(self._hot_identities) > self._hot_identity_capacity:
            self._evict_oldest_hot_identity_locked()
        return False

    def _expire_hot_identities_locked(self) -> None:
        if self._watermark_us is None:
            return
        horizon_us = int(_HOT_IDENTITY_HORIZON.total_seconds() * 1_000_000)
        cutoff = self._watermark_us - horizon_us
        while self._hot_identity_heap and self._hot_identity_heap[0][0] < cutoff:
            self._evict_oldest_hot_identity_locked()

    def _evict_oldest_hot_identity_locked(self) -> None:
        timestamp_us, key = heappop(self._hot_identity_heap)
        if self._hot_identities.get(key) == timestamp_us:
            del self._hot_identities[key]

    def _minimum_retained_hour_locked(self) -> int | None:
        if self._watermark_us is None:
            return None
        watermark_hour = self._watermark_us // 3_600_000_000
        return watermark_hour - (_WINDOW_HORIZON_HOURS - 1)

    def _expire_window_buckets_locked(self) -> None:
        minimum_hour = self._minimum_retained_hour_locked()
        if minimum_hour is None:
            return
        for aggregate in self._aggregates.values():
            expired = [hour for hour in aggregate.occurrence_hour_counts if hour < minimum_hour]
            for hour in expired:
                del aggregate.occurrence_hour_counts[hour]

    def _window_count_locked(
        self,
        aggregate: _IntentExecutionAggregate,
        hours: int,
    ) -> int:
        if self._watermark_us is None:
            return 0
        watermark_hour = self._watermark_us // 3_600_000_000
        minimum_hour = watermark_hour - (hours - 1)
        return sum(
            count
            for hour, count in aggregate.occurrence_hour_counts.items()
            if hour >= minimum_hour
        )

    def _watermark_datetime_locked(self) -> datetime | None:
        if self._watermark_us is None:
            return None
        return datetime.fromtimestamp(self._watermark_us / 1_000_000, tz=UTC)

    def _retained_bytes_locked(self) -> int:
        total = (
            sys.getsizeof(self._aggregates)
            + sys.getsizeof(self._hot_identities)
            + sys.getsizeof(self._hot_identity_heap)
        )
        for intent_id, aggregate in self._aggregates.items():
            total += sys.getsizeof(intent_id) + sys.getsizeof(aggregate)
            total += sys.getsizeof(aggregate.source_counts)
            total += sys.getsizeof(aggregate.occurrence_hour_counts)
            for compact in (aggregate.action_ids, aggregate.occurrence_ids):
                total += sys.getsizeof(compact) + sys.getsizeof(compact.sample)
                total += sum(
                    sys.getsizeof(identity) + sys.getsizeof(digest)
                    for identity, digest in compact.sample.items()
                )
            total += sum(
                sys.getsizeof(key) + sys.getsizeof(count)
                for key, count in aggregate.source_counts.items()
            )
            total += sum(
                sys.getsizeof(hour) + sys.getsizeof(count)
                for hour, count in aggregate.occurrence_hour_counts.items()
            )
        total += sum(
            sys.getsizeof(key) + sys.getsizeof(timestamp_us)
            for key, timestamp_us in self._hot_identities.items()
        )
        total += sum(sys.getsizeof(item) for item in self._hot_identity_heap)
        return total


def _datetime_to_epoch_us(value: datetime) -> int:
    """Normalize one event timestamp to an integer UTC microsecond frontier."""

    normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return int(normalized.timestamp() * 1_000_000)


def _semantic_spec_fingerprint(spec: BaseModel) -> str:
    """Return a stable fingerprint of execution semantics, excluding documentation metadata."""

    payload = spec.model_dump(mode="json", exclude_none=False)
    payload.pop("description", None)
    payload.pop("technique", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:24]
