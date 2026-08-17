# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Independent authored-intent ledger for future ground-truth reconciliation."""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from collections import Counter
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from heapq import heappop, heappush
from secrets import token_bytes
from threading import RLock, get_ident
from typing import TYPE_CHECKING

from pydantic import BaseModel

from evidenceforge.events.contracts import OccurrenceRole, SemanticOccurrenceKey
from evidenceforge.models.exceptions import StateError
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


MAX_INTENT_EXECUTION_BATCH_DELTAS = 16_384
MAX_INTENT_EXECUTION_BATCH_RESERVATIONS = 4_096
MAX_INTENT_EXECUTION_PREPARED_INTENTS = 65_536
MAX_INTENT_EXECUTION_PREPARED_DELTAS = 65_536


class IntentExecutionBatchError(StateError):
    """A prepared intent-execution batch capability is invalid or unavailable."""


class IntentExecutionBatchConflictError(IntentExecutionBatchError):
    """An intent is reserved by another prepared execution batch."""


class IntentExecutionBatchInProgressError(IntentExecutionBatchConflictError):
    """A prepared execution batch already owns reservations or the mutation fence."""


@dataclass(frozen=True, slots=True)
class IntentOccurrenceDelta:
    """One immutable occurrence increment in an ordered prepared batch."""

    intent_id: str
    occurrence_key: SemanticOccurrenceKey
    timestamp: datetime | None = None

    def __post_init__(self) -> None:
        """Require exact occurrence identity and normalize optional canonical time."""

        if type(self.intent_id) is not str or not self.intent_id.strip():
            raise ValueError("Intent occurrence deltas require a non-empty intent_id")
        if type(self.occurrence_key) is not SemanticOccurrenceKey:
            raise ValueError("Intent occurrence deltas require an exact SemanticOccurrenceKey")
        if (
            type(self.occurrence_key.action_id) is not str
            or not self.occurrence_key.action_id.strip()
        ):
            raise ValueError("Semantic occurrence action_id must be a non-empty exact str")
        if type(self.occurrence_key.role) is not OccurrenceRole:
            raise ValueError("Semantic occurrence role must be an exact OccurrenceRole")
        if (
            type(self.occurrence_key.instance_key) is not str
            or not self.occurrence_key.instance_key.strip()
        ):
            raise ValueError("Semantic occurrence instance_key must be a non-empty exact str")
        object.__setattr__(self, "timestamp", _normalize_optional_datetime(self.timestamp))

    @property
    def identity(self) -> tuple[str, str, str]:
        """Return the exact occurrence identity used for duplicate rejection."""

        return ("occurrence", self.intent_id, self.occurrence_key.occurrence_id)


@dataclass(frozen=True, slots=True)
class IntentObservationDelta:
    """One immutable source-observation increment in an ordered prepared batch."""

    intent_id: str
    source: str
    status: str
    timestamp: datetime | None = None

    def __post_init__(self) -> None:
        """Require source semantics and normalize optional canonical time."""

        if type(self.intent_id) is not str or not self.intent_id.strip():
            raise ValueError("Intent observation deltas require a non-empty intent_id")
        if type(self.source) is not str or not self.source.strip():
            raise ValueError("Intent observation deltas require a non-empty source")
        if type(self.status) is not str or not self.status.strip():
            raise ValueError("Intent observation deltas require a non-empty status")
        object.__setattr__(self, "timestamp", _normalize_optional_datetime(self.timestamp))


IntentExecutionDelta = IntentOccurrenceDelta | IntentObservationDelta


@dataclass(frozen=True, slots=True)
class IntentExecutionBatchRequest:
    """Bounded ordered occurrence/observation multiset prepared as one commit."""

    deltas: tuple[IntentExecutionDelta, ...]

    def __post_init__(self) -> None:
        """Reject mutable, empty, oversized, malformed, or duplicate occurrence input."""

        if type(self.deltas) is not tuple:
            raise ValueError("Intent execution batch deltas must be an immutable tuple")
        if not self.deltas:
            raise ValueError("Intent execution batch cannot be empty")
        if len(self.deltas) > MAX_INTENT_EXECUTION_BATCH_DELTAS:
            raise ValueError(
                "Intent execution batch contains "
                f"{len(self.deltas)} deltas; the bounded maximum is "
                f"{MAX_INTENT_EXECUTION_BATCH_DELTAS}. Split the action cohort into "
                "smaller atomic publications."
            )
        occurrence_identities: set[tuple[str, str, str, str]] = set()
        for delta in self.deltas:
            if type(delta) not in {IntentOccurrenceDelta, IntentObservationDelta}:
                raise ValueError("Intent execution batch contains an unsupported delta")
            if type(delta) is IntentOccurrenceDelta:
                if type(delta.intent_id) is not str or not delta.intent_id.strip():
                    raise ValueError("Intent occurrence intent_id must be a non-empty exact str")
                key = delta.occurrence_key
                if type(key) is not SemanticOccurrenceKey:
                    raise ValueError("Intent occurrence key must be an exact SemanticOccurrenceKey")
                if type(key.action_id) is not str or not key.action_id.strip():
                    raise ValueError("Semantic occurrence action_id must be a non-empty exact str")
                if type(key.role) is not OccurrenceRole:
                    raise ValueError("Semantic occurrence role must be an exact OccurrenceRole")
                if type(key.instance_key) is not str or not key.instance_key.strip():
                    raise ValueError(
                        "Semantic occurrence instance_key must be a non-empty exact str"
                    )
                if delta.timestamp is not None and type(delta.timestamp) is not datetime:
                    raise ValueError(
                        "Intent occurrence timestamp must be an exact datetime or None"
                    )
                identity = (delta.intent_id, key.action_id, key.role.value, key.instance_key)
                if identity in occurrence_identities:
                    raise ValueError(
                        "Intent execution batch repeats exact occurrence identity "
                        f"for action {key.action_id!r} and intent {delta.intent_id!r}"
                    )
                occurrence_identities.add(identity)
            else:
                for name in ("intent_id", "source", "status"):
                    value = getattr(delta, name)
                    if type(value) is not str or not value.strip():
                        raise ValueError(f"Intent observation {name} must be a non-empty exact str")
                if delta.timestamp is not None and type(delta.timestamp) is not datetime:
                    raise ValueError(
                        "Intent observation timestamp must be an exact datetime or None"
                    )

    @property
    def intent_ids(self) -> tuple[str, ...]:
        """Return every affected intent once in deterministic sorted order."""

        return tuple(sorted({delta.intent_id for delta in self.deltas}))


@dataclass(frozen=True, slots=True)
class IntentExecutionBatchToken:
    """Opaque authenticated reservation for one exact execution batch."""

    request: IntentExecutionBatchRequest
    ledger_id: str
    preparation_id: int
    expected_watermark: datetime | None
    plan_digest: str
    _integrity: str = field(repr=False)

    @property
    def publication_token(self) -> str:
        """Return the opaque proof suitable for a composite receipt."""

        return self._integrity


@dataclass(frozen=True, slots=True)
class IntentExecutionBatchResult:
    """Immutable bounded summary of one committed execution delta."""

    preparation_id: int
    expected_watermark: datetime | None
    prior_watermark: datetime | None
    committed_watermark: datetime | None
    delta_count: int
    occurrence_count: int
    observation_count: int
    ordered_delta_digest: str

    @property
    def watermark(self) -> datetime | None:
        """Compatibility alias for the committed execution frontier."""

        return self.committed_watermark


@dataclass(frozen=True, slots=True)
class IntentExecutionBatchReceipt:
    """Authenticated proof of one exact intent-execution batch commit."""

    request: IntentExecutionBatchRequest
    result: IntentExecutionBatchResult
    ledger_id: str
    preparation_id: int
    expected_watermark: datetime | None
    plan_digest: str
    committed_digest: str
    _integrity: str = field(repr=False)

    @property
    def publication_token(self) -> str:
        """Return the opaque proof suitable for a composite receipt."""

        return self._integrity

    @property
    def prior_watermark(self) -> datetime | None:
        """Return the exact frontier observed when this batch was claimed."""

        return self.result.prior_watermark

    @property
    def committed_watermark(self) -> datetime | None:
        """Return the exact frontier after this batch committed."""

        return self.result.committed_watermark


@dataclass(frozen=True, slots=True)
class IntentExecutionBatchCensus:
    """Constant-time census of transient prepared execution capabilities."""

    reservations: int
    claimed_reservations: int
    reserved_intents: int
    capability_locators: int
    prepared_deltas: int
    prepared_commit_plans: int
    mutation_fences: int
    retained_bytes: int
    reservation_capacity: int
    prepared_intent_capacity: int
    prepared_delta_capacity: int


@dataclass(slots=True)
class _PreparedIntentExecutionBatchPlan:
    """Prevalidated immutable receipt retained by one claimed reservation."""

    token: IntentExecutionBatchToken
    receipt: IntentExecutionBatchReceipt


@dataclass(slots=True)
class _IntentExecutionBatchReservation:
    """Transient exact-intent reservation containing no execution truth."""

    token: IntentExecutionBatchToken
    canonical_token: IntentExecutionBatchToken
    intent_ids: tuple[str, ...]
    claimed: bool = False
    claim_thread_id: int | None = None
    commit_plan: _PreparedIntentExecutionBatchPlan | None = None
    retained_bytes: int = 0


_BATCH_RETAINED_RECORD_TYPES = frozenset(
    {
        SemanticOccurrenceKey,
        IntentOccurrenceDelta,
        IntentObservationDelta,
        IntentExecutionBatchRequest,
        IntentExecutionBatchToken,
        IntentExecutionBatchResult,
        IntentExecutionBatchReceipt,
        _PreparedIntentExecutionBatchPlan,
        _IntentExecutionBatchReservation,
    }
)


def _validate_intent_execution_batch_request(request: object) -> None:
    """Require a recursively exact primitive request before canonical copying."""

    if type(request) is not IntentExecutionBatchRequest:
        raise ValueError("prepare_batch requires an exact IntentExecutionBatchRequest")
    if type(request.deltas) is not tuple:
        raise ValueError("Intent execution batch deltas must be an immutable tuple")
    if not request.deltas:
        raise ValueError("Intent execution batch cannot be empty")
    if len(request.deltas) > MAX_INTENT_EXECUTION_BATCH_DELTAS:
        raise ValueError(
            "Intent execution batch exceeds MAX_INTENT_EXECUTION_BATCH_DELTAS; "
            "split the action cohort into smaller atomic publications"
        )
    occurrence_identities: set[tuple[str, str, str, str]] = set()
    for delta in request.deltas:
        if type(delta) is IntentOccurrenceDelta:
            if type(delta.intent_id) is not str or not delta.intent_id.strip():
                raise ValueError("Intent occurrence intent_id must be a non-empty exact str")
            key = delta.occurrence_key
            if type(key) is not SemanticOccurrenceKey:
                raise ValueError("Intent occurrence key must be an exact SemanticOccurrenceKey")
            if type(key.action_id) is not str or not key.action_id.strip():
                raise ValueError("Semantic occurrence action_id must be a non-empty exact str")
            if type(key.role) is not OccurrenceRole:
                raise ValueError("Semantic occurrence role must be an exact OccurrenceRole")
            if type(key.instance_key) is not str or not key.instance_key.strip():
                raise ValueError("Semantic occurrence instance_key must be a non-empty exact str")
            if delta.timestamp is not None and type(delta.timestamp) is not datetime:
                raise ValueError("Intent occurrence timestamp must be an exact datetime or None")
            identity = (delta.intent_id, key.action_id, key.role.value, key.instance_key)
            if identity in occurrence_identities:
                raise ValueError("Intent execution batch repeats an exact occurrence identity")
            occurrence_identities.add(identity)
        elif type(delta) is IntentObservationDelta:
            for name in ("intent_id", "source", "status"):
                value = getattr(delta, name)
                if type(value) is not str or not value.strip():
                    raise ValueError(f"Intent observation {name} must be a non-empty exact str")
            if delta.timestamp is not None and type(delta.timestamp) is not datetime:
                raise ValueError("Intent observation timestamp must be an exact datetime or None")
        else:
            raise ValueError("Intent execution batch contains an unsupported exact delta type")


def _intent_execution_batch_retained_bytes(value: object, seen: set[int] | None = None) -> int:
    """Return deterministic retained heap bytes for one primitive reservation graph."""

    active = set() if seen is None else seen
    object_id = id(value)
    if object_id in active:
        return 0
    active.add(object_id)
    if value is None or type(value) in {bool, int, str, datetime, OccurrenceRole}:
        return sys.getsizeof(value)
    if type(value) is tuple:
        return sys.getsizeof(value) + sum(
            _intent_execution_batch_retained_bytes(item, active) for item in value
        )
    if type(value) in _BATCH_RETAINED_RECORD_TYPES:
        return sys.getsizeof(value) + sum(
            _intent_execution_batch_retained_bytes(getattr(value, item.name), active)
            for item in fields(value)
        )
    raise AssertionError(
        "Prepared intent execution reservation retained a non-primitive value: "
        f"{type(value).__module__}.{type(value).__qualname__}"
    )


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


class PreparedIntentExecutionBatch:
    """One-shot no-validation commit capability for a claimed execution batch."""

    __slots__ = ("_active", "_committed", "_ledger", "_receipt", "_token")

    def __init__(
        self,
        ledger: IntentExecutionLedger,
        token: IntentExecutionBatchToken,
    ) -> None:
        self._ledger = ledger
        self._token = token
        self._active = True
        self._committed = False
        self._receipt: IntentExecutionBatchReceipt | None = None

    @property
    def committed(self) -> bool:
        """Return whether this exact capability has committed."""

        return self._committed

    @property
    def receipt(self) -> IntentExecutionBatchReceipt | None:
        """Return the immutable authenticated receipt after commit."""

        return self._receipt

    def commit_no_fail(self) -> IntentExecutionBatchReceipt:
        """Publish the prevalidated bounded delta exactly once under the ledger lock."""

        if not self._active:
            raise IntentExecutionBatchError("Prepared intent execution batch is no longer active")
        if self._committed:
            raise IntentExecutionBatchError("Prepared intent execution batch is already committed")
        self._receipt = self._ledger._commit_claimed_batch(self._token)
        self._committed = True
        return self._receipt

    def _close(self) -> None:
        self._active = False


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
        self._batch_ledger_id = token_bytes(16).hex()
        self._batch_secret = token_bytes(32)
        self._next_batch_preparation_id = 1
        self._batch_reservations: dict[int, _IntentExecutionBatchReservation] = {}
        self._batch_capability_locators: dict[int, int] = {}
        self._batch_reserved_intents: dict[str, int] = {}
        self._batch_claimed_reservations = 0
        self._batch_claimed_preparation_id: int | None = None
        self._batch_prepared_deltas = 0
        self._batch_prepared_commit_plans = 0
        self._batch_retained_bytes = 0
        self._batch_reservation_capacity = MAX_INTENT_EXECUTION_BATCH_RESERVATIONS
        self._batch_prepared_intent_capacity = MAX_INTENT_EXECUTION_PREPARED_INTENTS
        self._batch_prepared_delta_capacity = MAX_INTENT_EXECUTION_PREPARED_DELTAS

    def _aggregate(self, intent_id: str) -> _IntentExecutionAggregate:
        aggregate = self._aggregates.get(intent_id)
        if aggregate is None:
            aggregate = _IntentExecutionAggregate(self._identity_sample_limit)
            self._aggregates[intent_id] = aggregate
        return aggregate

    @staticmethod
    def _batch_plan_digest(request: IntentExecutionBatchRequest) -> str:
        """Return a deterministic digest over ordered, ordinal-bound deltas."""

        payload: list[dict[str, object]] = []
        for ordinal, delta in enumerate(request.deltas):
            timestamp = "" if delta.timestamp is None else delta.timestamp.isoformat()
            if type(delta) is IntentOccurrenceDelta:
                payload.append(
                    {
                        "ordinal": ordinal,
                        "kind": "occurrence",
                        "intent_id": delta.intent_id,
                        "action_id": delta.occurrence_key.action_id,
                        "role": delta.occurrence_key.role.value,
                        "instance_key": delta.occurrence_key.instance_key,
                        "timestamp": timestamp,
                    }
                )
            else:
                payload.append(
                    {
                        "ordinal": ordinal,
                        "kind": "observation",
                        "intent_id": delta.intent_id,
                        "source": delta.source,
                        "status": delta.status,
                        "timestamp": timestamp,
                    }
                )
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @staticmethod
    def _batch_watermark_text(watermark: datetime | None) -> str:
        return "" if watermark is None else watermark.isoformat()

    def _batch_token_integrity(
        self,
        *,
        preparation_id: int,
        expected_watermark: datetime | None,
        plan_digest: str,
    ) -> str:
        payload = (
            f"intent-execution-batch-admission\0{self._batch_ledger_id}\0"
            f"{preparation_id}\0{self._batch_watermark_text(expected_watermark)}\0"
            f"{plan_digest}"
        ).encode()
        return hmac.new(self._batch_secret, payload, hashlib.sha256).hexdigest()

    def _batch_receipt_integrity(
        self,
        *,
        preparation_id: int,
        expected_watermark: datetime | None,
        prior_watermark: datetime | None,
        committed_watermark: datetime | None,
        plan_digest: str,
        committed_digest: str,
    ) -> str:
        payload = (
            f"intent-execution-batch-receipt\0{self._batch_ledger_id}\0"
            f"{preparation_id}\0{self._batch_watermark_text(expected_watermark)}\0"
            f"{self._batch_watermark_text(prior_watermark)}\0"
            f"{self._batch_watermark_text(committed_watermark)}\0"
            f"{plan_digest}\0{committed_digest}"
        ).encode()
        return hmac.new(self._batch_secret, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def _batch_committed_digest(
        request: IntentExecutionBatchRequest,
        result: IntentExecutionBatchResult,
        *,
        expected_watermark: datetime | None,
    ) -> str:
        payload = {
            "plan_digest": IntentExecutionLedger._batch_plan_digest(request),
            "preparation_id": result.preparation_id,
            "receipt_expected_watermark": IntentExecutionLedger._batch_watermark_text(
                expected_watermark
            ),
            "result_expected_watermark": IntentExecutionLedger._batch_watermark_text(
                result.expected_watermark
            ),
            "prior_watermark": IntentExecutionLedger._batch_watermark_text(result.prior_watermark),
            "committed_watermark": IntentExecutionLedger._batch_watermark_text(
                result.committed_watermark
            ),
            "delta_count": result.delta_count,
            "occurrence_count": result.occurrence_count,
            "observation_count": result.observation_count,
            "ordered_delta_digest": result.ordered_delta_digest,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def _batch_result_locked(
        self,
        request: IntentExecutionBatchRequest,
        *,
        preparation_id: int,
        expected_watermark: datetime | None,
        plan_digest: str,
    ) -> IntentExecutionBatchResult:
        # Simulate the legacy primitive in exact tuple order. A first explicit
        # timestamp establishes even a pre-epoch frontier, while a first absent
        # timestamp establishes the Unix epoch.
        prior_watermark = self._watermark_datetime_locked()
        resulting_watermark_us = self._watermark_us
        for delta in request.deltas:
            timestamp_us = (
                _datetime_to_epoch_us(delta.timestamp)
                if delta.timestamp is not None
                else resulting_watermark_us
                if resulting_watermark_us is not None
                else 0
            )
            if resulting_watermark_us is None or timestamp_us > resulting_watermark_us:
                resulting_watermark_us = timestamp_us
        occurrence_count = sum(type(delta) is IntentOccurrenceDelta for delta in request.deltas)
        return IntentExecutionBatchResult(
            preparation_id=preparation_id,
            expected_watermark=expected_watermark,
            prior_watermark=prior_watermark,
            committed_watermark=(
                None
                if resulting_watermark_us is None
                else _epoch_us_to_datetime(resulting_watermark_us)
            ),
            delta_count=len(request.deltas),
            occurrence_count=occurrence_count,
            observation_count=len(request.deltas) - occurrence_count,
            ordered_delta_digest=hashlib.sha256(
                f"intent-execution-ordered-delta-v1\0{plan_digest}".encode()
            ).hexdigest(),
        )

    def _batch_watermark_matches_locked(self, expected: datetime | None) -> bool:
        """Accept only the one harmless no-timestamp frontier initialization."""

        current = self._watermark_datetime_locked()
        return current == expected or (
            expected is None
            and self._watermark_us == 0
            and current == datetime.fromtimestamp(0, tz=UTC)
        )

    def _validate_batch_token_locked(self, token: IntentExecutionBatchToken) -> None:
        try:
            if type(token) is not IntentExecutionBatchToken:
                raise IntentExecutionBatchError(
                    "Intent execution batch token must have its exact opaque type"
                )
            if type(token.ledger_id) is not str:
                raise IntentExecutionBatchError("Intent execution batch ledger ID is malformed")
            if type(token.preparation_id) is not int or token.preparation_id <= 0:
                raise IntentExecutionBatchError(
                    "Intent execution batch preparation ID is malformed"
                )
            if (
                token.expected_watermark is not None
                and type(token.expected_watermark) is not datetime
            ):
                raise IntentExecutionBatchError(
                    "Intent execution batch expected watermark is malformed"
                )
            if type(token.plan_digest) is not str or type(token._integrity) is not str:
                raise IntentExecutionBatchError("Intent execution batch digest is malformed")
            _validate_intent_execution_batch_request(token.request)
            if token.ledger_id != self._batch_ledger_id:
                raise IntentExecutionBatchError(
                    "Intent execution batch token belongs to another ledger"
                )
            plan_digest = self._batch_plan_digest(token.request)
            expected = self._batch_token_integrity(
                preparation_id=token.preparation_id,
                expected_watermark=token.expected_watermark,
                plan_digest=plan_digest,
            )
            if token.plan_digest != plan_digest or not hmac.compare_digest(
                token._integrity,
                expected,
            ):
                raise IntentExecutionBatchError(
                    "Intent execution batch token integrity check failed"
                )
        except IntentExecutionBatchError:
            raise
        except Exception as exc:
            raise IntentExecutionBatchError(
                "Intent execution batch token integrity check failed"
            ) from exc

    def _active_batch_reservation_locked(
        self,
        token: IntentExecutionBatchToken,
    ) -> _IntentExecutionBatchReservation:
        preparation_id = self._batch_capability_locators.get(id(token))
        if preparation_id is None:
            self._validate_batch_token_locked(token)
            raise IntentExecutionBatchError("Intent execution batch token is stale or consumed")
        reservation = self._batch_reservations.get(preparation_id)
        if reservation is None or reservation.token is not token:
            self._batch_capability_locators.pop(id(token), None)
            raise IntentExecutionBatchError("Intent execution batch token is stale or consumed")
        try:
            self._validate_batch_token_locked(token)
            if token != reservation.canonical_token:
                raise IntentExecutionBatchError(
                    "Intent execution batch token was mutated after preparation"
                )
        except Exception as exc:
            self._release_batch_reservation_locked(reservation)
            if isinstance(exc, IntentExecutionBatchError):
                raise
            raise IntentExecutionBatchError(
                "Intent execution batch token integrity check failed"
            ) from exc
        return reservation

    def _release_batch_reservation_locked(
        self,
        reservation: _IntentExecutionBatchReservation,
    ) -> None:
        preparation_id = reservation.canonical_token.preparation_id
        if self._batch_reservations.pop(preparation_id, None) is not reservation:
            return
        if reservation.claimed:
            self._batch_claimed_reservations -= 1
            if self._batch_claimed_preparation_id == preparation_id:
                self._batch_claimed_preparation_id = None
        if reservation.commit_plan is not None:
            self._batch_prepared_commit_plans -= 1
        self._batch_prepared_deltas -= len(reservation.canonical_token.request.deltas)
        self._batch_retained_bytes -= reservation.retained_bytes
        self._batch_capability_locators.pop(id(reservation.token), None)
        for intent_id in reservation.intent_ids:
            if self._batch_reserved_intents.get(intent_id) == preparation_id:
                self._batch_reserved_intents.pop(intent_id)

    def _release_stale_batch_reservations_locked(self) -> None:
        """Bound retention by eagerly consuming every unclaimed stale token."""

        for reservation in tuple(self._batch_reservations.values()):
            if reservation.claimed:
                continue
            if not self._batch_watermark_matches_locked(
                reservation.canonical_token.expected_watermark
            ):
                self._release_batch_reservation_locked(reservation)

    def _reject_reserved_intent_locked(self, intent_id: str) -> None:
        if intent_id in self._batch_reserved_intents:
            raise IntentExecutionBatchConflictError(
                f"Intent {intent_id!r} has a prepared execution batch"
            )

    def _reject_mutation_while_batch_claimed_locked(self) -> None:
        if self._batch_claimed_preparation_id is not None:
            raise IntentExecutionBatchInProgressError(
                "A claimed intent execution batch temporarily fences ledger mutation; "
                "commit or exit the claim before retrying"
            )

    def prepare_batch(
        self,
        request: IntentExecutionBatchRequest,
    ) -> IntentExecutionBatchToken:
        """Validate and reserve one ordered batch without execution-ledger mutation."""

        _validate_intent_execution_batch_request(request)
        public_request = deepcopy(request)
        _validate_intent_execution_batch_request(public_request)
        with self._lock:
            self._release_stale_batch_reservations_locked()
            conflicting_ids = {
                preparation_id
                for intent_id in public_request.intent_ids
                if (preparation_id := self._batch_reserved_intents.get(intent_id)) is not None
            }
            if conflicting_ids and all(
                (active := self._batch_reservations.get(preparation_id)) is not None
                and active.canonical_token.request == public_request
                for preparation_id in conflicting_ids
            ):
                raise IntentExecutionBatchInProgressError(
                    "Exact intent execution batch is already in progress"
                )
            if conflicting_ids:
                raise IntentExecutionBatchConflictError(
                    "An intent in this execution batch is already reserved"
                )
            for delta in public_request.deltas:
                if type(delta) is not IntentOccurrenceDelta:
                    continue
                hot_key = (delta.intent_id, "occurrence", delta.occurrence_key.occurrence_id)
                if hot_key in self._hot_identities:
                    raise IntentExecutionBatchConflictError(
                        "Prepared execution batches reject an occurrence identity already "
                        f"present in the exact hot cache: {delta.occurrence_key.occurrence_id}"
                    )

            requested_intents = len(public_request.intent_ids)
            requested_deltas = len(public_request.deltas)
            if len(self._batch_reservations) >= self._batch_reservation_capacity:
                raise IntentExecutionBatchError(
                    "Prepared intent execution batch reservation capacity "
                    f"({self._batch_reservation_capacity}) is exhausted. Cancel or commit "
                    "an existing batch before retrying."
                )
            if (
                len(self._batch_reserved_intents) + requested_intents
                > self._batch_prepared_intent_capacity
            ):
                raise IntentExecutionBatchError(
                    "Prepared intent capacity "
                    f"({self._batch_prepared_intent_capacity}) would be exceeded. "
                    "Cancel or commit existing batches, or split the cohort."
                )
            if self._batch_prepared_deltas + requested_deltas > self._batch_prepared_delta_capacity:
                raise IntentExecutionBatchError(
                    "Prepared intent delta capacity "
                    f"({self._batch_prepared_delta_capacity}) would be exceeded. "
                    "Cancel or commit existing batches before retrying."
                )

            preparation_id = self._next_batch_preparation_id
            expected_watermark = self._watermark_datetime_locked()
            plan_digest = self._batch_plan_digest(public_request)
            token = IntentExecutionBatchToken(
                request=public_request,
                ledger_id=self._batch_ledger_id,
                preparation_id=preparation_id,
                expected_watermark=expected_watermark,
                plan_digest=plan_digest,
                _integrity=self._batch_token_integrity(
                    preparation_id=preparation_id,
                    expected_watermark=expected_watermark,
                    plan_digest=plan_digest,
                ),
            )
            canonical_token = deepcopy(token)
            reservation = _IntentExecutionBatchReservation(
                token=token,
                canonical_token=canonical_token,
                intent_ids=public_request.intent_ids,
            )
            reservation.retained_bytes = _intent_execution_batch_retained_bytes(reservation)
            self._next_batch_preparation_id += 1
            self._batch_reservations[preparation_id] = reservation
            self._batch_capability_locators[id(token)] = preparation_id
            self._batch_prepared_deltas += requested_deltas
            self._batch_retained_bytes += reservation.retained_bytes
            for intent_id in reservation.intent_ids:
                self._batch_reserved_intents[intent_id] = preparation_id
            return token

    def cancel_batch(self, token: IntentExecutionBatchToken) -> None:
        """Cancel one unclaimed batch reservation with zero execution mutation."""

        with self._lock:
            reservation = self._active_batch_reservation_locked(token)
            if reservation.claimed:
                raise IntentExecutionBatchError("Claimed intent execution batch cannot cancel")
            self._release_batch_reservation_locked(reservation)

    def authenticates_batch_token(
        self,
        token: object,
        *,
        request: IntentExecutionBatchRequest | None = None,
    ) -> bool:
        """Totally authenticate one active token without claiming or consuming it."""

        if type(token) is not IntentExecutionBatchToken:
            return False
        with self._lock:
            try:
                reservation = self._active_batch_reservation_locked(token)
                if request is not None:
                    _validate_intent_execution_batch_request(request)
                return request is None or reservation.canonical_token.request == request
            except Exception:
                return False

    def batch_preparation_census(self) -> IntentExecutionBatchCensus:
        """Return transient capability counts without scanning execution truth."""

        with self._lock:
            return IntentExecutionBatchCensus(
                reservations=len(self._batch_reservations),
                claimed_reservations=self._batch_claimed_reservations,
                reserved_intents=len(self._batch_reserved_intents),
                capability_locators=len(self._batch_capability_locators),
                prepared_deltas=self._batch_prepared_deltas,
                prepared_commit_plans=self._batch_prepared_commit_plans,
                mutation_fences=int(self._batch_claimed_preparation_id is not None),
                retained_bytes=self._batch_retained_bytes,
                reservation_capacity=self._batch_reservation_capacity,
                prepared_intent_capacity=self._batch_prepared_intent_capacity,
                prepared_delta_capacity=self._batch_prepared_delta_capacity,
            )

    @contextmanager
    def claimed_batch(
        self,
        token: IntentExecutionBatchToken,
    ) -> Iterator[PreparedIntentExecutionBatch]:
        """Yield one unlocked capability while fencing execution-ledger mutation."""

        with self._lock:
            reservation = self._active_batch_reservation_locked(token)
            if reservation.claimed:
                raise IntentExecutionBatchError("Intent execution batch token is already claimed")
            if self._batch_claimed_preparation_id is not None:
                raise IntentExecutionBatchInProgressError(
                    "Another intent execution batch is already claimed; commit or exit it "
                    "before claiming this batch"
                )
            if not self._batch_watermark_matches_locked(
                reservation.canonical_token.expected_watermark
            ):
                self._release_batch_reservation_locked(reservation)
                raise IntentExecutionBatchError(
                    "Intent execution batch admission is stale after watermark advance"
                )
            result = self._batch_result_locked(
                reservation.canonical_token.request,
                preparation_id=reservation.canonical_token.preparation_id,
                expected_watermark=reservation.canonical_token.expected_watermark,
                plan_digest=reservation.canonical_token.plan_digest,
            )
            committed_digest = self._batch_committed_digest(
                reservation.canonical_token.request,
                result,
                expected_watermark=reservation.canonical_token.expected_watermark,
            )
            reservation.commit_plan = _PreparedIntentExecutionBatchPlan(
                token=reservation.canonical_token,
                receipt=IntentExecutionBatchReceipt(
                    request=reservation.canonical_token.request,
                    result=result,
                    ledger_id=self._batch_ledger_id,
                    preparation_id=reservation.canonical_token.preparation_id,
                    expected_watermark=reservation.canonical_token.expected_watermark,
                    plan_digest=reservation.canonical_token.plan_digest,
                    committed_digest=committed_digest,
                    _integrity=self._batch_receipt_integrity(
                        preparation_id=reservation.canonical_token.preparation_id,
                        expected_watermark=reservation.canonical_token.expected_watermark,
                        prior_watermark=result.prior_watermark,
                        committed_watermark=result.committed_watermark,
                        plan_digest=reservation.canonical_token.plan_digest,
                        committed_digest=committed_digest,
                    ),
                ),
            )
            reservation.claimed = True
            reservation.claim_thread_id = get_ident()
            self._batch_claimed_reservations += 1
            self._batch_prepared_commit_plans += 1
            self._batch_claimed_preparation_id = token.preparation_id
            prior_retained_bytes = reservation.retained_bytes
            reservation.retained_bytes = _intent_execution_batch_retained_bytes(reservation)
            self._batch_retained_bytes += reservation.retained_bytes - prior_retained_bytes

        capability = PreparedIntentExecutionBatch(self, token)
        try:
            yield capability
        except BaseException:
            if not capability.committed:
                self._discard_batch_for_token(token)
            raise
        else:
            if not capability.committed:
                self._discard_batch_for_token(token)
                raise IntentExecutionBatchError(
                    "Claimed intent execution batch exited without commit_no_fail"
                )
        finally:
            capability._close()

    def _discard_batch_for_token(self, token: IntentExecutionBatchToken) -> None:
        """Best-effort release keyed by the exact unforgeable token object."""

        with self._lock:
            preparation_id = self._batch_capability_locators.get(id(token))
            if preparation_id is None:
                return
            reservation = self._batch_reservations.get(preparation_id)
            if reservation is not None and reservation.token is token:
                self._release_batch_reservation_locked(reservation)

    def authenticates_batch_receipt(
        self,
        receipt: object,
        *,
        request: IntentExecutionBatchRequest | None = None,
    ) -> bool:
        """Totally authenticate one immutable committed batch receipt."""

        try:
            if type(receipt) is not IntentExecutionBatchReceipt:
                return False
            _validate_intent_execution_batch_request(receipt.request)
            if request is not None:
                _validate_intent_execution_batch_request(request)
            if type(receipt.result) is not IntentExecutionBatchResult:
                return False
            if type(receipt.ledger_id) is not str:
                return False
            if type(receipt.preparation_id) is not int or receipt.preparation_id <= 0:
                return False
            if (
                receipt.expected_watermark is not None
                and type(receipt.expected_watermark) is not datetime
            ):
                return False
            if type(receipt.plan_digest) is not str or type(receipt.committed_digest) is not str:
                return False
            if type(receipt._integrity) is not str:
                return False
            result = receipt.result
            if type(result.preparation_id) is not int or result.preparation_id <= 0:
                return False
            if result.preparation_id != receipt.preparation_id:
                return False
            for watermark in (
                result.expected_watermark,
                result.prior_watermark,
                result.committed_watermark,
            ):
                if watermark is not None and type(watermark) is not datetime:
                    return False
            if result.expected_watermark != receipt.expected_watermark:
                return False
            for count in (
                result.delta_count,
                result.occurrence_count,
                result.observation_count,
            ):
                if type(count) is not int or count < 0:
                    return False
            if type(result.ordered_delta_digest) is not str:
                return False
            if receipt.ledger_id != self._batch_ledger_id:
                return False
            if request is not None and receipt.request != request:
                return False
            plan_digest = self._batch_plan_digest(receipt.request)
            if receipt.plan_digest != plan_digest:
                return False
            committed_digest = self._batch_committed_digest(
                receipt.request,
                receipt.result,
                expected_watermark=receipt.expected_watermark,
            )
            if receipt.committed_digest != committed_digest:
                return False
            expected = self._batch_receipt_integrity(
                preparation_id=receipt.preparation_id,
                expected_watermark=receipt.expected_watermark,
                prior_watermark=receipt.result.prior_watermark,
                committed_watermark=receipt.result.committed_watermark,
                plan_digest=plan_digest,
                committed_digest=committed_digest,
            )
            return hmac.compare_digest(receipt._integrity, expected)
        except Exception:
            return False

    def _commit_claimed_batch(
        self,
        token: IntentExecutionBatchToken,
    ) -> IntentExecutionBatchReceipt:
        """Commit one claimed token exactly once under the sole ledger lock."""

        with self._lock:
            reservation = self._active_batch_reservation_locked(token)
            canonical_token = reservation.canonical_token
            plan = reservation.commit_plan
            if not reservation.claimed or plan is None:
                raise IntentExecutionBatchError("Intent execution batch token is not claimed")
            if reservation.claim_thread_id != get_ident():
                raise IntentExecutionBatchError(
                    "Intent execution batch must commit on its claiming thread"
                )
            if not self._batch_watermark_matches_locked(canonical_token.expected_watermark):
                raise IntentExecutionBatchError(
                    "Intent execution batch admission is stale after watermark advance"
                )
            for intent_id in reservation.intent_ids:
                if self._batch_reserved_intents.get(intent_id) != token.preparation_id:
                    raise IntentExecutionBatchError(
                        f"Intent execution batch lost reservation for {intent_id!r}"
                    )
            self._validate_batch_token_locked(token)

            for delta in canonical_token.request.deltas:
                if type(delta) is IntentOccurrenceDelta:
                    self._record_occurrence_locked(
                        delta.intent_id,
                        delta.occurrence_key,
                        delta.timestamp,
                    )
                else:
                    self._record_observation_locked(
                        delta.intent_id,
                        delta.source,
                        delta.status,
                        delta.timestamp,
                    )
            self._release_batch_reservation_locked(reservation)
            self._release_stale_batch_reservations_locked()
            return plan.receipt

    def mark_planned(self, intent_id: str) -> None:
        """Record that execution entered the planner path for one authored intent."""

        with self._lock:
            self._reject_mutation_while_batch_claimed_locked()
            self._reject_reserved_intent_locked(intent_id)
            self._aggregate(intent_id).planned = True

    def record_occurrence(
        self,
        intent_id: str,
        occurrence_key: SemanticOccurrenceKey,
        timestamp: datetime | None = None,
    ) -> None:
        """Record one occurrence into bounded aggregates and the exact hot cache."""

        with self._lock:
            self._reject_mutation_while_batch_claimed_locked()
            self._reject_reserved_intent_locked(intent_id)
            self._record_occurrence_locked(intent_id, occurrence_key, timestamp)
            self._release_stale_batch_reservations_locked()

    def _record_occurrence_locked(
        self,
        intent_id: str,
        occurrence_key: SemanticOccurrenceKey,
        timestamp: datetime | None,
    ) -> None:
        """Apply one already-admitted occurrence while the ledger lock is held."""

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
            self._reject_mutation_while_batch_claimed_locked()
            self._reject_reserved_intent_locked(intent_id)
            self._record_observation_locked(intent_id, source, status, timestamp)
            self._release_stale_batch_reservations_locked()

    def _record_observation_locked(
        self,
        intent_id: str,
        source: str,
        status: str,
        timestamp: datetime | None,
    ) -> None:
        """Apply one already-admitted observation while the ledger lock is held."""

        self._advance_watermark_locked(timestamp)
        self._aggregate(intent_id).source_counts[(source, status)] += 1

    def advance_watermark(self, watermark: datetime) -> None:
        """Advance exact-ID and window retention without recording an occurrence."""

        with self._lock:
            self._reject_mutation_while_batch_claimed_locked()
            self._advance_watermark_locked(watermark)
            self._release_stale_batch_reservations_locked()

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


def _epoch_us_to_datetime(value: int) -> datetime:
    """Return an exact UTC datetime for one integer microsecond frontier."""

    return datetime.fromtimestamp(value / 1_000_000, tz=UTC)


def _normalize_optional_datetime(value: datetime | None) -> datetime | None:
    """Normalize an optional datetime while rejecting malformed runtime input."""

    if value is None:
        return None
    if type(value) is not datetime:
        raise ValueError("Intent execution delta timestamp must be an exact datetime or None")
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _semantic_spec_fingerprint(spec: BaseModel) -> str:
    """Return a stable fingerprint of execution semantics, excluding documentation metadata."""

    payload = spec.model_dump(mode="json", exclude_none=False)
    payload.pop("description", None)
    payload.pop("technique", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:24]
