# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared timing runtime and bounded diagnostic counters."""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from types import MappingProxyType
from weakref import ReferenceType, ref

from evidenceforge.generation.timing.clocks import (
    SourceClockRegistry,
    SourceClockRegistryCensus,
    SourceClockRegistryPreparation,
)
from evidenceforge.generation.timing.distributions import TimingDistributionError, TimingSampler

_COMPATIBILITY_REFERENCE_TIME = datetime(1970, 1, 1, tzinfo=UTC)
_TIMING_DISTRIBUTION_KINDS = frozenset(
    {
        "constant",
        "mixture",
        "triangular",
        "truncated_lognormal",
        "truncated_normal",
    }
)


@dataclass(slots=True)
class _RelationshipCounterSlot:
    """One deterministic bounded relationship-count bucket."""

    label: str
    count: int = 0
    collided: bool = False


class _BoundedRelationshipCounter:
    """Bound relationship metrics without depending on first-arrival order.

    Relationship names map to stable hash slots.  The common no-collision case
    retains the exact relationship name.  A collision deterministically keeps
    the lexicographically smallest label and marks the bucket, while counts are
    aggregated.  The final snapshot is therefore independent of worker arrival
    order and retains no unbounded set of previously observed names.
    """

    __slots__ = ("_capacity", "_estimated_slot_bytes", "_slots", "_total")

    def __init__(self, capacity: int) -> None:
        self._capacity = capacity
        self._slots: dict[int, _RelationshipCounterSlot] = {}
        self._estimated_slot_bytes = 0
        self._total = 0

    def increment(self, key: str) -> None:
        """Increment the stable bucket for one relationship name."""

        digest = hashlib.blake2b(
            key.encode("utf-8"),
            digest_size=8,
            person=b"eforge-time",
        ).digest()
        slot_id = int.from_bytes(digest, "big") % self._capacity
        slot = self._slots.get(slot_id)
        self._total += 1
        if slot is None:
            slot = _RelationshipCounterSlot(label=key, count=1)
            self._slots[slot_id] = slot
            self._estimated_slot_bytes += (
                sys.getsizeof(slot_id) + sys.getsizeof(slot) + sys.getsizeof(key)
            )
            return
        slot.count += 1
        if slot.label != key:
            prior_label_size = sys.getsizeof(slot.label)
            slot.label = min(slot.label, key)
            slot.collided = True
            self._estimated_slot_bytes += sys.getsizeof(slot.label) - prior_label_size

    @property
    def total(self) -> int:
        """Return the total observations assigned to relationship slots."""

        return self._total

    def census(self, *, estimate_bytes: bool = False) -> tuple[int, int, int]:
        """Return live slots, capacity, and a constant-time byte estimate."""

        estimated_bytes = 0
        if estimate_bytes:
            estimated_bytes = (
                sys.getsizeof(self) + sys.getsizeof(self._slots) + self._estimated_slot_bytes
            )
        return len(self._slots), self._capacity, estimated_bytes

    def freeze(self) -> Mapping[str, int]:
        """Return a deterministic immutable snapshot."""

        snapshot: dict[str, int] = {}
        for slot_id, slot in self._slots.items():
            label = slot.label if not slot.collided else f"{slot.label} [bucket:{slot_id}]"
            # A real relationship name may equal another slot's rendered
            # collision label. Aggregate that vanishingly rare presentation
            # collision instead of overwriting counts and corrupting totals.
            snapshot[label] = snapshot.get(label, 0) + slot.count
        return MappingProxyType(dict(sorted(snapshot.items())))

    def clone(self) -> _BoundedRelationshipCounter:
        """Return an exact bounded copy without mutating source counters."""

        copied = _BoundedRelationshipCounter(self._capacity)
        copied._slots = {
            slot_id: _RelationshipCounterSlot(
                label=slot.label,
                count=slot.count,
                collided=slot.collided,
            )
            for slot_id, slot in self._slots.items()
        }
        copied._estimated_slot_bytes = self._estimated_slot_bytes
        copied._total = self._total
        return copied


@dataclass(frozen=True, slots=True)
class TimingAuditSummary:
    """Immutable snapshot of timing samples and exceptional planner outcomes."""

    sample_counts: Mapping[str, int]
    distribution_counts: Mapping[str, int]
    repair_counts: Mapping[str, int]
    saturation_counts: Mapping[str, int]
    fallback_counts: Mapping[str, int]

    @property
    def total_samples(self) -> int:
        """Return the total number of completed timing samples."""

        return sum(self.sample_counts.values())

    @property
    def total_repairs(self) -> int:
        """Return the total number of constraint repairs."""

        return sum(self.repair_counts.values())

    @property
    def total_saturations(self) -> int:
        """Return the total number of exhausted constraint windows."""

        return sum(self.saturation_counts.values())

    @property
    def total_fallbacks(self) -> int:
        """Return the total number of explicit timing fallbacks."""

        return sum(self.fallback_counts.values())


@dataclass(frozen=True, slots=True)
class TimingAuditCensus:
    """Constant-time capacity and activity census for bounded timing diagnostics."""

    relationship_slots_live: int
    relationship_slots_capacity: int
    relationship_slots_estimated_bytes: int
    distribution_keys_live: int
    sample_count: int
    repair_count: int
    saturation_count: int
    fallback_count: int
    estimated_index_bytes: int
    estimated_bytes: int


@dataclass(frozen=True, slots=True)
class TimingRuntimeCensus:
    """Public constant-time census for one engine-owned timing runtime."""

    clocks: SourceClockRegistryCensus
    audit: TimingAuditCensus
    estimated_index_bytes: int
    estimated_bytes: int


class TimingAudit:
    """Thread-safe bounded counters for timing behavior diagnostics."""

    def __init__(self, *, max_relationship_keys: int = 4096) -> None:
        if max_relationship_keys < 1:
            raise TimingDistributionError("max_relationship_keys must be at least one")
        self._sample_counts = _BoundedRelationshipCounter(max_relationship_keys)
        self._distribution_counts: Counter[str] = Counter()
        self._repair_counts = _BoundedRelationshipCounter(max_relationship_keys)
        self._saturation_counts = _BoundedRelationshipCounter(max_relationship_keys)
        self._fallback_counts = _BoundedRelationshipCounter(max_relationship_keys)
        self._lock = RLock()
        self._mutation_version = 0
        self._owner_runtime: TimingRuntime | None = None

    def _enter_public_mutation(self) -> TimingRuntime | None:
        """Enter the shared runtime lane before one canonical counter write."""

        owner = self._owner_runtime
        if owner is not None:
            owner._enter_public_mutation()
        return owner

    @staticmethod
    def _leave_public_mutation(owner: TimingRuntime | None) -> None:
        if owner is not None:
            owner._leave_public_mutation()

    @staticmethod
    def _validate_relationship_key(relationship_key: object) -> None:
        """Require one bounded-counter-safe public relationship label."""

        if type(relationship_key) is not str or not relationship_key:
            raise TimingDistributionError("relationship_key must be a non-empty string")
        try:
            relationship_key.encode("utf-8")
        except UnicodeEncodeError as error:
            raise TimingDistributionError("relationship_key must be valid UTF-8") from error

    @staticmethod
    def _validate_distribution_kind(distribution_kind: object) -> None:
        """Restrict public audit cardinality to the sampler's closed kind set."""

        if type(distribution_kind) is not str or (
            distribution_kind not in _TIMING_DISTRIBUTION_KINDS
        ):
            raise TimingDistributionError("distribution_kind is not a supported timing kind")

    def record_sample(self, relationship_key: str, distribution_kind: str) -> None:
        """Record one completed sample by relationship and distribution type."""

        owner = self._enter_public_mutation()
        try:
            self._validate_relationship_key(relationship_key)
            self._validate_distribution_kind(distribution_kind)
            with self._lock:
                self._sample_counts.increment(relationship_key)
                self._distribution_counts[distribution_kind] += 1
                self._mutation_version += 1
        finally:
            self._leave_public_mutation(owner)

    def record_repair(self, relationship_key: str) -> None:
        """Record one constraint repair."""

        owner = self._enter_public_mutation()
        try:
            self._validate_relationship_key(relationship_key)
            with self._lock:
                self._repair_counts.increment(relationship_key)
                self._mutation_version += 1
        finally:
            self._leave_public_mutation(owner)

    def record_saturation(self, relationship_key: str) -> None:
        """Record one exhausted or impossible timing window."""

        owner = self._enter_public_mutation()
        try:
            self._validate_relationship_key(relationship_key)
            with self._lock:
                self._saturation_counts.increment(relationship_key)
                self._mutation_version += 1
        finally:
            self._leave_public_mutation(owner)

    def record_fallback(self, relationship_key: str) -> None:
        """Record one explicit compatibility or policy fallback."""

        owner = self._enter_public_mutation()
        try:
            self._validate_relationship_key(relationship_key)
            with self._lock:
                self._fallback_counts.increment(relationship_key)
                self._mutation_version += 1
        finally:
            self._leave_public_mutation(owner)

    @property
    def mutation_version(self) -> int:
        """Return the monotonic version covering every observable counter write."""

        with self._lock:
            return self._mutation_version

    def snapshot(self) -> TimingAuditSummary:
        """Return an immutable point-in-time copy of every counter."""

        with self._lock:
            return TimingAuditSummary(
                sample_counts=self._sample_counts.freeze(),
                distribution_counts=self._freeze(self._distribution_counts),
                repair_counts=self._repair_counts.freeze(),
                saturation_counts=self._saturation_counts.freeze(),
                fallback_counts=self._fallback_counts.freeze(),
            )

    def census(self, *, estimate_bytes: bool = False) -> TimingAuditCensus:
        """Return bounded slot capacity and totals without freezing relationship maps."""

        with self._lock:
            counters = (
                self._sample_counts,
                self._repair_counts,
                self._saturation_counts,
                self._fallback_counts,
            )
            counter_census = tuple(
                counter.census(estimate_bytes=estimate_bytes) for counter in counters
            )
            relationship_slots_live = sum(item[0] for item in counter_census)
            relationship_slots_capacity = sum(item[1] for item in counter_census)
            relationship_slots_estimated_bytes = sum(item[2] for item in counter_census)
            estimated_bytes = 0
            estimated_index_bytes = 0
            if estimate_bytes:
                estimated_index_bytes = relationship_slots_estimated_bytes + sys.getsizeof(
                    self._distribution_counts
                )
                estimated_bytes = (
                    sys.getsizeof(self) + estimated_index_bytes + sys.getsizeof(self._lock)
                )
            return TimingAuditCensus(
                relationship_slots_live=relationship_slots_live,
                relationship_slots_capacity=relationship_slots_capacity,
                relationship_slots_estimated_bytes=relationship_slots_estimated_bytes,
                distribution_keys_live=len(self._distribution_counts),
                sample_count=self._sample_counts.total,
                repair_count=self._repair_counts.total,
                saturation_count=self._saturation_counts.total,
                fallback_count=self._fallback_counts.total,
                estimated_index_bytes=estimated_index_bytes,
                estimated_bytes=estimated_bytes,
            )

    def _clone_locked(self) -> TimingAudit:
        """Return an exact copy while the caller owns ``_lock``."""

        copied = object.__new__(TimingAudit)
        copied._sample_counts = self._sample_counts.clone()
        copied._distribution_counts = self._distribution_counts.copy()
        copied._repair_counts = self._repair_counts.clone()
        copied._saturation_counts = self._saturation_counts.clone()
        copied._fallback_counts = self._fallback_counts.clone()
        copied._lock = RLock()
        copied._mutation_version = self._mutation_version
        copied._owner_runtime = None
        return copied

    def _apply_prepared_operations_locked(
        self,
        operations: tuple[tuple[str, str, str], ...],
    ) -> None:
        """Apply prevalidated bounded counter operations under ``_lock``."""

        for kind, relationship_key, distribution_kind in operations:
            if kind == "sample":
                self._sample_counts.increment(relationship_key)
                self._distribution_counts[distribution_kind] += 1
            elif kind == "repair":
                self._repair_counts.increment(relationship_key)
            elif kind == "saturation":
                self._saturation_counts.increment(relationship_key)
            else:
                self._fallback_counts.increment(relationship_key)
            self._mutation_version += 1

    @staticmethod
    def _freeze(counter: Counter[str]) -> Mapping[str, int]:
        """Freeze a sorted counter copy for deterministic diagnostics."""

        return MappingProxyType(dict(sorted(counter.items())))


class _PreparedTimingAudit:
    """Copy-on-write audit observer used by one timing preparation."""

    __slots__ = ("_base", "_base_version", "_operations", "_owner_preparation")

    def __init__(self, base: TimingAudit) -> None:
        self._base = base
        self._base_version = base.mutation_version
        self._operations: list[tuple[str, str, str]] = []
        self._owner_preparation: ReferenceType[TimingRuntimePreparation] | None = None

    def _require_public_staging(self) -> None:
        """Reject retained audit mutation after its runtime capability closes."""

        owner_ref = self._owner_preparation
        if owner_ref is None:
            return
        owner = owner_ref()
        if owner is None:
            raise TimingDistributionError("Timing runtime preparation is not open for staging")
        owner._require_public_staging()

    @property
    def base_version(self) -> int:
        """Return the audit version captured before staging began."""

        return self._base_version

    @property
    def operations(self) -> tuple[tuple[str, str, str], ...]:
        """Return the immutable staged operation sequence."""

        return tuple(self._operations)

    def record_sample(self, relationship_key: str, distribution_kind: str) -> None:
        """Stage one sample without touching canonical audit counters."""

        self._require_public_staging()
        TimingAudit._validate_relationship_key(relationship_key)
        TimingAudit._validate_distribution_kind(distribution_kind)
        self._operations.append(("sample", relationship_key, distribution_kind))

    def record_repair(self, relationship_key: str) -> None:
        """Stage one repair counter."""

        self._require_public_staging()
        TimingAudit._validate_relationship_key(relationship_key)
        self._operations.append(("repair", relationship_key, ""))

    def record_saturation(self, relationship_key: str) -> None:
        """Stage one saturation counter."""

        self._require_public_staging()
        TimingAudit._validate_relationship_key(relationship_key)
        self._operations.append(("saturation", relationship_key, ""))

    def record_fallback(self, relationship_key: str) -> None:
        """Stage one fallback counter."""

        self._require_public_staging()
        TimingAudit._validate_relationship_key(relationship_key)
        self._operations.append(("fallback", relationship_key, ""))

    def _merged(self) -> TimingAudit:
        """Build a bounded read-only merged view for diagnostics."""

        with self._base._lock:
            copied = self._base._clone_locked()
        with copied._lock:
            copied._apply_prepared_operations_locked(self.operations)
        return copied

    def snapshot(self) -> TimingAuditSummary:
        """Return canonical plus staged counters without canonical mutation."""

        return self._merged().snapshot()

    def census(self, *, estimate_bytes: bool = False) -> TimingAuditCensus:
        """Return canonical plus staged bounded diagnostics."""

        return self._merged().census(estimate_bytes=estimate_bytes)

    def overlay_digest(self) -> str:
        """Return a deterministic digest of the staged audit sequence."""

        payload = json.dumps(self._operations, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class TimingRuntime:
    """Own one sampler, audit sink, and source-clock registry."""

    def __init__(
        self,
        *,
        reference_time: datetime,
        namespace: str = "shared-timing-v1",
        generation_seed: int | None = None,
        max_clock_cache_entries: int = 2048,
        max_audit_relationship_keys: int = 4096,
    ) -> None:
        self._owner_lane_lock = RLock()
        self._owner_lane: object | None = None
        self._owner_lane_epoch = 0
        self.audit = TimingAudit(max_relationship_keys=max_audit_relationship_keys)
        self.sampler = TimingSampler(
            namespace=namespace,
            observer=self.audit,
            generation_seed=generation_seed,
        )
        self.clocks = SourceClockRegistry(
            reference_time=reference_time,
            sampler=self.sampler,
            max_cache_entries=max_clock_cache_entries,
        )
        self.audit._owner_runtime = self
        self.clocks._owner_runtime = self

    def _enter_public_mutation(self) -> None:
        """Serialize a public canonical mutation against an owner claim lane."""

        observed_epoch = self._owner_lane_epoch
        if self._owner_lane is not None:
            raise TimingDistributionError(
                "Timing runtime canonical mutation is blocked by an active owner claim"
            )
        self._owner_lane_lock.acquire()
        if self._owner_lane is not None or self._owner_lane_epoch != observed_epoch:
            self._owner_lane_lock.release()
            raise TimingDistributionError(
                "Timing runtime canonical mutation overlapped an active owner claim"
            )

    def _leave_public_mutation(self) -> None:
        """Leave one public canonical mutation lane."""

        self._owner_lane_lock.release()

    def _install_owner_lane(self, marker: object) -> None:
        """Install one exact exclusive owner lane before its state snapshot."""

        with self._owner_lane_lock:
            if self._owner_lane is not None:
                raise TimingDistributionError("Timing runtime already has an active owner claim")
            self._owner_lane_epoch += 1
            self._owner_lane = marker

    def _release_owner_lane(self, marker: object) -> None:
        """Release only the exact owner lane installed by ``marker``."""

        with self._owner_lane_lock:
            if self._owner_lane is not marker:
                raise TimingDistributionError("Timing runtime owner claim is not active")
            self._owner_lane = None
            self._owner_lane_epoch += 1

    @classmethod
    def compatibility_default(cls) -> TimingRuntime:
        """Return an inert-compatible runtime for directly constructed components.

        Production generation injects a runtime whose reference is the
        generation epoch. The fixed UTC epoch here keeps legacy unit and helper
        construction deterministic until every caller has an owning engine.
        """

        return cls(reference_time=_COMPATIBILITY_REFERENCE_TIME)

    @property
    def source_clock_registry(self) -> SourceClockRegistry:
        """Return the shared source-clock registry."""

        return self.clocks

    def census(self, *, estimate_bytes: bool = False) -> TimingRuntimeCensus:
        """Return a constant-time structural census for clocks and audit slots."""

        clock_census = self.clocks.census(estimate_bytes=estimate_bytes)
        audit_census = self.audit.census(estimate_bytes=estimate_bytes)
        estimated_bytes = 0
        estimated_index_bytes = 0
        if estimate_bytes:
            estimated_index_bytes = (
                clock_census.estimated_bytes + audit_census.estimated_index_bytes
            )
            estimated_bytes = (
                sys.getsizeof(self) + clock_census.estimated_bytes + audit_census.estimated_bytes
            )
        return TimingRuntimeCensus(
            clocks=clock_census,
            audit=audit_census,
            estimated_index_bytes=estimated_index_bytes,
            estimated_bytes=estimated_bytes,
        )

    def prepared(self) -> TimingRuntimePreparation:
        """Return a bounded copy-on-write audit and source-clock overlay."""

        self._enter_public_mutation()
        try:
            return TimingRuntimePreparation(self)
        finally:
            self._leave_public_mutation()

    def _prepared_for_owner(self, marker: object) -> TimingRuntimePreparation:
        """Build one overlay for the exact already-installed owner lane."""

        with self._owner_lane_lock:
            if self._owner_lane is not marker:
                raise TimingDistributionError("Timing runtime owner claim is not active")
            return TimingRuntimePreparation(self)

    def state_digest(self) -> str:
        """Return a constant-time digest of observable runtime state versions."""

        census = self.census()
        payload = (
            self.audit.mutation_version,
            self.clocks.mutation_version,
            census.clocks.live_entries,
            census.clocks.high_water_mark,
            census.clocks.lookup_count,
            census.clocks.cache_hit_count,
            census.clocks.cache_miss_count,
            census.clocks.eviction_count,
            census.audit.relationship_slots_live,
            census.audit.distribution_keys_live,
            census.audit.sample_count,
            census.audit.repair_count,
            census.audit.saturation_count,
            census.audit.fallback_count,
        )
        return hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()


class TimingRuntimePreparation:
    """One bounded transactional view of timing audit and source-clock state."""

    __slots__ = (
        "__weakref__",
        "_base",
        "_claim_held",
        "_source_timing_owner",
        "_state",
        "audit",
        "clocks",
        "sampler",
    )

    def __init__(self, base: TimingRuntime) -> None:
        self._base = base
        self._source_timing_owner: object | None = None
        self.audit = _PreparedTimingAudit(base.audit)
        self.sampler = TimingSampler(
            namespace=base.sampler.namespace,
            observer=self.audit,
            generation_seed=base.sampler.generation_seed,
        )
        self.clocks = base.clocks._prepare(sampler=self.sampler)
        self._state = "open"
        self._claim_held = False
        owner_ref = ref(self)
        self.audit._owner_preparation = owner_ref
        self.clocks._owner_preparation = owner_ref

    def _require_public_staging(self) -> None:
        """Reject mutation through a retained or cross-context staged capability."""

        if self._state != "open":
            raise TimingDistributionError("Timing runtime preparation is not open for staging")
        source_timing_owner = self._source_timing_owner
        if source_timing_owner is not None:
            planner = source_timing_owner._owner
            if not planner.is_active_preparation(source_timing_owner):
                raise TimingDistributionError(
                    "Timing runtime preparation is outside its active source timing claim"
                )

    @property
    def source_clock_registry(self) -> SourceClockRegistryPreparation:
        """Return the staged source-clock view."""

        return self.clocks

    @property
    def base_versions(self) -> tuple[int, int]:
        """Return captured audit and clock versions."""

        return (self.audit.base_version, self.clocks.base_version)

    @property
    def committed(self) -> bool:
        """Return whether the staged runtime has committed once."""

        return self._state == "committed"

    def census(self, *, estimate_bytes: bool = False) -> TimingRuntimeCensus:
        """Return canonical plus staged runtime diagnostics."""

        clock_census = self.clocks.census(estimate_bytes=estimate_bytes)
        audit_census = self.audit.census(estimate_bytes=estimate_bytes)
        estimated_index_bytes = 0
        estimated_bytes = 0
        if estimate_bytes:
            estimated_index_bytes = (
                clock_census.estimated_bytes + audit_census.estimated_index_bytes
            )
            estimated_bytes = (
                sys.getsizeof(self) + clock_census.estimated_bytes + audit_census.estimated_bytes
            )
        return TimingRuntimeCensus(
            clocks=clock_census,
            audit=audit_census,
            estimated_index_bytes=estimated_index_bytes,
            estimated_bytes=estimated_bytes,
        )

    def overlay_digest(self) -> str:
        """Return a deterministic digest of staged audit and clock operations."""

        payload = (self.audit.overlay_digest(), self.clocks.overlay_digest())
        return hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()

    def _acquire_claim(self) -> None:
        """Own runtime locks and reject any stale canonical snapshot."""

        if self._state != "open":
            raise TimingDistributionError(
                f"Timing runtime preparation cannot be claimed from state {self._state!r}"
            )
        self._base.audit._lock.acquire()
        try:
            self._base.clocks._lock.acquire()
        except BaseException:
            self._base.audit._lock.release()
            raise
        self._claim_held = True
        if self._base.audit._mutation_version != self.audit.base_version or (
            self._base.clocks._mutation_version != self.clocks.base_version
        ):
            self._release_claim()
            raise TimingDistributionError("Timing runtime preparation is stale")
        self._state = "claimed"

    def _commit_no_fail(self) -> None:
        """Apply prevalidated staged runtime state while claim locks are held."""

        if self._state != "claimed" or not self._claim_held:
            raise TimingDistributionError("Timing runtime preparation is not claimed")
        self._base.audit._apply_prepared_operations_locked(self.audit.operations)
        self.clocks._commit_locked()
        self._state = "committed"

    def _release_claim(self) -> None:
        """Release runtime claim locks in reverse global order."""

        if not self._claim_held:
            return
        if self._state == "claimed":
            self._state = "open"
        self._claim_held = False
        self._base.clocks._lock.release()
        self._base.audit._lock.release()

    def cancel(self) -> None:
        """Discard an unclaimed runtime overlay without canonical mutation."""

        if self._state == "committed":
            raise TimingDistributionError("Committed timing runtime preparation cannot cancel")
        if self._claim_held:
            self._release_claim()
        self._state = "cancelled"
