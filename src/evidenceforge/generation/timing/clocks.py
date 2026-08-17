# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Deterministic source-clock projection for endpoint and sensor evidence."""

from __future__ import annotations

import hashlib
import json
import math
import sys
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import RLock

from evidenceforge.generation.timing.distributions import (
    ConstantDistribution,
    DistributionSpec,
    TimingDistributionError,
    TimingSampler,
    TimingScope,
    validate_distribution_spec,
)


@dataclass(frozen=True, slots=True)
class SourceClockKey:
    """Stable identity of one physical or logical source clock."""

    kind: str
    identity: str
    profile: str = ""

    def __post_init__(self) -> None:
        """Require source kind and identity."""

        if not self.kind:
            raise TimingDistributionError("SourceClockKey.kind must not be empty")
        if not self.identity:
            raise TimingDistributionError("SourceClockKey.identity must not be empty")


@dataclass(frozen=True, slots=True)
class ClockWanderSpec:
    """Smooth clock-wander values sampled at deterministic temporal knots."""

    knot_distribution_microseconds: DistributionSpec = ConstantDistribution(0.0)
    knot_interval: timedelta = timedelta(minutes=5)

    def __post_init__(self) -> None:
        """Validate the knot interval."""

        validate_distribution_spec(self.knot_distribution_microseconds)
        if self.knot_interval <= timedelta(0):
            raise TimingDistributionError("clock wander knot_interval must be positive")


@dataclass(frozen=True, slots=True)
class SourceClockSpec:
    """Distributions controlling one source clock's offset, drift, and wander."""

    offset_microseconds: DistributionSpec = ConstantDistribution(0.0)
    drift_ppm: DistributionSpec = ConstantDistribution(0.0)
    wander: ClockWanderSpec = ClockWanderSpec()

    def __post_init__(self) -> None:
        """Validate every clock component before it can enter the registry."""

        validate_distribution_spec(self.offset_microseconds)
        validate_distribution_spec(self.drift_ppm)
        if not isinstance(self.wander, ClockWanderSpec):
            raise TimingDistributionError("wander must be a ClockWanderSpec")


@dataclass(frozen=True, slots=True)
class SourceClockState:
    """Stable per-clock parameters derived from a source-clock specification."""

    offset_microseconds: float
    drift_ppm: float


@dataclass(frozen=True, slots=True)
class SourceClockRegistryCensus:
    """Constant-time structural and activity census for source-clock state."""

    live_entries: int
    capacity: int
    high_water_mark: int
    backing_entries: int
    estimated_bytes: int
    lookup_count: int
    cache_hit_count: int
    cache_miss_count: int
    eviction_count: int


class SourceClockRegistry:
    """Project canonical timestamps through deterministic source clocks.

    Cached clock states are an optimization only. The cache is bounded and a
    state evicted from it is reconstructed exactly from its semantic key.
    """

    def __init__(
        self,
        *,
        reference_time: datetime,
        sampler: TimingSampler,
        max_cache_entries: int = 2048,
    ) -> None:
        self._require_aware(reference_time, "reference_time")
        if max_cache_entries < 0:
            raise TimingDistributionError("max_cache_entries must be non-negative")
        self._reference_time = reference_time
        self._sampler = sampler
        self._value_sampler = TimingSampler(
            namespace=sampler.namespace,
            generation_seed=sampler.generation_seed,
        )
        self._max_cache_entries = max_cache_entries
        self._states: OrderedDict[tuple[int, SourceClockKey, SourceClockSpec], SourceClockState] = (
            OrderedDict()
        )
        self._lock = RLock()
        self._high_water_mark = 0
        self._cache_entry_estimated_bytes = 0
        self._lookup_count = 0
        self._cache_hit_count = 0
        self._cache_miss_count = 0
        self._eviction_count = 0
        self._mutation_version = 0

    @property
    def reference_time(self) -> datetime:
        """Return the epoch used for drift and wander calculations."""

        return self._reference_time

    @property
    def cache_size(self) -> int:
        """Return the number of cached clock states."""

        with self._lock:
            return len(self._states)

    @property
    def max_cache_entries(self) -> int:
        """Return the configured clock-state cache bound."""

        return self._max_cache_entries

    def clear_cache(self) -> None:
        """Discard cached clock states without changing future projections."""

        with self._lock:
            if not self._states:
                return
            self._states.clear()
            self._cache_entry_estimated_bytes = 0
            self._mutation_version += 1

    @property
    def mutation_version(self) -> int:
        """Return the monotonic version of cache state and lookup diagnostics."""

        with self._lock:
            return self._mutation_version

    def census(self, *, estimate_bytes: bool = False) -> SourceClockRegistryCensus:
        """Return constant-time cache capacity, retention, and lookup metrics."""

        with self._lock:
            estimated_bytes = 0
            if estimate_bytes:
                estimated_bytes = (
                    sys.getsizeof(self)
                    + sys.getsizeof(self._states)
                    + self._cache_entry_estimated_bytes
                )
            live_entries = len(self._states)
            return SourceClockRegistryCensus(
                live_entries=live_entries,
                capacity=self._max_cache_entries,
                high_water_mark=self._high_water_mark,
                backing_entries=live_entries,
                estimated_bytes=estimated_bytes,
                lookup_count=self._lookup_count,
                cache_hit_count=self._cache_hit_count,
                cache_miss_count=self._cache_miss_count,
                eviction_count=self._eviction_count,
            )

    def state(self, key: SourceClockKey, spec: SourceClockSpec) -> SourceClockState:
        """Return stable offset and drift parameters for one clock."""

        self._sampler.record_logical_sample(
            spec.offset_microseconds,
            relationship_key="clock.offset_microseconds",
        )
        self._sampler.record_logical_sample(
            spec.drift_ppm,
            relationship_key="clock.drift_ppm",
        )
        cache_key = (self._sampler.generation_seed, key, spec)
        with self._lock:
            self._lookup_count += 1
            self._mutation_version += 1
            if self._max_cache_entries:
                cached = self._states.get(cache_key)
                if cached is not None:
                    self._cache_hit_count += 1
                    self._states.move_to_end(cache_key)
                    return cached
            self._cache_miss_count += 1

        scope = self._scope(key)
        state = SourceClockState(
            offset_microseconds=self._value_sampler.sample_value(
                spec.offset_microseconds,
                relationship_key="clock.offset_microseconds",
                scope=scope,
                sample_key="offset",
            ),
            drift_ppm=self._value_sampler.sample_value(
                spec.drift_ppm,
                relationship_key="clock.drift_ppm",
                scope=scope,
                sample_key="drift",
            ),
        )
        if self._max_cache_entries:
            with self._lock:
                existing = self._states.get(cache_key)
                if existing is not None:
                    self._states.move_to_end(cache_key)
                    return existing
                self._states[cache_key] = state
                self._cache_entry_estimated_bytes += self._estimate_cache_entry_bytes(
                    cache_key,
                    state,
                )
                while len(self._states) > self._max_cache_entries:
                    evicted_key, evicted_state = self._states.popitem(last=False)
                    self._cache_entry_estimated_bytes -= self._estimate_cache_entry_bytes(
                        evicted_key,
                        evicted_state,
                    )
                    self._eviction_count += 1
                self._high_water_mark = max(self._high_water_mark, len(self._states))
        return state

    @staticmethod
    def _estimate_cache_entry_bytes(
        cache_key: tuple[int, SourceClockKey, SourceClockSpec],
        state: SourceClockState,
    ) -> int:
        """Return a constant-shape shallow estimate for one retained clock entry."""

        generation_seed, key, spec = cache_key
        return sum(
            sys.getsizeof(value)
            for value in (
                cache_key,
                generation_seed,
                key,
                key.kind,
                key.identity,
                key.profile,
                spec,
                spec.offset_microseconds,
                spec.drift_ppm,
                spec.wander,
                spec.wander.knot_distribution_microseconds,
                state,
            )
        )

    def adjustment_microseconds(
        self,
        canonical_time: datetime,
        *,
        key: SourceClockKey,
        spec: SourceClockSpec,
    ) -> float:
        """Return total source-clock adjustment at one canonical timestamp."""

        self._require_aware(canonical_time, "canonical_time")
        elapsed_seconds = (canonical_time - self._reference_time).total_seconds()
        state = self.state(key, spec)
        drift_microseconds = elapsed_seconds * state.drift_ppm
        wander_microseconds = self._wander_microseconds(
            elapsed_seconds,
            key=key,
            spec=spec.wander,
        )
        return state.offset_microseconds + drift_microseconds + wander_microseconds

    def adjustment(
        self,
        canonical_time: datetime,
        *,
        key: SourceClockKey,
        spec: SourceClockSpec,
    ) -> timedelta:
        """Return total source-clock adjustment as a timedelta."""

        return timedelta(
            microseconds=self.adjustment_microseconds(
                canonical_time,
                key=key,
                spec=spec,
            )
        )

    def project(
        self,
        canonical_time: datetime,
        *,
        key: SourceClockKey,
        spec: SourceClockSpec,
    ) -> datetime:
        """Project canonical time into one source clock's timestamp domain."""

        return canonical_time + self.adjustment(canonical_time, key=key, spec=spec)

    def _wander_microseconds(
        self,
        elapsed_seconds: float,
        *,
        key: SourceClockKey,
        spec: ClockWanderSpec,
    ) -> float:
        """Interpolate deterministic adjacent clock-wander knots."""

        interval_seconds = spec.knot_interval.total_seconds()
        left_ordinal = math.floor(elapsed_seconds / interval_seconds)
        fraction = (elapsed_seconds - left_ordinal * interval_seconds) / interval_seconds
        smooth_fraction = fraction * fraction * (3.0 - 2.0 * fraction)
        left = self._wander_knot(key, spec, left_ordinal)
        right = self._wander_knot(key, spec, left_ordinal + 1)
        return left + (right - left) * smooth_fraction

    def _wander_knot(
        self,
        key: SourceClockKey,
        spec: ClockWanderSpec,
        ordinal: int,
    ) -> float:
        """Return one stateless wander-knot value."""

        scope = self._scope(key, ordinal=ordinal)
        return self._sampler.sample_value(
            spec.knot_distribution_microseconds,
            relationship_key="clock.wander_microseconds",
            scope=scope,
            sample_key="knot",
        )

    @staticmethod
    def _scope(key: SourceClockKey, *, ordinal: int = 0) -> TimingScope:
        """Build the semantic sampling scope for a source clock."""

        return TimingScope(
            stable_id=f"{key.kind}:{key.identity}",
            source=key.kind,
            lifecycle_id=key.profile,
            ordinal=ordinal,
        )

    @staticmethod
    def _require_aware(value: datetime, name: str) -> None:
        """Require timezone-aware canonical and reference timestamps."""

        if value.tzinfo is None or value.utcoffset() is None:
            raise TimingDistributionError(f"{name} must be timezone-aware")

    def _prepare(self, *, sampler: TimingSampler) -> SourceClockRegistryPreparation:
        """Return a bounded copy-on-write source-clock preparation."""

        with self._lock:
            return SourceClockRegistryPreparation(
                base=self,
                sampler=sampler,
                base_version=self._mutation_version,
                states=OrderedDict(self._states),
                high_water_mark=self._high_water_mark,
                cache_entry_estimated_bytes=self._cache_entry_estimated_bytes,
                lookup_count=self._lookup_count,
                cache_hit_count=self._cache_hit_count,
                cache_miss_count=self._cache_miss_count,
                eviction_count=self._eviction_count,
            )


class SourceClockRegistryPreparation:
    """Bounded source-clock overlay with exact cache and diagnostic parity."""

    __slots__ = (
        "_base",
        "_base_version",
        "_cache_entry_estimated_bytes",
        "_cache_hit_count",
        "_cache_miss_count",
        "_eviction_count",
        "_high_water_mark",
        "_lookup_count",
        "_operations",
        "_sampler",
        "_states",
        "_value_sampler",
        "_version_delta",
    )

    def __init__(
        self,
        *,
        base: SourceClockRegistry,
        sampler: TimingSampler,
        base_version: int,
        states: OrderedDict[tuple[int, SourceClockKey, SourceClockSpec], SourceClockState],
        high_water_mark: int,
        cache_entry_estimated_bytes: int,
        lookup_count: int,
        cache_hit_count: int,
        cache_miss_count: int,
        eviction_count: int,
    ) -> None:
        self._base = base
        self._sampler = sampler
        self._value_sampler = TimingSampler(
            namespace=sampler.namespace,
            generation_seed=sampler.generation_seed,
        )
        self._base_version = base_version
        self._states = states
        self._high_water_mark = high_water_mark
        self._cache_entry_estimated_bytes = cache_entry_estimated_bytes
        self._lookup_count = lookup_count
        self._cache_hit_count = cache_hit_count
        self._cache_miss_count = cache_miss_count
        self._eviction_count = eviction_count
        self._version_delta = 0
        self._operations: list[tuple[str, str]] = []

    @property
    def reference_time(self) -> datetime:
        """Return the canonical drift epoch."""

        return self._base.reference_time

    @property
    def cache_size(self) -> int:
        """Return canonical plus staged clock entries."""

        return len(self._states)

    @property
    def max_cache_entries(self) -> int:
        """Return the inherited cache bound."""

        return self._base.max_cache_entries

    @property
    def base_version(self) -> int:
        """Return the canonical version captured before staging."""

        return self._base_version

    def clear_cache(self) -> None:
        """Stage a cache clear without mutating the canonical registry."""

        if not self._states:
            return
        self._states.clear()
        self._cache_entry_estimated_bytes = 0
        self._version_delta += 1
        self._operations.append(("clear", ""))

    def census(self, *, estimate_bytes: bool = False) -> SourceClockRegistryCensus:
        """Return canonical plus staged source-clock diagnostics."""

        estimated_bytes = 0
        if estimate_bytes:
            estimated_bytes = (
                sys.getsizeof(self)
                + sys.getsizeof(self._states)
                + self._cache_entry_estimated_bytes
            )
        live_entries = len(self._states)
        return SourceClockRegistryCensus(
            live_entries=live_entries,
            capacity=self.max_cache_entries,
            high_water_mark=self._high_water_mark,
            backing_entries=live_entries,
            estimated_bytes=estimated_bytes,
            lookup_count=self._lookup_count,
            cache_hit_count=self._cache_hit_count,
            cache_miss_count=self._cache_miss_count,
            eviction_count=self._eviction_count,
        )

    def state(self, key: SourceClockKey, spec: SourceClockSpec) -> SourceClockState:
        """Return one staged clock state without canonical cache mutation."""

        self._sampler.record_logical_sample(
            spec.offset_microseconds,
            relationship_key="clock.offset_microseconds",
        )
        self._sampler.record_logical_sample(
            spec.drift_ppm,
            relationship_key="clock.drift_ppm",
        )
        cache_key = (self._sampler.generation_seed, key, spec)
        self._lookup_count += 1
        self._version_delta += 1
        cached = self._states.get(cache_key) if self.max_cache_entries else None
        if cached is not None:
            self._cache_hit_count += 1
            self._states.move_to_end(cache_key)
            self._operations.append(("hit", repr(cache_key)))
            return cached
        self._cache_miss_count += 1

        scope = SourceClockRegistry._scope(key)
        state = SourceClockState(
            offset_microseconds=self._value_sampler.sample_value(
                spec.offset_microseconds,
                relationship_key="clock.offset_microseconds",
                scope=scope,
                sample_key="offset",
            ),
            drift_ppm=self._value_sampler.sample_value(
                spec.drift_ppm,
                relationship_key="clock.drift_ppm",
                scope=scope,
                sample_key="drift",
            ),
        )
        if self.max_cache_entries:
            self._states[cache_key] = state
            self._cache_entry_estimated_bytes += SourceClockRegistry._estimate_cache_entry_bytes(
                cache_key,
                state,
            )
            while len(self._states) > self.max_cache_entries:
                evicted_key, evicted_state = self._states.popitem(last=False)
                self._cache_entry_estimated_bytes -= (
                    SourceClockRegistry._estimate_cache_entry_bytes(evicted_key, evicted_state)
                )
                self._eviction_count += 1
            self._high_water_mark = max(self._high_water_mark, len(self._states))
        self._operations.append(("miss", repr(cache_key)))
        return state

    def adjustment_microseconds(
        self,
        canonical_time: datetime,
        *,
        key: SourceClockKey,
        spec: SourceClockSpec,
    ) -> float:
        """Return the staged clock adjustment in microseconds."""

        SourceClockRegistry._require_aware(canonical_time, "canonical_time")
        elapsed_seconds = (canonical_time - self.reference_time).total_seconds()
        state = self.state(key, spec)
        drift_microseconds = elapsed_seconds * state.drift_ppm
        wander_microseconds = self._wander_microseconds(
            elapsed_seconds,
            key=key,
            spec=spec.wander,
        )
        return state.offset_microseconds + drift_microseconds + wander_microseconds

    def adjustment(
        self,
        canonical_time: datetime,
        *,
        key: SourceClockKey,
        spec: SourceClockSpec,
    ) -> timedelta:
        """Return the staged source-clock adjustment."""

        return timedelta(
            microseconds=self.adjustment_microseconds(
                canonical_time,
                key=key,
                spec=spec,
            )
        )

    def project(
        self,
        canonical_time: datetime,
        *,
        key: SourceClockKey,
        spec: SourceClockSpec,
    ) -> datetime:
        """Project one timestamp through canonical plus staged clock state."""

        return canonical_time + self.adjustment(canonical_time, key=key, spec=spec)

    def _wander_microseconds(
        self,
        elapsed_seconds: float,
        *,
        key: SourceClockKey,
        spec: ClockWanderSpec,
    ) -> float:
        interval_seconds = spec.knot_interval.total_seconds()
        left_ordinal = math.floor(elapsed_seconds / interval_seconds)
        fraction = (elapsed_seconds - left_ordinal * interval_seconds) / interval_seconds
        smooth_fraction = fraction * fraction * (3.0 - 2.0 * fraction)
        left = self._wander_knot(key, spec, left_ordinal)
        right = self._wander_knot(key, spec, left_ordinal + 1)
        return left + (right - left) * smooth_fraction

    def _wander_knot(
        self,
        key: SourceClockKey,
        spec: ClockWanderSpec,
        ordinal: int,
    ) -> float:
        return self._sampler.sample_value(
            spec.knot_distribution_microseconds,
            relationship_key="clock.wander_microseconds",
            scope=SourceClockRegistry._scope(key, ordinal=ordinal),
            sample_key="knot",
        )

    def overlay_digest(self) -> str:
        """Return a stable digest of clock-cache operations."""

        payload = json.dumps(self._operations, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _commit_locked(self) -> None:
        """Replace canonical cache state after version validation under ``_lock``."""

        self._base._states = OrderedDict(self._states)
        self._base._high_water_mark = self._high_water_mark
        self._base._cache_entry_estimated_bytes = self._cache_entry_estimated_bytes
        self._base._lookup_count = self._lookup_count
        self._base._cache_hit_count = self._cache_hit_count
        self._base._cache_miss_count = self._cache_miss_count
        self._base._eviction_count = self._eviction_count
        self._base._mutation_version += self._version_delta
