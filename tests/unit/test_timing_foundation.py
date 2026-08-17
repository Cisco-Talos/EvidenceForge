# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the shared deterministic timing foundation."""

from __future__ import annotations

import statistics
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.generation.timing import (
    ClockWanderSpec,
    ConstantDistribution,
    MixtureDistribution,
    SourceClockKey,
    SourceClockRegistry,
    SourceClockSpec,
    TimingAudit,
    TimingAuditSummary,
    TimingDistributionError,
    TimingRuntime,
    TimingSampler,
    TimingScope,
    TriangularDistribution,
    TruncatedLognormalDistribution,
    TruncatedNormalDistribution,
    WeightedDistribution,
)
from evidenceforge.utils.rng import generation_seed_scope

T0 = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


def _scopes(count: int, *, prefix: str = "sample") -> list[TimingScope]:
    """Return a deterministic population of independent semantic scopes."""

    return [TimingScope(stable_id=f"{prefix}:{index}", ordinal=index) for index in range(count)]


def test_sampler_is_deterministic_and_call_order_independent() -> None:
    """Semantic scopes, rather than mutable RNG position, must own every draw."""

    distribution = TruncatedLognormalDistribution(
        median=125_000,
        sigma=0.7,
        minimum=2_000,
        maximum=3_000_000,
    )
    scopes = _scopes(128)
    first_sampler = TimingSampler(namespace="order-test")
    first = {
        scope.stable_id: first_sampler.sample_microseconds(
            distribution,
            relationship_key="source.process_create",
            scope=scope,
        )
        for scope in scopes
    }

    second_sampler = TimingSampler(namespace="order-test")
    second = {
        scope.stable_id: second_sampler.sample_microseconds(
            distribution,
            relationship_key="source.process_create",
            scope=scope,
        )
        for scope in reversed(scopes)
    }

    assert first == second
    assert len(set(first.values())) > 120


def test_sampler_generation_seed_is_stable_across_worker_contexts() -> None:
    """A runtime-owned sampler must not fall back to a worker's default seed."""

    distribution = TriangularDistribution(minimum=1_000, mode=4_000, maximum=20_000)
    scopes = _scopes(512, prefix="seeded-worker")
    with generation_seed_scope(9_137):
        sampler = TimingSampler(namespace="seeded-worker-test")
        serial = {
            scope.stable_id: sampler.sample_microseconds(
                distribution,
                relationship_key="source.seeded_worker",
                scope=scope,
            )
            for scope in scopes
        }

    with ThreadPoolExecutor(max_workers=8) as executor:
        concurrent_values = tuple(
            executor.map(
                lambda scope: sampler.sample_microseconds(
                    distribution,
                    relationship_key="source.seeded_worker",
                    scope=scope,
                ),
                reversed(scopes),
            )
        )
    concurrent = {
        scope.stable_id: value
        for scope, value in zip(reversed(scopes), concurrent_values, strict=True)
    }

    assert sampler.generation_seed == 9_137
    assert concurrent == serial


@pytest.mark.parametrize(
    "distribution",
    [
        TriangularDistribution(minimum=0, mode=175_000, maximum=1_000_000),
        TruncatedNormalDistribution(
            mean=400_000,
            standard_deviation=225_000,
            minimum=0,
            maximum=1_000_000,
        ),
        TruncatedLognormalDistribution(
            median=125_000,
            sigma=0.8,
            minimum=1_000,
            maximum=3_000_000,
        ),
    ],
)
def test_continuous_timedelta_samples_are_diverse_without_boundary_atoms(
    distribution: (
        TriangularDistribution | TruncatedNormalDistribution | TruncatedLognormalDistribution
    ),
) -> None:
    """Continuous timing families must not collapse probability onto hard bounds."""

    sampler = TimingSampler(namespace=f"boundary-{type(distribution).__name__}")
    values = [
        sampler.sample_microseconds(
            distribution,
            relationship_key="source.latency",
            scope=scope,
        )
        for scope in _scopes(4096, prefix=type(distribution).__name__)
    ]

    assert min(values) > distribution.minimum
    assert max(values) < distribution.maximum
    assert values.count(round(distribution.minimum)) == 0
    assert values.count(round(distribution.maximum)) == 0
    assert len(set(values)) > 3800


def test_truncated_distribution_quantiles_follow_requested_shape() -> None:
    """Large deterministic cohorts should retain their intended center and tail."""

    sampler = TimingSampler(namespace="quantile-test")
    distribution = TruncatedLognormalDistribution(
        median=100_000,
        sigma=0.65,
        minimum=1,
        maximum=10_000_000,
    )
    values = [
        sampler.sample_value(
            distribution,
            relationship_key="source.collection_delay",
            scope=scope,
        )
        for scope in _scopes(8192, prefix="quantile")
    ]
    ordered = sorted(values)
    median = statistics.median(ordered)
    p90 = ordered[round(0.9 * (len(ordered) - 1))]
    p99 = ordered[round(0.99 * (len(ordered) - 1))]

    assert median == pytest.approx(distribution.median, rel=0.04)
    assert p90 > 2 * median
    assert p99 > 3 * median


def test_mixture_weights_and_constant_components_are_deterministic() -> None:
    """Mixtures should select weighted components without a mutable global stream."""

    sampler = TimingSampler(namespace="mixture-test")
    distribution = MixtureDistribution(
        components=(
            WeightedDistribution(0.8, ConstantDistribution(10_000)),
            WeightedDistribution(0.2, ConstantDistribution(900_000)),
        )
    )
    values = [
        sampler.sample_microseconds(
            distribution,
            relationship_key="source.fast_or_batched",
            scope=scope,
        )
        for scope in _scopes(5000, prefix="mixture")
    ]

    assert set(values) == {10_000, 900_000}
    assert values.count(900_000) / len(values) == pytest.approx(0.2, abs=0.02)


def test_distribution_specs_reject_invalid_nested_components() -> None:
    """Typed mixture and clock specs should fail before a bad component is sampled."""

    with pytest.raises(TimingDistributionError, match="unsupported timing distribution"):
        WeightedDistribution(1.0, object())  # type: ignore[arg-type]
    with pytest.raises(TimingDistributionError, match="unsupported timing distribution"):
        SourceClockSpec(offset_microseconds=object())  # type: ignore[arg-type]


def test_quantization_resamples_instead_of_clamping_to_a_boundary() -> None:
    """A tail-conditioned distribution must not turn into a maximum-value spike."""

    sampler = TimingSampler(namespace="tail-boundary-test")
    distribution = TruncatedNormalDistribution(
        mean=2_000,
        standard_deviation=400,
        minimum=0,
        maximum=1_000,
    )
    values = [
        sampler.sample_microseconds(
            distribution,
            relationship_key="constraint.repair",
            scope=scope,
        )
        for scope in _scopes(2048, prefix="tail")
    ]

    assert 1_000 not in values
    assert all(0 < value < 1_000 for value in values)
    assert len(set(values)) > 400


def test_audit_counters_are_bounded_and_do_not_change_samples() -> None:
    """Diagnostics should count behavior without becoming part of RNG state."""

    audit = TimingAudit(max_relationship_keys=2)
    observed = TimingSampler(namespace="audit-test", observer=audit)
    unobserved = TimingSampler(namespace="audit-test")
    distribution = TriangularDistribution(minimum=0, mode=50, maximum=100)
    scope = TimingScope(stable_id="audit:1")

    assert observed.sample_value(
        distribution,
        relationship_key="one",
        scope=scope,
    ) == unobserved.sample_value(distribution, relationship_key="one", scope=scope)
    observed.sample_value(distribution, relationship_key="two", scope=scope)
    observed.sample_value(distribution, relationship_key="three", scope=scope)
    audit.record_repair("one")
    audit.record_saturation("one")
    audit.record_fallback("legacy")
    summary = audit.snapshot()

    assert summary.total_samples == 3
    assert summary.distribution_counts == {"triangular": 3}
    assert summary.total_repairs == 1
    assert summary.total_saturations == 1
    assert summary.total_fallbacks == 1
    assert len(summary.sample_counts) <= 2


def test_audit_relationship_buckets_are_arrival_order_independent() -> None:
    """Worker arrival order must not select different retained relationship keys."""

    counts = {"alpha": 5, "bravo": 3, "charlie": 7, "delta": 2}
    forward = TimingAudit(max_relationship_keys=2)
    reverse = TimingAudit(max_relationship_keys=2)

    for key, count in counts.items():
        for _ in range(count):
            forward.record_sample(key, "constant")
    for key, count in reversed(tuple(counts.items())):
        for _ in range(count):
            reverse.record_sample(key, "constant")

    assert forward.snapshot() == reverse.snapshot()
    assert forward.snapshot().total_samples == sum(counts.values())


def test_audit_relationship_buckets_are_worker_schedule_independent() -> None:
    """Concurrent writers must produce the same bounded audit as serial writers."""

    keys = tuple(f"relationship-{ordinal % 17}" for ordinal in range(2_000))
    serial = TimingAudit(max_relationship_keys=8)
    concurrent = TimingAudit(max_relationship_keys=8)
    for key in keys:
        serial.record_sample(key, "constant")
    with ThreadPoolExecutor(max_workers=8) as executor:
        tuple(executor.map(lambda key: concurrent.record_sample(key, "constant"), keys))

    assert concurrent.snapshot() == serial.snapshot()


def test_audit_rendered_bucket_label_cannot_overwrite_an_exact_relationship() -> None:
    """A relationship matching a collision label must not corrupt audit totals."""

    audit = TimingAudit(max_relationship_keys=2)
    audit.record_sample("bravo", "constant")
    audit.record_sample("charlie", "constant")
    audit.record_sample("bravo [bucket:1]", "constant")

    summary = audit.snapshot()

    assert summary.total_samples == 3
    assert sum(summary.sample_counts.values()) == 3


def test_source_clock_audit_is_independent_of_cache_hits_and_eviction() -> None:
    """Logical clock audit totals must not depend on the optimization cache."""

    key = SourceClockKey(kind="endpoint", identity="WKSTN-01", profile="enterprise")
    spec = SourceClockSpec(
        offset_microseconds=ConstantDistribution(100_000),
        drift_ppm=ConstantDistribution(10),
    )

    def project_with_cache(cache_size: int) -> TimingAuditSummary:
        audit = TimingAudit()
        sampler = TimingSampler(namespace="clock-audit-test", observer=audit)
        registry = SourceClockRegistry(
            reference_time=T0,
            sampler=sampler,
            max_cache_entries=cache_size,
        )
        for ordinal in range(8):
            registry.project(T0 + timedelta(seconds=ordinal), key=key, spec=spec)
        return audit.snapshot()

    uncached = project_with_cache(0)
    cached = project_with_cache(1)

    assert cached == uncached
    assert cached.sample_counts["clock.offset_microseconds"] == 8
    assert cached.sample_counts["clock.drift_ppm"] == 8


@pytest.mark.parametrize("worker_count", [1, 4, 8])
@pytest.mark.parametrize("cache_size", [0, 1, 7, 128])
def test_source_clock_values_and_audit_are_worker_and_eviction_independent(
    worker_count: int,
    cache_size: int,
) -> None:
    """Clock values and logical counters must ignore cache and worker scheduling."""

    audit = TimingAudit(max_relationship_keys=16)
    registry = SourceClockRegistry(
        reference_time=T0,
        sampler=TimingSampler(namespace="clock-worker-cache-test", observer=audit),
        max_cache_entries=cache_size,
    )
    spec = SourceClockSpec(
        offset_microseconds=TruncatedNormalDistribution(
            mean=0,
            standard_deviation=75_000,
            minimum=-300_000,
            maximum=300_000,
        ),
        drift_ppm=TruncatedNormalDistribution(
            mean=0,
            standard_deviation=2,
            minimum=-8,
            maximum=8,
        ),
        wander=ClockWanderSpec(
            knot_distribution_microseconds=TruncatedNormalDistribution(
                mean=0,
                standard_deviation=10_000,
                minimum=-40_000,
                maximum=40_000,
            ),
            knot_interval=timedelta(minutes=3),
        ),
    )
    operations = tuple(
        (
            ordinal,
            T0 + timedelta(seconds=(ordinal * 37) % 3_600),
            SourceClockKey(
                kind="endpoint" if ordinal % 2 else "sensor",
                identity=f"source-{ordinal % 41}",
                profile="enterprise",
            ),
        )
        for ordinal in range(1_024)
    )

    def project(
        operation: tuple[int, datetime, SourceClockKey],
    ) -> tuple[int, datetime]:
        ordinal, canonical_time, key = operation
        return ordinal, registry.project(canonical_time, key=key, spec=spec)

    if worker_count == 1:
        values = tuple(project(operation) for operation in operations)
    else:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            values = tuple(executor.map(project, operations))

    reference_audit = TimingAudit(max_relationship_keys=16)
    reference_registry = SourceClockRegistry(
        reference_time=T0,
        sampler=TimingSampler(
            namespace="clock-worker-cache-test",
            observer=reference_audit,
        ),
        max_cache_entries=0,
    )
    reference_values = tuple(
        (
            ordinal,
            reference_registry.project(canonical_time, key=key, spec=spec),
        )
        for ordinal, canonical_time, key in operations
    )

    assert values == reference_values
    assert audit.snapshot() == reference_audit.snapshot()
    assert audit.snapshot().sample_counts == {
        "clock.drift_ppm": len(operations),
        "clock.offset_microseconds": len(operations),
        "clock.wander_microseconds": len(operations) * 2,
    }
    assert registry.cache_size <= cache_size


def test_source_clock_applies_offset_and_epoch_based_drift() -> None:
    """Clock drift should accumulate from a stable epoch instead of resetting daily."""

    sampler = TimingSampler(namespace="clock-drift-test")
    registry = SourceClockRegistry(reference_time=T0, sampler=sampler)
    key = SourceClockKey(kind="endpoint", identity="WKSTN-01", profile="enterprise")
    spec = SourceClockSpec(
        offset_microseconds=ConstantDistribution(100_000),
        drift_ppm=ConstantDistribution(10),
    )

    assert registry.adjustment_microseconds(T0, key=key, spec=spec) == 100_000
    assert (
        registry.adjustment_microseconds(
            T0 + timedelta(seconds=100),
            key=key,
            spec=spec,
        )
        == 101_000
    )
    assert registry.project(T0, key=key, spec=spec) == T0 + timedelta(milliseconds=100)


def test_source_clock_wander_is_smooth_and_continuous_across_midnight() -> None:
    """Smooth epoch-based wander must not introduce a midnight clock discontinuity."""

    reference = datetime(2026, 8, 16, 23, 55, tzinfo=UTC)
    runtime = TimingRuntime(reference_time=reference, namespace="midnight-test")
    key = SourceClockKey(kind="sensor", identity="core-tap", profile="messy")
    spec = SourceClockSpec(
        offset_microseconds=TruncatedNormalDistribution(
            mean=0,
            standard_deviation=50_000,
            minimum=-200_000,
            maximum=200_000,
        ),
        drift_ppm=TruncatedNormalDistribution(
            mean=0,
            standard_deviation=5,
            minimum=-20,
            maximum=20,
        ),
        wander=ClockWanderSpec(
            knot_distribution_microseconds=TruncatedNormalDistribution(
                mean=0,
                standard_deviation=15_000,
                minimum=-50_000,
                maximum=50_000,
            ),
            knot_interval=timedelta(minutes=2),
        ),
    )
    before = datetime(2026, 8, 16, 23, 59, 59, 999_000, tzinfo=UTC)
    after = before + timedelta(milliseconds=2)
    projected_before = runtime.clocks.project(before, key=key, spec=spec)
    projected_after = runtime.clocks.project(after, key=key, spec=spec)

    assert projected_after - projected_before == pytest.approx(
        timedelta(milliseconds=2),
        abs=timedelta(microseconds=5),
    )
    duplicate = TimingRuntime(reference_time=reference, namespace="midnight-test")
    assert duplicate.clocks.project(before, key=key, spec=spec) == projected_before
    assert duplicate.clocks.project(after, key=key, spec=spec) == projected_after


def test_source_clock_cache_is_bounded_and_recomputation_is_exact() -> None:
    """LRU eviction may affect work performed, never a projected timestamp."""

    registry = SourceClockRegistry(
        reference_time=T0,
        sampler=TimingSampler(namespace="clock-cache-test"),
        max_cache_entries=2,
    )
    spec = SourceClockSpec(
        offset_microseconds=TruncatedNormalDistribution(
            mean=0,
            standard_deviation=100_000,
            minimum=-500_000,
            maximum=500_000,
        ),
        drift_ppm=TruncatedNormalDistribution(
            mean=0,
            standard_deviation=3,
            minimum=-10,
            maximum=10,
        ),
    )
    first_key = SourceClockKey(kind="endpoint", identity="host-1")
    first = registry.project(T0 + timedelta(hours=1), key=first_key, spec=spec)
    for identity in ("host-2", "host-3"):
        registry.project(
            T0 + timedelta(hours=1),
            key=SourceClockKey(kind="endpoint", identity=identity),
            spec=spec,
        )

    assert registry.cache_size == 2
    assert registry.project(T0 + timedelta(hours=1), key=first_key, spec=spec) == first
    assert registry.cache_size == 2


def test_runtime_census_reports_default_clock_plateau_without_private_scans() -> None:
    """The public census must expose a real 2,048-entry cache plateau in constant time."""

    runtime = TimingRuntime(reference_time=T0, namespace="clock-census-test")
    spec = SourceClockSpec(
        offset_microseconds=TruncatedNormalDistribution(
            mean=0,
            standard_deviation=80_000,
            minimum=-300_000,
            maximum=300_000,
        ),
        drift_ppm=TruncatedNormalDistribution(
            mean=0,
            standard_deviation=3,
            minimum=-12,
            maximum=12,
        ),
    )
    for ordinal in range(4_096):
        runtime.clocks.state(
            SourceClockKey(
                kind="endpoint" if ordinal % 3 else "sensor",
                identity=f"source-instance-{ordinal}",
                profile="complete" if ordinal % 2 else "messy",
            ),
            spec,
        )

    census = runtime.census(estimate_bytes=True)

    assert census.clocks.live_entries == 2_048
    assert census.clocks.backing_entries == 2_048
    assert census.clocks.capacity == 2_048
    assert census.clocks.high_water_mark == 2_048
    assert census.clocks.lookup_count == 4_096
    assert census.clocks.cache_hit_count == 0
    assert census.clocks.cache_miss_count == 4_096
    assert census.clocks.eviction_count == 2_048
    assert census.clocks.estimated_bytes > 0
    assert census.audit.relationship_slots_live == 2
    assert census.audit.relationship_slots_capacity == 4 * 4_096
    assert census.audit.sample_count == 2 * 4_096
    assert census.audit.estimated_index_bytes > 0
    assert census.audit.estimated_bytes > 0
    assert census.estimated_index_bytes == (
        census.clocks.estimated_bytes + census.audit.estimated_index_bytes
    )
    assert census.estimated_bytes >= (census.clocks.estimated_bytes + census.audit.estimated_bytes)

    runtime.clocks.state(
        SourceClockKey(
            kind="sensor",
            identity="source-instance-4095",
            profile="complete",
        ),
        spec,
    )
    after_hit = runtime.census()
    assert after_hit.clocks.cache_hit_count == 1
    assert after_hit.clocks.lookup_count == 4_097
    assert after_hit.audit.sample_count == 2 * 4_097


def test_source_clock_rejects_naive_reference_and_canonical_times() -> None:
    """Clock projection must not silently mix naive and aware timestamp domains."""

    sampler = TimingSampler(namespace="clock-awareness-test")
    with pytest.raises(TimingDistributionError, match="reference_time"):
        SourceClockRegistry(reference_time=datetime(2026, 8, 16), sampler=sampler)

    registry = SourceClockRegistry(reference_time=T0, sampler=sampler)
    with pytest.raises(TimingDistributionError, match="canonical_time"):
        registry.project(
            datetime(2026, 8, 16),
            key=SourceClockKey(kind="endpoint", identity="host-1"),
            spec=SourceClockSpec(),
        )
