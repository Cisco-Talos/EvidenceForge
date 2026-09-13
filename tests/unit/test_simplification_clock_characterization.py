"""Characterize live/staged clock parity before consolidating clock arithmetic."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.generation.timing import (
    ClockWanderSpec,
    SourceClockKey,
    SourceClockSpec,
    TimingDistributionError,
    TimingRuntime,
    TriangularDistribution,
)


@pytest.mark.parametrize("seed", [42, 137])
@pytest.mark.parametrize("cache_size", [0, 1, 4])
@pytest.mark.parametrize("commit", [False, True])
def test_prepared_clock_boundaries_preserve_values_audit_and_cache_ownership(
    seed: int, cache_size: int, commit: bool
) -> None:
    epoch = datetime(2024, 1, 15, tzinfo=UTC)
    options = {
        "reference_time": epoch,
        "generation_seed": seed,
        "namespace": "cleanup-wander-boundaries",
        "max_clock_cache_entries": cache_size,
    }
    live = TimingRuntime(**options)
    staged = TimingRuntime(**options)
    keys = tuple(SourceClockKey(kind="endpoint", identity=f"HOST-{i}") for i in range(3))
    spec = SourceClockSpec(
        offset_microseconds=TriangularDistribution(minimum=-1000, mode=30, maximum=500),
        drift_ppm=TriangularDistribution(minimum=-3, mode=0, maximum=4),
        wander=ClockWanderSpec(
            knot_distribution_microseconds=TriangularDistribution(
                minimum=-10000, mode=20, maximum=10000
            ),
            knot_interval=timedelta(seconds=300),
        ),
    )
    for runtime in (live, staged):
        runtime.clocks.project(epoch, key=keys[0], spec=spec)
    before = staged.state_digest()
    before_audit = staged.audit.snapshot()
    before_census = staged.census()
    preparation = staged.prepared()
    elapsed = (-600.000001, -600, -599.999999, -0.000001, 0, 0.000001, 299.999999, 300, 300.000001)
    for index, seconds in enumerate(elapsed * 2):
        key = keys[index % len(keys)]
        at = epoch + timedelta(seconds=seconds)
        expected = live.clocks.adjustment_microseconds(at, key=key, spec=spec)
        actual = preparation.clocks.adjustment_microseconds(at, key=key, spec=spec)
        assert actual.hex() == expected.hex()
    assert staged.state_digest() == before
    assert staged.audit.snapshot() == before_audit
    assert staged.census() == before_census
    assert preparation.audit.snapshot() == live.audit.snapshot()
    assert preparation.clocks.census() == live.clocks.census()
    assert preparation.audit.snapshot().sample_counts["clock.wander_microseconds"] == 38
    if commit:
        preparation._acquire_claim()
        try:
            preparation._commit_no_fail()
        finally:
            preparation._release_claim()
        assert staged.state_digest() == live.state_digest()
        assert staged.audit.snapshot() == live.audit.snapshot()
        assert staged.census() == live.census()
    else:
        preparation.cancel()
        assert staged.state_digest() == before
        assert staged.census() == before_census
        with pytest.raises(TimingDistributionError, match="not open for staging"):
            preparation.clocks.project(epoch, key=keys[0], spec=spec)
