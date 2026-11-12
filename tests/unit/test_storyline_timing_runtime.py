# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Runtime and distribution tests for storyline timing."""

from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from evidenceforge.generation.engine.storyline import _storyline_session_required_until
from evidenceforge.generation.storyline_timing import (
    STORYLINE_EVENT_JITTER_SECONDS,
    StorylineTimingPlanner,
)
from evidenceforge.generation.timing import TimingRuntime

T0 = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


def test_authored_placement_preserves_windows_and_identity_across_execution_order() -> None:
    runtime = TimingRuntime(reference_time=T0, namespace="authored-placement")
    planner = StorylineTimingPlanner(runtime)

    def place(index: int) -> datetime:
        return planner.place_event(
            T0, event_id=f"event-{index}", host="MAC-01", section="storyline"
        )

    ordered = {index: place(index) for index in range(256)}
    with ThreadPoolExecutor(max_workers=4) as executor:
        reversed_values = dict(
            zip(reversed(range(256)), executor.map(place, reversed(range(256))), strict=True)
        )
    assert ordered == reversed_values
    assert all(
        -STORYLINE_EVENT_JITTER_SECONDS
        < (value - T0).total_seconds()
        < STORYLINE_EVENT_JITTER_SECONDS + 1
        for value in ordered.values()
    )
    assert sum(value.microsecond == 0 for value in ordered.values()) < 3
    assert (
        planner.place_event(T0, event_id="event-0", host="MAC-01", section="red_herring")
        != (ordered[0])
    )


def test_storyline_session_lifetime_covers_remaining_child_cadence() -> None:
    """An authored session remains available through its final planned child."""

    session_time = T0 + timedelta(seconds=30)
    assert _storyline_session_required_until(session_time, (0.0, 30.0, 90.0), 1) == (
        session_time + timedelta(seconds=60)
    )
    assert _storyline_session_required_until(session_time, (0.0, 30.0, 90.0), 2) is None
    process_horizon = _storyline_session_required_until(
        session_time,
        (0.0, 30.0, 90.0),
        1,
        (
            SimpleNamespace(
                type="process",
                process_name="/usr/bin/scp",
                command_line="scp /tmp/report.csv archive:/srv/report.csv",
            ),
        ),
    )
    assert process_horizon is not None
    assert process_horizon > session_time + timedelta(seconds=60)


def _timing_population(
    *,
    cache_size: int,
    workers: int,
    reverse: bool,
) -> dict[int, float]:
    """Sample one storyline family under varied scheduling/cache shapes."""

    runtime = TimingRuntime(
        reference_time=T0,
        namespace="storyline-order-worker-cache",
        max_clock_cache_entries=cache_size,
    )
    planner = StorylineTimingPlanner(runtime)
    ordinals = list(range(512))
    if reverse:
        ordinals.reverse()

    def sample(ordinal: int) -> tuple[int, float]:
        return ordinal, planner.right_skew_seconds(
            relationship_key="storyline.test.worker_cache",
            stable_id=f"storyline-worker:{ordinal}",
            minimum=0.05,
            median=0.18,
            maximum=0.8,
            sigma=0.7,
            host=f"host-{ordinal % 17}",
            ordinal=ordinal,
        )

    if workers == 1:
        values = tuple(sample(ordinal) for ordinal in ordinals)
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            values = tuple(executor.map(sample, ordinals))
    assert runtime.clocks.cache_size <= cache_size
    return dict(values)


@pytest.mark.parametrize("cache_size,workers", [(0, 1), (1, 4), (17, 8)])
def test_storyline_runtime_is_order_worker_and_cache_independent(
    cache_size: int,
    workers: int,
) -> None:
    """Stateless storyline samples must ignore order, workers, and clock eviction."""

    assert _timing_population(cache_size=cache_size, workers=workers, reverse=True) == (
        _timing_population(cache_size=0, workers=1, reverse=False)
    )


def test_storyline_runtime_is_hash_seed_independent() -> None:
    """Storyline timing scopes must not depend on Python hash randomization."""

    script = """
import json
from datetime import UTC, datetime
from evidenceforge.generation.storyline_timing import StorylineTimingPlanner
from evidenceforge.generation.timing import TimingRuntime

t0 = datetime(2026, 8, 16, 12, tzinfo=UTC)
planner = StorylineTimingPlanner(
    TimingRuntime(reference_time=t0, namespace='storyline-hash-seed')
)
values = {
    str(ordinal): planner.right_skew_seconds(
        relationship_key='storyline.test.hash_seed',
        stable_id=f'storyline-hash:{ordinal}',
        minimum=0.05,
        median=0.18,
        maximum=0.8,
        sigma=0.7,
        host=f'host-{ordinal % 11}',
        ordinal=ordinal,
    )
    for ordinal in reversed(range(256))
}
print(json.dumps(values, sort_keys=True))
"""
    outputs = []
    for seed in ("1", "8675309"):
        result = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        outputs.append(json.loads(result.stdout))
    assert outputs[0] == outputs[1]


def test_storyline_right_skew_has_no_ceiling_flat_bins_or_millisecond_atoms() -> None:
    """Typed storyline durations should be open, skewed, and microsecond-granular."""

    runtime = TimingRuntime(reference_time=T0, namespace="storyline-shape")
    planner = StorylineTimingPlanner(runtime)
    values = [
        planner.right_skew_seconds(
            relationship_key="storyline.test.shape",
            stable_id=f"storyline-shape:{ordinal}",
            minimum=0.05,
            median=0.18,
            maximum=0.8,
            sigma=0.7,
            ordinal=ordinal,
        )
        for ordinal in range(4_096)
    ]
    bins = [0] * 10
    for value in values:
        bins[min(9, int((value - 0.05) / 0.075))] += 1

    assert min(values) > 0.05
    assert max(values) < 0.8
    assert statistics.mean(values) > statistics.median(values)
    assert statistics.pstdev(bins) / statistics.mean(bins) > 0.1
    exact_ms = sum(round(value * 1_000_000) % 1_000 == 0 for value in values)
    assert exact_ms / len(values) < 0.005
    audit = runtime.audit.snapshot()
    assert audit.total_saturations / max(1, audit.total_samples) < 0.005
