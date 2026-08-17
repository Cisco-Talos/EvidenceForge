# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Runtime and distribution tests for baseline timing."""

from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest

from evidenceforge.generation.baseline_timing import BaselineTimingPlanner
from evidenceforge.generation.timing import TimingRuntime

T0 = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


def _timing_population(
    *,
    cache_size: int,
    workers: int,
    reverse: bool,
) -> dict[int, float]:
    """Sample one baseline family under varied scheduling/cache shapes."""

    runtime = TimingRuntime(
        reference_time=T0,
        namespace="baseline-order-worker-cache",
        max_clock_cache_entries=cache_size,
    )
    planner = BaselineTimingPlanner(runtime)
    ordinals = list(range(512))
    if reverse:
        ordinals.reverse()

    def sample(ordinal: int) -> tuple[int, float]:
        return ordinal, planner.right_skew_seconds(
            relationship_key="baseline.test.worker_cache",
            stable_id=f"baseline-worker:{ordinal}",
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
def test_baseline_runtime_is_order_worker_and_cache_independent(
    cache_size: int,
    workers: int,
) -> None:
    """Stateless baseline samples must ignore order, workers, and clock eviction."""

    assert _timing_population(cache_size=cache_size, workers=workers, reverse=True) == (
        _timing_population(cache_size=0, workers=1, reverse=False)
    )


def test_baseline_runtime_is_hash_seed_independent() -> None:
    """Baseline timing scopes must not depend on Python hash randomization."""

    script = """
import json
from datetime import UTC, datetime
from evidenceforge.generation.baseline_timing import BaselineTimingPlanner
from evidenceforge.generation.timing import TimingRuntime

t0 = datetime(2026, 8, 16, 12, tzinfo=UTC)
planner = BaselineTimingPlanner(
    TimingRuntime(reference_time=t0, namespace='baseline-hash-seed')
)
values = {
    str(ordinal): planner.right_skew_seconds(
        relationship_key='baseline.test.hash_seed',
        stable_id=f'baseline-hash:{ordinal}',
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


def test_baseline_right_skew_has_no_ceiling_flat_bins_or_millisecond_atoms() -> None:
    """Typed timing should be interior, visibly skewed, and microsecond-granular."""

    runtime = TimingRuntime(reference_time=T0, namespace="baseline-shape")
    planner = BaselineTimingPlanner(runtime)
    values = [
        planner.right_skew_seconds(
            relationship_key="baseline.test.shape",
            stable_id=f"baseline-shape:{ordinal}",
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


def test_clustered_network_phases_have_no_bounds_or_millisecond_atoms() -> None:
    """Profile traffic phases should retain clustered, microsecond-granular shape."""

    runtime = TimingRuntime(reference_time=T0, namespace="baseline-clustered-phase-shape")
    planner = BaselineTimingPlanner(runtime)
    values = [
        planner.clustered_phase_seconds(
            relationship_key="baseline.test.clustered_phase",
            stable_id=f"clustered-phase:{ordinal}",
            centers=(480.0, 1320.0, 2460.0, 3180.0),
            cluster_width=180.0,
            minimum=0.000001,
            maximum=3599.999999,
            ordinal=ordinal,
        )
        for ordinal in range(4_096)
    ]
    bins = [0] * 12
    for value in values:
        bins[min(11, int(value // 300))] += 1

    assert min(values) > 0.000001
    assert max(values) < 3599.999999
    assert statistics.pstdev(bins) / statistics.mean(bins) > 0.15
    exact_ms = sum(round(value * 1_000_000) % 1_000 == 0 for value in values)
    assert exact_ms / len(values) < 0.005
    audit = runtime.audit.snapshot()
    assert audit.total_saturations / max(1, audit.total_samples) < 0.005
