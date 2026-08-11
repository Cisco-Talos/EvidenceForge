# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Duration-stability gates for PID allocation and retained process state."""

import pytest
from scripts.batch7b_state_probe import _run_duration, run_probe


def test_pid_allocator_state_reaches_same_plateau_across_durations() -> None:
    """Deterministic allocator work and retained bytes cannot scale with elapsed hours."""
    results = [_run_duration(hours, 8) for hours in (24, 7 * 24, 30 * 24)]

    assert {
        (
            result.allocator_open_allocations,
            result.allocator_open_ordinals,
            result.allocator_transient_reservations,
        )
        for result in results
    } == {(0, 0, 0)}
    assert all(
        result.allocator_candidate_probes == result.allocator_allocations for result in results
    )
    assert results[1].allocator_retained_bytes == results[2].allocator_retained_bytes


@pytest.mark.slow
def test_pid_allocator_late_window_performance_is_stable_across_repeated_probes() -> None:
    """Repeated 30-day probes keep final-window cost within 25% of steady state."""
    for _repeat in range(3):
        result = run_probe(64)
        ratios = result["late_hour_cost_ratio_vs_24h"]
        assert isinstance(ratios, dict)
        assert float(ratios[str(30 * 24)]) <= 1.25
        assert result["allocator_memory_ratio_30d_vs_7d"] == 1.0
