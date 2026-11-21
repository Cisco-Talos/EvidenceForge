# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Ordered canonical phase allocation preserves exact external timing anchors."""

from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.generation.timing.distributions import TimingDistributionError


@pytest.mark.parametrize(
    "microseconds,weights", [(10000, (2, 3, 5)), (3, (999, 1, 2)), (10001, (1, 8)), (1, (1,))]
)
def test_weighted_phases_preserve_anchors_and_positive_microsecond_intervals(
    microseconds: int, weights: tuple[int, ...]
) -> None:
    from evidenceforge.generation.timing.phase_allocation import partition_phase_interval

    start = datetime(2026, 11, 2, 13, tzinfo=UTC)
    end = start + timedelta(microseconds=microseconds)
    arguments = tuple(timedelta(microseconds=v) for v in weights)
    phases = partition_phase_interval(start, end, arguments)
    assert phases == partition_phase_interval(start, end, arguments)
    assert phases[0] == start and phases[-1] == end
    assert len(phases) == len(weights) + 1
    assert all(b - a >= timedelta(microseconds=1) for a, b in zip(phases, phases[1:], strict=False))


@pytest.mark.parametrize("weights", [(), (0,), (-1,), (1, 0), (1, -1)])
def test_phase_allocation_rejects_incompatible_weights(weights: tuple[int, ...]) -> None:
    from evidenceforge.generation.timing.phase_allocation import partition_phase_interval

    start = datetime(2026, 11, 2, 13, tzinfo=UTC)
    with pytest.raises(TimingDistributionError, match="positive weights"):
        partition_phase_interval(
            start, start + timedelta(seconds=1), tuple(timedelta(microseconds=w) for w in weights)
        )


def test_phase_allocation_rejects_too_short_or_naive_intervals() -> None:
    from evidenceforge.generation.timing.phase_allocation import partition_phase_interval

    start = datetime(2026, 11, 2, 13, tzinfo=UTC)
    with pytest.raises(TimingDistributionError, match="positive transitions"):
        partition_phase_interval(
            start, start + timedelta(microseconds=1), (timedelta(seconds=1),) * 2
        )
    with pytest.raises(TimingDistributionError, match="aware anchors"):
        partition_phase_interval(
            start.replace(tzinfo=None), start + timedelta(seconds=1), (timedelta(seconds=1),)
        )
