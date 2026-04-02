# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Tests for event timing models (Hawkes, periodic, typing cadence)."""

import random
import statistics

import pytest

from evidenceforge.utils.timing import (
    hawkes_timestamps,
    periodic_timestamps,
    typing_cadence,
)


def _make_rng(seed: int = 42) -> random.Random:
    return random.Random(seed)


# --- hawkes_timestamps ---


class TestHawkesTimestamps:
    def test_count_within_tolerance(self):
        """Generated count should be within 30% of target."""
        rng = _make_rng()
        offsets, _ = hawkes_timestamps(
            num_events=30, duration=3600, mu=0.005, alpha=0.03, beta=0.05, rng=rng
        )
        assert len(offsets) >= 20  # at least 67% of target
        assert len(offsets) <= 40  # at most 133% of target

    def test_sorted(self):
        rng = _make_rng()
        offsets, _ = hawkes_timestamps(
            num_events=20, duration=3600, mu=0.004, alpha=0.02, beta=0.05, rng=rng
        )
        assert offsets == sorted(offsets)

    def test_bounded(self):
        """All offsets should be within [0, duration)."""
        rng = _make_rng()
        offsets, _ = hawkes_timestamps(
            num_events=20, duration=3600, mu=0.004, alpha=0.02, beta=0.05, rng=rng
        )
        for t in offsets:
            assert 0 <= t < 3600

    def test_burstiness_cv(self):
        """CV of inter-event gaps should indicate bursty behavior (CV > 0.8)."""
        rng = _make_rng(seed=123)
        offsets, _ = hawkes_timestamps(
            num_events=50,
            duration=3600,
            mu=0.008,
            alpha=0.04,
            beta=0.06,
            rng=rng,
        )
        if len(offsets) < 10:
            pytest.skip("Too few events for CV calculation")
        gaps = [offsets[i + 1] - offsets[i] for i in range(len(offsets) - 1)]
        mean_gap = statistics.mean(gaps)
        std_gap = statistics.stdev(gaps)
        cv = std_gap / mean_gap if mean_gap > 0 else 0
        assert cv > 0.8, f"CV {cv} too low — not bursty enough"

    def test_stability_check(self):
        """alpha >= beta should raise ValueError."""
        rng = _make_rng()
        with pytest.raises(ValueError, match="unstable"):
            hawkes_timestamps(num_events=10, duration=3600, mu=0.01, alpha=0.05, beta=0.05, rng=rng)
        with pytest.raises(ValueError, match="unstable"):
            hawkes_timestamps(num_events=10, duration=3600, mu=0.01, alpha=0.06, beta=0.05, rng=rng)

    def test_state_continuity(self):
        """Intensity should carry across windows via HawkesState."""
        rng1 = _make_rng(seed=99)
        # First window: generate events that build up intensity
        offsets1, state1 = hawkes_timestamps(
            num_events=20, duration=3600, mu=0.004, alpha=0.03, beta=0.05, rng=rng1
        )
        assert state1.auxiliary_intensity > 0 or len(offsets1) == 0

        # Second window with carried state: should have non-zero starting intensity
        rng2 = _make_rng(seed=100)
        elapsed = 3600 - state1.last_event_time if offsets1 else 3600
        offsets2, state2 = hawkes_timestamps(
            num_events=20,
            duration=3600,
            mu=0.004,
            alpha=0.03,
            beta=0.05,
            rng=rng2,
            state=state1,
            elapsed_since_last=elapsed,
        )
        # Both windows should produce events
        assert len(offsets1) > 0
        assert len(offsets2) > 0

    def test_deterministic_with_same_seed(self):
        """Same seed should produce identical offsets."""
        kwargs = {
            "num_events": 15,
            "duration": 3600,
            "mu": 0.003,
            "alpha": 0.02,
            "beta": 0.05,
        }
        offsets1, _ = hawkes_timestamps(**kwargs, rng=_make_rng(42))
        offsets2, _ = hawkes_timestamps(**kwargs, rng=_make_rng(42))
        assert offsets1 == offsets2

    def test_zero_events(self):
        """num_events=0 should return empty list."""
        offsets, state = hawkes_timestamps(
            num_events=0, duration=3600, mu=0.01, alpha=0.02, beta=0.05, rng=_make_rng()
        )
        assert offsets == []


# --- periodic_timestamps ---


class TestPeriodicTimestamps:
    def test_correct_count(self):
        """600s interval in 3600s window should produce ~6 events."""
        offsets = periodic_timestamps(
            interval=600, phase=0, duration=3600, jitter_fraction=0.0, rng=_make_rng()
        )
        assert 5 <= len(offsets) <= 7

    def test_spacing(self):
        """Gaps should be close to interval when jitter is small."""
        offsets = periodic_timestamps(
            interval=600, phase=0, duration=3600, jitter_fraction=0.01, rng=_make_rng()
        )
        for i in range(len(offsets) - 1):
            gap = offsets[i + 1] - offsets[i]
            assert 550 < gap < 650, f"Gap {gap} too far from interval 600"

    def test_phase_alignment(self):
        """First tick should align with phase offset."""
        offsets = periodic_timestamps(
            interval=600, phase=100, duration=3600, jitter_fraction=0.0, rng=_make_rng()
        )
        assert len(offsets) > 0
        # First tick should be near 500 (600 - 100 phase into cycle)
        assert offsets[0] < 600

    def test_sorted(self):
        offsets = periodic_timestamps(
            interval=300, phase=50, duration=3600, jitter_fraction=0.02, rng=_make_rng()
        )
        assert offsets == sorted(offsets)

    def test_bounded(self):
        offsets = periodic_timestamps(
            interval=300, phase=0, duration=3600, jitter_fraction=0.05, rng=_make_rng()
        )
        for t in offsets:
            assert 0 <= t < 3600

    def test_zero_interval(self):
        offsets = periodic_timestamps(
            interval=0, phase=0, duration=3600, jitter_fraction=0.0, rng=_make_rng()
        )
        assert offsets == []

    def test_cross_hour_alignment(self):
        """Phase should be consistent across adjacent hours."""
        # Hour 0 and Hour 1 should have ticks at the same phase
        offsets_h0 = periodic_timestamps(
            interval=600,
            phase=100,
            duration=3600,
            jitter_fraction=0.0,
            rng=_make_rng(),
            global_offset=0,
        )
        offsets_h1 = periodic_timestamps(
            interval=600,
            phase=100,
            duration=3600,
            jitter_fraction=0.0,
            rng=_make_rng(),
            global_offset=3600,
        )
        # Both should have same number of ticks (same interval/duration)
        assert len(offsets_h0) == len(offsets_h1)


# --- typing_cadence ---


class TestTypingCadence:
    def test_correct_length(self):
        offsets = typing_cadence(5, _make_rng())
        assert len(offsets) == 5

    def test_first_is_zero(self):
        offsets = typing_cadence(3, _make_rng())
        assert offsets[0] == 0.0

    def test_monotonic(self):
        offsets = typing_cadence(10, _make_rng())
        for i in range(len(offsets) - 1):
            assert offsets[i] < offsets[i + 1]

    def test_single_event(self):
        offsets = typing_cadence(1, _make_rng())
        assert offsets == [0.0]

    def test_zero_events(self):
        offsets = typing_cadence(0, _make_rng())
        assert offsets == []

    def test_reasonable_total_duration(self):
        """10 events with default params shouldn't span more than ~2 minutes."""
        offsets = typing_cadence(10, _make_rng())
        assert offsets[-1] < 120  # 2 minutes max for 10 events

    def test_deterministic(self):
        offsets1 = typing_cadence(5, _make_rng(42))
        offsets2 = typing_cadence(5, _make_rng(42))
        assert offsets1 == offsets2
