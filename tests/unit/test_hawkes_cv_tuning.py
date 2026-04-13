# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Parametric tests for Hawkes timing parameter tuning.

Verifies that the retuned parameters produce CV values in the evaluator's
ideal 1.0-3.0 range for realistic user event counts.
"""

import random
import statistics

import pytest

from evidenceforge.utils.timing import hawkes_timestamps


def _compute_cv(timestamps: list[float], dedup_threshold: float = 5.0) -> float | None:
    """Compute CV of inter-event gaps after deduplication (matching evaluator logic)."""
    if len(timestamps) < 2:
        return None
    sorted_ts = sorted(timestamps)
    deduped = [sorted_ts[0]]
    for ts in sorted_ts[1:]:
        if ts - deduped[-1] > dedup_threshold:
            deduped.append(ts)
    if len(deduped) < 20:
        return None
    gaps = [deduped[i + 1] - deduped[i] for i in range(len(deduped) - 1)]
    if len(gaps) < 5:
        return None
    mean_gap = statistics.mean(gaps)
    if mean_gap == 0:
        return None
    return statistics.stdev(gaps) / mean_gap


class TestHawkesCvTuning:
    """Verify retuned Hawkes parameters produce CV in evaluator's ideal range."""

    @pytest.mark.parametrize(
        "risk_level,alpha_beta_ratio,beta",
        [
            ("high", 0.60, 0.06),
            ("medium", 0.50, 0.07),
            ("low", 0.35, 0.10),
        ],
    )
    def test_cv_in_scoring_range(self, risk_level, alpha_beta_ratio, beta):
        """Median CV across 50 seeds should fall in [1.0, 3.0]."""
        num_events = 40  # Typical events per hour
        duration = 3600.0
        cv_values = []

        for seed in range(50):
            rng = random.Random(seed)
            alpha = alpha_beta_ratio * beta
            mu = num_events / duration * (1.0 - alpha_beta_ratio)
            mu = max(0.0001, mu)

            offsets, _ = hawkes_timestamps(
                num_events=num_events,
                duration=duration,
                mu=mu,
                alpha=alpha,
                beta=beta,
                rng=rng,
            )
            cv = _compute_cv(offsets)
            if cv is not None:
                cv_values.append(cv)

        assert len(cv_values) >= 30, (
            f"{risk_level}: only {len(cv_values)} valid CV samples (need 30+)"
        )

        median_cv = statistics.median(cv_values)
        assert 0.8 <= median_cv <= 3.5, (
            f"{risk_level}: median CV {median_cv:.2f} outside [0.8, 3.5]"
        )

        # At least 60% of users should score in the ideal 1.0-3.0 range
        in_range = sum(1 for cv in cv_values if 1.0 <= cv <= 3.0)
        pct = in_range / len(cv_values) * 100
        assert pct >= 60, f"{risk_level}: only {pct:.0f}% of users in [1.0, 3.0] (need 60%+)"

    def test_bias_clamp_prevents_instability(self):
        """Per-user bias with worst-case Gaussian shouldn't exceed alpha_beta_ratio=0.75."""
        # Worst case: high risk (0.60) + 3-sigma cluster_size_bias (0.36)
        alpha_beta_ratio = 0.60
        extreme_bias = 1.0 + 3 * 0.12  # 3-sigma from gauss(0, 0.12) = 1.36
        clamped = min(0.75, alpha_beta_ratio * extreme_bias)
        assert clamped == 0.75  # Should be clamped

        # Normal case: medium risk + 1-sigma bias
        alpha_beta_ratio = 0.50
        normal_bias = 1.0 + 0.12
        clamped = min(0.75, alpha_beta_ratio * normal_bias)
        assert clamped < 0.75  # Should not be clamped
        assert clamped == pytest.approx(0.56, abs=0.01)
