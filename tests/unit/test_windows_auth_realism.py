# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unit tests for windows auth realism config helpers."""

import random
import statistics

from evidenceforge.generation.activity import windows_auth_realism


def test_min_unlock_gap_seconds_clamps_too_large_values(monkeypatch):
    """min_unlock_gap_seconds clamps excessively large values to safe maximum."""

    monkeypatch.setattr(
        windows_auth_realism,
        "workstation_lock_config",
        lambda: {"min_unlock_gap_seconds": 10**50},
    )

    assert windows_auth_realism.min_unlock_gap_seconds() == 86_400


def test_remote_auth_duration_profiles_are_source_aware_and_right_skewed():
    """Successful machine auth has a long tail while anonymous auth stays short."""

    machine = [
        windows_auth_realism.sample_remote_auth_transport_duration(
            source="machine_account_logon",
            outcome="success",
            rng=random.Random(seed),
        )
        for seed in range(500)
    ]
    anonymous = [
        windows_auth_realism.sample_remote_auth_transport_duration(
            source="anonymous_logon",
            outcome="success",
            rng=random.Random(seed),
        )
        for seed in range(500)
    ]

    assert statistics.mean(machine) > statistics.median(machine)
    assert max(machine) > 45.0
    assert min(machine) >= 0.5
    assert max(machine) <= 120.0
    assert max(anonymous) <= 12.0
    assert statistics.median(anonymous) < statistics.median(machine)


def test_remote_auth_failure_profile_remains_short_and_deterministic():
    """Failure transports remain bounded and identical for an identical RNG seed."""

    first = windows_auth_realism.sample_remote_auth_transport_duration(
        source="activity_generator",
        outcome="failure",
        rng=random.Random(42),
    )
    second = windows_auth_realism.sample_remote_auth_transport_duration(
        source="activity_generator",
        outcome="failure",
        rng=random.Random(42),
    )

    assert first == second
    assert 0.02 <= first <= 1.5
