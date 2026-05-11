# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unit tests for windows auth realism config helpers."""

from evidenceforge.generation.activity import windows_auth_realism


def test_min_unlock_gap_seconds_clamps_too_large_values(monkeypatch):
    """min_unlock_gap_seconds clamps excessively large values to safe maximum."""

    monkeypatch.setattr(
        windows_auth_realism,
        "workstation_lock_config",
        lambda: {"min_unlock_gap_seconds": 10**50},
    )

    assert windows_auth_realism.min_unlock_gap_seconds() == 86_400
