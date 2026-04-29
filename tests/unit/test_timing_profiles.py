# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for data-driven timing profile loading."""

from datetime import timedelta

from evidenceforge.generation.activity.timing_profiles import (
    get_timing_window,
    reset_timing_profiles_cache,
    sample_timing_delta,
    windows_collision_spacing_config,
)


def test_timing_profiles_load_default_relationship():
    reset_timing_profiles_cache()

    window = get_timing_window(
        "network.dns_before_tcp",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )

    assert window.position == "before"
    assert window.min_ms == 20
    assert window.max_ms == 1500
    assert window.relationship_class == "causal_prerequisite"

    source_window = get_timing_window(
        "source.ecar_flow",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    assert source_window.position == "after"
    assert source_window.relationship_class == "source_latency"
    assert source_window.min_ms > 0

    tls_window = get_timing_window(
        "network.tls_completed_min_duration",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    assert tls_window.relationship_class == "same_observation"
    assert tls_window.min_ms >= 650


def test_timing_profiles_overlay_overrides_relationship(tmp_path, monkeypatch):
    overlay = tmp_path / ".eforge" / "config" / "activity"
    overlay.mkdir(parents=True)
    (overlay / "timing_profiles.yaml").write_text(
        """
relationships:
  network.dns_before_tcp:
    class: causal_prerequisite
    position: before
    min_ms: 250
    max_ms: 750
windows_event_time:
  collision_spacing:
    near_zero_until: 3
    near_gap_min_us: 10
    near_gap_max_us: 20
    large_gap_min_ms: 2000
    large_gap_max_ms: 3000
""".lstrip()
    )
    monkeypatch.chdir(tmp_path)
    reset_timing_profiles_cache()

    window = get_timing_window(
        "network.dns_before_tcp",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    spacing = windows_collision_spacing_config()

    assert window.min_ms == 250
    assert window.max_ms == 750
    assert spacing["near_zero_until"] == 3
    assert spacing["large_gap_min_ms"] == 2000


def test_sample_timing_delta_is_deterministic_and_bounded():
    reset_timing_profiles_cache()

    first = sample_timing_delta("network.dns_before_tcp", seed_parts=("host01", "example.com"))
    second = sample_timing_delta("network.dns_before_tcp", seed_parts=("host01", "example.com"))

    assert first == second
    assert timedelta(milliseconds=20) <= first <= timedelta(milliseconds=1500)
