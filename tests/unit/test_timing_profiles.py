# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for data-driven timing profile loading."""

from datetime import timedelta

import pytest

from evidenceforge.generation.activity.timing_profiles import (
    get_timing_window,
    network_sensor_observation_timing,
    reset_timing_profiles_cache,
    sample_timing_delta,
    windows_collision_spacing_config,
)


@pytest.fixture(autouse=True)
def _reset_cache():
    reset_timing_profiles_cache()
    yield
    reset_timing_profiles_cache()


def test_timing_profiles_load_default_relationship():

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

    navigation_window = get_timing_window(
        "web.session_navigation",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    asset_window = get_timing_window(
        "web.asset_stylesheet_script_after_page",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    assert navigation_window.relationship_class == "human_workflow"
    assert navigation_window.min_ms >= 3000
    assert asset_window.relationship_class == "burst_fanout"
    assert asset_window.min_ms >= 1500

    zeek_conn_window = get_timing_window(
        "source.zeek_conn_start",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    zeek_http_window = get_timing_window(
        "source.zeek_http_request",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    assert asset_window.min_ms > zeek_conn_window.max_ms + zeek_http_window.max_ms

    sensor_timing = network_sensor_observation_timing()
    assert sensor_timing.clock_skew_min_us == -4000
    assert sensor_timing.clock_skew_max_us == 4000
    assert sensor_timing.path_delay_min_us == 250
    assert sensor_timing.path_delay_max_us == 8000


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
network_sensor_observation:
  default_profile: lab
  profiles:
    lab:
      clock_skew_us:
        min: -250
        max: 250
      path_delay_us:
        min: 25
        max: 500
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
    sensor_timing = network_sensor_observation_timing()

    assert window.min_ms == 250
    assert window.max_ms == 750
    assert spacing["near_zero_until"] == 3
    assert spacing["large_gap_min_ms"] == 2000
    assert sensor_timing.clock_skew_min_us == -250
    assert sensor_timing.path_delay_max_us == 500


def test_sample_timing_delta_is_deterministic_and_bounded():
    reset_timing_profiles_cache()

    first = sample_timing_delta("network.dns_before_tcp", seed_parts=("host01", "example.com"))
    second = sample_timing_delta("network.dns_before_tcp", seed_parts=("host01", "example.com"))

    assert first == second
    assert timedelta(milliseconds=20) <= first <= timedelta(milliseconds=1500)


def test_timing_profiles_overlay_invalid_values_fall_back_safely(tmp_path, monkeypatch):
    overlay = tmp_path / ".eforge" / "config" / "activity"
    overlay.mkdir(parents=True)
    (overlay / "timing_profiles.yaml").write_text(
        """
relationships:
  network.dns_before_tcp:
    min_ms: nope
    max_ms: 999999999999
windows_event_time:
  collision_spacing:
    near_zero_until: bad
    near_gap_min_us: -1
    near_gap_max_us: 2000000
    large_gap_min_ms: bad
    large_gap_max_ms: 999999999
network_sensor_observation:
  default_profile: bad
  profiles:
    bad:
      clock_skew_us:
        min: later
        max: -later
      path_delay_us:
        min: 5000
        max: 100
""".lstrip()
    )
    monkeypatch.chdir(tmp_path)
    reset_timing_profiles_cache()

    window = get_timing_window(
        "network.dns_before_tcp",
        default_min_ms=20,
        default_max_ms=1500,
        default_position="before",
    )
    spacing = windows_collision_spacing_config()
    sensor_timing = network_sensor_observation_timing()

    assert window.min_ms == 20
    assert window.max_ms == 86_400_000
    assert spacing["near_zero_until"] == 25
    assert spacing["near_gap_min_us"] == 1
    assert spacing["near_gap_max_us"] == 1_000_000
    assert spacing["large_gap_min_ms"] == 1000
    assert spacing["large_gap_max_ms"] == 60_000
    assert sensor_timing.clock_skew_min_us == -4000
    assert sensor_timing.clock_skew_max_us == 4000
    assert sensor_timing.path_delay_min_us == 250
    assert sensor_timing.path_delay_max_us == 8000
