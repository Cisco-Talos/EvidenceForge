# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for data-driven timing profile loading."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import HostContext, ProcessContext
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.timing_profiles import (
    get_timing_window,
    network_sensor_observation_timing,
    reset_timing_profiles_cache,
    sample_timing_delta,
    windows_collision_spacing_config,
)
from evidenceforge.generation.source_timing import SourceTimingPlanner


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

    security_process_window = get_timing_window(
        "source.windows_security_process_create",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    sysmon_process_window = get_timing_window(
        "source.sysmon_process_create",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    ecar_process_window = get_timing_window(
        "source.ecar_process_create",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    assert security_process_window.max_ms >= 4000
    assert sysmon_process_window.max_ms >= 2000
    assert ecar_process_window.max_ms >= 900

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

    account_reset_window = get_timing_window(
        "windows.account_password_reset_from_add",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    account_change_window = get_timing_window(
        "windows.account_attributes_from_add",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    assert account_reset_window.relationship_class == "source_latency"
    assert account_reset_window.position == "after"
    assert account_reset_window.max_ms < account_change_window.min_ms

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
    assert sensor_timing.clock_skew_min_us == -18000
    assert sensor_timing.clock_skew_max_us == 22000
    assert sensor_timing.path_delay_min_us == 1200
    assert sensor_timing.path_delay_max_us == 58000


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


def test_windows_process_source_timing_respects_visible_parent_create():
    """Child process source-create times should not sort before visible parent create."""
    generator = object.__new__(ActivityGenerator)
    generator._source_timing_planner = SourceTimingPlanner()
    parent_visible_time = datetime(2024, 3, 18, 12, 0, 4, tzinfo=UTC)
    generator._process_source_create_times = {("WS-01", 1000): parent_visible_time}
    event_time = datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC)
    event = SecurityEvent(
        timestamp=event_time,
        event_type="process_create",
        src_host=HostContext(
            hostname="WS-01",
            ip="10.10.1.10",
            os="Windows 11",
            os_category="windows",
            system_type="workstation",
        ),
        process=ProcessContext(
            pid=1200,
            parent_pid=1000,
            image=r"C:\Windows\System32\cmd.exe",
            command_line="cmd.exe /c whoami",
            username="alice",
        ),
    )

    generator._plan_process_source_create_times(event)
    assert event.source_timing is not None
    source_times = event.source_timing.source_times
    sysmon_time = next(
        value
        for key, value in source_times.items()
        if key.startswith("source.sysmon_process_create|")
    )
    security_time = next(
        value
        for key, value in source_times.items()
        if key.startswith("source.windows_security_process_create|")
    )

    assert sysmon_time >= parent_visible_time + timedelta(milliseconds=1)
    assert security_time >= sysmon_time + timedelta(milliseconds=250)

    delayed_event = replace(event, timestamp=event.timestamp + timedelta(seconds=3))
    delayed_sysmon_time = generator._source_timing_planner.source_time(
        delayed_event,
        "source.sysmon_process_create",
        seed_parts=("WS-01", 1200, event_time),
        not_before=event_time,
    )
    assert delayed_sysmon_time == sysmon_time


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
    assert sensor_timing.clock_skew_min_us == -18000
    assert sensor_timing.clock_skew_max_us == 22000
    assert sensor_timing.path_delay_min_us == 1200
    assert sensor_timing.path_delay_max_us == 58000
