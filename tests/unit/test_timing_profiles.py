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
    endpoint_clock_timing,
    get_timing_window,
    network_sensor_observation_timing,
    reset_timing_profiles_cache,
    sample_timing_delta,
    windows_collision_spacing_config,
)
from evidenceforge.generation.causal.engine import ExpandedEvent
from evidenceforge.generation.causal.timing import TimingSpec
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.models.scenario import System


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
    assert source_window.max_ms >= 1500

    security_process_window = get_timing_window(
        "source.windows_security_process_create",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    security_terminate_window = get_timing_window(
        "source.windows_security_process_terminate",
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
    sysmon_terminate_window = get_timing_window(
        "source.sysmon_process_terminate",
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
    ecar_after_sysmon_window = get_timing_window(
        "source.ecar_after_sysmon_process_create_gap",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    assert security_process_window.max_ms <= 1000
    assert 0 < security_terminate_window.min_ms < security_terminate_window.max_ms
    assert sysmon_process_window.max_ms <= 1200
    assert 0 < sysmon_terminate_window.min_ms < sysmon_terminate_window.max_ms
    assert ecar_process_window.max_ms >= 900
    assert 0 < ecar_after_sysmon_window.min_ms < ecar_after_sysmon_window.max_ms
    assert ecar_after_sysmon_window.max_ms >= 3000
    remote_thread_after_open_window = get_timing_window(
        "source.ecar_remote_thread_after_process_open",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    assert 0 < remote_thread_after_open_window.min_ms < remote_thread_after_open_window.max_ms
    assert remote_thread_after_open_window.max_ms <= 300
    remote_thread_process_access_window = get_timing_window(
        "process.remote_thread_process_access",
        default_min_ms=0,
        default_max_ms=0,
        default_position="before",
    )
    assert (
        0
        < remote_thread_process_access_window.min_ms
        < remote_thread_process_access_window.max_ms
        <= 200
    )
    security_gap_window = get_timing_window(
        "source.windows_security_after_sysmon_process_create_gap",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    assert 0 < security_gap_window.min_ms < security_gap_window.max_ms <= 700
    audit_after_command_window = get_timing_window(
        "windows.audit_after_visible_admin_command",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    assert audit_after_command_window.min_ms > 0
    remote_logon_ready_window = get_timing_window(
        "windows.remote_logon_source_ready",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    assert 0 < remote_logon_ready_window.min_ms < remote_logon_ready_window.max_ms

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
    assert sensor_timing.path_delay_max_us == 18000
    assert sensor_timing.clock_drift_min_ppm == -2
    assert sensor_timing.event_jitter_max_us == 750
    assert sensor_timing.capture_loss_probability == 0.0

    endpoint_timing = endpoint_clock_timing("enterprise_standard", "windows")
    assert endpoint_timing.host_offset_min_ms == -1250
    assert endpoint_timing.host_offset_max_ms == 1800
    assert endpoint_timing.host_drift_min_ppm == -8
    assert endpoint_timing.host_drift_max_ppm == 8


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
endpoint_clock:
  profiles:
    complete:
      windows:
        host_offset_ms:
          min: 0
          max: 0
        host_drift_ppm:
          min: 0
          max: 0
      linux:
        host_offset_ms:
          min: 0
          max: 0
        host_drift_ppm:
          min: 0
          max: 0
    lab:
      windows:
        host_offset_ms:
          min: -10
          max: 20
        host_drift_ppm:
          min: -1
          max: 1
      linux:
        host_offset_ms:
          min: -30
          max: 40
        host_drift_ppm:
          min: -2
          max: 2
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
    endpoint_timing = endpoint_clock_timing("lab", "linux")

    assert window.min_ms == 250
    assert window.max_ms == 750
    assert spacing["near_zero_until"] == 3
    assert spacing["large_gap_min_ms"] == 2000
    assert sensor_timing.clock_skew_min_us == -250
    assert sensor_timing.path_delay_max_us == 500
    assert endpoint_timing.host_offset_min_ms == -30
    assert endpoint_timing.host_drift_max_ppm == 2


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
    ecar_time = next(
        value
        for key, value in source_times.items()
        if key.startswith("source.ecar_process_create|")
    )

    assert sysmon_time >= parent_visible_time + timedelta(milliseconds=1)
    assert security_time >= parent_visible_time + timedelta(milliseconds=1)
    assert ecar_time >= event_time

    order_deltas: list[float] = []
    for pid in range(1200, 1250):
        sampled_event = replace(
            event,
            process=replace(event.process, pid=pid),
            source_timing=None,
        )
        sampled_generator = object.__new__(ActivityGenerator)
        sampled_generator._source_timing_planner = SourceTimingPlanner()
        sampled_generator._process_source_create_times = {}
        sampled_generator._plan_process_source_create_times(sampled_event)
        assert sampled_event.source_timing is not None
        sampled_source_times = sampled_event.source_timing.source_times
        sampled_sysmon_time = next(
            value
            for key, value in sampled_source_times.items()
            if key.startswith("source.sysmon_process_create|")
        )
        sampled_security_time = next(
            value
            for key, value in sampled_source_times.items()
            if key.startswith("source.windows_security_process_create|")
        )
        order_deltas.append((sampled_security_time - sampled_sysmon_time).total_seconds())
    assert any(delta < 0 for delta in order_deltas)
    assert any(delta > 0 for delta in order_deltas)

    delayed_event = replace(event, timestamp=event.timestamp + timedelta(seconds=3))
    delayed_sysmon_time = generator._source_timing_planner.source_time(
        delayed_event,
        "source.sysmon_process_create",
        seed_parts=("WS-01", 1200, event_time),
        not_before=event_time,
    )
    assert delayed_sysmon_time == sysmon_time


def test_process_source_terminate_time_preserves_visible_ecar_lifetime():
    """Stored source-terminate time should preserve lifetime from the real create."""
    generator = object.__new__(ActivityGenerator)
    generator._source_timing_planner = SourceTimingPlanner()
    generator._process_source_create_times = {}
    generator._process_source_terminate_times = {}
    start_time = datetime(2024, 3, 18, 17, 15, 41, tzinfo=UTC)
    terminate_time = start_time + timedelta(seconds=8)
    event = SecurityEvent(
        timestamp=terminate_time,
        event_type="process_terminate",
        src_host=HostContext(
            hostname="DB-PROD-01",
            ip="10.10.4.10",
            os="Ubuntu 22.04",
            os_category="linux",
            system_type="server",
        ),
        process=ProcessContext(
            pid=699072,
            parent_pid=698948,
            image="/usr/bin/gzip",
            command_line="",
            username="root",
            start_time=start_time,
        ),
    )

    generator._record_process_source_terminate_time("DB-PROD-01", 699072, event)

    source_terminate_time = generator.process_source_terminate_time("DB-PROD-01", 699072)
    assert source_terminate_time is not None
    assert source_terminate_time >= terminate_time
    assert source_terminate_time < terminate_time + timedelta(seconds=2)


def test_process_source_terminate_time_uses_stored_visible_create_anchor():
    """Termination planning should not add the full process lifetime twice."""
    generator = object.__new__(ActivityGenerator)
    generator._source_timing_planner = SourceTimingPlanner()
    start_time = datetime(2024, 3, 18, 13, 48, 41, tzinfo=UTC)
    terminate_time = start_time + timedelta(hours=2, minutes=4, seconds=48)
    visible_create_time = start_time + timedelta(milliseconds=350)
    generator._process_source_create_times = {("WS-01", 5396): visible_create_time}
    generator._process_source_terminate_times = {}
    event = SecurityEvent(
        timestamp=terminate_time,
        event_type="process_terminate",
        src_host=HostContext(
            hostname="WS-01",
            ip="10.10.1.22",
            os="Windows 11",
            os_category="windows",
            system_type="workstation",
        ),
        process=ProcessContext(
            pid=5396,
            parent_pid=5092,
            image=r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
            command_line="",
            username="alice",
            start_time=start_time,
        ),
    )

    generator._record_process_source_terminate_time("WS-01", 5396, event)

    source_terminate_time = generator.process_source_terminate_time("WS-01", 5396)
    assert source_terminate_time is not None
    assert source_terminate_time >= terminate_time
    assert source_terminate_time < terminate_time + timedelta(seconds=2)


def test_process_causal_audit_expansion_waits_for_visible_command_create():
    """Command-derived audit effects should not beat the visible 4688 command row."""

    class _Engine:
        def expand(self, _event_type, _ctx):
            return [
                ExpandedEvent(
                    method="_capture_expanded_audit",
                    kwargs={},
                    timing=TimingSpec(min_ms=100, max_ms=100, position="after"),
                )
            ]

    generator = object.__new__(ActivityGenerator)
    generator._causal_engine = _Engine()
    generator._expanding_types = set()
    generator._dns_cache = {}
    generator._kerberos_cache = {}
    generator._dc_systems = []
    generator._created_account_sids = {}
    generator.sid_registry = {}
    visible_process_time = datetime(2024, 3, 18, 12, 0, 2, tzinfo=UTC)
    generator._process_source_create_times = {("WS-01", 4321): visible_process_time}
    captured: list[datetime] = []

    def _capture_expanded_audit(**kwargs):
        captured.append(kwargs["time"])

    generator._capture_expanded_audit = _capture_expanded_audit
    system = System(hostname="WS-01", ip="10.10.1.10", os="Windows 11", type="workstation")

    generator._expand_and_emit(
        "process_create",
        datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC),
        target_system=system,
        source_pid=4321,
    )

    expected_gap = sample_timing_delta(
        "windows.audit_after_visible_admin_command",
        seed_parts=(
            system.hostname,
            4321,
            visible_process_time,
            datetime(2024, 3, 18, 12, 0, 0, 100000, tzinfo=UTC),
        ),
    )
    assert captured == [visible_process_time + expected_gap]


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
