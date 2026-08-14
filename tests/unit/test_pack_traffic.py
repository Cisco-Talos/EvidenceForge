# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for structured, scenario-local pack traffic cadence."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock
from zoneinfo import ZoneInfo

from evidenceforge.generation.activity.pack_traffic import (
    cadence_allows_event_time,
    cadence_allows_local_time,
    scheduled_pack_event_times,
)
from evidenceforge.generation.engine.baseline import BaselineMixin


def _pack_runtime_harness(current_hour: datetime) -> tuple[BaselineMixin, SimpleNamespace]:
    """Build the minimal baseline runtime needed for pack-traffic ownership tests."""

    harness = object.__new__(BaselineMixin)
    session = SimpleNamespace(
        username="alex.morgan",
        system="LAB-WS-01",
        logon_type=2,
        logon_id="0x1001",
        start_time=current_hour - timedelta(hours=1),
        end_plan=None,
        network_close_time=None,
    )
    harness.scenario = SimpleNamespace(
        name="pack-process-ownership",
        environment=SimpleNamespace(systems=[]),
    )
    harness.start_time = current_hour
    harness._scenario_tz = UTC
    harness.state_manager = SimpleNamespace(
        get_sessions_on_system=Mock(return_value=[session]),
        set_current_time=Mock(),
        get_process=Mock(return_value=SimpleNamespace(image="custom-client.exe")),
    )
    harness.activity_generator = SimpleNamespace(
        _ip_to_system={},
        generate_connection=Mock(),
    )
    harness.world_planner = SimpleNamespace(ensure_connection_process=Mock(return_value=4242))
    harness._resolve_role = Mock(return_value=("198.51.100.44", "service.pack.example"))
    harness._pace_interactive_startup_activity = Mock(
        side_effect=lambda **kwargs: kwargs["candidate_time"]
    )
    harness._package_maintenance_connection_allowed = Mock(return_value=True)
    harness._is_server_admin_persona_source = Mock(return_value=False)
    harness._emit_browsing_session = Mock()
    return harness, session


def _pack_group(connection: dict[str, object]) -> dict[str, object]:
    """Return one deterministic weighted pack-traffic group."""

    return {
        "id": "custom:heartbeat",
        "cadence": {
            "pattern": "weighted",
            "days": ["mon"],
            "windows": [{"start": "10:00", "end": "11:00"}],
        },
        "outbound": [connection],
    }


def test_default_cadence_retains_weekday_business_gate() -> None:
    """Omitted cadence preserves the legacy Monday-Friday 07:00-20:00 gate."""

    assert cadence_allows_local_time(None, datetime(2026, 8, 10, 7, 0))
    assert cadence_allows_local_time(None, datetime(2026, 8, 10, 19, 59))
    assert not cadence_allows_local_time(None, datetime(2026, 8, 10, 20, 0))
    assert not cadence_allows_local_time(None, datetime(2026, 8, 9, 12, 0))


def test_cross_midnight_window_is_owned_by_its_start_day() -> None:
    """A Friday overnight window remains active early Saturday, but not early Sunday."""

    cadence = {
        "pattern": "weighted",
        "days": ["fri"],
        "windows": [{"start": "22:00", "end": "02:00"}],
    }

    assert cadence_allows_local_time(cadence, datetime(2026, 8, 14, 23, 30))
    assert cadence_allows_local_time(cadence, datetime(2026, 8, 15, 1, 30))
    assert not cadence_allows_local_time(cadence, datetime(2026, 8, 16, 1, 30))


def test_paced_event_time_is_rechecked_in_scenario_timezone() -> None:
    """Moving a scheduled event past a narrow local window makes it ineligible."""

    cadence = {
        "pattern": "weighted",
        "days": ["mon"],
        "windows": [{"start": "09:00", "end": "09:05"}],
    }
    zone = ZoneInfo("America/New_York")

    assert cadence_allows_event_time(cadence, datetime(2026, 8, 10, 13, 4, tzinfo=UTC), zone)
    assert not cadence_allows_event_time(
        cadence,
        datetime(2026, 8, 10, 13, 6, tzinfo=UTC),
        zone,
    )


def test_periodic_cadence_is_deterministic_and_timezone_local() -> None:
    """Periodic ticks honor local windows and reproduce independently of caller RNG."""

    cadence = {
        "pattern": "periodic",
        "days": ["mon"],
        "windows": [{"start": "09:00", "end": "10:00"}],
        "interval_minutes": 15,
        "jitter_minutes": 2,
    }
    kwargs = {
        "cadence": cadence,
        "scenario_start": datetime(2026, 8, 10, 0, tzinfo=UTC),
        "current_hour": datetime(2026, 8, 10, 13, tzinfo=UTC),
        "zone": ZoneInfo("America/New_York"),
        "schedule_key": "periodic:test",
        "weighted_count": 0,
    }

    first = scheduled_pack_event_times(rng=random.Random(1), **kwargs)
    second = scheduled_pack_event_times(rng=random.Random(999), **kwargs)

    assert first == second
    assert first
    assert all(9 <= value.astimezone(kwargs["zone"]).hour < 10 for value in first)


def test_burst_cadence_emits_once_per_window_and_reproduces() -> None:
    """Burst counts are stable and stay inside the selected local window."""

    cadence = {
        "pattern": "burst",
        "days": ["mon"],
        "windows": [{"start": "09:00", "end": "10:00"}],
        "jitter_minutes": 3,
        "burst_count": [4, 4],
    }
    kwargs = {
        "cadence": cadence,
        "scenario_start": datetime(2026, 8, 10, 0, tzinfo=UTC),
        "current_hour": datetime(2026, 8, 10, 9, tzinfo=UTC),
        "zone": UTC,
        "schedule_key": "burst:test",
        "weighted_count": 0,
    }

    first = scheduled_pack_event_times(rng=random.Random(1), **kwargs)
    second = scheduled_pack_event_times(rng=random.Random(2), **kwargs)

    assert first == second
    assert len(first) == 4
    assert all(value.hour == 9 for value in first)


def test_weighted_cadence_uses_scoped_rng_and_window() -> None:
    """Weighted scheduling is reproducible and never escapes its local window."""

    cadence = {
        "pattern": "weighted",
        "days": ["mon"],
        "windows": [{"start": "09:00", "end": "10:00"}],
    }
    kwargs = {
        "cadence": cadence,
        "scenario_start": datetime(2026, 8, 10, 0, tzinfo=UTC),
        "current_hour": datetime(2026, 8, 10, 9, tzinfo=UTC),
        "zone": UTC,
        "schedule_key": "weighted:test",
        "weighted_count": 6,
    }

    first = scheduled_pack_event_times(rng=random.Random(42), **kwargs)
    second = scheduled_pack_event_times(rng=random.Random(42), **kwargs)

    assert first == second
    assert len(first) == 6
    assert all(value.hour == 9 for value in first)


def test_pack_groups_are_claimed_once_per_user_host_and_hour() -> None:
    """Multiple active sessions cannot multiply one user-owned cadence schedule."""

    harness = object.__new__(BaselineMixin)
    group = {"id": "custom:review-burst"}
    system = type("System", (), {"hostname": "LAB-WS-01"})()
    user = type("User", (), {"username": "alex.morgan"})()
    first_hour = datetime(2026, 8, 10, 13, tzinfo=UTC)

    first = harness._claim_hourly_pack_traffic_groups(
        current_hour=first_hour,
        system=system,
        user_obj=user,
        groups=[group],
    )
    second_session = harness._claim_hourly_pack_traffic_groups(
        current_hour=first_hour,
        system=system,
        user_obj=user,
        groups=[group],
    )
    next_hour = harness._claim_hourly_pack_traffic_groups(
        current_hour=first_hour.replace(hour=14),
        system=system,
        user_obj=user,
        groups=[group],
    )

    assert first == [group]
    assert second_session == []
    assert next_hour == [group]


def test_low_level_pack_outbound_is_processless() -> None:
    """Low-level pack traffic emits a bare connection without an ambient app."""

    current_hour = datetime(2026, 8, 10, 10, tzinfo=UTC)
    harness, _session = _pack_runtime_harness(current_hour)
    system = SimpleNamespace(hostname="LAB-WS-01", ip="10.77.30.21", type="workstation")
    user = SimpleNamespace(username="alex.morgan", persona="custom:operator")
    connection = {
        "role": "_external",
        "port": 8443,
        "proto": "tcp",
        "service": "ssl",
        "weight": 1,
        "emit_dns": True,
        "dns_tags": ["custom:updates"],
    }

    harness._generate_pack_persona_traffic(
        current_hour=current_hour,
        system=system,
        user_obj=user,
        groups=[_pack_group(connection)],
        os_cat="windows",
        count_range=(1, 1),
        planned_logoffs=None,
        use_server_admin_persona=False,
    )

    harness.world_planner.ensure_connection_process.assert_not_called()
    harness._emit_browsing_session.assert_not_called()
    harness.activity_generator.generate_connection.assert_called_once()
    connection_args = harness.activity_generator.generate_connection.call_args.kwargs
    assert connection_args["pid"] == -1
    assert connection_args["suppress_source_pid_inference"] is True


def test_application_bound_pack_traffic_keeps_exact_process_owner() -> None:
    """Application bindings still resolve and attach their exact owning process."""

    current_hour = datetime(2026, 8, 10, 10, tzinfo=UTC)
    harness, _session = _pack_runtime_harness(current_hour)
    system = SimpleNamespace(hostname="LAB-WS-01", ip="10.77.30.21", type="workstation")
    user = SimpleNamespace(username="alex.morgan", persona="custom:operator")
    connection = {
        "role": "_external",
        "port": 5432,
        "proto": "tcp",
        "service": "postgresql",
        "weight": 1,
        "emit_dns": True,
        "dns_tags": ["custom:database"],
        "pack_application": "custom:case-client",
        "application_ids": ["custom:case-client"],
    }

    harness._generate_pack_persona_traffic(
        current_hour=current_hour,
        system=system,
        user_obj=user,
        groups=[_pack_group(connection)],
        os_cat="windows",
        count_range=(1, 1),
        planned_logoffs=None,
        use_server_admin_persona=False,
    )

    harness.world_planner.ensure_connection_process.assert_called_once()
    assert harness.world_planner.ensure_connection_process.call_args.kwargs["application_ids"] == [
        "custom:case-client"
    ]
    harness.activity_generator.generate_connection.assert_called_once()
    connection_args = harness.activity_generator.generate_connection.call_args.kwargs
    assert connection_args["pid"] == 4242
    assert connection_args["suppress_source_pid_inference"] is False


def test_no_pack_groups_do_not_enter_pack_process_resolution() -> None:
    """Scenarios without pack traffic never touch the pack ownership path."""

    current_hour = datetime(2026, 8, 10, 10, tzinfo=UTC)
    harness, _session = _pack_runtime_harness(current_hour)
    system = SimpleNamespace(hostname="LAB-WS-01", ip="10.77.30.21", type="workstation")
    user = SimpleNamespace(username="alex.morgan", persona="developer")

    harness._generate_pack_persona_traffic(
        current_hour=current_hour,
        system=system,
        user_obj=user,
        groups=[],
        os_cat="windows",
        count_range=(1, 1),
        planned_logoffs=None,
        use_server_admin_persona=False,
    )

    harness.world_planner.ensure_connection_process.assert_not_called()
    harness.activity_generator.generate_connection.assert_not_called()
