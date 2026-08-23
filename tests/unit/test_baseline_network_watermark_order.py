# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused baseline scheduling contracts for the strict network watermark."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import evidenceforge.generation.engine.baseline as baseline_module
from evidenceforge.generation.engine.baseline import BaselineMixin, _dns_query_seconds_for_hour
from evidenceforge.models import System, User
from evidenceforge.utils.rng import _stable_seed

_WINDOW_START = datetime(2024, 3, 18, 10, tzinfo=UTC)


def test_system_dns_skips_candidate_jittered_before_runtime_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A candidate jittered before the first hour is skipped, not clamped."""

    system = System(
        hostname="WS-AJOHNSON-01",
        ip="10.10.1.35",
        os="Windows 11",
        type="workstation",
    )
    observed: list[datetime] = []

    class StopAfterFirstConnectionError(Exception):
        """Stop the broad system-traffic pass after the first DNS request."""

    class Activity:
        _dns_server_ips = ("10.10.2.10",)

        @staticmethod
        def generate_connection(**kwargs: object) -> None:
            observed.append(kwargs["time"])  # type: ignore[arg-type]
            raise StopAfterFirstConnectionError

    baseline = BaselineMixin()
    baseline.scenario = SimpleNamespace(environment=SimpleNamespace(systems=[system]))
    baseline._uses_linux_smb_prepass = lambda: False
    baseline._scenario_tz = None
    baseline._infra_ips = {"dns": [], "ntp": []}
    baseline._system_service_defaults = {system.hostname: ["dns-client"]}
    baseline._system_pids = {system.hostname: {"svchost_net_svc": 1240}}
    baseline._generation_epoch = _WINDOW_START
    baseline._resolve_traffic_rate = lambda _name: (798, 2393)
    baseline._scaled_interval_range = lambda _system, _name, low, high: (low, high)
    baseline.state_manager = SimpleNamespace(set_current_time=lambda _time: None)
    baseline.activity_generator = Activity()
    monkeypatch.setattr(baseline_module, "_get_rng", lambda: random.Random(5))

    with pytest.raises(StopAfterFirstConnectionError):
        baseline._generate_system_traffic(_WINDOW_START)

    assert len(observed) == 1
    assert _WINDOW_START <= observed[0] < _WINDOW_START + timedelta(hours=1)
    assert observed[0] > _WINDOW_START + timedelta(minutes=10)


def test_dns_jittered_observations_are_disjoint_across_consecutive_hours() -> None:
    """Consecutive half-open hours cannot both emit one jittered observation."""

    hostname = "WS-AJOHNSON-01"
    interval = 1076
    first_rng = random.Random(13)
    second_rng = random.Random(29)

    first_hour = _dns_query_seconds_for_hour(hostname, 0, interval, first_rng)
    second_hour = _dns_query_seconds_for_hour(hostname, 3600, interval, second_rng)

    assert all(0 <= second < 3600 for second in first_hour)
    assert all(3600 <= second < 7200 for second in second_hour)
    assert set(first_hour).isdisjoint(second_hour)
    assert len(first_hour) == len(set(first_hour))
    assert len(second_hour) == len(set(second_hour))
    assert _stable_seed(f"dns_ph_{hostname}") % interval == 8


def test_partial_output_pass_uses_actual_window_end_without_shortening_warmup() -> None:
    """Only the real final pass is shortened; whole-hour warm-up scheduling is retained."""

    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = _WINDOW_START + timedelta(minutes=10)

    assert baseline._baseline_pass_end(_WINDOW_START) == baseline.end_time
    warmup_hour = _WINDOW_START - timedelta(hours=1)
    assert baseline._baseline_pass_end(warmup_hour) == _WINDOW_START


@pytest.mark.parametrize(
    ("current_hour", "end_time", "terminal"),
    [
        (_WINDOW_START - timedelta(hours=1), _WINDOW_START + timedelta(hours=2), False),
        (_WINDOW_START, _WINDOW_START + timedelta(hours=2), False),
        (_WINDOW_START + timedelta(hours=1), _WINDOW_START + timedelta(hours=2), True),
        (_WINDOW_START, _WINDOW_START + timedelta(minutes=10), True),
    ],
)
def test_terminal_output_pass_owns_known_lifecycle_end(
    current_hour: datetime,
    end_time: datetime,
    terminal: bool,
) -> None:
    """Only the terminal output pass rejects a known end beyond its boundary."""

    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = end_time
    pass_end = baseline._baseline_pass_end(current_hour)
    start = current_hour + timedelta(seconds=1)

    assert baseline._baseline_pass_is_terminal(current_hour) is terminal
    assert baseline._baseline_pass_admits(current_hour, start=start, end=pass_end) is True
    assert (
        baseline._baseline_pass_admits(
            current_hour,
            start=start,
            end=pass_end + timedelta(microseconds=1),
        )
        is not terminal
    )
    assert baseline._baseline_pass_admits(current_hour, start=pass_end) is False


@pytest.mark.parametrize("window_duration", [timedelta(minutes=10), timedelta(hours=1)])
def test_terminal_output_pass_keeps_safe_ssh_noise_with_action_deadline(
    monkeypatch: pytest.MonkeyPatch,
    window_duration: timedelta,
) -> None:
    """A final output pass retains SSH that fits the owner's bounded close."""

    user = User(
        username="admin",
        full_name="Admin User",
        email="admin@example.test",
        persona="sysadmin",
    )
    server = System(
        hostname="LINUX-01",
        ip="10.0.0.20",
        os="Ubuntu 24.04",
        type="server",
    )
    activity = SimpleNamespace(timing_runtime=object())

    world_planner = SimpleNamespace(ensure_user_session=Mock())

    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = _WINDOW_START + window_duration
    baseline.activity_generator = activity
    baseline.world_planner = world_planner
    baseline.scenario = SimpleNamespace(
        baseline_activity=SimpleNamespace(suspicious_noise="high"),
        environment=SimpleNamespace(
            users=[user],
            systems=[server],
            domain="example.test",
        ),
        personas=[],
    )
    monkeypatch.setattr(baseline_module, "get_suspicious_event_count", lambda *_args: 1)
    monkeypatch.setattr(
        baseline_module,
        "pick_suspicious_pattern",
        lambda *_args: {"type": "after_hours_admin"},
    )
    monkeypatch.setattr(
        baseline_module,
        "generate_after_hours_admin",
        lambda *_args: {
            "user": user,
            "system": server,
            "time": _WINDOW_START + timedelta(minutes=1),
            "logon_type": 10,
        },
    )

    baseline._generate_suspicious_noise(_WINDOW_START)

    assert world_planner.ensure_user_session.call_count == 1
    call = world_planner.ensure_user_session.call_args
    assert call.kwargs["session_kind"] == "ssh"
    assert call.kwargs["allow_existing"] is False
    assert call.kwargs["session_end_plan"].authority == "action_bundle"
    assert call.kwargs["session_end_plan"].canonical_end == baseline.end_time
