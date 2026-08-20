# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused baseline scheduling contracts for the strict network watermark."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

import evidenceforge.generation.engine.baseline as baseline_module
from evidenceforge.generation.engine.baseline import BaselineMixin, _dns_query_seconds_for_hour
from evidenceforge.models import System
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
