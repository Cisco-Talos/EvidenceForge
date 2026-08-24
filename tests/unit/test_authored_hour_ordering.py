# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused regression tests for same-hour authored event ordering."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from evidenceforge.generation.engine.baseline import BaselineMixin


def test_same_hour_authored_events_execute_chronologically_with_storyline_ties_first() -> None:
    """A +5h10 red herring must run before +5h55 authored storyline work."""

    scenario_start = datetime(2024, 3, 18, 12, tzinfo=UTC)
    current_hour = scenario_start + timedelta(hours=5)
    early_red_herring = scenario_start + timedelta(hours=5, minutes=10)
    tied_late_time = scenario_start + timedelta(hours=5, minutes=55)
    hour_key = int(current_hour.timestamp())
    calls: list[tuple[str, int]] = []
    finalized_at: list[datetime] = []

    baseline = BaselineMixin()
    baseline._storyline_by_hour = {hour_key: [(tied_late_time, 11)]}
    baseline._red_herring_by_hour = {hour_key: [(early_red_herring, 21), (tied_late_time, 22)]}
    baseline._storyline_executed = set()
    baseline._red_herring_executed = set()
    baseline.activity_generator = SimpleNamespace(
        finalize_ssh_session_lifecycles=finalized_at.append
    )
    baseline._execute_single_storyline_event = lambda event_idx: calls.append(
        ("storyline", event_idx)
    )
    baseline._execute_single_red_herring_event = lambda event_idx: calls.append(
        ("red_herring", event_idx)
    )

    baseline._execute_authored_events_for_hour(current_hour)
    baseline._execute_authored_events_for_hour(current_hour)

    assert calls == [
        ("red_herring", 21),
        ("storyline", 11),
        ("red_herring", 22),
    ]
    assert finalized_at == [early_red_herring, tied_late_time, tied_late_time]
    assert baseline._storyline_executed == {11}
    assert baseline._red_herring_executed == {21, 22}
