# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused regression tests for same-hour authored event ordering."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml


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


@pytest.mark.parametrize(
    "start",
    [
        "2026-10-09T12:00:00Z",
        "2026-10-09T09:59:00Z",
        "2026-10-06T09:59:00Z",
        "2026-10-09T09:59:17.125Z",
        "2026-10-09T23:59:00Z",
        "2026-10-09T11:59:00+02:00",
    ],
)
def test_authored_entries_execute_in_their_generation_pass_before_lifecycle_cleanup(
    start: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real event indexing must match passes anchored to any scenario start."""

    document = load_yaml(Path(__file__).parents[1] / "fixtures/scenarios/minimal.yaml")
    document["time_window"] = {"start": start, "duration": "2h15m", "warmup": "2h"}
    document["storyline"] = [
        {
            "id": f"story-{index}",
            "time": time,
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Authored workstation lock",
            "events": [{"type": "workstation_lock"}],
        }
        for index, time in enumerate(["+0", "+3599", "+1h", "+1h44m", "+2h14m"])
    ]
    document["storyline"][3]["events"].append({"type": "rdp_session", "source_ip": "10.0.0.2"})
    # An absolute timestamp uses the same pass as a relative offset, including
    # when its authored UTC offset differs from the engine's UTC representation.
    absolute_time = datetime.fromisoformat(start.replace("Z", "+00:00")) + timedelta(
        hours=2, minutes=14
    )
    document["storyline"][4]["time"] = absolute_time.isoformat()
    document["red_herrings"] = [
        {
            "id": f"red-{index}",
            "time": time,
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Benign authentication failure",
            "explanation": "Mistyped password",
            "events": [{"type": "failed_logon"}],
        }
        for index, time in enumerate(["+30m", "+1h", "+2h"])
    ]
    engine = GenerationEngine(Scenario.model_validate(document), tmp_path / "output")
    monkeypatch.setattr(engine, "_init_emitters", lambda: None)
    monkeypatch.setattr(engine, "_seed_system_process_trees", lambda: None)
    engine._initialize()
    rdp_lower_bound = engine._authored_rdp_transport_lower_bound(engine.start_time)
    assert rdp_lower_bound is not None
    assert engine.start_time + timedelta(hours=1) < rdp_lower_bound
    assert rdp_lower_bound < engine.start_time + timedelta(hours=1, minutes=44)
    assert (
        engine._authored_rdp_transport_lower_bound(engine.start_time + timedelta(hours=2)) is None
    )
    calls: list[tuple[str, int]] = []
    finalized_at: list[datetime] = []
    monkeypatch.setattr(
        engine, "_execute_single_storyline_event", lambda index: calls.append(("story", index))
    )
    monkeypatch.setattr(
        engine, "_execute_single_red_herring_event", lambda index: calls.append(("red", index))
    )
    monkeypatch.setattr(
        engine.activity_generator, "finalize_ssh_session_lifecycles", finalized_at.append
    )
    expected_passes = [
        [("story", 0), ("red", 0), ("story", 1)],
        [("story", 2), ("red", 1), ("story", 3)],
        [("red", 2), ("story", 4)],
    ]

    for pass_index, expected in enumerate(expected_passes):
        current_hour = engine.start_time + timedelta(hours=pass_index)
        assert engine._authored_workstation_transition_in_hour(
            engine.scenario.environment.users[0], "TEST-01", current_hour
        )
        previous_count = len(calls)
        engine._execute_authored_events_for_hour(current_hour)
        assert calls[previous_count:] == expected
        engine._execute_authored_events_for_hour(current_hour)
        assert len(calls) == previous_count + len(expected)

    assert engine._storyline_executed == set(range(5))
    assert engine._red_herring_executed == set(range(3))
    assert finalized_at == [
        engine.start_time + timedelta(seconds=offset)
        for offset in [0, 1800, 3599, 3600, 3600, 6240, 7200, 8040]
    ]
