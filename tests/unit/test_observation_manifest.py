# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the machine-readable observation manifest sidecar."""

from evidenceforge.events.observation_manifest import (
    OBSERVATION_MANIFEST_FILENAME,
    build_observation_manifest,
    load_observation_manifest,
    write_observation_manifest,
)
from evidenceforge.models import (
    BaselineActivity,
    Environment,
    OutputSpec,
    Scenario,
    StorylineEvent,
    System,
    TimeWindow,
    User,
)


def _scenario() -> Scenario:
    return Scenario(
        version="1.0",
        name="manifest-test",
        description="Manifest test",
        environment=Environment(
            description="Test",
            users=[
                User(
                    username="alice",
                    full_name="Alice Example",
                    email="alice@example.com",
                    enabled=True,
                ),
            ],
            systems=[System(hostname="WS-01", ip="10.0.0.10", os="Windows 11", type="workstation")],
        ),
        time_window=TimeWindow(start="2026-02-03T13:00:00Z", duration="2h"),
        baseline_activity=BaselineActivity(description="Low", intensity="low", variation="low"),
        observation_profile="enterprise_standard",
        output=OutputSpec(logs=[{"format": "windows_event_security"}], destination="./out"),
        storyline=[
            StorylineEvent(
                id="step-001",
                time="+10m",
                actor="alice",
                system="WS-01",
                activity="Run command",
                events=[{"type": "process", "process_name": "powershell.exe"}],
            )
        ],
    )


def test_build_manifest_summarizes_storyline_source_status() -> None:
    """Manifest should preserve per-storyline status and aggregate source counts."""
    manifest = build_observation_manifest(
        _scenario(),
        {
            "step-001": {
                "windows_security": {"visible": 1},
                "sysmon": {"dropped": 2},
            }
        },
    )

    assert manifest.observation_profile == "enterprise_standard"
    assert manifest.collection_window["start"] == "2026-02-03T13:00:00Z"
    assert manifest.collection_window["end"] == "2026-02-03T15:00:00Z"
    assert manifest.source_summary == {
        "windows_security": {"visible": 1},
        "sysmon": {"dropped": 2},
    }
    assert manifest.storyline_events[0].storyline_id == "step-001"
    assert manifest.storyline_events[0].source_status["sysmon"] == {"dropped": 2}


def test_load_manifest_finds_scenario_root_from_data_dir(tmp_path) -> None:
    """Eval should find the manifest beside GROUND_TRUTH.md when pointed at data/."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    write_observation_manifest(
        tmp_path / OBSERVATION_MANIFEST_FILENAME,
        _scenario(),
        {"step-001": {"windows_security": {"dropped": 1}}},
    )

    loaded = load_observation_manifest(data_dir)

    assert loaded is not None
    assert loaded.storyline_events[0].source_status == {"windows_security": {"dropped": 1}}
