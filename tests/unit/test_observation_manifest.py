# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the machine-readable observation manifest sidecar."""

import pytest

from evidenceforge.events.observation_manifest import (
    OBSERVATION_MANIFEST_FILENAME,
    build_observation_manifest,
    load_observation_manifest,
    observation_manifest_matches_scenario,
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


def _scenario(time_window: TimeWindow | None = None) -> Scenario:
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
        time_window=time_window or TimeWindow(start="2026-02-03T13:00:00Z", duration="2h"),
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


def test_build_manifest_uses_explicit_end_time_window() -> None:
    """Manifest should support scenarios that define an explicit end instead of duration."""
    manifest = build_observation_manifest(
        _scenario(
            TimeWindow(
                start="2026-02-03T13:00:00Z",
                end="2026-02-03T14:30:00Z",
            )
        ),
        {},
    )

    assert manifest.collection_window["start"] == "2026-02-03T13:00:00Z"
    assert manifest.collection_window["end"] == "2026-02-03T14:30:00Z"


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


def test_write_manifest_rejects_dangling_symlink(tmp_path) -> None:
    """Manifest writes should not follow dangling sidecar symlinks."""
    output_path = tmp_path / OBSERVATION_MANIFEST_FILENAME
    outside_target = tmp_path / "outside-manifest.json"
    try:
        output_path.symlink_to(outside_target)
    except OSError as exc:
        pytest.skip(f"Symlink creation unsupported in this environment: {exc}")

    with pytest.raises(PermissionError):
        write_observation_manifest(
            output_path,
            _scenario(),
            {"step-001": {"windows_security": {"visible": 1}}},
        )

    assert output_path.is_symlink()
    assert not outside_target.exists()


def test_load_manifest_rejects_symlinked_sidecar(tmp_path) -> None:
    """Eval should not trust a manifest symlinked out of the evaluated tree."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    attacker_dir = tmp_path / "attacker"
    attacker_dir.mkdir()
    attacker_manifest = attacker_dir / OBSERVATION_MANIFEST_FILENAME
    write_observation_manifest(
        attacker_manifest,
        _scenario(),
        {"step-001": {"windows_security": {"dropped": 1}}},
    )
    try:
        (tmp_path / OBSERVATION_MANIFEST_FILENAME).symlink_to(attacker_manifest)
    except OSError as exc:
        pytest.skip(f"Symlink creation unsupported in this environment: {exc}")

    assert load_observation_manifest(data_dir, _scenario()) is None


def test_load_manifest_rejects_complete_scenario_profile(tmp_path) -> None:
    """Complete-profile scenarios should ignore observation sidecars entirely."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    scenario = _scenario()
    write_observation_manifest(
        tmp_path / OBSERVATION_MANIFEST_FILENAME,
        scenario,
        {"step-001": {"windows_security": {"dropped": 1}}},
    )
    scenario.observation_profile = "complete"

    assert load_observation_manifest(data_dir, scenario) is None


def test_load_manifest_rejects_mismatched_scenario_metadata(tmp_path) -> None:
    """Forged manifests must match the evaluated scenario, not only storyline IDs."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    scenario = _scenario()
    forged = _scenario()
    forged.name = "different-scenario"
    write_observation_manifest(
        tmp_path / OBSERVATION_MANIFEST_FILENAME,
        forged,
        {"step-001": {"windows_security": {"dropped": 1}}},
    )

    assert load_observation_manifest(data_dir, scenario) is None


def test_manifest_binding_requires_storyline_metadata_match() -> None:
    """Manifest event exemptions should be bound to actor/system/event metadata."""
    scenario = _scenario()
    manifest = build_observation_manifest(
        scenario,
        {"step-001": {"windows_security": {"dropped": 1}}},
    )
    manifest.storyline_events[0].actor = "mallory"

    assert observation_manifest_matches_scenario(manifest, scenario) is False
