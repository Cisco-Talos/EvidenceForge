# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for source-instance-aware behavior evidence reachability."""

from pathlib import Path

import pytest

from evidenceforge.events.evidence_requirements import (
    PERSISTENT_WINDOWS_SMB_EVIDENCE,
    PERSISTENT_WINDOWS_SMB_TARGET_FORMATS,
)
from evidenceforge.models import Scenario
from evidenceforge.models.scenario import SourceObservationOverride
from evidenceforge.utils import load_yaml
from evidenceforge.validation import ScenarioValidator
from evidenceforge.validation.evidence_reachability import analyze_evidence_reachability


def _smb_scenario(scenarios_dir: Path, *formats: str) -> Scenario:
    data = load_yaml(scenarios_dir / "windows-smb-evidence-reachability.yaml")
    data["output"]["logs"] = [{"format": source_format} for source_format in formats]
    return Scenario.model_validate(data)


def test_persistent_smb_runtime_targets_derive_from_the_reachability_contract() -> None:
    """Runtime target priority must have no second private format declaration."""

    assert all(
        len(alternative.formats) == 1
        for alternative in PERSISTENT_WINDOWS_SMB_EVIDENCE.alternatives
    )
    assert PERSISTENT_WINDOWS_SMB_TARGET_FORMATS == (
        "zeek_conn",
        "zeek_smb_mapping",
        "zeek_smb_files",
        "zeek_files",
        "ecar",
        "windows_event_security",
    )


def test_persistent_windows_smb_without_projection_is_a_validation_error(
    scenarios_dir: Path,
) -> None:
    """A guaranteed persistent-SMB runtime failure is rejected before generation."""

    scenario = _smb_scenario(scenarios_dir, "windows_event_sysmon")

    issue = next(
        issue
        for issue in ScenarioValidator(scenario).validate()
        if "persistent Windows SMB activity" in issue.message
    )

    assert issue.severity == "error"
    assert issue.field_path == "output.logs"
    assert "Potentially observable source formats: windows_event_sysmon" in issue.message
    assert "windows, ecar, or applicable Zeek" in issue.suggestion


@pytest.mark.parametrize("source_format", ["windows_event_security", "ecar", "zeek_conn"])
def test_persistent_windows_smb_accepts_each_supported_projection_family(
    scenarios_dir: Path,
    source_format: str,
) -> None:
    """Any runtime-supported SMB projection route makes the behavior reachable."""

    scenario = _smb_scenario(scenarios_dir, source_format)
    if source_format == "zeek_conn":
        scenario_data = scenario.model_dump(mode="python")
        scenario_data["environment"]["network"]["sensors"] = [
            {
                "type": "network",
                "name": "core-zeek",
                "monitoring_segments": ["internal"],
                "direction": "bidirectional",
                "placement": "span",
                "log_formats": ["zeek_conn"],
            }
        ]
        scenario = Scenario.model_validate(scenario_data)

    findings = analyze_evidence_reachability(scenario)

    assert not any(finding.behavior_id == "persistent_windows_smb" for finding in findings)


def test_authored_unobservable_process_is_a_nonblocking_warning(scenarios_dir: Path) -> None:
    """Valid but wholly invisible authored behavior remains an intentional author choice."""

    data = load_yaml(scenarios_dir / "minimal.yaml")
    data["output"]["logs"] = [{"format": "zeek_conn"}]
    data["storyline"] = [
        {
            "id": "process-only",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Run an endpoint-only process",
            "events": [
                {
                    "type": "process",
                    "process_name": "calc.exe",
                    "command_line": "calc.exe",
                }
            ],
        }
    ]
    scenario = Scenario.model_validate(data)

    finding = next(
        finding
        for finding in analyze_evidence_reachability(scenario)
        if finding.behavior_id == "authored_process"
    )

    assert finding.severity == "warning"
    assert finding.field_path == "storyline.0.events.0"
    assert "no possible evidence projection" in finding.message


@pytest.mark.parametrize("missingness, expected_warning", [(0.5, False), (1.0, True)])
def test_reachability_distinguishes_possible_from_certain_observation_loss(
    scenarios_dir: Path,
    missingness: float,
    expected_warning: bool,
) -> None:
    """Probabilistic loss remains reachable; deterministic loss does not."""

    data = load_yaml(scenarios_dir / "minimal.yaml")
    data["output"]["logs"] = [{"format": "ecar"}]
    data["environment"]["observation_overrides"] = [
        {
            "source_instance": "ecar:test-01",
            "missingness": missingness,
        }
    ]
    data["storyline"] = [
        {
            "id": "observed-process",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Run a process",
            "events": [
                {
                    "type": "process",
                    "process_name": "calc.exe",
                    "command_line": "calc.exe",
                }
            ],
        }
    ]
    scenario = Scenario.model_validate(data)
    assert isinstance(scenario.environment.observation_overrides[0], SourceObservationOverride)

    findings = analyze_evidence_reachability(scenario)
    has_warning = any(finding.behavior_id == "authored_process" for finding in findings)

    assert has_warning is expected_warning
