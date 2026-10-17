# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mac process exposures remain visible without inventing Linux tool installations."""

import json
from pathlib import Path

import pytest
import yaml

from evidenceforge.evaluation.engine import EvaluationEngine
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario


@pytest.mark.slow
def test_mac_process_exposures_correlate_with_existing_canonical_lifecycle(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    data = yaml.safe_load(
        (root / "scenarios/macos-workstation-example/native-workspace.yaml").read_text()
    )
    data["name"] = "mac-process-exposure-test"
    data["output"]["logs"] = [{"format": "ecar"}]
    specs = [
        {"type": "spillage", "surface": "process_command_line", "family": family}
        for family in ("aws_iam", "github_pat", "db_uri", "password_generic")
    ] + [
        {
            "type": "adversarial_payload",
            "surface": "process_command_line",
            "value": "EFORGE_TEST_example",
        }
    ]
    data["storyline"].extend(
        {
            "id": f"exposure-{index}",
            "time": f"+{index + 3}m",
            "actor": "alex",
            "system": "MAC-01",
            "activity": "Independently invented process exposure",
            "events": [spec],
        }
        for index, spec in enumerate(specs)
    )
    data["storyline"].append(
        {
            "id": "close-session",
            "time": "+12m",
            "actor": "alex",
            "system": "MAC-01",
            "activity": "Close the explicit local session and its processes",
            "events": [{"type": "logoff"}],
        }
    )
    scenario = Scenario(**data)
    output = tmp_path / "bundle"
    GenerationEngine(scenario, output).generate()
    ground_truth = json.loads((output / "GROUND_TRUTH.json").read_text())
    exposures = [
        item
        for item in ground_truth["events"]
        if item["kind"] in {"spillage", "adversarial_payload"}
    ]
    assert len(exposures) == len(specs)
    rows = [
        json.loads(line)
        for path in output.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    for exposure in exposures:
        value = exposure["attributes"]["rendered_value"]
        creates = [
            row
            for row in rows
            if row["object"] == "PROCESS"
            and row["action"] == "CREATE"
            and value in row["properties"]["command_line"]
        ]
        assert len(creates) == 1
        create = creates[0]
        assert create["principal"] == "alex"
        assert create["properties"]["image_path"] == "/usr/bin/env"
        assert create["properties"]["parent_image_path"].startswith("/")
        assert create["ppid"] != 4
        assert create["properties"]["session_id"]
        assert any(
            row["object"] == "PROCESS"
            and row["action"] == "TERMINATE"
            and row["objectID"] == create["objectID"]
            for row in rows
        )
    report = EvaluationEngine(output_dir=output, scenario=scenario).run()
    presence = next(
        score
        for pillar in report.pillars
        for score in pillar.sub_scores
        if score.key == "event_presence"
    )
    assert presence.score == 100
