# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Ground-truth agreement uses the deployed identity of network sensors."""

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from evidenceforge.cli.commands import app


def test_sensor_with_uppercase_hostname_agrees_with_its_ground_truth(
    tmp_path: Path, scenarios_dir: Path
) -> None:
    # Deployed source identities fold hostname case; the evaluator must use the same identity
    # for capture views and sensor-local UIDs or every row from such a sensor disagrees.
    scenario = yaml.safe_load((scenarios_dir / "minimal.yaml").read_text(encoding="utf-8"))
    scenario["environment"]["systems"].append(
        {
            "hostname": "FILE-01",
            "ip": "10.0.0.30",
            "os": "Windows Server 2022",
            "type": "server",
            "services": ["smb"],
        }
    )
    scenario["environment"]["network"]["segments"][0]["systems"].append("FILE-01")
    for sensor in scenario["environment"]["network"]["sensors"]:
        if sensor["name"] == "core-zeek":
            sensor["hostname"] = "CORE-ZEEK"
    scenario["storyline"] = [
        {
            "id": "reach-file-server",
            "time": "+15m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Connect to the file server",
            "events": [
                {
                    "type": "connection",
                    "dst_ip": "10.0.0.30",
                    "dst_port": 445,
                    "service": "smb",
                }
            ],
        }
    ]
    path = tmp_path / "scenario.yaml"
    path.write_text(yaml.safe_dump(scenario), encoding="utf-8")
    output = tmp_path / "run"
    runner = CliRunner()
    generated = runner.invoke(app, ["generate", str(path), "--output", str(output)])
    assert generated.exit_code == 0, generated.output[-4000:]

    evaluated = runner.invoke(app, ["eval", str(output), "--format", "json"])

    assert evaluated.exit_code == 0, evaluated.output[-4000:]
    agreement = json.loads(evaluated.stdout)["supplementary"]["ground_truth_agreement"]
    failures = agreement["failure_counts"]
    assert "capture_profile_identity_disagreement" not in failures, agreement["findings"][:3]
    assert "source_identifier_disagreement" not in failures, agreement["findings"][:3]
