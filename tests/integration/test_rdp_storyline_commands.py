# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Storyline commands run inside authored RDP sessions on both RDP publication paths."""

from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from evidenceforge.cli.commands import app


@pytest.mark.parametrize(
    "formats",
    [["windows", "zeek"], ["windows", "zeek", "ecar"]],
    ids=["compatibility-no-ecar", "exact-with-ecar"],
)
def test_storyline_command_runs_inside_its_rdp_session(
    tmp_path: Path, scenarios_dir: Path, formats: list[str]
) -> None:
    # Without eCAR the RDP session never enters the reconnect manager; its later command
    # must still execute rather than fail ground truth with rdp_session_not_connected.
    scenario = yaml.safe_load((scenarios_dir / "minimal.yaml").read_text(encoding="utf-8"))
    scenario["environment"]["systems"].append(
        {
            "hostname": "JUMP-01",
            "ip": "10.0.0.20",
            "os": "Windows Server 2022",
            "type": "server",
            "services": ["rdp"],
        }
    )
    scenario["environment"]["network"]["segments"][0]["systems"].append("JUMP-01")
    scenario["output"]["logs"] = [{"format": name} for name in formats]
    scenario["storyline"] = [
        {
            "id": "jump",
            "time": "+10m",
            "actor": "test_user",
            "system": "JUMP-01",
            "activity": "Connect to the jump host over RDP",
            "events": [{"type": "rdp_session", "source_ip": "10.0.0.1"}],
        },
        {
            "id": "identity",
            "time": "+17m",
            "actor": "test_user",
            "system": "JUMP-01",
            "activity": "Check identity from the RDP desktop",
            "events": [
                {
                    "type": "process",
                    "process_name": "C:\\Windows\\System32\\whoami.exe",
                    "command_line": "whoami /all",
                }
            ],
        },
    ]
    path = tmp_path / "scenario.yaml"
    path.write_text(yaml.safe_dump(scenario), encoding="utf-8")
    output = tmp_path / "run"

    result = CliRunner().invoke(app, ["generate", str(path), "--output", str(output)])

    assert result.exit_code == 0, result.output[-4000:]
    security = next(output.joinpath("data").glob("JUMP-01*/windows_event_security.xml"))
    assert "whoami.exe" in security.read_text(encoding="utf-8")
