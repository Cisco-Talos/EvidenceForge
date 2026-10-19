# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


@pytest.mark.slow
def test_authored_root_process_has_native_parent_without_service_login(tmp_path: Path) -> None:
    data = yaml.safe_load(Path("scenarios/macos-workstation-example/scenario.yaml").read_text())
    data["time_window"]["duration"] = "10m"
    data["storyline"] = [
        dict(
            id="root-process",
            time="+1m",
            actor="root",
            system="MAC-01",
            activity="Invented privileged provisioning process",
            events=[dict(type="process", process_name="/usr/local/libexec/invented-provisioner")],
        )
    ]
    scenario = tmp_path / "root.yaml"
    scenario.write_text(yaml.safe_dump(data))
    output = tmp_path / "output"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            str(scenario),
            "--output",
            str(output),
            "--seed",
            "123",
            "--checkpoint-hours",
            "0",
            "--project-root",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    rows = [
        json.loads(line)
        for path in (output / "data").rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    assert not any(
        row["object"] == "USER_SESSION" and row.get("principal") == "root" for row in rows
    )
    processes = [
        row
        for row in rows
        if row["object"] == "PROCESS"
        and row["action"] == "CREATE"
        and row.get("properties", {}).get("image_path") == "/usr/local/libexec/invented-provisioner"
    ]
    assert len(processes) == 1
    created = processes[0]
    assert created["principal"] == "root"
    assert created["ppid"] == 1
    assert created["properties"]["parent_image_path"] == "/sbin/launchd"
    assert not created["properties"].get("logon_id")
    assert any(
        row["objectID"] == created["objectID"] and row["action"] == "TERMINATE" for row in rows
    )
