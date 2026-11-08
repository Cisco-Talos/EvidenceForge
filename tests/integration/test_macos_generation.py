# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mixed-platform generation, fresh-process determinism and source filtering."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.support.output_equivalence import deterministic_bundle_files


@pytest.mark.slow
@pytest.mark.parametrize("helpers", [False, True], ids=["ordinary", "browser-helpers"])
def test_mac_mixed_fleet_isolation_fresh_process_determinism_and_filtering(
    tmp_path: Path, helpers: bool
) -> None:
    scenario = Path("scenarios/macos-workstation-example/mixed-fleet.yaml").resolve()
    if helpers:
        payload = yaml.safe_load(scenario.read_text())
        payload["baseline_activity"]["intensity"] = "high"
        payload["environment"]["deployment_overrides"] = [
            {
                "system": "MAC-01",
                "user_applications": [{"user": "alex", "applications": ["chrome", "macos-zsh"]}],
            }
        ]
        scenario = tmp_path / "helpers.yaml"
        scenario.write_text(yaml.safe_dump(payload))
    outputs: list[Path] = []
    for label, hash_seed, formats in [
        ("first", "17", ""),
        ("second", "91", ""),
        ("ecar", "6", "ecar"),
    ]:
        output = tmp_path / label
        arguments = [
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
        ]
        if formats:
            arguments.extend(["--formats", formats])
        result = subprocess.run(
            arguments,
            env=os.environ | {"PYTHONHASHSEED": hash_seed},
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        outputs.append(output)
    first, second, filtered = map(deterministic_bundle_files, outputs)
    assert first == second
    endpoint_files = {
        name: content for name, content in first.items() if name.endswith("/ecar.json")
    }
    assert len(endpoint_files) == 3
    assert endpoint_files == {
        name: content for name, content in filtered.items() if name.endswith("/ecar.json")
    }
    mac_files = {name: content for name, content in first.items() if "/MAC-01." in name}
    assert mac_files
    assert any(name.endswith(".zsh_history") for name in mac_files)
    assert all(
        not name.endswith((".xml", ".bash_history")) and "/syslog/" not in name
        for name in mac_files
    )
    assert all("/MAC-01." in name for name in first if name.endswith(".zsh_history"))
    mac_ecar = next(content for name, content in mac_files.items() if name.endswith("/ecar.json"))
    rows = [json.loads(line) for line in mac_ecar.splitlines()]
    processes = [row for row in rows if row["object"] == "PROCESS"]
    assert processes
    assert "systemd" not in json.dumps(processes)
    assert "C:\\" not in json.dumps(processes)
    assert any("/WIN-01." in name and name.endswith(".xml") for name in first)
    assert any("/LINUX-01." in name and "syslog" in name for name in first)

    if helpers:
        children = [
            row
            for row in processes
            if row["action"] == "MODIFY"
            and row["properties"].get("operation") == "exec"
            and "/Helpers/" in row["properties"]["image_path"]
        ]
        assert children
        creates = {row["objectID"]: row for row in processes if row["action"] == "CREATE"}
        ends = {row["objectID"]: row for row in processes if row["action"] == "TERMINATE"}
        for child in children:
            birth = creates[child["objectID"]]
            # Fork CREATE retains its parent's image; helper exec is a later MODIFY.
            assert birth["properties"]["image_path"].endswith("/MacOS/Google Chrome")
            assert birth["timestamp_ms"] < child["timestamp_ms"]
            parent_id = birth["actorID"]
            assert birth["properties"]["source_process_uuid"] == parent_id
            assert int(birth["properties"]["source_pid"]) == birth["ppid"] == child["ppid"]
            assert birth["properties"]["logon_id"] == child["properties"]["logon_id"]
            parent = creates.get(parent_id)
            if parent is not None:
                parent_execs = [
                    row
                    for row in processes
                    if row["objectID"] == parent_id
                    and row["action"] == "MODIFY"
                    and row["properties"].get("operation") == "exec"
                    and row["properties"]["image_path"].endswith("/MacOS/Google Chrome")
                ]
                assert len(parent_execs) == 1
                assert (
                    parent["timestamp_ms"] < parent_execs[0]["timestamp_ms"] < birth["timestamp_ms"]
                )
                assert parent["pid"] == child["ppid"]
                assert parent_execs[0]["properties"]["logon_id"] == child["properties"]["logon_id"]
            # Parents born during warm-up have no in-window CREATE; their exact
            # fork source identity above and any visible end still constrain children.
            if parent_id in ends:
                assert (
                    child["timestamp_ms"]
                    < ends[child["objectID"]]["timestamp_ms"]
                    <= ends[parent_id]["timestamp_ms"]
                )
            else:
                # An active session beyond collection need not have a visible close.
                assert child["objectID"] not in ends
