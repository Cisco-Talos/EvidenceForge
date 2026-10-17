# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Experimental native export isolation and fresh-process determinism."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from evidenceforge.formats.macos_unified_log import decode_unified_log_record
from tests.support.output_equivalence import deterministic_bundle_files


@pytest.mark.slow
def test_native_workspace_generation_is_deterministic_filtered_and_mac_local(
    tmp_path: Path,
) -> None:
    data = yaml.safe_load(Path("scenarios/macos-workstation-example/mixed-fleet.yaml").read_text())
    data["time_window"]["warmup"] = "1h"
    data["time_window"]["duration"] = "1h"
    data["storyline"] = [
        {
            "id": "workspace-login",
            "time": "+1m",
            "actor": "alex",
            "system": "MAC-01",
            "activity": "Request the local workspace",
            "events": [{"type": "logon", "logon_type": 2}],
        }
    ]
    data["output"]["logs"].append({"format": "macos_unified_log"})
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text(yaml.safe_dump(data, sort_keys=False))
    outputs: list[dict[str, bytes]] = []
    for label, seed, formats in [
        ("all", "17", ""),
        ("repeat", "91", ""),
        ("native", "6", "macos_unified_log"),
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
            env=os.environ | {"PYTHONHASHSEED": seed},
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        outputs.append(deterministic_bundle_files(output))
    assert outputs[0] == outputs[1]
    native = {
        name: value
        for name, value in outputs[0].items()
        if name.endswith("macos_unified_log.ndjson")
    }
    assert len(native) == 1 and all("MAC-01." in name for name in native)
    assert native == {
        name: value
        for name, value in outputs[2].items()
        if name.endswith("macos_unified_log.ndjson")
    }
    records = [
        decode_unified_log_record(line)
        for content in native.values()
        for line in content.splitlines()
    ]
    assert records
    assert all(
        record.user_id == 0 and record.process_image_path.endswith("/loginwindow")
        for record in records
    )
    assert all(record.event_message == "-[Login1 launchWorkspace] | enter" for record in records)
    mac_ecar = next(
        content
        for name, content in outputs[0].items()
        if "MAC-01." in name and name.endswith("/ecar.json")
    )
    logins = [
        json.loads(line)
        for line in mac_ecar.splitlines()
        if json.loads(line).get("object") == "USER_SESSION"
        and json.loads(line).get("action") == "LOGIN"
        and json.loads(line)["properties"].get("outcome") == "success"
        and json.loads(line)["properties"].get("session_id") is not None
    ]
    assert len(records) == len(logins)
