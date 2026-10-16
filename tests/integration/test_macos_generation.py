# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mixed-platform generation, fresh-process determinism and source filtering."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.support.output_equivalence import deterministic_bundle_files


@pytest.mark.slow
def test_mac_mixed_fleet_isolation_fresh_process_determinism_and_filtering(tmp_path: Path) -> None:
    scenario = Path("scenarios/macos-workstation-example/mixed-fleet.yaml").resolve()
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
