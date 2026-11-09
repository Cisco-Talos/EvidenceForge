# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""A bounded public command workload includes each terminal's complete native startup."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.utils import load_yaml


@pytest.mark.slow
@pytest.mark.parametrize("terminal_id", ["macos-terminal", "macos-iterm2"])
def test_terminal_public_cli_is_complete_native_ingestible_and_filter_independent(
    tmp_path: Path, terminal_id: str
) -> None:
    raw = load_yaml(Path("scenarios/macos-workstation-example/scenario.yaml"))
    raw["time_window"].update(duration="15m", warmup="1h")
    raw["baseline_activity"]["traffic_rates"] = {"user_activity": 1, "persona_connections": 1}
    raw["macos_process_coverage"] = "complete"
    raw["environment"]["deployment_overrides"] = [
        {"system": "MAC-01", "user_applications": [{"user": "alex", "applications": [terminal_id]}]}
    ]
    raw["output"]["logs"] = [{"format": "ecar"}, {"format": "macos_endpoint_security"}]
    raw["storyline"] = [
        {
            "id": "close-warmup-session",
            "time": "+5s",
            "actor": "alex",
            "system": "MAC-01",
            "activity": "Close the warmup desktop session before the fresh-start workload",
            "events": [{"type": "logoff"}],
        },
        {
            "id": "local-login",
            "time": "+1m",
            "actor": "alex",
            "system": "MAC-01",
            "activity": "Open the modeled GUI session",
            "events": [{"type": "logon", "logon_type": 2}],
        },
        {
            "id": "terminal-command",
            "time": "+2m",
            "actor": "alex",
            "system": "MAC-01",
            "activity": "Run a local query in the selected terminal",
            "events": [{"type": "process", "process_name": "/usr/bin/id", "supplementary": "none"}],
        },
    ]
    scenario = tmp_path / "terminal.yaml"
    scenario.write_text(yaml.safe_dump(raw, sort_keys=False))
    snapshots = []
    for label, hash_seed, formats in (
        ("full", "37", None),
        ("native", "83", "macos_endpoint_security"),
    ):
        output = tmp_path / label
        command = [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            str(scenario),
            "--output",
            str(output),
            "--seed",
            "364",
            "--checkpoint-hours",
            "0",
            "--project-root",
            str(tmp_path),
        ]
        if formats is not None:
            command.extend(["--formats", formats])
        result = subprocess.run(
            command,
            env=os.environ | {"PYTHONHASHSEED": hash_seed},
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        paths = sorted((output / "data").rglob("macos_endpoint_security.ndjson"))
        snapshots.append({str(path.relative_to(output)): path.read_bytes() for path in paths})
        records = [
            decode_endpoint_security_record(line)
            for path in paths
            for line in path.read_text().splitlines()
        ]
        images = [row.event.exec.target.executable.path for row in records if row.event_type == 9]
        assert (
            "/usr/libexec/xpcproxy" in images
            and "/usr/bin/login" in images
            and "/bin/zsh" in images
            and "/usr/bin/id" in images
        )
        assert any(image.endswith("/iTermServer-3.7.6") for image in images) == (
            terminal_id == "macos-iterm2"
        )
        assert any(image.endswith("/ShellLauncher") for image in images) == (
            terminal_id == "macos-iterm2"
        )
        truth = json.loads((output / "GROUND_TRUTH.json").read_text())
        census = truth["macos_native_coverage"]["hosts"][0]["process_census"]
        assert census["complete"] and census["aggregate_births"] == 0
        assert census["expected_forks"] == census["published_forks"]
        assert census["expected_execs"] == census["published_execs"]
    assert snapshots[0] == snapshots[1]


@pytest.mark.slow
@pytest.mark.parametrize("terminal_id", ["macos-terminal", "macos-iterm2"])
def test_terminal_public_checkpoint_resume_preserves_native_startup_and_later_commands(
    tmp_path: Path, scenarios_dir: Path, terminal_id: str
) -> None:
    from tests.integration.test_checkpoint_smoke import (
        test_short_generation_checkpoint_suspension_and_resume as checkpoint_gate,
    )

    checkpoint_gate(
        tmp_path,
        scenarios_dir,
        "default",
        None,
        True,
        None,
        False,
        False,
        False,
        terminal_id=terminal_id,
    )
