# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Filesystem workload survives a real CLI checkpoint and output-source selection."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

from evidenceforge.generation.checkpoints.packed import loads
from evidenceforge.generation.checkpoints.state_values import decode_state_value
from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore
from tests.support.output_equivalence import deterministic_bundle_files


@pytest.mark.slow
def test_macos_filesystem_exact_resume_and_native_source_filtering(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/scenarios/macos-filesystem-smoke.yaml")
    document = yaml.safe_load(fixture.read_text())
    document["time_window"]["duration"] = "4h"
    source = tmp_path / "scenario.yaml"
    source.write_text(yaml.safe_dump(document))
    # Exercise every bounded operation deterministically, without increasing the
    # nominal production workload's probability or frequency to satisfy a test.
    overlay = tmp_path / ".eforge/config/activity/macos_execution_metadata.yaml"
    overlay.parent.mkdir(parents=True)
    overlay.write_text(
        yaml.safe_dump(
            {
                "filesystem_workload": {
                    "count_min": 2,
                    "count_max": 2,
                    "idle_probability": 0.0,
                    "atomic_replace_probability": 1.0,
                    "cleanup_probability": 1.0,
                }
            }
        )
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("EFORGE_TEST_CHECKPOINT_SYNC_")
    }

    def run(label: str, *arguments: str | Path) -> str:
        result = subprocess.run(
            [sys.executable, "-m", "evidenceforge", *map(str, arguments)],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            timeout=180,
            check=False,
        )
        log = tmp_path / f"{label}.txt"
        log.write_bytes(result.stdout + result.stderr)
        assert result.returncode == 0, log.read_text()[-7000:]
        return result.stdout.decode()

    output = tmp_path / "resumed"
    sync = tmp_path / "sync"
    sync.mkdir()
    log = tmp_path / "suspending.txt"
    with log.open("wb") as stream:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "evidenceforge",
                "generate",
                str(source),
                "--output",
                str(output),
                "--checkpoint-hours",
                "1",
            ],
            cwd=tmp_path,
            env=environment
            | {
                "EFORGE_TEST_CHECKPOINT_SYNC_DIR": str(sync),
                "EFORGE_TEST_CHECKPOINT_SYNC_HOUR": "2",
                "EFORGE_TEST_CHECKPOINT_SYNC_TIMEOUT": "120",
            },
            stdout=stream,
            stderr=subprocess.STDOUT,
        )
        try:
            marker = sync / "00000000000000000002.ready"
            deadline = time.monotonic() + 90
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            assert marker.exists(), log.read_text()[-7000:]
            run("suspend", "checkpoint", "suspend", output)
            (sync / "00000000000000000002.continue").touch()
            assert process.wait(timeout=90) == 0, log.read_text()[-7000:]
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=15)
    status = json.loads(run("status", "checkpoint", "status", output, "--json"))
    assert status["state"] == "resumable" and status["suspended"] is True
    store = IncrementalCheckpointStore(output)
    recovery = store.recover(read_only=True)
    head = loads(store.read_head(recovery, "state-manager"))
    assert decode_state_value(head["simple"]["_macos_filesystem_inodes"])
    assert decode_state_value(head["simple"]["_macos_filesystem_directories"])
    assert "local-artifacts" in {head.owner for head in recovery.manifest.participant_heads}
    run("resume", "generate", "--output", output, "--resume", "--resume-policy", "exact")
    control = tmp_path / "control"
    run("control", "generate", source, "--output", control, "--checkpoint-hours", "1")
    assert deterministic_bundle_files(output) == deterministic_bundle_files(control)
    filtered = tmp_path / "native-only"
    run(
        "native-only",
        "generate",
        source,
        "--output",
        filtered,
        "--formats",
        "macos_endpoint_security,macos_unified_log",
        "--checkpoint-hours",
        "1",
    )

    def native(root: Path) -> dict[str, bytes]:
        return {
            str(path.relative_to(root / "data")): path.read_bytes()
            for path in (root / "data").rglob("macos_endpoint_security.ndjson")
        }

    assert native(output) and native(output) == native(filtered)
    rows = [json.loads(line) for data in native(output).values() for line in data.splitlines()]
    assert {12, 13, 25, 32} <= {row["event_type"] for row in rows}
    report = json.loads(run("evaluation", "eval", output, "--format", "json"))
    assert report["acceptance_passed"] is True
