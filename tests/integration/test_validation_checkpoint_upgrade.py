# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Historical checkpoint compatibility gate; supply the retained baseline interpreter."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

from tests.support.output_equivalence import deterministic_bundle_files

pytestmark = pytest.mark.slow


def _snapshot(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*")
        if p.is_file()
    }


def test_baseline_checkpoint_upgrade(tmp_path: Path) -> None:
    baseline = os.environ.get("EFORGE_VALIDATION_BASELINE_PYTHON")
    if not baseline:
        pytest.skip("Historical gate requires the isolated 787fd733 baseline interpreter")
    data = yaml.safe_load(Path("tests/fixtures/scenarios/checkpoint-all-formats.yaml").read_text())
    data["time_window"].update(warmup="1h", duration="3h")
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text(yaml.safe_dump(data))
    output = tmp_path / "suspended"
    sync = tmp_path / "sync"
    sync.mkdir()
    environment = {
        k: v for k, v in os.environ.items() if not k.startswith("EFORGE_TEST_CHECKPOINT_SYNC_")
    }

    environment["TMPDIR"] = str(tmp_path.resolve())

    def run(exe: str, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [exe, "-m", "evidenceforge", *args],
            env=environment,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )

    with (tmp_path / "suspend.log").open("w") as log:
        process = subprocess.Popen(
            [
                baseline,
                "-m",
                "evidenceforge",
                "generate",
                str(scenario),
                "--output",
                str(output),
                "--seed",
                "42",
                "--checkpoint-hours",
                "1",
            ],
            env=environment
            | {
                "EFORGE_TEST_CHECKPOINT_SYNC_DIR": str(sync),
                "EFORGE_TEST_CHECKPOINT_SYNC_HOUR": "2",
                "EFORGE_TEST_CHECKPOINT_SYNC_TIMEOUT": "120",
            },
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            marker = sync / "00000000000000000002.ready"
            deadline = time.monotonic() + 120
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            assert marker.exists()
            suspended = run(baseline, "checkpoint", "suspend", str(output))
            assert suspended.returncode == 0, suspended.stderr
            (sync / "00000000000000000002.continue").touch()
            assert process.wait(timeout=120) == 0
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=30)
    preserved = tmp_path / "preserved"
    shutil.copytree(output, preserved)
    original = _snapshot(output)
    exact = run(
        sys.executable, "generate", "--output", str(output), "--resume", "--resume-policy", "exact"
    )
    assert exact.returncode != 0
    assert "exact" in (exact.stdout + exact.stderr).lower()
    assert _snapshot(output) == original
    status = run(sys.executable, "checkpoint", "status", str(output), "--json")
    assert status.returncode == 0, status.stderr
    assert "not-guaranteed" in status.stdout
    verify = run(sys.executable, "checkpoint", "verify", str(output))
    assert verify.returncode == 0, verify.stderr
    assert _snapshot(output) == original
    resumed = run(sys.executable, "generate", "--output", str(output), "--resume")
    assert resumed.returncode == 0, resumed.stderr
    assert _snapshot(preserved) == original
    controls = []
    for label, exe in (("baseline", baseline), ("candidate", sys.executable)):
        control = tmp_path / label
        result = run(
            exe,
            "generate",
            str(scenario),
            "--output",
            str(control),
            "--seed",
            "42",
            "--checkpoint-hours",
            "0",
        )
        assert result.returncode == 0, result.stderr
        controls.append(control)

    def evidence(root: Path) -> dict[str, bytes]:
        return {
            name: value
            for name, value in deterministic_bundle_files(root).items()
            if name != "RESOLVED_SCENARIO.yaml"
        }

    assert evidence(output) == evidence(controls[0]) == evidence(controls[1])
    manifest = json.loads((output / "GENERATION_MANIFEST.json").read_text())
    text = json.dumps(manifest)
    assert '"accepted_policy": "compatible"' in text
    assert '"migration_count": 1' in text
    assert "json-logic-qubit" in text
    (tmp_path / "upgrade-evidence.json").write_text(
        json.dumps(
            {
                "exact_exit": exact.returncode,
                "checkpoint_unchanged": True,
                "status": json.loads(status.stdout),
                "resume_exit": resumed.returncode,
                "evidence_files": len(evidence(output)),
                "manifest": manifest,
            },
            indent=2,
        )
    )
