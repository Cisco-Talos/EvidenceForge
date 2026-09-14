"""Routine native-platform coverage for the complete checkpoint CLI lifecycle."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import yaml

from tests.support.output_equivalence import deterministic_bundle_files


def _run_cli(*arguments: str, environment: dict[str, str]) -> str:
    result = subprocess.run(
        [sys.executable, "-m", "evidenceforge", *arguments],
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def test_short_generation_checkpoint_suspension_and_resume(tmp_path: Path) -> None:
    scenario_data = yaml.safe_load(
        Path("tests/fixtures/scenarios/minimal.yaml").read_text(encoding="utf-8")
    )
    scenario_data["time_window"].update(warmup="1h", duration="3h")
    scenario_data["baseline_activity"]["intensity"] = "low"
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text(yaml.safe_dump(scenario_data), encoding="utf-8")
    output = tmp_path / "suspended"
    control = tmp_path / "control"
    sync = tmp_path / "sync"
    sync.mkdir()
    environment = os.environ.copy()
    environment["PYTHONUTF8"] = "1"
    suspended_environment = environment | {
        "EFORGE_TEST_CHECKPOINT_SYNC_DIR": str(sync),
        "EFORGE_TEST_CHECKPOINT_SYNC_HOUR": "2",
        "EFORGE_TEST_CHECKPOINT_SYNC_TIMEOUT": "120",
    }
    # A file avoids pipe-buffer deadlock while the parent waits for the ready marker.
    with (tmp_path / "generation-output.txt").open("w+b") as log:
        process = subprocess.Popen(
            [
                sys.executable,
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
            env=suspended_environment,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            marker = sync / "00000000000000000002.ready"
            deadline = time.monotonic() + 120
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            log.seek(0)
            assert marker.exists(), log.read().decode("utf-8", errors="replace")
            cursor = json.loads(marker.read_bytes())
            assert cursor["completed_simulated_hours"] == 2
            assert cursor["phase"] == "collection"
            _run_cli("checkpoint", "suspend", str(output), environment=environment)
            (sync / "00000000000000000002.continue").touch()
            process.wait(timeout=120)
            log.seek(0)
            assert process.returncode == 0, log.read().decode("utf-8", errors="replace")
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=30)

    status = json.loads(
        _run_cli("checkpoint", "status", str(output), "--json", environment=environment)
    )
    assert status["state"] == "resumable"
    assert status["suspended"] is True
    assert 2 <= status["simulated_hour"] < 4
    index = output / ".eforge-generation" / "CURRENT.json"
    before_verify = index.read_bytes()
    _run_cli("checkpoint", "verify", str(output), environment=environment)
    assert index.read_bytes() == before_verify
    _run_cli("generate", "--output", str(output), "--resume", environment=environment)
    assert not (output / ".eforge-generation").exists()
    _run_cli(
        "generate",
        str(scenario),
        "--output",
        str(control),
        "--seed",
        "42",
        "--checkpoint-hours",
        "0",
        environment=environment,
    )
    resumed_files = deterministic_bundle_files(output)
    assert resumed_files == deterministic_bundle_files(control)
    assert any(
        b"<Event " in content for name, content in resumed_files.items() if name.startswith("data/")
    )
    assert any(
        any(line and not line.startswith(b"#") for line in content.splitlines())
        for name, content in resumed_files.items()
        if name.endswith("/conn.json")
    )
