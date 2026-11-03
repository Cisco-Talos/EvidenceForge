"""Finite combined acceptance of the supported Mac workload through exact recovery."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml
from scripts.measure_macos_workstation import Case, Workload, summarize

from evidenceforge.generation.checkpoints.packed import loads
from evidenceforge.generation.checkpoints.state_values import decode_state_value
from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore
from tests.support.output_equivalence import deterministic_bundle_files


@pytest.mark.slow
def test_combined_macos_workstation_exact_recovery(tmp_path: Path) -> None:
    source = Path("scenarios/macos-workstation-recovery/source/scenario.yaml").resolve()
    spec = Workload.model_validate(
        yaml.safe_load(Path("scenarios/macos-workstation-acceptance/WORKLOAD.yaml").read_text())
    )
    document = yaml.safe_load(source.read_text())
    case = Case(
        name="combined-recovery",
        description="All supported families across exact recovery",
        steps=tuple(step["id"] for step in document["storyline"]),
        required_images=tuple(
            dict.fromkeys(image for member in spec.cases for image in member.required_images)
        ),
        required_executions=tuple(
            role for member in spec.cases for role in member.required_executions
        ),
        allowed_noop_steps=spec.allowed_noop_steps,
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("EFORGE_TEST_CHECKPOINT_SYNC_")
    }

    def run(label: str, *arguments: str | Path) -> str:
        target = tmp_path / f"{label}.txt"
        with target.open("wb") as stream:
            result = subprocess.run(
                [sys.executable, "-m", "evidenceforge", *map(str, arguments)],
                env=environment,
                stdout=stream,
                stderr=subprocess.STDOUT,
                timeout=300,
                check=False,
            )
        text = target.read_text()
        assert result.returncode == 0, text[-7000:]
        return text

    output = tmp_path / "resumed"
    sync = tmp_path / "sync"
    sync.mkdir()
    with (tmp_path / "suspending.txt").open("wb") as stream:
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
            deadline = time.monotonic() + 120
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            assert marker.exists(), (tmp_path / "suspending.txt").read_text()[-7000:]
            cursor = json.loads(marker.read_bytes())
            assert cursor["phase"] == "collection" and cursor["completed_simulated_hours"] == 2
            run("suspend", "checkpoint", "suspend", output)
            (sync / "00000000000000000002.continue").touch()
            assert process.wait(timeout=180) == 0
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=30)

    status = json.loads(run("status", "checkpoint", "status", output, "--json"))
    assert status["state"] == "resumable" and status["suspended"] is True
    # Suspension can seal the following hourly cursor after the request is read.
    assert 2 <= status["simulated_hour"] <= 3
    store = IncrementalCheckpointStore(output)
    recovery = store.recover(read_only=True)
    head = loads(store.read_head(recovery, "state-manager"))
    processes = decode_state_value(head["stores"]["_running_processes"])
    live_images = [process.image for _key, process in processes]
    activity = loads(store.read_head(recovery, "activity-generator"))
    retained_modes = {
        member[0]
        for row in activity["ssh_lifecycles"]
        for member in row
        if isinstance(member, list) and member and isinstance(member[0], str)
    }
    # SSH retains exact process snapshots in its lifecycle continuation; eagerly
    # frozen future terminals need not remain in State's live-process mapping.
    assert {"macos-v2", "macos-v3-pty"} <= retained_modes
    assert any("Terminal.app" in image for image in live_images)
    assert any("iTerm.app" in image for image in live_images)
    assert sum("/Helpers/" in image for image in live_images) >= 3
    index = output / ".eforge-generation/CURRENT.json"
    before = index.read_bytes()
    run("verify", "checkpoint", "verify", output)
    assert before == index.read_bytes()
    run("resume", "generate", "--output", output, "--resume", "--resume-policy", "exact")
    control = tmp_path / "control"
    run("control", "generate", source, "--output", control, "--checkpoint-hours", "1")
    resumed_files = deterministic_bundle_files(output)
    assert resumed_files == deterministic_bundle_files(control)
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
            for path in (root / "data").rglob("*")
            if path.is_file()
            and path.name in {"macos_endpoint_security.ndjson", "macos_unified_log.ndjson"}
        }

    assert native(output) and native(output) == native(filtered)
    ulf = [
        json.loads(line)
        for path in (output / "data").rglob("macos_unified_log.ndjson")
        for line in path.read_text().splitlines()
    ]
    accepted = [
        row for row in ulf if row["eventMessage"].startswith("Accepted keyboard-interactive/pam ")
    ]
    publickey = [row for row in ulf if row["eventMessage"].startswith("Accepted publickey ")]
    # Authentication methods retain their actual distinct payloads through one logger.
    assert len(ulf) == 4 and len(accepted) == len(publickey) == 1
    assert all(
        row["userID"] == 0
        and row["processImagePath"] == "/usr/libexec/sshd-session"
        and row["messageType"] == "Info"
        and row["formatString"] == "%.500s"
        for row in (*accepted, *publickey)
    )
    measurements = [
        summarize(path, case, full=True, exit_code=0, text="") for path in (output, control)
    ]
    assert all(
        item.activity_supported and item.census_complete and item.background_native_execs > 0
        for item in measurements
    ), measurements
    assert all(
        item.native_exit_rows > 0 and item.exit_outcomes_unknown > 0 for item in measurements
    )
    (tmp_path / "RESULTS.json").write_text(
        json.dumps(
            {
                "exact_resume_files_equal": True,
                "native_filter_bytes_equal": True,
                "ulf_rows": len(ulf),
                "ssh_pam_success_rows": len(accepted),
                "ssh_publickey_success_rows": len(publickey),
                "deterministic_files_compared": len(resumed_files),
                "checkpoint_hour": status["simulated_hour"],
                "measurements": [item.model_dump(mode="json") for item in measurements],
            },
            indent=2,
        )
        + "\n"
    )
