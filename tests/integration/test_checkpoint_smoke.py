"""Routine native-platform coverage for the complete checkpoint CLI lifecycle."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from tests.support.macos_smb import macos_smb_scenario
from tests.support.macos_ssh import macos_ssh_scenario
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


@pytest.mark.parametrize(
    "target,start,macos,smb_server,ssh_client,macos_receiver,authored_close",
    [
        ("default", None, False, None, False, False, False),
        ("sof-elk", None, False, None, False, False, False),
        pytest.param(
            "default",
            "2026-10-09T09:59:17.125Z",
            False,
            None,
            False,
            False,
            False,
            marks=pytest.mark.slow,
        ),
        pytest.param("default", None, True, None, False, False, False, marks=pytest.mark.slow),
        pytest.param("default", None, True, "windows", False, False, False, marks=pytest.mark.slow),
        pytest.param("default", None, True, "linux", False, False, False, marks=pytest.mark.slow),
        pytest.param(
            "default", None, True, None, True, False, False, marks=pytest.mark.slow, id="mac-ssh"
        ),
        pytest.param(
            "default",
            None,
            True,
            None,
            True,
            True,
            False,
            marks=pytest.mark.slow,
            id="mac-ssh-receiver",
        ),
        pytest.param(
            "default",
            None,
            True,
            None,
            True,
            True,
            True,
            marks=pytest.mark.slow,
            id="mac-ssh-authored-close",
        ),
    ],
)
def test_short_generation_checkpoint_suspension_and_resume(
    tmp_path: Path,
    scenarios_dir: Path,
    target: str,
    start: str | None,
    macos: bool,
    smb_server: str | None,
    ssh_client: bool,
    macos_receiver: bool,
    authored_close: bool,
    native: bool = False,
    helpers: bool = False,
    denied_launch: bool = False,
    failed_exec: bool = False,
    persistence: bool = False,
    persistence_active: bool = False,
) -> None:
    scenario_path = (
        Path("scenarios/macos-workstation-example/scenario.yaml")
        if macos
        else Path("tests/fixtures/scenarios")
        / ("checkpoint-all-formats.yaml" if target == "sof-elk" else "minimal.yaml")
    )
    scenario_data = yaml.safe_load(scenario_path.read_text(encoding="utf-8"))
    if ssh_client:
        scenario_data = macos_ssh_scenario(
            scenarios_dir, macos_receiver=macos_receiver, authored_close=authored_close
        ).model_dump(mode="json", exclude_none=True)
        if macos_receiver:
            scenario_data["storyline"][1]["time"] = "+50m"
        if authored_close:
            scenario_data["storyline"][1]["time"] = "+1h50m"
            scenario_data["storyline"][2]["time"] = "+2h20m"
        second_session = dict(scenario_data["storyline"][1])
        second_session.update(id="ssh-after-resume", time="+2h30m" if authored_close else "+1h30m")
        scenario_data["storyline"].append(second_session)
        if authored_close:
            second_close = dict(scenario_data["storyline"][2])
            second_close.update(id="close-after-resume", time="+2h45m")
            scenario_data["storyline"].append(second_close)
    if smb_server is not None:
        scenario_data = macos_smb_scenario(scenarios_dir, server_platform=smb_server).model_dump(
            mode="json", exclude_none=True
        )
        second_read = dict(scenario_data["storyline"][0])
        second_read.update(id="read-after-resume", time="+1h30m")
        scenario_data["storyline"].append(second_read)
        scenario_data["storyline"].insert(
            0,
            {
                "id": "mac-local-login",
                "time": "+1m",
                "actor": "test_user",
                "system": "TEST-01",
                "activity": "Start the Mac session owning shared-file activity",
                "events": [{"type": "logon", "logon_type": 2}],
            },
        )
    if native:
        scenario_data["output"]["logs"].append({"format": "macos_unified_log"})
        scenario_data["storyline"] = [
            {
                "id": f"workspace-{index}",
                "time": when,
                "actor": "alex",
                "system": "MAC-01",
                "activity": "Local session transition across checkpoint recovery",
                "events": [{"type": kind, **({"logon_type": 2} if kind == "logon" else {})}],
            }
            for index, (when, kind) in enumerate(
                [
                    ("+1m", "logoff"),
                    ("+2m", "logon"),
                    ("+1h10m", "logoff"),
                    ("+1h11m", "logon"),
                ]
            )
        ]
    if denied_launch or failed_exec:
        scenario_data["storyline"] = [
            {
                "id": "caller-before-checkpoint",
                "time": "+1m",
                "actor": "alex",
                "system": "MAC-01",
                "activity": "Retain the caller across recovery",
                "events": [
                    {"type": "process", "process_name": "/bin/zsh", "process_ref": "caller"}
                ],
            },
            {
                "id": "denied-after-checkpoint",
                "time": "+1h10m",
                "actor": "alex",
                "system": "MAC-01",
                "activity": "Reject a launch before allocating a child",
                "events": [
                    {
                        "type": "process",
                        "process_name": "/usr/local/libexec/invented-blocked-helper",
                        "parent_ref": "caller",
                        "outcome": "exec_failed" if failed_exec else "denied",
                    }
                ],
            },
        ]
    if persistence:
        scenario_data = yaml.safe_load(
            Path("scenarios/macos-persistence-example/scenario.yaml").read_text()
        )
        # Retain the file and loaded job before recovery; remove and activate later.
        times = (
            ("+1m", "+2m", "+3m", "+4m", "+50m", "+1h10m", "+1h11m", "+1h12m")
            if persistence_active
            else ("+1m", "+2m", "+3m", "+1h10m", "+1h11m", "+1h12m", "+1h13m", "+1h14m")
        )
        for step, when in zip(scenario_data["storyline"], times, strict=True):
            step["time"] = when
    scenario_data["time_window"].update(warmup="1h", duration="3h")
    scenario_data["baseline_activity"]["intensity"] = "low"
    if helpers:
        # Cross the normal GUI session close, not only the collection cutoff.
        scenario_data["time_window"]["duration"] = "12h"
        # Exercise helper retention with the established high-intensity seed;
        # low-intensity baseline may legitimately start no browser before recovery.
        scenario_data["baseline_activity"]["intensity"] = "high"
        scenario_data["environment"]["deployment_overrides"] = [
            {
                "system": "MAC-01",
                "user_applications": [{"user": "alex", "applications": ["chrome", "macos-zsh"]}],
            }
        ]
    if start is not None:
        scenario_data["time_window"]["start"] = start
        scenario_data["storyline"] = [
            {
                "id": f"authored-{index}",
                "time": time,
                "actor": "test_user",
                "system": "TEST-01",
                "activity": "Authored process across checkpoint recovery",
                "events": [
                    {
                        "type": "process",
                        "process_name": r"C:\Windows\System32\cmd.exe",
                        "command_line": f"cmd.exe /c echo checkpoint-hour-{index}",
                    }
                ],
            }
            for index, time in enumerate(["+30m", "+1h30m"])
        ]
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text(yaml.safe_dump(scenario_data), encoding="utf-8")
    seed = "123" if macos else "42"
    output = tmp_path / "suspended"
    control = tmp_path / "control"
    sync = tmp_path / "sync"
    sync.mkdir()
    environment = os.environ.copy()
    for name in (
        "EFORGE_TEST_CHECKPOINT_SYNC_DIR",
        "EFORGE_TEST_CHECKPOINT_SYNC_HOUR",
        "EFORGE_TEST_CHECKPOINT_SYNC_TIMEOUT",
    ):
        environment.pop(name, None)
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
                seed,
                "--target",
                target,
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
    if macos_receiver:
        from evidenceforge.generation.checkpoints.packed import loads
        from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore

        store = IncrementalCheckpointStore(output)
        recovery = store.recover(read_only=True)
        head = loads(store.read_head(recovery, "activity-generator"))
        assert any(
            any(isinstance(member, list) and member and member[0] == "macos-v2" for member in row)
            for row in head["ssh_lifecycles"]
        ), "The checkpoint must retain an active Mac receiver close continuation"
        if authored_close:
            assert any(len(row) == 32 and row[31] is not None for row in head["ssh_lifecycles"]), (
                "The active continuation must retain its authored end owner"
            )
    retained_helpers: set[str] = set()
    if helpers:
        from evidenceforge.generation.checkpoints.packed import loads
        from evidenceforge.generation.checkpoints.state_values import decode_state_value
        from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore

        store = IncrementalCheckpointStore(output)
        recovery = store.recover(read_only=True)
        head = loads(store.read_head(recovery, "state-manager"))
        processes = decode_state_value(head["stores"]["_running_processes"])
        retained_helpers = {
            process.ecar_object_id for _key, process in processes if "/Helpers/" in process.image
        }
        assert retained_helpers, "The checkpoint must retain live browser helpers"
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
        seed,
        "--checkpoint-hours",
        "0",
        "--target",
        target,
        environment=environment,
    )
    resumed_files = deterministic_bundle_files(output)
    assert resumed_files == deterministic_bundle_files(control)
    if denied_launch or failed_exec:
        assert b"invented-blocked-helper" not in b"".join(
            content for name, content in resumed_files.items() if name.startswith("data/")
        )
        truth = json.loads((output / "GROUND_TRUTH.json").read_text())
        denied = next(
            row for row in truth["events"] if row["storyline_id"] == "denied-after-checkpoint"
        )
        assert denied["emitted"] is False
        assert denied["attributes"]["outcome"] == ("exec_failed" if failed_exec else "denied")
        assert denied["skipped_reason"] == (
            "exec_failed_caller_preserved" if failed_exec else "execution_denied_before_spawn"
        )
    if native:
        from evidenceforge.formats.macos_unified_log import decode_unified_log_record

        records = [
            decode_unified_log_record(line)
            for name, content in resumed_files.items()
            if name.endswith("/macos_unified_log.ndjson")
            for line in content.splitlines()
        ]
        assert len(records) >= 2
        assert len({record.boot_uuid for record in records}) == 1
        assert len({record.process_id for record in records}) == 1
        # Assert observations on both sides of the recovery cursor; session-close
        # holds and modeled source clocks need not equal authored minute anchors.
        cursor_time = datetime(2026, 10, 19, 15, tzinfo=UTC)
        timestamps = [datetime.fromisoformat(record.timestamp) for record in records]
        assert any(timestamp < cursor_time for timestamp in timestamps)
        assert any(timestamp > cursor_time for timestamp in timestamps)
    if helpers:
        rows = [
            json.loads(line)
            for name, content in resumed_files.items()
            if "/MAC-01." in name and name.endswith("/ecar.json")
            for line in content.splitlines()
        ]
        ends = {row["objectID"]: row for row in rows if row["action"] == "TERMINATE"}
        cursor_ms = int(datetime(2026, 10, 19, 15, tzinfo=UTC).timestamp() * 1000)
        assert retained_helpers <= ends.keys()
        assert all(ends[object_id]["timestamp_ms"] > cursor_ms for object_id in retained_helpers)
    if start is not None:
        for index in range(2):
            assert any(
                f"checkpoint-hour-{index}".encode() in content
                for name, content in resumed_files.items()
                if name.startswith("data/")
            )
    if ssh_client:
        client_ecar = next(
            content
            for name, content in resumed_files.items()
            if "/TEST-01." in name and name.endswith("/ecar.json")
        )
        rows = [json.loads(line) for line in client_ecar.splitlines()]
        clients = [
            row
            for row in rows
            if row["object"] == "PROCESS"
            and row["action"] == "CREATE"
            and row["properties"]["image_path"] == "/usr/bin/ssh"
        ]
        assert len(clients) >= 2
        terminated = {row["objectID"] for row in rows if row["action"] == "TERMINATE"}
        assert all(row["objectID"] in terminated for row in clients)
    elif smb_server is not None:
        client_ecar = next(
            content
            for name, content in resumed_files.items()
            if "/TEST-01." in name and name.endswith("/ecar.json")
        )
        reads = [
            json.loads(line)
            for line in client_ecar.splitlines()
            if json.loads(line).get("properties", {}).get("file_path")
            == "/Volumes/team/Reports/plan.txt"
        ]
        assert len(reads) >= 2
    elif macos:
        if not denied_launch and not failed_exec and not persistence and not native:
            assert any(name.endswith(".zsh_history") for name in resumed_files)
        assert not any(name.endswith(".bash_history") for name in resumed_files)
    else:
        assert any(
            (b"MSWinEventLog" if target == "sof-elk" else b"<Event ") in content
            for name, content in resumed_files.items()
            if name.startswith("data/")
        )
    assert any(
        any(line and not line.startswith(b"#") for line in content.splitlines())
        for name, content in resumed_files.items()
        if name.endswith("/conn.json")
    )


@pytest.mark.slow
def test_macos_native_workspace_checkpoint_resume(tmp_path: Path, scenarios_dir: Path) -> None:
    test_short_generation_checkpoint_suspension_and_resume(
        tmp_path, scenarios_dir, "default", None, True, None, False, False, False, native=True
    )


@pytest.mark.slow
def test_macos_browser_helper_checkpoint_resume(tmp_path: Path, scenarios_dir: Path) -> None:
    test_short_generation_checkpoint_suspension_and_resume(
        tmp_path,
        scenarios_dir,
        "default",
        None,
        True,
        None,
        False,
        False,
        False,
        helpers=True,
    )


@pytest.mark.slow
def test_macos_denied_launch_checkpoint_resume(tmp_path: Path, scenarios_dir: Path) -> None:
    test_short_generation_checkpoint_suspension_and_resume(
        tmp_path,
        scenarios_dir,
        "default",
        None,
        True,
        None,
        False,
        False,
        False,
        denied_launch=True,
    )


@pytest.mark.slow
@pytest.mark.parametrize("active", [False, True])
def test_macos_persistence_checkpoint(tmp_path: Path, scenarios_dir: Path, active: bool) -> None:
    test_short_generation_checkpoint_suspension_and_resume(
        tmp_path,
        scenarios_dir,
        "default",
        None,
        True,
        None,
        False,
        False,
        False,
        persistence=True,
        persistence_active=active,
    )


@pytest.mark.slow
def test_macos_failed_exec_checkpoint_resume(tmp_path: Path, scenarios_dir: Path) -> None:
    test_short_generation_checkpoint_suspension_and_resume(
        tmp_path,
        scenarios_dir,
        "default",
        None,
        True,
        None,
        False,
        False,
        False,
        failed_exec=True,
    )
