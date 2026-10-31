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

from evidenceforge.utils.time import parse_duration
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
    persistence_group: bool = False,
    history_spillage: bool = False,
    endpoint_forks: bool = False,
    finder: bool = False,
    terminal_id: str | None = None,
    complete_native_ssh: bool = False,
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
    if complete_native_ssh:
        assert ssh_client
        scenario_data["macos_process_coverage"] = "complete"
        scenario_data["output"]["logs"].append({"format": "macos_endpoint_security"})
        scenario_data["baseline_activity"]["traffic_rates"] = {
            "user_activity": 1,
            "persona_connections": 1,
        }
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
    if endpoint_forks:
        scenario_data["output"]["logs"].append({"format": "macos_endpoint_security"})
        for system in scenario_data["environment"]["systems"]:
            if system["os"].startswith("macOS"):
                system["os_build"] = "26A100"
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
    if finder:
        scenario_data["macos_process_coverage"] = "partial"
        scenario_data["output"]["logs"].append({"format": "macos_endpoint_security"})
        scenario_data["storyline"] = [
            {
                "id": f"finder-{index}",
                "time": when,
                "actor": "alex",
                "system": "MAC-01",
                "activity": "Invented Finder startup across checkpoint recovery",
                "events": [
                    {
                        "type": "process",
                        "launch_method": "finder",
                        "supplementary": "none",
                        "process_name": "/Applications/EForgeReference.app/Contents/MacOS/EForgeReference",
                    }
                ],
            }
            for index, when in enumerate(("+30m", "+2h10m"))
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
            (
                Path("scenarios/macos-persistence-example")
                / ("group-cleanup.yaml" if persistence_group else "scenario.yaml")
            ).read_text()
        )
        # Suspension requested at hour 2 may seal at hour 3 (16:00). Keep the
        # loaded job through either allowed recovery cursor, then complete it.
        times = (
            ("+1m", "+2m", "+3m", "+4m", "+50m", "+2h10m", "+2h11m", "+2h12m")
            if persistence_active
            else ("+1m", "+2m", "+3m", "+2h10m", "+2h11m", "+2h12m", "+2h13m", "+2h14m")
        )
        if persistence_group:
            times = ("+1m", "+2m", "+3m", "+49m", "+50m", "+51m", "+2h10m", "+2h12m")
        for step, when in zip(scenario_data["storyline"], times, strict=True):
            step["time"] = when
    if history_spillage:
        scenario_data["storyline"] = [
            {
                "id": "history-login",
                "time": "+2m",
                "actor": "alex",
                "system": "MAC-01",
                "activity": "Open the explicit local history owner",
                "events": [{"type": "logon", "logon_type": 2}],
            },
            *[
                {
                    "id": f"history-{index}",
                    "time": when,
                    "actor": "alex",
                    "system": "MAC-01",
                    "activity": "Invented interactive submission across recovery",
                    "events": [
                        {
                            "type": "spillage",
                            "surface": "shell_history",
                            "value": f"EvidenceForgeFake_CHECKPOINT_{index}",
                        }
                    ],
                }
                for index, when in enumerate(("+50m", "+1h30m"))
            ],
        ]
    scenario_data["time_window"].update(warmup="1h", duration="3h")
    scenario_data["baseline_activity"]["intensity"] = "low"
    if terminal_id is not None:
        scenario_data["macos_process_coverage"] = "complete"
        scenario_data["output"]["logs"] = [
            {"format": "ecar"},
            {"format": "macos_endpoint_security"},
            {"format": "zsh_history"},
            {"format": "zeek"},
        ]
        scenario_data["environment"]["deployment_overrides"] = [
            {
                "system": "MAC-01",
                "user_applications": [{"user": "alex", "applications": [terminal_id]}],
            }
        ]
        scenario_data["baseline_activity"]["traffic_rates"] = {
            "user_activity": 1,
            "persona_connections": 1,
        }
        scenario_data["storyline"] = [
            {
                "id": "close-warmup",
                "time": "+5s",
                "actor": "alex",
                "system": "MAC-01",
                "activity": "Close the warmup desktop",
                "events": [{"type": "logoff"}],
            },
            {
                "id": "fresh-login",
                "time": "+1m",
                "actor": "alex",
                "system": "MAC-01",
                "activity": "Start the measured terminal workload",
                "events": [{"type": "logon", "logon_type": 2}],
            },
            *[
                {
                    "id": f"query-{i}",
                    "time": when,
                    "actor": "alex",
                    "system": "MAC-01",
                    "activity": "Local query across checkpoint recovery",
                    "events": [
                        {"type": "process", "process_name": "/usr/bin/id", "supplementary": "none"}
                    ],
                }
                for i, when in enumerate(("+2m", "+1h30m"))
            ],
        ]
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
    if terminal_id is not None:
        from evidenceforge.generation.checkpoints.packed import loads
        from evidenceforge.generation.checkpoints.state_values import decode_state_value
        from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore

        store = IncrementalCheckpointStore(output)
        recovery = store.recover(read_only=True)
        head = loads(store.read_head(recovery, "state-manager"))
        processes = decode_state_value(head["stores"]["_running_processes"])
        app_suffix = "/Terminal" if terminal_id == "macos-terminal" else "/iTerm2"
        apps = [process for _key, process in processes if process.image.endswith(app_suffix)]
        assert apps and all(process.execution_ordinal == 2 for process in apps)
        assert len({process.logon_id for process in apps}) == len(apps)
        shells = [
            process
            for _key, process in processes
            if process.image == "/bin/zsh" and process.privilege_drop is not None
        ]
        assert shells and all(process.credentials.effective_uid != 0 for process in shells)
    if finder:
        from evidenceforge.generation.checkpoints.packed import loads
        from evidenceforge.generation.checkpoints.state_values import decode_state_value
        from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore

        store = IncrementalCheckpointStore(output)
        recovery = store.recover(read_only=True)
        head = loads(store.read_head(recovery, "state-manager"))
        processes = decode_state_value(head["stores"]["_running_processes"])
        apps = [
            process for _key, process in processes if process.image.endswith("/EForgeReference")
        ]
        assert len(apps) == 1 and apps[0].execution_ordinal == 2
        assert apps[0].service_drop is not None and apps[0].service_drop.gui_session is not None
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
    retained_group: set[str] = set()
    if persistence:
        from evidenceforge.generation.checkpoints.packed import loads
        from evidenceforge.generation.checkpoints.state_values import decode_state_value
        from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore

        store = IncrementalCheckpointStore(output)
        recovery = store.recover(read_only=True)
        head = loads(store.read_head(recovery, "state-manager"))
        processes = decode_state_value(head["stores"]["_running_processes"])
        members = [
            process
            for _key, process in processes
            if process.image
            in {
                "/usr/local/libexec/invented-worker",
                "/usr/local/libexec/invented-helper-1",
                "/usr/local/libexec/invented-helper-2",
            }
        ]
        assert len(members) == (3 if persistence_group else 1 if persistence_active else 0)
        if members:
            assert len({member.job_control for member in members}) == 1
        retained_group = {member.ecar_object_id for member in members}
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
    if finder:
        truth = json.loads((output / "GROUND_TRUTH.json").read_text())
        pids = {
            event["attributes"]["pid"]
            for event in truth["events"]
            if (event.get("storyline_id") or "").startswith("finder-")
        }
        assert len(pids) == 2
        for pid in pids:
            targets = [
                json.loads(line)["event"]["exec"]["target"]["executable"]["path"]
                for name, content in resumed_files.items()
                if name.endswith("macos_endpoint_security.ndjson")
                for line in content.splitlines()
                if (row := json.loads(line))["event_type"] == 9
                and row["event"]["exec"]["target"]["audit_token"]["pid"] == pid
            ]
            assert targets == [
                "/usr/libexec/xpcproxy",
                "/Applications/EForgeReference.app/Contents/MacOS/EForgeReference",
            ]
    if endpoint_forks:
        from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record

        native_by_source = {
            name: [json.loads(line) for line in content.splitlines()]
            for name, content in resumed_files.items()
            if name.endswith("/macos_endpoint_security.ndjson")
        }
        receiver = [
            row for name, rows in native_by_source.items() if "/SSH-TEST." in name for row in rows
        ]
        assert len(receiver) == 6 and all(row["event_type"] == 11 for row in receiver)
        for rows in native_by_source.values():
            for row in rows:
                decode_endpoint_security_record(json.dumps(row))
                assert row["version"] == 11 and row["event_type"] in {9, 11, 15}
            global_sequences = [row["global_seq_num"] for row in rows]
            assert global_sequences == sorted(set(global_sequences))
        sequences = [row["seq_num"] for row in receiver]
        assert sequences == list(range(sequences[0], sequences[0] + 6))
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
    if history_spillage:
        history = b"\n".join(
            value for name, value in resumed_files.items() if name.endswith(".zsh_history")
        )
        assert history.count(b"EvidenceForgeFake_CHECKPOINT_0") == 1
        assert history.count(b"EvidenceForgeFake_CHECKPOINT_1") == 1
        truth = json.loads((output / "GROUND_TRUTH.json").read_text())
        spills = [row for row in truth["events"] if row["kind"] == "spillage"]
        assert len(spills) == 2 and all(row["emitted"] for row in spills)
        assert all(row["attributes"]["expected_sources"] == ["zsh_history"] for row in spills)
    if persistence_group:
        truth = json.loads((output / "GROUND_TRUTH.json").read_text())
        unload = next(
            event
            for event in truth["events"]
            if event.get("attributes", {}).get("launchd_operation") == "unload"
        )
        assert set(unload["attributes"]["process_object_ids"]) == retained_group
        ends = [
            json.loads(line)["objectID"]
            for name, content in resumed_files.items()
            if name.endswith("/ecar.json")
            for line in content.splitlines()
            if json.loads(line)["action"] == "TERMINATE"
        ]
        assert all(ends.count(object_id) == 1 for object_id in retained_group)
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
        clients = {
            row["objectID"]: row
            for row in rows
            if row["object"] == "PROCESS"
            and (
                row["action"] == "CREATE"
                or (row["action"] == "MODIFY" and row["properties"].get("operation") == "exec")
            )
            and row["properties"]["image_path"] == "/usr/bin/ssh"
        }
        assert len(clients) >= 2
        terminated = {row["objectID"] for row in rows if row["action"] == "TERMINATE"}
        # Baseline clients can outlive collection. Require termination only for
        # their transports that close inside the window; no retrospective or
        # post-window endpoint close is fabricated for the other clients.
        conn_closes = {}
        for name, content in resumed_files.items():
            if not name.endswith("/conn.json"):
                continue
            for line in content.splitlines():
                conn = json.loads(line)
                if conn["id.resp_p"] != 22 or conn.get("duration") is None:
                    continue
                key = tuple(
                    str(conn[field])
                    for field in ("id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p")
                )
                ts = conn["ts"]
                opened = datetime.fromisoformat(ts).timestamp() if type(ts) is str else ts
                conn_closes[key] = max(conn_closes.get(key, 0), opened + conn["duration"])
        client_closes = {}
        for row in rows:
            if row["object"] != "FLOW" or row.get("actorID") not in clients:
                continue
            props = row["properties"]
            key = tuple(str(props[field]) for field in ("src_ip", "src_port", "dst_ip", "dst_port"))
            if key in conn_closes:
                client_closes[row["actorID"]] = conn_closes[key]
        # Zeek emits these connection rows at close. A connection still open
        # at collection end need not have a row or an endpoint termination.
        cutoff = (
            datetime.fromisoformat(scenario_data["time_window"]["start"])
            + parse_duration(scenario_data["time_window"]["duration"])
        ).timestamp()
        eligible = {oid for oid, close in client_closes.items() if close < cutoff}
        assert len(eligible) >= 2 and eligible <= terminated
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


@pytest.mark.slow
def test_macos_authored_history_checkpoint_resume(tmp_path: Path, scenarios_dir: Path) -> None:
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
        history_spillage=True,
    )


@pytest.mark.slow
def test_macos_active_persistence_group_checkpoint(tmp_path: Path, scenarios_dir: Path) -> None:
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
        persistence_group=True,
    )
