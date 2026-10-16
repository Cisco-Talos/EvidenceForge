# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded Mac SMB client evidence through the production action owner."""

import json
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.utils.rng import generation_seed_scope, reset_thread_rng
from tests.support.macos_smb import macos_smb_scenario


@pytest.mark.slow
@pytest.mark.parametrize("server_platform", ["windows", "linux"])
@pytest.mark.parametrize("explicit_actor", [False, True])
def test_mac_mounted_read_correlates_client_network_and_server(
    scenarios_dir: Path, tmp_path: Path, server_platform: str, explicit_actor: bool
) -> None:
    scenario = macos_smb_scenario(scenarios_dir, server_platform=server_platform)
    engine = GenerationEngine(scenario, tmp_path)
    try:
        engine._initialize()
        generator = engine.activity_generator
        user, client = scenario.environment.users[0], scenario.environment.systems[0]
        with generation_seed_scope(scenario.generation_seed):
            reset_thread_rng()
            logon = generator.generate_logon(user, client, engine.start_time + timedelta(minutes=1))
            shell_pid = generator.ensure_macos_session_shell(
                user, client, logon, engine.start_time + timedelta(minutes=2)
            )
            assert shell_pid is not None
            process_pid = -1
            if explicit_actor:
                process_pid = generator.generate_process(
                    user=user,
                    system=client,
                    time=engine.start_time + timedelta(minutes=3),
                    logon_id=logon,
                    process_name="/usr/bin/head",
                    command_line='head -c 4096 "/Volumes/team/Reports/plan.txt"',
                    parent_pid=shell_pid,
                )
                assert process_pid > 0
            result = generator.generate_smb_activity(
                spec=scenario.storyline[0].events[0],
                actor=user,
                parent_system=client,
                time=engine.start_time + timedelta(minutes=10),
                activity_source="storyline",
                process_pid=process_pid,
                client_logon_id=logon if explicit_actor else "",
            )
            assert len(result.transport_uids) == 1
    finally:
        engine._close_emitters()
    rows = {
        path.parent.name: [json.loads(line) for line in path.read_text().splitlines()]
        for path in tmp_path.rglob("ecar.json")
    }
    client_rows = next(value for key, value in rows.items() if key.startswith("TEST-01"))
    server_rows = next(value for key, value in rows.items() if key.startswith("FS-TEST"))
    files = [row for row in client_rows if row["object"] == "FILE"]
    assert files and "/Volumes/team/Reports/plan.txt" in json.dumps(files)
    server_files = [row for row in server_rows if row["object"] == "FILE"]
    assert {row["objectID"] for row in files} == {row["objectID"] for row in server_files}
    flows = [row for row in client_rows if row["object"] == "FLOW"]
    assert flows
    assert all("actorID" not in row and "pid" not in row for row in flows)
    creates = {
        row["objectID"]: row
        for row in client_rows
        if row["object"] == "PROCESS" and row["action"] == "CREATE"
    }
    closes = {
        row["objectID"]: row
        for row in client_rows
        if row["object"] == "PROCESS" and row["action"] == "TERMINATE"
    }
    for row in files:
        actor = row["actorID"]
        assert actor in creates
        assert creates[actor]["timestamp_ms"] < row["timestamp_ms"]
        if not explicit_actor:
            assert actor in closes and row["timestamp_ms"] < closes[actor]["timestamp_ms"]
    assert not list(tmp_path.glob("**/TEST-01*/windows_event_security.xml"))
    assert not list(tmp_path.glob("**/TEST-01*/syslog.log"))


@pytest.mark.slow
@pytest.mark.parametrize("server_platform", ["windows", "linux"])
@pytest.mark.parametrize(
    "operation",
    ["browse", "create", "update", "copy", "move", "delete", "denied", "upload", "encrypted"],
)
def test_mac_mounted_operations_preserve_effects_and_actor_ownership(
    scenarios_dir: Path, tmp_path: Path, server_platform: str, operation: str
) -> None:
    from evidenceforge.models.scenario import Scenario

    data = macos_smb_scenario(scenarios_dir, server_platform=server_platform).model_dump()
    spec = data["storyline"][0]["events"][0]
    spec["operation"] = (
        "read"
        if operation in {"denied", "encrypted"}
        else "copy"
        if operation == "upload"
        else operation
    )
    if operation == "create":
        spec["target"] = {"type": "share", "share": "FS-TEST.team", "path": "Reports/new.txt"}
    elif operation in {"copy", "move"}:
        spec["source"] = spec.pop("target")
        spec["destination"] = {"type": "client", "path": "/Users/test_user/Downloads/plan.txt"}
    elif operation == "denied":
        spec["outcome"] = "access_denied"
        data["environment"]["storage"]["servers"][0]["shares"][0]["access"]["deny"] = ["test_user"]
    elif operation == "encrypted":
        data["environment"]["storage"]["servers"][0]["shares"][0]["encryption"] = "required"
    elif operation == "upload":
        spec.pop("target")
        spec["source"] = {"type": "client", "file_set": "local-documents", "file_ref": "upload"}
        spec["destination"] = {
            "type": "share",
            "share": "FS-TEST.team",
            "path": "Reports/upload.txt",
        }
        data["environment"]["storage"]["file_sets"] = [
            {
                "id": "local-documents",
                "system": "TEST-01",
                "preset": "homes",
                "root": "/Users/test_user/Documents",
                "population": "small",
                "seed_files": [{"ref": "upload", "path": "upload.txt", "size_bytes": 4096}],
            }
        ]
    scenario = Scenario.model_validate(data)
    engine = GenerationEngine(scenario, tmp_path)
    try:
        engine._initialize()
        generator = engine.activity_generator
        user, client = scenario.environment.users[0], scenario.environment.systems[0]
        with generation_seed_scope(scenario.generation_seed):
            reset_thread_rng()
            logon = generator.generate_logon(user, client, engine.start_time + timedelta(minutes=1))
            generator.ensure_macos_session_shell(
                user, client, logon, engine.start_time + timedelta(minutes=2)
            )
            before = generator.state_manager.get_state_summary()["smb_mutations"]
            result = generator.generate_smb_activity(
                spec=scenario.storyline[0].events[0],
                actor=user,
                parent_system=client,
                time=engine.start_time + timedelta(minutes=10),
                activity_source="storyline",
            )
            assert {item["outcome"] for item in result.operations} == {
                "access_denied" if operation == "denied" else "success"
            }
            if operation == "denied":
                assert generator.state_manager.get_state_summary()["smb_mutations"] == before
                assert all(item["fuid"] is None for item in result.operations)
    finally:
        engine._close_emitters()
    client_file = next(path for path in tmp_path.rglob("ecar.json") if "TEST-01." in str(path))
    rows = [json.loads(line) for line in client_file.read_text().splitlines()]
    files = [row for row in rows if row["object"] == "FILE"]
    if operation == "encrypted":
        for name in ("smb_files.json", "files.json"):
            assert all("plan.txt" not in path.read_text() for path in tmp_path.rglob(name))
    if operation == "denied":
        assert not files
    else:
        assert files
        expected_path = (
            "/Users/test_user/Downloads/plan.txt"
            if operation in {"copy", "move"}
            else "/Users/test_user/Documents/upload.txt"
            if operation == "upload"
            else "/Volumes/team/Reports/new.txt"
            if operation == "create"
            else "/Volumes/team/Reports"
            if operation == "browse"
            else "/Volumes/team/Reports/plan.txt"
        )
        assert any(row["properties"]["file_path"] == expected_path for row in files)
        creates = {
            row["objectID"]: row
            for row in rows
            if row["object"] == "PROCESS" and row["action"] == "CREATE"
        }
        closes = {
            row["objectID"]: row
            for row in rows
            if row["object"] == "PROCESS" and row["action"] == "TERMINATE"
        }
        for row in files:
            actor = row["actorID"]
            assert (
                creates[actor]["timestamp_ms"] < row["timestamp_ms"] < closes[actor]["timestamp_ms"]
            )


@pytest.mark.slow
def test_mac_smb_fresh_process_determinism_and_endpoint_filtering(tmp_path: Path) -> None:
    import os
    import subprocess
    import sys

    from tests.support.output_equivalence import deterministic_bundle_files

    scenario = Path("scenarios/macos-workstation-example/smb-client.yaml").resolve()
    snapshots: list[dict[str, bytes]] = []
    for label, hash_seed, formats in [
        ("first", "23", ""),
        ("second", "61", ""),
        ("filtered", "8", "ecar"),
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
            "99",
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
            timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        snapshots.append(deterministic_bundle_files(output))
    first, second, filtered = snapshots
    assert first == second
    assert {name: body for name, body in first.items() if name.endswith("/ecar.json")} == {
        name: body for name, body in filtered.items() if name.endswith("/ecar.json")
    }
    client = next(
        body for name, body in first.items() if "/TEST-01." in name and name.endswith("/ecar.json")
    )
    rows = [json.loads(line) for line in client.splitlines()]
    assert any(row["object"] == "FILE" and row["action"] == "READ" for row in rows)
