# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mac client evidence agrees with the shared Linux-receiver SSH bundle."""

import json
import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.utils.rng import generation_seed_scope, reset_thread_rng
from tests.support.macos_ssh import macos_ssh_scenario
from tests.support.output_equivalence import deterministic_bundle_files


@pytest.mark.slow
@pytest.mark.parametrize("deferred_close", [False, True])
@pytest.mark.parametrize("source_session", [False, True])
def test_mac_ssh_client_process_history_transport_and_close(
    scenarios_dir: Path, tmp_path: Path, deferred_close: bool, source_session: bool
) -> None:
    scenario = macos_ssh_scenario(scenarios_dir)
    engine = GenerationEngine(scenario, tmp_path)
    try:
        engine._initialize()
        generator = engine.activity_generator
        user = scenario.environment.users[0]
        client, server = scenario.environment.systems
        opened = engine.start_time + timedelta(minutes=10)
        with generation_seed_scope(scenario.generation_seed):
            reset_thread_rng()
            logon = (
                generator.generate_logon(user, client, engine.start_time + timedelta(minutes=1))
                if source_session
                else ""
            )
            uid = generator.generate_ssh_session(
                user=user,
                target_system=server,
                time=opened,
                source_ip=client.ip,
                source_system=client,
                source_port=50001,
                duration=120,
                orig_bytes=12345,
                resp_bytes=54321,
                emit_session_close=True,
                defer_session_close=deferred_close,
            )
            assert uid
            generator.finalize_ssh_session_lifecycles(opened + timedelta(minutes=5))
            if logon:
                generator.generate_logoff(user, client, opened + timedelta(minutes=10), logon)
    finally:
        engine._close_emitters()
    client_file = next(path for path in tmp_path.rglob("ecar.json") if "TEST-01." in str(path))
    server_file = next(path for path in tmp_path.rglob("ecar.json") if "SSH-TEST." in str(path))
    clients = [json.loads(line) for line in client_file.read_text().splitlines()]
    servers = [json.loads(line) for line in server_file.read_text().splitlines()]
    creates = [
        row
        for row in clients
        if row["object"] == "PROCESS"
        and row["action"] == "CREATE"
        and row["properties"]["image_path"] == "/usr/bin/ssh"
    ]
    history = "".join(path.read_text() for path in tmp_path.rglob("*.zsh_history"))
    logins = [
        row for row in servers if row["object"] == "USER_SESSION" and row["action"] == "LOGIN"
    ]
    assert len(logins) == 1
    assert not list(client_file.parent.glob("*.xml"))
    assert not list(client_file.parent.glob("syslog.log"))
    if not source_session:
        assert creates == []
        assert not history
        flows = [row for row in clients if row["object"] == "FLOW"]
        assert len(flows) == 1 and "actorID" not in flows[0]
        assert flows[0]["timestamp_ms"] < logins[0]["timestamp_ms"]
        return
    assert len(creates) == 1
    process = creates[0]
    identity = engine.state_manager.get_process_identity_by_object_id(process["objectID"])
    assert identity is not None and identity.credentials is not None
    account = generator.identity_directory.macos_account(user.username, client.hostname)
    assert identity.credentials.real_uid == identity.credentials.effective_uid == account.uid
    assert identity.credentials.real_gid == identity.credentials.effective_gid == account.gid
    assert identity.credentials.audit_uid is None
    assert identity.credentials.audit_session_id is None
    close = next(
        row
        for row in clients
        if row["objectID"] == process["objectID"] and row["action"] == "TERMINATE"
    )
    flows = [
        row
        for row in clients
        if row["object"] == "FLOW" and row.get("actorID") == process["objectID"]
    ]
    assert len(flows) == 1
    login = logins[0]
    assert (
        process["timestamp_ms"] < min(row["timestamp_ms"] for row in flows) < login["timestamp_ms"]
    )
    assert close["timestamp_ms"] >= (opened + timedelta(seconds=120)).timestamp() * 1000
    assert history.count("/usr/bin/ssh test_user@SSH-TEST") == 1


@pytest.mark.slow
@pytest.mark.parametrize("external_source", [False, True])
def test_mac_ssh_fresh_process_and_endpoint_filtering(
    tmp_path: Path, scenarios_dir: Path, external_source: bool
) -> None:
    import yaml

    scenario_path = tmp_path / "ssh.yaml"
    data = macos_ssh_scenario(scenarios_dir).model_dump(mode="json")
    if external_source:
        data["storyline"][1]["events"][0]["source_ip"] = "198.51.100.41"
    scenario_path.write_text(yaml.safe_dump(data))
    snapshots: list[dict[str, bytes]] = []
    for label, hash_seed, formats in [
        ("first", "7", ""),
        ("second", "31", ""),
        ("filtered", "13", "ecar"),
    ]:
        output = tmp_path / label
        args = [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            str(scenario_path),
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
            args.extend(["--formats", formats])
        result = subprocess.run(
            args,
            env=os.environ | {"PYTHONHASHSEED": hash_seed},
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        snapshots.append(deterministic_bundle_files(output))
    first, second, filtered = snapshots
    assert first == second
    assert {name: body for name, body in first.items() if name.endswith("/ecar.json")} == {
        name: body for name, body in filtered.items() if name.endswith("/ecar.json")
    }
    if not external_source:
        assert any(
            b"/usr/bin/ssh test_user@SSH-TEST" in body
            for name, body in first.items()
            if name.endswith(".zsh_history")
        )
