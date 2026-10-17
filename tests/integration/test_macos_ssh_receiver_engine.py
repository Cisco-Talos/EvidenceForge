# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mixed-platform source clients use shared ownership with the internal Mac receiver."""

import json
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.actions.ssh_session import SshSessionActionBundle, SshSessionRequest
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.rng import generation_seed_scope, reset_thread_rng
from tests.support.macos_ssh import macos_ssh_scenario


@pytest.mark.slow
@pytest.mark.parametrize("platform", ["macos", "linux", "windows"])
@pytest.mark.parametrize("collection", ["all", "network"])
@pytest.mark.parametrize("deferred", [False, True])
def test_macos_receiver_implicit_client_real_engine(
    scenarios_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    collection: str,
    deferred: bool,
) -> None:
    data = macos_ssh_scenario(scenarios_dir).model_dump(mode="json")
    data["environment"]["systems"][1].update(
        os="macOS 26", architecture="arm64", type="workstation", assigned_user="test_user"
    )
    if platform != "macos":
        data["environment"]["systems"][0].update(
            os="Ubuntu 24.04" if platform == "linux" else "Windows 11", architecture="x64"
        )
    data["storyline"] = []
    if collection == "network":
        data["output"]["logs"] = [{"format": "zeek"}]
    scenario = Scenario.model_validate(data)
    engine = GenerationEngine(scenario, tmp_path)
    clients: list[tuple[int, str] | None] = []
    try:
        engine._initialize()
        generator = engine.activity_generator
        user = scenario.environment.users[0]
        source, target = scenario.environment.systems
        create_client = generator.ensure_ssh_client_process

        def capture(**kwargs: object) -> tuple[int, str] | None:
            client = create_client(**kwargs)
            clients.append(client)
            return client

        monkeypatch.setattr(generator, "ensure_ssh_client_process", capture)
        with generation_seed_scope(scenario.generation_seed):
            reset_thread_rng()
            source_logon = generator.generate_logon(
                user, source, engine.start_time + timedelta(minutes=1)
            )
            request = SshSessionRequest(
                user=user,
                target_system=target,
                source_ip=source.ip,
                source_system=source,
                time=engine.start_time + timedelta(minutes=10),
                source_port=50001,
                duration=120,
                emit_session_close=True,
                defer_session_close=deferred,
            )
            uid, logon = SshSessionActionBundle(request, generator).execute_with_identity()
            assert uid and logon and len(clients) == 1 and clients[0] is not None
            client_pid, client_image = clients[0]
            assert engine.state_manager.get_process(source.hostname, client_pid) is None
            assert engine.state_manager.get_session(source_logon) is not None
            assert (engine.state_manager.get_session(logon) is not None) == deferred
            generator.finalize_ssh_session_lifecycles(request.time + timedelta(minutes=5))
            assert engine.state_manager.get_session(logon) is None
            assert generator.ssh_close_journal_census().total_pending == 0
            assert (
                engine.state_manager.get_process(target.hostname, 1).credentials.effective_uid == 0
            )
    finally:
        engine._close_emitters()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    if collection == "network":
        assert rows == []
        return
    client_rows = [
        row
        for row in rows
        if row.get("hostname") == source.hostname
        and row.get("object") == "PROCESS"
        and row["properties"].get("image_path") == client_image
    ]
    creates = [row for row in client_rows if row["action"] == "CREATE"]
    deletes = [row for row in client_rows if row["action"] == "TERMINATE"]
    assert len(creates) == len(deletes) == 1
    assert creates[0]["objectID"] == deletes[0]["objectID"]
    sessions = [
        row
        for row in rows
        if row.get("hostname") == target.hostname and row.get("object") == "USER_SESSION"
    ]
    assert [row["action"] for row in sessions] == ["LOGIN", "LOGOUT"]
    flow = [
        row
        for row in rows
        if row.get("hostname") == target.hostname and row.get("object") == "FLOW"
    ]
    assert flow and max(row["timestamp_ms"] for row in flow) < sessions[0]["timestamp_ms"]
    assert creates[0]["timestamp_ms"] < sessions[0]["timestamp_ms"] < deletes[0]["timestamp_ms"]
    if platform == "macos":
        history = "".join(path.read_text() for path in tmp_path.rglob("*.zsh_history"))
        assert "ssh " in history
    assert not any("SSH-TEST" in str(path) for path in tmp_path.rglob("syslog.log"))


@pytest.mark.slow
def test_authored_mac_receiver_command_uses_remote_shell_and_closes(tmp_path: Path) -> None:
    from evidenceforge.utils import load_yaml

    scenario = Scenario.model_validate(
        load_yaml(Path("scenarios/macos-ssh-workstations/scenario.yaml"))
    )
    engine = GenerationEngine(scenario, tmp_path)
    engine.generate()
    path = next(path for path in tmp_path.rglob("ecar.json") if "MAC-02." in str(path))
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    command = next(
        row
        for row in rows
        if row["action"] == "CREATE"
        and row.get("properties", {}).get("command_line") == "/usr/bin/id"
    )
    assert command["properties"]["parent_image_path"] == "/bin/zsh"
    sessions = [
        row
        for row in rows
        if row["object"] == "USER_SESSION"
        and row.get("properties", {}).get("logon_id") == command["properties"]["logon_id"]
    ]
    assert [row["action"] for row in sessions] == ["LOGIN", "LOGOUT"]
    assert all(row["properties"]["session_type"] == "ssh" for row in sessions)
    assert sessions[0]["timestamp_ms"] < command["timestamp_ms"] < sessions[1]["timestamp_ms"]
    assert any(
        row["objectID"] == command["objectID"] and row["action"] == "TERMINATE" for row in rows
    )
    assert not list(path.parent.glob("syslog.log"))
