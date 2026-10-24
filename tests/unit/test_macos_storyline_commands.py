# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Authored Mac shell commands keep execution, completion and history together."""

import json
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import LogonEventSpec, ProcessEventSpec, Scenario
from tests.unit.test_macos_foundations import _TIME, _system, _user


def _engine(tmp_path: Path) -> GenerationEngine:
    scenario = Scenario.model_validate(
        {
            "version": "1.0",
            "name": "mac-command-contract",
            "description": "Mac commands",
            "environment": {
                "description": "One Mac",
                "users": [_user().model_dump()],
                "systems": [_system().model_dump()],
            },
            "time_window": {"start": _TIME, "duration": "2h"},
            "baseline_activity": {"description": "Minimal", "intensity": "low", "variation": "low"},
            "output": {
                "logs": [{"format": "ecar"}, {"format": "zsh_history"}],
                "destination": str(tmp_path),
            },
        }
    )
    engine = GenerationEngine(scenario, tmp_path)
    engine._initialize()
    engine._execute_typed_event(
        LogonEventSpec(logon_type=2), _user(), _system(), _TIME, "Interactive login", {"logon"}
    )
    return engine


def test_mac_discovery_sequence_executes_every_command_and_submits_history(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    commands = [
        "/usr/bin/id",
        "/usr/bin/sw_vers",
        "/sbin/ifconfig -a",
        "/bin/ps aux",
        "/usr/bin/dscl . -list /Users",
    ]
    results = []
    try:
        for index, command in enumerate(commands):
            result = engine._execute_typed_event(
                ProcessEventSpec(process_name=command.split()[0], command_line=command),
                _user(),
                _system(),
                _TIME + timedelta(minutes=2, seconds=index * 20),
                "Explicit interactive discovery",
                {"process"},
            )
            results.append(result)
        engine._flush_story_process_terminations(release_time=_TIME + timedelta(minutes=10))
    finally:
        engine._close_emitters()

    assert all(result is not None and result.get("pid", 0) > 0 for result in results), results
    history = list(tmp_path.rglob("*.zsh_history"))
    assert len(history) == 1
    rows = history[0].read_text().splitlines()
    assert [row.split(";", 1)[1] for row in rows] == commands
    ecar_files = list(tmp_path.rglob("ecar.json"))
    records = [json.loads(line) for path in ecar_files for line in path.read_text().splitlines()]
    creates = {
        row["pid"]: row
        for row in records
        if row.get("object") == "PROCESS" and row.get("action") == "CREATE"
    }
    closes = {
        row["pid"]: row
        for row in records
        if row.get("object") == "PROCESS" and row.get("action") == "TERMINATE"
    }
    for result in results:
        pid = result["pid"]
        assert pid in creates and pid in closes
        assert 0 < closes[pid]["timestamp_ms"] - creates[pid]["timestamp_ms"] < 50000


@pytest.mark.parametrize("returned_pid", [0, -1])
def test_rejected_launch_does_not_record_a_success_or_history(
    tmp_path: Path, returned_pid: int
) -> None:
    engine = _engine(tmp_path)
    try:
        with patch.object(engine.activity_generator, "generate_process", return_value=returned_pid):
            result = engine._execute_typed_event(
                ProcessEventSpec(process_name="/usr/bin/id", process_ref="rejected"),
                _user(),
                _system(),
                _TIME + timedelta(minutes=2),
                "Rejected command",
                {"process"},
            )
    finally:
        engine._close_emitters()
    assert result.get("skipped_reason") == "process_launch_unavailable"
    assert "pid" not in result
    assert not list(tmp_path.rglob("*.zsh_history"))


def test_first_local_command_waits_for_new_session_shell(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    try:
        result = engine._execute_typed_event(
            ProcessEventSpec(process_name="/usr/bin/id"),
            _user(),
            _system(),
            _TIME + timedelta(milliseconds=500),
            "First local command",
            {"process"},
        )
        assert result.get("pid", 0) > 0
        assert result["time"] > _TIME + timedelta(milliseconds=500)
    finally:
        engine._close_emitters()
    assert any("/usr/bin/id" in path.read_text() for path in tmp_path.rglob("*.zsh_history"))


def test_unknown_foreground_command_keeps_its_shell_until_explicit_release(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    try:
        first = engine._execute_typed_event(
            ProcessEventSpec(
                process_name="/usr/local/bin/kubectl",
                command_line="/usr/local/bin/kubectl get pods --watch",
            ),
            _user(),
            _system(),
            _TIME + timedelta(minutes=2),
            "Watch",
            {"process"},
        )
        second = engine._execute_typed_event(
            ProcessEventSpec(process_name="/usr/bin/id"),
            _user(),
            _system(),
            _TIME + timedelta(minutes=2, seconds=10),
            "Occupied shell",
            {"process"},
        )
        assert first.get("pid", 0) > 0
        assert second.get("skipped_reason") == "foreground_shell_unavailable"
        assert "pid" not in second
        engine._flush_story_process_terminations(release_time=_TIME + timedelta(minutes=10))
        assert engine.state_manager.get_process(_system().hostname, first["pid"]) is not None
    finally:
        engine._close_emitters()
    rows = [
        line for path in tmp_path.rglob("*.zsh_history") for line in path.read_text().splitlines()
    ]
    assert len(rows) == 1 and "--watch" in rows[0]


def test_authored_command_uses_free_time_before_later_baseline_booking(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    try:
        generator = engine.activity_generator
        session = engine.state_manager.get_sessions_for_user(_user().username)[0]
        shell = generator.ensure_macos_session_shell(
            _user(), _system(), session.logon_id, _TIME + timedelta(minutes=2)
        )
        pid = generator.generate_process(
            _user(),
            _system(),
            _TIME + timedelta(minutes=30),
            session.logon_id,
            "/usr/bin/id",
            "/usr/bin/id",
            parent_pid=shell,
        )
        assert pid > 0
        result = engine._execute_typed_event(
            ProcessEventSpec(process_name="/usr/bin/id"),
            _user(),
            _system(),
            _TIME + timedelta(minutes=5),
            "Earlier authored command",
            {"process"},
        )
        assert result.get("pid", 0) > 0
        assert result["time"] < _TIME + timedelta(minutes=6)
    finally:
        engine._close_emitters()


@pytest.mark.parametrize("native_mode", ["absent", "visible", "filtered"])
def test_ssh_shell_commands_own_real_forks_and_history(tmp_path: Path, native_mode: str) -> None:
    from tests.unit.test_macos_installed_provisioning import _scenario

    scenario = _scenario()
    system = scenario.environment.systems[0]
    user = scenario.environment.users[0]
    system.services = ["ssh"]
    scenario.output.logs = [{"format": "ecar"}, {"format": "zsh_history"}]
    native = native_mode != "absent"
    if native:
        scenario.output.logs.append({"format": "macos_endpoint_security"})
    if native_mode == "filtered":
        from evidenceforge.models.scenario import SourceObservationOverride

        scenario.environment.observation_overrides = [
            SourceObservationOverride(
                source_instance="macos_endpoint_security:mac-01", enabled=False
            )
        ]
    engine = GenerationEngine(scenario, tmp_path, generation_seed=328)
    try:
        engine._initialize()
        generator = engine.activity_generator
        generator.generate_ssh_session(
            user,
            system,
            engine.start_time + timedelta(minutes=10),
            source_ip="192.0.2.200",
            duration=300,
            emit_session_close=True,
            defer_session_close=True,
        )
        continuation = generator._pending_ssh_session_closures[0]
        engine._record_storyline_logon(user, system, continuation.plan.logon_id)
        commands = [
            "/usr/bin/id",
            "/usr/bin/sw_vers",
            "/bin/ps aux",
            '/usr/bin/find /Users/alex/Documents -maxdepth 2 -type f -name "*.pdf"',
        ]
        results = [
            engine._execute_typed_event(
                ProcessEventSpec(process_name=command.split()[0], command_line=command),
                user,
                system,
                engine.start_time + timedelta(minutes=11, seconds=index * 20),
                "SSH discovery",
                {"process"},
            )
            for index, command in enumerate(commands)
        ]
        for result in results:
            assert result.get("pid", 0) > 0, result
        generator.finalize_ssh_session_lifecycles(engine.end_time)
    finally:
        engine._close_emitters()
    history = list(tmp_path.rglob("*.zsh_history"))
    assert len(history) == 1
    assert [row.split(";", 1)[1] for row in history[0].read_text().splitlines()] == commands
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    for result, command in zip(results, commands, strict=True):
        process = [
            row
            for row in rows
            if row.get("pid") == result["pid"] and row.get("object") == "PROCESS"
        ]
        assert [row["action"] for row in process] == ["CREATE", "MODIFY", "TERMINATE"]
        assert process[0]["properties"]["image_path"] == "/bin/zsh"
        assert process[1]["properties"]["image_path"] == command.split()[0]
    paths = list(tmp_path.rglob("macos_endpoint_security.ndjson"))
    assert len(paths) == int(native_mode == "visible")
    if native_mode == "visible":
        records = [json.loads(line) for line in paths[0].read_text().splitlines()]
        assert len(records) == 7
        assert all(row["event_type"] == 11 for row in records)
        submissions = {
            line.split(";", 1)[1]: int(line.split(":", 2)[1])
            for line in history[0].read_text().splitlines()
        }
        for result, command in zip(results, commands, strict=True):
            fork = next(
                row
                for row in records
                if row["event"]["fork"]["child"]["audit_token"][5] == result["pid"]
            )
            assert submissions[command] <= datetime.fromisoformat(fork["time"]).timestamp()


@pytest.mark.parametrize("after_write", [False, True])
def test_command_native_write_recovery_does_not_repeat_fork_exec_or_counters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_write: bool
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
    from tests.unit.test_macos_installed_provisioning import _scenario

    scenario = _scenario()
    system, user = scenario.environment.systems[0], scenario.environment.users[0]
    system.services = ["ssh"]
    scenario.output.logs = [{"format": "ecar"}, {"format": "macos_endpoint_security"}]
    engine = GenerationEngine(scenario, tmp_path, generation_seed=328)
    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def fail_once(writer: ExternalSortedLineWriter, key: tuple, digest: str, row: object) -> None:
        nonlocal attempts
        if writer.output_path.name == "macos_endpoint_security.ndjson":
            attempts += 1
            if attempts == 1:
                if after_write:
                    original(writer, key, digest, row)
                raise RuntimeError("invented command native write failure")
        original(writer, key, digest, row)

    try:
        engine._initialize()
        generator = engine.activity_generator
        generator.generate_ssh_session(
            user,
            system,
            engine.start_time + timedelta(minutes=10),
            source_ip="192.0.2.200",
            duration=300,
            emit_session_close=True,
            defer_session_close=True,
        )
        session = engine.state_manager.get_session(
            generator._pending_ssh_session_closures[0].plan.logon_id
        )
        with monkeypatch.context() as scoped:
            scoped.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail_once)
            with pytest.raises(
                RuntimeError, match="invented command native write failure"
            ) as caught:
                generator.generate_process(
                    user,
                    system,
                    engine.start_time + timedelta(minutes=11),
                    session.logon_id,
                    "/usr/bin/id",
                    "/usr/bin/id",
                    parent_pid=session.session_shell_pid,
                    from_storyline=True,
                )
            state_version = engine.state_manager.materialization_version
            collector = engine.dispatcher.es_collectors.connection("mac-01:macos_endpoint_security")
            engine.dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
            assert engine.state_manager.materialization_version == state_version
            assert (
                engine.dispatcher.es_collectors.connection(collector.source_instance) == collector
            )
        engine.dispatcher.assert_exact_projection_recoveries_drained()
    finally:
        engine._close_emitters()
    native = [
        json.loads(line)
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    assert len(native) == 4 and attempts == 2
    commands = [
        process
        for process in engine.state_manager.get_processes_for_session(session.logon_id)
        if process.image == "/usr/bin/id"
    ]
    assert len(commands) == 1 and commands[0].execution_ordinal == 1
