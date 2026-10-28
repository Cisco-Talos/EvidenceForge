# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Accepted ordinary command executions must have matching native ES exec records."""

import shlex
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.activity.direct_exec import literal_shell_child_arguments
from evidenceforge.models.scenario import LogonEventSpec
from tests.support.macos_ssh import MACOS_NATIVE_QUERY_COMMANDS
from tests.unit.test_macos_command_exit_outcomes import _engine


@pytest.mark.parametrize("native", [False, True], ids=["filtered", "collected"])
@pytest.mark.parametrize("launch", ["local", "ssh"])
def test_every_accepted_ordinary_command_has_one_native_exec(
    tmp_path: Path, scenarios_dir: Path, native: bool, launch: str
) -> None:
    expected: list[tuple[ProcessIdentity, tuple[str, ...]]] = []
    with _engine(tmp_path, scenarios_dir, native=native) as fixture:
        engine, target, user, session = fixture
        generator = engine.activity_generator
        terminal: ProcessIdentity | None = None
        if launch == "local":
            engine._execute_typed_event(
                LogonEventSpec(logon_type=2),
                user,
                target,
                engine.start_time + timedelta(minutes=1),
                "Invented local login",
                {"logon"},
            )
            session = next(
                item
                for item in engine.state_manager.get_sessions_for_user(user.username)
                if item.system == target.hostname and item.session_kind == "interactive"
            )
            shell_pid = generator.ensure_macos_session_shell(
                user, target, session.logon_id, engine.start_time + timedelta(minutes=2)
            )
            assert shell_pid is not None
            terminal = engine.state_manager.get_process_identity(
                target.hostname, session.process_tree_root
            )
            assert terminal is not None
        for ordinal, command in enumerate(MACOS_NATIVE_QUERY_COMMANDS):
            arguments = tuple(shlex.split(command))
            at = engine.start_time + timedelta(minutes=11, seconds=ordinal * 20)
            pid = generator.generate_process(
                user,
                target,
                at,
                session.logon_id,
                arguments[0],
                command,
                parent_pid=session.session_shell_pid,
                require_exact_parent=True,
            )
            assert pid > 0, command
            process = engine.state_manager.get_process_identity(target.hostname, pid)
            assert process is not None and process.arguments == arguments, command
            assert process.execution_ordinal == 1, command
            expected.append((process, arguments))

    records = [
        record
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
        if (record := decode_endpoint_security_record(line)).event_type == 9
    ]
    if not native:
        assert not records
        return

    missing = [
        arguments[0]
        for process, arguments in expected
        if not any(
            record.event.exec.target.audit_token.pid == process.pid
            and record.event.exec.target.audit_token.pidversion == process.audit_pid_version
            for record in records
        )
    ]
    assert not missing, f"Accepted commands missing native ES exec: {missing}"
    assert len(records) == len(expected) == len(MACOS_NATIVE_QUERY_COMMANDS)
    for process, arguments in expected:
        matches = [
            record
            for record in records
            if record.event.exec.target.audit_token.pid == process.pid
            and record.event.exec.target.audit_token.pidversion == process.audit_pid_version
        ]
        assert len(matches) == 1, arguments
        record = matches[0]
        assert record.event.exec.target.executable.path == arguments[0]
        assert tuple(record.event.exec.args) == arguments
        assert record.process.audit_token.pid == process.pid
        assert record.process.audit_token.pidversion != process.audit_pid_version
        assert datetime.fromisoformat(record.time) == process.execution_started_at
        if terminal is not None:
            assert record.event.exec.target.responsible_audit_token.pid == terminal.pid
            assert (
                record.event.exec.target.responsible_audit_token.pidversion
                == terminal.audit_pid_version
            )


def test_legacy_terminal_profile_preserves_unknown_responsibility(
    tmp_path: Path, scenarios_dir: Path
) -> None:
    with _engine(tmp_path, scenarios_dir) as fixture:
        engine, target, user, _session = fixture
        provider = engine.macos_execution_metadata
        raw = provider.profile.model_dump()
        del raw["terminal_responsibility"]
        provider.profile = type(provider.profile).model_validate(raw)
        at = engine.start_time + timedelta(minutes=1)
        logon = engine.activity_generator.generate_logon(
            user, target, at, allow_local_session_reuse=False
        )
        shell_pid = engine.activity_generator.ensure_macos_session_shell(
            user, target, logon, at + timedelta(minutes=1)
        )
        assert shell_pid is not None
        shell = engine.state_manager.get_process_identity(target.hostname, shell_pid)
        assert shell.responsibility is None
        assert provider.profile.terminal_responsibility is None


def test_local_logoff_uses_current_exec_without_rewriting_lifetime_birth(
    tmp_path: Path, scenarios_dir: Path
) -> None:
    with _engine(tmp_path, scenarios_dir) as fixture:
        engine, target, user, _ssh_session = fixture
        generator = engine.activity_generator
        logon = generator.generate_logon(
            user, target, engine.start_time + timedelta(minutes=1), allow_local_session_reuse=False
        )
        shell_pid = generator.ensure_macos_session_shell(
            user, target, logon, engine.start_time + timedelta(minutes=2)
        )
        assert shell_pid is not None
        pid = generator.generate_process(
            user,
            target,
            engine.start_time + timedelta(minutes=11),
            logon,
            "/bin/bash",
            "/bin/bash",
            parent_pid=shell_pid,
            require_exact_parent=True,
        )
        process = engine.state_manager.get_process_identity(target.hostname, pid)
        assert process.execution_ordinal == 1
        registry = generator._lifecycle_authority.registry
        before = registry.get_process(process.object_id)
        assert before.identity.image == "/bin/zsh"
        assert before.current_view.image == "/bin/bash"
        generator.generate_logoff(user, target, engine.start_time + timedelta(minutes=15), logon)
        assert engine.state_manager.get_process(target.hostname, pid) is None
        closed = registry.get_process(process.object_id)
        assert closed.closed_at is not None
        assert closed.identity == before.identity
        assert closed.current_view.image == "/bin/bash"
        assert closed.current_view.execution_ordinal == 1


@pytest.mark.parametrize(
    "command,arguments",
    [
        ("/bin/zsh -c 'id; groups'", ("/bin/zsh", "-c", "id; groups")),
        ('/bin/zsh -c "id; groups"', ("/bin/zsh", "-c", "id; groups")),
        ("/bin/zsh -c 'printf %s $HOME'", ("/bin/zsh", "-c", "printf %s $HOME")),
        ("/bin/zsh -c id; groups", None),
        ('/bin/zsh -c "$HOME"', None),
        ("/bin/zsh -c $(id)", None),
        ("/bin/zsh -c `id`", None),
        ("/bin/zsh *", None),
        ("/bin/zsh id | cat", None),
        ("/bin/zsh id > output", None),
        ("/bin/zsh 'a'b", None),
        ("/bin/zsh\nid", None),
        ("/bin/zsh bad\0word", None),
    ],
)
def test_literal_exec_arguments_preserve_quoted_input_without_expansion(
    command: str, arguments: tuple[str, ...] | None
) -> None:
    assert literal_shell_child_arguments("/bin/zsh", command) == arguments


def test_quoted_shell_invocation_has_its_own_exec_without_inventing_inner_processes(
    tmp_path: Path, scenarios_dir: Path
) -> None:
    with _engine(tmp_path, scenarios_dir) as fixture:
        engine, target, user, session = fixture
        pid = engine.activity_generator.generate_process(
            user,
            target,
            engine.start_time + timedelta(minutes=11),
            session.logon_id,
            "/bin/zsh",
            "/bin/zsh -c 'id; groups'",
            parent_pid=session.session_shell_pid,
            require_exact_parent=True,
        )
        process = engine.state_manager.get_process_identity(target.hostname, pid)
        assert process.execution_ordinal == 1
        assert process.arguments == ("/bin/zsh", "-c", "id; groups")
        assert not any(
            item.parent_pid == pid
            for item in engine.state_manager.get_processes_for_session(session.logon_id)
        )
    executions = [
        record
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
        if (record := decode_endpoint_security_record(line)).event_type == 9
    ]
    assert len(executions) == 1
    assert executions[0].event.exec.target.audit_token.pid == pid
    assert executions[0].event.exec.args == ("/bin/zsh", "-c", "id; groups")


def test_explicit_argv_does_not_require_reinterpreting_display_quoting(
    tmp_path: Path, scenarios_dir: Path
) -> None:
    arguments = ("/usr/bin/id", "it's literal", "$HOME", ";", "")
    with _engine(tmp_path, scenarios_dir) as fixture:
        engine, target, user, session = fixture
        pid = engine.activity_generator.generate_process(
            user,
            target,
            engine.start_time + timedelta(minutes=11),
            session.logon_id,
            arguments[0],
            shlex.join(arguments),
            parent_pid=session.session_shell_pid,
            require_exact_parent=True,
            arguments=arguments,
        )
        process = engine.state_manager.get_process_identity(target.hostname, pid)
        assert process.execution_ordinal == 1 and process.arguments == arguments
    executions = [
        record
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
        if (record := decode_endpoint_security_record(line)).event_type == 9
    ]
    assert len(executions) == 1
    assert executions[0].event.exec.args == arguments
