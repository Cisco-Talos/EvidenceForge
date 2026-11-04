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
from evidenceforge.models.scenario import LogonEventSpec, ProcessEventSpec
from tests.support.macos_ssh import MACOS_NATIVE_QUERY_COMMANDS
from tests.unit.test_macos_command_exit_outcomes import _engine


@pytest.mark.parametrize("native", [False, True], ids=["filtered", "collected"])
@pytest.mark.parametrize("launch", ["local", "ssh"])
def test_every_accepted_ordinary_command_has_one_native_exec(
    tmp_path: Path, scenarios_dir: Path, native: bool, launch: str
) -> None:
    expected: list[tuple[ProcessIdentity, tuple[str, ...]]] = []
    with _engine(
        tmp_path, scenarios_dir, native=native, chronological=launch == "local"
    ) as fixture:
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
    command_records = [
        record
        for record in records
        if any(
            process.pid == record.event.exec.target.audit_token.pid
            for process, _arguments in expected
        )
    ]
    assert len(command_records) == len(expected) == len(MACOS_NATIVE_QUERY_COMMANDS)
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
        del raw["terminal_startups"]
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
    with _engine(tmp_path, scenarios_dir, chronological=True) as fixture:
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
        ("/bin/zsh 'a'b", ("/bin/zsh", "ab")),
        ('/bin/zsh --execute="SELECT 1"', ("/bin/zsh", "--execute=SELECT 1")),
        ("/bin/zsh --label='a; b'", ("/bin/zsh", "--label=a; b")),
        ('/bin/zsh --label=""', ("/bin/zsh", "--label=")),
        ('/bin/zsh --label="prefix"suffix', ("/bin/zsh", "--label=prefixsuffix")),
        ('/bin/zsh --label="safe"$HOME', None),
        ('/bin/zsh --label="safe"$(id)', None),
        ('/bin/zsh --label="safe"`id`', None),
        ('/bin/zsh --label="safe"*', None),
        ('/bin/zsh --label="safe";id', None),
        ('/bin/zsh --label="safe"|cat', None),
        ('/bin/zsh --label="safe">output', None),
        ("/bin/zsh --label='literal'$HOME", None),
        ('/bin/zsh --label="unterminated', None),
        ("/bin/zsh\nid", None),
        ("/bin/zsh bad\0word", None),
    ],
)
def test_literal_exec_arguments_preserve_quoted_input_without_expansion(
    command: str, arguments: tuple[str, ...] | None
) -> None:
    assert literal_shell_child_arguments("/bin/zsh", command) == arguments


def test_mysql_option_value_quoting_uses_the_canonical_fork_exec_owner(
    tmp_path: Path, scenarios_dir: Path
) -> None:
    image = "/opt/homebrew/opt/mysql-client/bin/mysql"
    command = image + ' --host=db01.example.test --execute="SELECT 1"'
    with _engine(tmp_path, scenarios_dir) as fixture:
        engine, target, user, session = fixture
        pid = engine.activity_generator.generate_process(
            user,
            target,
            engine.start_time + timedelta(minutes=11),
            session.logon_id,
            image,
            command,
            parent_pid=session.session_shell_pid,
            require_exact_parent=True,
        )
        process = engine.state_manager.get_process_identity(target.hostname, pid)
        assert process is not None and process.execution_ordinal == 1
        assert process.initial_image == "/bin/zsh"
        assert process.arguments == (image, "--host=db01.example.test", "--execute=SELECT 1")
        binary = engine.dispatcher.resolve_loaded_process_binary_identity(process)
        assert binary.code_signature.entitlements == "absent"
        assert binary.code_signature.signing_id == (
            "mysql-55554944" + binary.mach_o_image.build_uuid.replace("-", "").lower()
        )
    records = [
        decode_endpoint_security_record(line)
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    assert any(
        row.event_type == 11 and row.event.fork.child.audit_token.pid == pid for row in records
    )
    assert (
        sum(row.event_type == 9 and row.event.exec.target.audit_token.pid == pid for row in records)
        == 1
    )


@pytest.mark.parametrize("authored", [False, True], ids=["network-owner-api", "authored"])
def test_gui_executable_started_from_ssh_keeps_its_shell_launch_chain(
    tmp_path: Path, scenarios_dir: Path, authored: bool
) -> None:
    image = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    with _engine(tmp_path, scenarios_dir) as (engine, target, user, session):
        assert session.session_kind == "ssh"
        at = engine.start_time + timedelta(minutes=11)
        command = shlex.join((image,))
        if authored:
            engine._record_storyline_logon(user, target, session.logon_id)
            result = engine._execute_typed_event(
                ProcessEventSpec(process_name=image, command_line=command, supplementary="none"),
                user,
                target,
                at,
                "Direct app executable from SSH",
                {"process"},
            )
            pid = result["pid"]
            assert result["native_process_model"] == "fork_exec"
        else:
            pid = engine.activity_generator.generate_process(
                user,
                target,
                at,
                session.logon_id,
                image,
                command,
                parent_pid=session.session_shell_pid,
            )
        process = engine.state_manager.get_process_identity(target.hostname, pid)
        assert process.execution_ordinal == 1 and process.initial_image == "/bin/zsh"
        assert process.parent_pid == session.session_shell_pid
        assert process.logon_id == session.logon_id and process.arguments == (image,)
    rows = [
        decode_endpoint_security_record(line)
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    targets = [
        row.event.exec.target
        for row in rows
        if row.event_type == 9 and row.event.exec.target.audit_token.pid == pid
    ]
    assert len(targets) == 1 and targets[0].executable.path == image


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
