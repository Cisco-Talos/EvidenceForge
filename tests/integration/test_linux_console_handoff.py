# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Ordinary console login consumes a getty lifetime rather than forking login."""

from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.models.scenario import User
from tests.unit.test_sudo_logon_id_ownership import _SCENARIO_START, _sudo_generator


def test_console_login_executes_the_existing_getty_lifetime() -> None:
    generator, state, system = _sudo_generator()
    at = _SCENARIO_START + timedelta(minutes=10)
    getty_pid = generator.generate_system_process(
        system,
        _SCENARIO_START + timedelta(seconds=1),
        "/sbin/agetty",
        "/sbin/agetty --noclear tty1 linux",
        username="root",
        emit_linux_syslog=False,
    )
    before = state.get_process_identity(system.hostname, getty_pid)
    assert before is not None
    logon_id = generator.generate_logon(
        User(
            username="console-user",
            full_name="Console User",
            email="console-user@example.test",
            role="administrator",
        ),
        system,
        at,
        emit_network_evidence=False,
        allow_local_session_reuse=False,
    )
    session = state.get_session(logon_id)
    assert session is not None
    assert session.process_tree_root == getty_pid
    after = state.get_process_identity(system.hostname, getty_pid)
    assert after is not None
    assert after.image == "/bin/login"
    assert after.pid == before.pid and after.object_id == before.object_id
    assert after.started_at == before.started_at and after.parent_pid == before.parent_pid
    assert after.execution_ordinal == before.execution_ordinal + 1
    assert state.get_process_identity_at(system.hostname, getty_pid, before.started_at) == before
    events = [call.args[0] for call in generator.dispatcher.emitters["ecar"].emit.call_args_list]
    assert any(event.event_type == "process_exec" for event in events)
    assert not any(
        event.event_type == "process_create" and event.process.image == "/bin/login"
        for event in events
    )


def test_console_normal_logoff_owns_its_root_principal_login_process() -> None:
    generator, state, system = _sudo_generator()
    start = _SCENARIO_START + timedelta(minutes=10)
    getty_pid = generator.generate_system_process(
        system,
        _SCENARIO_START + timedelta(seconds=1),
        "/sbin/agetty",
        "/sbin/agetty --noclear tty1 linux",
        username="root",
        emit_linux_syslog=False,
    )
    user = User(
        username="console-user",
        full_name="Console User",
        email="console-user@example.test",
        role="administrator",
    )
    logon_id = generator.generate_logon(
        user,
        system,
        start,
        emit_network_evidence=False,
        allow_local_session_reuse=False,
    )
    generator.generate_logoff(user, system, start + timedelta(minutes=10), logon_id)
    assert state.get_process(system.hostname, getty_pid) is None
    events = [call.args[0] for call in generator.dispatcher.emitters["ecar"].emit.call_args_list]
    assert any(
        event.event_type == "process_terminate" and event.process.pid == getty_pid
        for event in events
    )


def test_concurrent_console_logins_cannot_reuse_one_getty() -> None:
    generator, state, system = _sudo_generator()
    pids = []
    for ordinal in (1, 2):
        pids.append(
            generator.generate_system_process(
                system,
                _SCENARIO_START + timedelta(seconds=ordinal),
                "/sbin/agetty",
                f"/sbin/agetty --noclear tty{ordinal} linux",
                username="root",
                emit_linux_syslog=False,
            )
        )
    roots = []
    for ordinal in (1, 2):
        user = User(
            username=f"console-{ordinal}",
            full_name="Console User",
            email=f"console-{ordinal}@example.test",
            role="administrator",
        )
        logon_id = generator.generate_logon(
            user,
            system,
            _SCENARIO_START + timedelta(minutes=10 + ordinal),
            emit_network_evidence=False,
            allow_local_session_reuse=False,
        )
        roots.append(state.get_session(logon_id).process_tree_root)
    assert roots == pids
    assert all(state.get_process(system.hostname, pid).image == "/bin/login" for pid in pids)


def test_console_shell_forks_from_replaced_login_not_from_stale_getty_image() -> None:
    generator, state, system = _sudo_generator()
    at = _SCENARIO_START + timedelta(minutes=10)
    getty_pid = generator.generate_system_process(
        system,
        _SCENARIO_START + timedelta(seconds=1),
        "/sbin/agetty",
        "/sbin/agetty --noclear tty1 linux",
        username="root",
        emit_linux_syslog=False,
    )
    user = User(
        username="console-user",
        full_name="Console User",
        email="console-user@example.test",
        role="administrator",
    )
    logon_id = generator.generate_logon(user, system, at, emit_network_evidence=False)
    pid = generator.ensure_linux_session_shell(
        user,
        system,
        logon_id,
        at,
        at + timedelta(seconds=30),
    )
    assert pid is not None and pid != getty_pid
    shell = state.get_process(system.hostname, pid)
    assert shell is not None and shell.parent_pid == getty_pid
    assert shell.username == user.username and shell.image == "/bin/bash"


def test_a_console_login_cannot_parent_another_users_session() -> None:
    generator, state, system = _sudo_generator()
    at = _SCENARIO_START + timedelta(minutes=10)
    getty_pid = generator.generate_system_process(
        system,
        _SCENARIO_START + timedelta(seconds=1),
        "/sbin/agetty",
        "/sbin/agetty --noclear tty1 linux",
        username="root",
        emit_linux_syslog=False,
    )
    owner = User(
        username="console-owner",
        full_name="Console Owner",
        email="console-owner@example.test",
        role="administrator",
    )
    generator.generate_logon(owner, system, at, emit_network_evidence=False)
    foreign = state.create_session(
        username="other-user",
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=at,
    )
    assert not generator._linux_parent_usable_for_child_at(
        system=system,
        parent_pid=getty_pid,
        time=at + timedelta(seconds=20),
        logon_id=foreign,
    )


def test_console_without_a_boot_getty_starts_one_before_exec() -> None:
    generator, state, system = _sudo_generator()
    user = User(
        username="console-user",
        full_name="Console User",
        email="console-user@example.test",
        role="administrator",
    )
    logon_id = generator.generate_logon(
        user,
        system,
        _SCENARIO_START + timedelta(minutes=10),
        emit_network_evidence=False,
        allow_local_session_reuse=False,
    )
    session = state.get_session(logon_id)
    assert session is not None
    login = state.get_process(system.hostname, session.process_tree_root)
    assert login is not None and login.image == "/bin/login"
    assert len(login.prior_executions) == 1
    getty = login.prior_executions[0]
    assert getty.image == "/sbin/agetty" and "tty1" in getty.command_line
    assert getty.started_at < login.executed_at < session.start_time
    assert getty.pid == login.pid


def test_linux_console_policy_rejects_duplicate_and_noncanonical_terminals() -> None:
    import pytest
    from pydantic import ValidationError

    from evidenceforge.config.schemas import LinuxConsolePolicy

    for terminals in (("tty1", "tty1"), ("pts/0",), ("tty0",), ("tty64",), ("tty01",)):
        with pytest.raises(ValidationError):
            LinuxConsolePolicy(
                terminals=terminals, getty_image="/sbin/agetty", login_image="/bin/login"
            )


def test_absent_legacy_console_policy_preserves_old_creation_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.generation.activity import system_processes

    monkeypatch.setattr(system_processes, "linux_console_policy", lambda: None)
    generator, state, system = _sudo_generator()
    getty_pid = generator.generate_system_process(
        system,
        _SCENARIO_START + timedelta(seconds=1),
        "/sbin/agetty",
        "/sbin/agetty --noclear tty1 linux",
        username="root",
        emit_linux_syslog=False,
    )
    user = User(
        username="console-user",
        full_name="Console User",
        email="console-user@example.test",
        role="administrator",
    )
    logon_id = generator.generate_logon(
        user,
        system,
        _SCENARIO_START + timedelta(minutes=10),
        emit_network_evidence=False,
    )
    session = state.get_session(logon_id)
    assert session is not None and session.process_tree_root != getty_pid
    assert state.get_process(system.hostname, getty_pid).image == "/sbin/agetty"
    login = state.get_process(system.hostname, session.process_tree_root)
    assert login is not None and login.parent_pid == getty_pid
    assert login.prior_executions == ()


def test_console_policy_overlay_is_frozen_and_isolated(tmp_path: Path) -> None:
    from evidenceforge.composition.compiler import build_management_effective_config
    from evidenceforge.config.provider import effective_config_scope
    from evidenceforge.generation.activity.system_processes import linux_console_policy
    from evidenceforge.validation.configuration import validate_config

    defaults = build_management_effective_config(tmp_path)
    path = tmp_path / ".eforge/config/activity/system_processes.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("linux_console:\n  terminals: [tty4, tty5]\n")
    selected = build_management_effective_config(tmp_path)
    with effective_config_scope(selected):
        assert not validate_config().errors
        assert linux_console_policy().terminals == ("tty4", "tty5")
        with effective_config_scope(defaults):
            assert linux_console_policy().terminals == tuple(f"tty{i}" for i in range(1, 7))
    path.write_text("linux_console:\n  terminals: [tty6]\n")
    with effective_config_scope(selected):
        assert linux_console_policy().terminals == ("tty4", "tty5")


def test_console_terminal_occupancy_survives_state_checkpoint() -> None:
    from evidenceforge.generation.actions.linux_console import plan_linux_console_login
    from evidenceforge.generation.activity.system_processes import linux_console_policy
    from evidenceforge.generation.state_manager import StateManager
    from tests.support.state_checkpoint import capture_complete_state, restore_complete_state

    generator, state, system = _sudo_generator()
    pids: list[int] = []
    for number in (1, 2):
        pids.append(
            generator.generate_system_process(
                system,
                _SCENARIO_START + timedelta(seconds=number),
                "/sbin/agetty",
                f"/sbin/agetty --noclear tty{number} linux",
                username="root",
                emit_linux_syslog=False,
            )
        )
    first = User(
        username="console-one",
        full_name="Console One",
        email="console-one@example.test",
        role="administrator",
    )
    generator.generate_logon(
        first,
        system,
        _SCENARIO_START + timedelta(minutes=10),
        emit_network_evidence=False,
    )
    restored = StateManager()
    restore_complete_state(restored, capture_complete_state(state))
    policy = linux_console_policy()
    assert policy is not None
    at = _SCENARIO_START + timedelta(minutes=20)
    expected = plan_linux_console_login(state, system, at, policy)
    actual = plan_linux_console_login(restored, system, at, policy)
    assert expected == actual
    assert actual.terminal == "tty2" and actual.existing_getty is not None
    assert actual.existing_getty.pid == pids[1]
    old = restored.get_process_identity(system.hostname, pids[0])
    assert old is not None and old.image == "/bin/login" and old.execution_ordinal == 1


@pytest.mark.slow
def test_console_active_exec_checkpoint_cli_is_byte_identical(
    tmp_path: Path, scenarios_dir: Path
) -> None:
    from tests.integration.test_checkpoint_smoke import (
        test_short_generation_checkpoint_suspension_and_resume,
    )

    test_short_generation_checkpoint_suspension_and_resume(
        tmp_path,
        scenarios_dir,
        target="default",
        start=None,
        macos=False,
        smb_server=None,
        ssh_client=False,
        macos_receiver=False,
        authored_close=False,
        linux_console=True,
    )


def test_gdm_workstation_authentication_does_not_consume_a_console_getty() -> None:
    generator, state, system = _sudo_generator()
    system = system.model_copy(update={"type": "workstation"})
    user = User(
        username="desktop-user",
        full_name="Desktop User",
        email="desktop-user@example.test",
        role="analyst",
    )
    generator.generate_logon(
        user,
        system,
        _SCENARIO_START + timedelta(minutes=10),
        emit_network_evidence=False,
    )
    assert all(
        process.image not in {"/sbin/agetty", "/bin/login"}
        for process in state.get_processes_on_system(system.hostname)
    )
    events = [call.args[0] for call in generator.dispatcher.emitters["ecar"].emit.call_args_list]
    assert any(
        event.syslog is not None and event.syslog.app_name == "gdm-password" for event in events
    )


def test_filtering_process_rows_does_not_prevent_canonical_getty_exec() -> None:
    generator, state, system = _sudo_generator()
    generator.dispatcher.emitters["ecar"].can_handle.return_value = False
    user = User(
        username="console-user",
        full_name="Console User",
        email="console-user@example.test",
        role="administrator",
    )
    logon_id = generator.generate_logon(
        user,
        system,
        _SCENARIO_START + timedelta(minutes=10),
        emit_network_evidence=False,
    )
    session = state.get_session(logon_id)
    assert session is not None
    login = state.get_process(system.hostname, session.process_tree_root)
    assert login is not None and login.image == "/bin/login" and login.execution_ordinal == 1
    assert login.prior_executions[0].pid == login.pid
    generator.dispatcher.emitters["ecar"].emit.assert_not_called()


def test_console_root_can_enter_exact_sudo_session_close_plan() -> None:
    generator, state, system = _sudo_generator()
    at = _SCENARIO_START + timedelta(minutes=10)
    user = User(
        username="console-user",
        full_name="Console User",
        email="console-user@example.test",
        role="administrator",
    )
    logon_id = generator.generate_logon(user, system, at, emit_network_evidence=False)
    session = state.get_session(logon_id)
    assert session is not None
    root = state.get_process(system.hostname, session.process_tree_root)
    assert root is not None and root.logon_id == "0x3e7"
    plans = generator._plan_linux_sudo_logoff_process_closes(
        system=system,
        session=session,
        processes=[root],
        base_logoff_time=at + timedelta(minutes=20),
        authoritative_end_plan=None,
    )
    assert len(plans) == 1 and plans[0].identity.pid == root.pid
    assert plans[0].identity.logon_id == "0x3e7"


@pytest.mark.parametrize("failure_mode", ["none", "fail-before", "lost-return"])
def test_strict_sudo_console_logoff_preserves_root_token_and_closes_login(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
) -> None:
    from tests.unit.test_sudo_logon_id_ownership import (
        _generate_sudo_processes,
        _strict_sudo_generator,
    )

    engine, generator, state, system = _strict_sudo_generator(tmp_path, exact_ecar=True)
    system = system.model_copy(update={"type": "server"})
    user = next(user for user in engine.scenario.environment.users if user.username == "linux_user")
    at = engine.start_time + timedelta(minutes=15)
    logon_id = generator.generate_logon(
        user,
        system,
        at,
        emit_network_evidence=False,
        allow_local_session_reuse=False,
    )
    session = state.get_session(logon_id)
    assert session is not None
    root_pid = session.process_tree_root
    root = state.get_process_identity(system.hostname, root_pid)
    assert root is not None and root.logon_id in {"", "0x3e7"}
    root_logon_id = root.logon_id
    sudo_pid, _, _, _ = _generate_sudo_processes(
        generator,
        system,
        sudo_time=at + timedelta(minutes=1),
        sudo_user=user.username,
        tty="tty1",
        lifecycle_group_id="console-sudo-close",
    )
    assert sudo_pid > 0
    assert state.get_process(system.hostname, sudo_pid).logon_id == logon_id
    if failure_mode == "none":
        generator.generate_logoff(user, system, at + timedelta(minutes=5), logon_id)
    else:
        import json

        from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

        original = ExternalSortedLineWriter._commit_exact_row
        attempts = 0

        def inject(
            writer: ExternalSortedLineWriter, key: object, digest: str, frozen: object
        ) -> None:
            nonlocal attempts
            row = (
                json.loads(frozen)
                if writer.output_path.name == "ecar.json" and type(frozen) is str
                else {}
            )
            if row.get("objectID") == root.object_id and row.get("action") == "TERMINATE":
                attempts += 1
                if attempts == 1:
                    if failure_mode == "lost-return":
                        original(writer, key, digest, frozen)
                    raise OSError("injected exact console root close")
            original(writer, key, digest, frozen)

        monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", inject)
        with pytest.raises(OSError, match="exact console root close"):
            generator.generate_logoff(user, system, at + timedelta(minutes=5), logon_id)
        assert generator.linux_sudo_logoff_journal_census().pending == 1
        generator.finalize_linux_sudo_logoffs()
        assert attempts == 2
        assert generator.linux_sudo_logoff_journal_census().pending == 0
        assert generator.dispatcher.exact_projection_recovery_census().unresolved_recoveries == 0

    assert state.get_session(logon_id) is None
    assert state.get_process(system.hostname, root_pid) is None
    assert state.get_process_identity(system.hostname, root_pid).logon_id == root_logon_id
    assert state.get_process_identity(system.hostname, root_pid) == root


@pytest.mark.parametrize(
    "wrong",
    [
        "principal",
        "auth",
        "initial_image",
        "argv",
        "ordinal",
        "root_pointer",
        "host",
        "session_kind",
    ],
)
def test_console_root_role_rejects_foreign_identity_or_session(wrong: str) -> None:
    from dataclasses import replace

    from evidenceforge.generation.actions.linux_console import console_session_root_matches

    generator, state, system = _sudo_generator()
    user = User(
        username="console-user",
        full_name="Console User",
        email="console-user@example.test",
        role="administrator",
    )
    logon_id = generator.generate_logon(
        user,
        system,
        _SCENARIO_START + timedelta(minutes=10),
        emit_network_evidence=False,
    )
    session = state.get_session(logon_id)
    assert session is not None
    identity = state.get_process_identity(system.hostname, session.process_tree_root)
    assert identity is not None and console_session_root_matches(identity, session)
    if wrong == "principal":
        identity = replace(identity, principal="other")
    elif wrong == "auth":
        identity = replace(identity, logon_id="0xother")
    elif wrong == "initial_image":
        identity = replace(identity, lifetime_image="/bin/bash")
    elif wrong == "argv":
        identity = replace(
            identity, arguments=("/bin/login", "--", "other"), command_line="/bin/login -- other"
        )
    elif wrong == "ordinal":
        identity = replace(identity, execution_ordinal=2)
    elif wrong == "root_pointer":
        session = replace(session, process_tree_root=identity.pid + 1)
    elif wrong == "host":
        session = replace(session, system="OTHER-LINUX")
    else:
        session = replace(session, session_kind="ssh")
    assert not console_session_root_matches(identity, session)
