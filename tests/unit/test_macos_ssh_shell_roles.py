# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""The canonical Mac login-shell exec installs one durable session role atomically."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.actions.macos_ssh_receiver import MacosSshReceiverStartup
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_audit_sessions import _START
from tests.unit.test_macos_ssh_process_graph import _bootstrap
from tests.unit.test_macos_ssh_startup import _request


@pytest.mark.parametrize("collected", [False, True])
@pytest.mark.parametrize("shell", ["macos-zsh", "macos-bash"])
def test_shell_exec_installs_session_role_and_restores_existing_checkpoint_field(
    tmp_path: Path, collected: bool, shell: str
) -> None:
    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path, collected)
    startup = MacosSshReceiverStartup(
        _request(receiver, shell), state=state, dispatcher=dispatcher, host=host
    )
    session = state.get_session(receiver.logon_id)
    for _ in range(10):
        startup.advance()
        assert session.session_shell_pid is None
    result = startup.advance()
    assert session.session_shell_pid == result.shell.pid
    assert session.transport_pid == session.process_tree_root == receiver.pid
    assert session.session_user_manager_pid is None
    assert session.session_winlogon_pid is None
    assert session.explorer_pid is None
    assert not session.windows_shell_bootstrapped
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_session(receiver.logon_id).session_shell_pid == result.shell.pid
    assert restored.get_process_identity(host.hostname, result.shell.pid) == result.shell
    emitter.close()


@pytest.mark.parametrize(
    "damage",
    [
        "existing_shell",
        "wrong_platform",
        "wrong_session_kind",
        "wrong_protocol",
        "missing_origin",
        "wrong_uid",
        "wrong_gid",
        "late_shell",
        "early_close",
        "wrong_transport",
    ],
)
def test_shell_binding_rejects_changed_session_owner_without_committing_exec(
    tmp_path: Path, damage: str
) -> None:
    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path, False)
    startup = MacosSshReceiverStartup(
        _request(receiver), state=state, dispatcher=dispatcher, host=host
    )
    for _ in range(10):
        startup.advance()
    before = startup._shell
    session = state.get_session(receiver.logon_id)
    if damage == "existing_shell":
        session.session_shell_pid = receiver.pid
    elif damage == "wrong_platform":
        state._pid_os[host.hostname] = "linux"
    elif damage == "wrong_session_kind":
        session.session_kind = "interactive"
    elif damage == "wrong_protocol":
        session.auth_protocol = "kerberos"
    elif damage == "missing_origin":
        session.audit_origin = None
    elif damage == "wrong_uid":
        session.effective_uid = 502
    elif damage == "wrong_gid":
        session.effective_gid = 21
    elif damage == "late_shell":
        session.source_ready_time = _START + timedelta(seconds=10)
    elif damage == "early_close":
        session.network_close_time = _START + timedelta(seconds=10)
    else:
        session.transport_pid = before.pid
    version = state.materialization_version
    with pytest.raises(StateError):
        startup.advance()
    assert state.materialization_version == version
    assert state.get_process_identity(host.hostname, before.pid) == before
    emitter.close()


def test_shell_binding_requires_the_same_builder_execution_and_rejects_duplicate_roles(
    tmp_path: Path,
) -> None:
    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path, False)
    startup = MacosSshReceiverStartup(
        _request(receiver), state=state, dispatcher=dispatcher, host=host
    )
    for _ in range(10):
        startup.advance()
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        startup._shell,
        image="/bin/zsh",
        command_line="-zsh",
        executed_at=_START + timedelta(seconds=11),
    )
    session = state.get_session_identity(receiver.logon_id)
    other = state.begin_action_cohort_materialization()
    with pytest.raises(StateError, match="same-cohort execution"):
        other.bind_macos_ssh_session_shell(session, shell=after)
    builder.bind_macos_ssh_session_shell(session, shell=after)
    with pytest.raises(StateError, match="repeats"):
        builder.bind_macos_ssh_session_shell(session, shell=after)
    plan = builder.seal()
    patch = plan.live_session_process_role_patches[0]
    changed = replace(patch, after=replace(patch.after, transport_pid=after.pid))
    tampered = replace(plan, _live_session_process_roles=(changed,))
    with pytest.raises(StateError):
        state.materialize_action_cohort(tampered)
    assert state.get_session(receiver.logon_id).session_shell_pid is None
    state.materialize_action_cohort(plan)
    assert state.get_session(receiver.logon_id).session_shell_pid == after.pid
    emitter.close()


def test_shell_binding_revalidates_session_roles_after_preparation(tmp_path: Path) -> None:
    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path, False)
    startup = MacosSshReceiverStartup(
        _request(receiver), state=state, dispatcher=dispatcher, host=host
    )
    for _ in range(10):
        startup.advance()
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        startup._shell,
        image="/bin/zsh",
        command_line="-zsh",
        executed_at=_START + timedelta(seconds=11),
    )
    builder.bind_macos_ssh_session_shell(state.get_session_identity(receiver.logon_id), shell=after)
    plan = builder.seal()
    session = state.get_session(receiver.logon_id)
    session.session_shell_pid = receiver.pid
    with pytest.raises(StateError):
        state.materialize_action_cohort(plan)
    assert session.session_shell_pid == receiver.pid
    assert state.get_process_identity(host.hostname, after.pid) == startup._shell
    emitter.close()


def test_shell_role_survives_lost_sink_return_without_repeating_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path)
    startup = MacosSshReceiverStartup(
        _request(receiver), state=state, dispatcher=dispatcher, host=host
    )
    for _ in range(10):
        startup.advance()
    original = ExternalSortedLineWriter._commit_exact_row

    failed = False

    def lose_return(writer: ExternalSortedLineWriter, *args: object) -> None:
        nonlocal failed
        original(writer, *args)
        if not failed:
            failed = True
            raise RuntimeError("injected shell publication lost return")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lose_return)
    with pytest.raises(RuntimeError, match="shell publication lost return"):
        startup.advance()
    assert startup.result is None
    session = state.get_session(receiver.logon_id)
    assert session.session_shell_pid == startup._shell.pid
    committed = state.get_process_identity(host.hostname, session.session_shell_pid)
    assert committed.execution_ordinal == 1
    version = state.materialization_version
    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", original)
    assert startup.advance().shell == committed
    assert state.materialization_version == version
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    lines = [line for path in tmp_path.rglob("ecar.json") for line in path.read_text().splitlines()]
    assert len(lines) == 11


def test_shell_role_and_exec_roll_back_together_on_state_commit_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path, False)
    startup = MacosSshReceiverStartup(
        _request(receiver), state=state, dispatcher=dispatcher, host=host
    )
    for _ in range(10):
        startup.advance()
    before = startup._shell
    original = StateManager._commit_action_cohort_live_session_process_roles

    def fail_after_roles(manager: StateManager, patch: object) -> None:
        original(manager, patch)
        raise RuntimeError("injected role commit failure")

    monkeypatch.setattr(
        StateManager, "_commit_action_cohort_live_session_process_roles", fail_after_roles
    )
    with pytest.raises(RuntimeError, match="role commit failure"):
        startup.advance()
    assert state.get_session(receiver.logon_id).session_shell_pid is None
    assert state.get_process_identity(host.hostname, before.pid) == before
    monkeypatch.setattr(StateManager, "_commit_action_cohort_live_session_process_roles", original)
    assert startup.advance().shell.pid == before.pid
    emitter.close()


@pytest.mark.parametrize("missing", [False, True])
def test_shell_role_requires_its_exact_session_in_the_source_occurrence(
    tmp_path: Path, missing: bool
) -> None:
    from evidenceforge.generation.actions.posix_process import process_exec_occurrence
    from evidenceforge.models.exceptions import EventContractError
    from tests.unit.test_process_exit_projection import _prepare

    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path, False)
    startup = MacosSshReceiverStartup(
        _request(receiver), state=state, dispatcher=dispatcher, host=host
    )
    for _ in range(10):
        startup.advance()
    before = startup._shell
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        before,
        image="/bin/zsh",
        command_line="-zsh",
        executed_at=_START + timedelta(seconds=11),
    )
    session = state.get_session_identity(receiver.logon_id)
    builder.bind_macos_ssh_session_shell(session, shell=after)
    event = process_exec_occurrence(
        host=host,
        before=before,
        after=after,
        integrity_level="Medium",
        session=None if missing else replace(session, principal="another-user"),
    )
    with pytest.raises(EventContractError):
        _prepare(
            dispatcher, builder.seal(), event, exact=True, root=f"process-exec:{after.execution_id}"
        )
    assert state.get_session(receiver.logon_id).session_shell_pid is None
    assert state.get_process_identity(host.hostname, before.pid) == before
    emitter.close()
