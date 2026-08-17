# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Authenticated live-session process-role transitions for State action cohorts."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

import pytest

import evidenceforge.generation.state_manager as state_manager_module
from evidenceforge.events.identity import SessionIdentity
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.generation.state_manager import (
    ActionCohortLiveSessionProcessRolesState,
    ActionCohortMaterializationBuilder,
    ActionCohortMaterializationPlan,
    ProcessMaterializationPlan,
    StateManager,
)
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 17, 15, 0, tzinfo=UTC)
_HOST = "WS-01"


@dataclass(frozen=True, slots=True)
class _ShellPlans:
    winlogon: ProcessMaterializationPlan | None
    userinit: ProcessMaterializationPlan
    explorer: ProcessMaterializationPlan
    caller: ProcessMaterializationPlan


def _live_session(
    manager: StateManager,
    *,
    hostname: str = _HOST,
    username: str = "analyst",
    logon_type: int = 2,
    session_kind: str = "interactive",
) -> SessionIdentity:
    manager.set_current_time(_START - timedelta(minutes=5))
    logon_id = manager.create_session(
        username,
        hostname,
        logon_type,
        "-",
        start_time=_START - timedelta(minutes=5),
        session_kind=session_kind,
    )
    manager.set_current_time(_START)
    identity = manager.get_session_identity(logon_id)
    assert identity is not None
    return identity


def _stage_shell(
    builder: ActionCohortMaterializationBuilder,
    target: SessionIdentity,
    *,
    hostname: str | None = None,
    username: str | None = None,
    logon_id: str | None = None,
    live_winlogon_pid: int | None = None,
    os_category: str = "windows",
    require_session: bool | None = None,
    fixed_pids: tuple[int, int, int, int] | None = None,
) -> _ShellPlans:
    process_host = hostname or target.hostname
    process_username = username or target.principal
    process_logon_id = logon_id or target.logon_id
    session_required = (
        process_host == target.hostname and process_logon_id == target.logon_id
        if require_session is None
        else require_session
    )
    planned_pids = fixed_pids or (None, None, None, None)
    winlogon = None
    if live_winlogon_pid is None:
        winlogon = builder.plan_process(
            system=process_host,
            parent_pid=4,
            image=r"C:\Windows\System32\winlogon.exe",
            command_line="winlogon.exe",
            username="SYSTEM",
            integrity_level="System",
            os_category=os_category,
            logon_id="0x3e7",
            start_time=_START + timedelta(milliseconds=100),
            fixed_pid=planned_pids[0],
        )
        winlogon_pid = winlogon.identity.pid
    else:
        winlogon_pid = live_winlogon_pid
    userinit = builder.plan_process(
        system=process_host,
        parent_pid=winlogon_pid,
        image=r"C:\Windows\System32\userinit.exe",
        command_line="userinit.exe",
        username=process_username,
        integrity_level="Medium",
        os_category=os_category,
        logon_id=process_logon_id,
        start_time=_START + timedelta(milliseconds=250),
        fixed_pid=planned_pids[1],
        require_session=session_required,
        parent_plan=winlogon,
    )
    explorer = builder.plan_process(
        system=process_host,
        parent_pid=userinit.identity.pid,
        image=r"C:\Windows\explorer.exe",
        command_line="explorer.exe",
        username=process_username,
        integrity_level="Medium",
        os_category=os_category,
        logon_id=process_logon_id,
        start_time=_START + timedelta(milliseconds=500),
        fixed_pid=planned_pids[2],
        require_session=session_required,
        parent_plan=userinit,
    )
    caller = builder.plan_process(
        system=process_host,
        parent_pid=explorer.identity.pid,
        image=r"C:\Windows\System32\runas.exe",
        command_line=r"runas.exe /netonly /user:EXAMPLE\admin cmd.exe",
        username=process_username,
        integrity_level="Medium",
        os_category=os_category,
        logon_id=process_logon_id,
        start_time=_START + timedelta(seconds=1),
        fixed_pid=planned_pids[3],
        require_session=session_required,
        parent_plan=explorer,
    )
    return _ShellPlans(
        winlogon=winlogon,
        userinit=userinit,
        explorer=explorer,
        caller=caller,
    )


def _bind_shell(
    builder: ActionCohortMaterializationBuilder,
    target: SessionIdentity,
    shell: _ShellPlans,
) -> None:
    builder.bind_live_windows_session_shell(
        target,
        winlogon_plan=shell.winlogon,
        explorer_plan=shell.explorer,
        process_tree_root_plan=shell.winlogon,
    )


def _live_shell_plan(
    manager: StateManager,
    target: SessionIdentity,
) -> tuple[ActionCohortMaterializationPlan, _ShellPlans]:
    builder = manager.begin_action_cohort_materialization()
    shell = _stage_shell(builder, target)
    _bind_shell(builder, target, shell)
    builder.terminate_process(
        shell.userinit,
        end_time=_START + timedelta(seconds=2),
        parent_activity_time=_START + timedelta(seconds=2),
    )
    builder.terminate_process(
        shell.caller,
        end_time=_START + timedelta(seconds=4),
        parent_activity_time=_START + timedelta(seconds=4),
    )
    return builder.seal(), shell


def test_live_windows_shell_roles_commit_exact_once_and_preserve_unrelated_roles() -> None:
    manager = StateManager()
    target = _live_session(manager)
    active = manager.get_session(target.logon_id)
    assert active is not None
    active.transport_pid = 101
    active.session_shell_pid = 102
    active.session_user_manager_pid = 103
    before = ActionCohortLiveSessionProcessRolesState(
        transport_pid=101,
        session_shell_pid=102,
        session_user_manager_pid=103,
    )
    digest = manager.materialization_digest()
    version = manager.materialization_version

    plan, shell = _live_shell_plan(manager, target)
    patch = plan.live_session_process_role_patches[0]

    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert patch.target == target
    assert patch.before == before
    assert patch.after == replace(
        before,
        session_winlogon_pid=shell.winlogon.identity.pid,
        explorer_pid=shell.explorer.identity.pid,
        initial_explorer_pid=shell.explorer.identity.pid,
        process_tree_root=shell.winlogon.identity.pid,
        windows_shell_bootstrapped=True,
    )
    assert manager.authenticates_action_cohort_plan(plan)
    with manager.prepared_action_cohort_materialization(plan):
        pass
    assert manager.materialization_digest() == digest

    result = manager.materialize_action_cohort(plan)

    active = manager.get_session(target.logon_id)
    assert active is not None
    assert result.prior_version == version
    assert result.committed_version == version + 1
    assert manager.materialization_version == version + 1
    assert active.transport_pid == 101
    assert active.session_shell_pid == 102
    assert active.session_user_manager_pid == 103
    assert active.session_winlogon_pid == shell.winlogon.identity.pid
    assert active.process_tree_root == shell.winlogon.identity.pid
    assert active.explorer_pid == shell.explorer.identity.pid
    assert active.initial_explorer_pid == shell.explorer.identity.pid
    assert active.windows_shell_bootstrapped is True
    assert manager.get_process(_HOST, shell.winlogon.identity.pid) is not None
    assert manager.get_process(_HOST, shell.explorer.identity.pid) is not None
    assert manager.get_process(_HOST, shell.userinit.identity.pid) is None
    assert manager.get_process(_HOST, shell.caller.identity.pid) is None


def test_live_windows_shell_roles_reuse_exact_retained_winlogon_without_rebinding_root() -> None:
    manager = StateManager()
    target = _live_session(manager)
    manager.set_current_time(_START - timedelta(seconds=1))
    winlogon_pid = manager.create_process(
        _HOST,
        4,
        r"C:\Windows\System32\winlogon.exe",
        "winlogon.exe",
        "SYSTEM",
        "System",
        logon_id="0x3e7",
    )
    active = manager.get_session(target.logon_id)
    assert active is not None
    active.session_winlogon_pid = winlogon_pid
    active.process_tree_root = winlogon_pid
    manager.set_current_time(_START)
    version = manager.materialization_version
    builder = manager.begin_action_cohort_materialization()
    shell = _stage_shell(builder, target, live_winlogon_pid=winlogon_pid)
    _bind_shell(builder, target, shell)
    builder.terminate_process(shell.userinit, end_time=_START + timedelta(seconds=2))
    builder.terminate_process(shell.caller, end_time=_START + timedelta(seconds=4))

    plan = builder.seal()
    patch = plan.live_session_process_role_patches[0]
    assert patch.winlogon_plan is None
    assert patch.process_tree_root_plan is None
    manager.materialize_action_cohort(plan)

    active = manager.get_session(target.logon_id)
    assert active is not None
    assert manager.materialization_version == version + 1
    assert active.session_winlogon_pid == winlogon_pid
    assert active.process_tree_root == winlogon_pid
    assert active.explorer_pid == shell.explorer.identity.pid
    assert active.initial_explorer_pid == shell.explorer.identity.pid


def test_live_windows_shell_role_builder_rejects_foreign_cross_owner_and_overwrite() -> None:
    manager = StateManager()
    target = _live_session(manager)
    digest = manager.materialization_digest()
    first = manager.begin_action_cohort_materialization()
    shell = _stage_shell(first, target)
    foreign_builder = manager.begin_action_cohort_materialization()

    with pytest.raises(StateError, match="same-cohort process plan"):
        foreign_builder.bind_live_windows_session_shell(
            target,
            winlogon_plan=shell.winlogon,
            explorer_plan=shell.explorer,
            process_tree_root_plan=shell.winlogon,
        )
    assert manager.materialization_digest() == digest
    foreign_builder.cancel()
    first.cancel()

    cross_host = manager.begin_action_cohort_materialization()
    cross_host_shell = _stage_shell(cross_host, target, hostname="WS-02")
    with pytest.raises(StateError, match="Explorer identity is incompatible"):
        _bind_shell(cross_host, target, cross_host_shell)
    assert manager.materialization_digest() == digest
    cross_host.cancel()

    other = _live_session(manager, username="other")
    post_other_digest = manager.materialization_digest()
    cross_logon = manager.begin_action_cohort_materialization()
    cross_logon_shell = _stage_shell(
        cross_logon,
        other,
        username=other.principal,
        logon_id=other.logon_id,
    )
    with pytest.raises(StateError, match="Explorer identity is incompatible"):
        _bind_shell(cross_logon, target, cross_logon_shell)
    assert manager.materialization_digest() == post_other_digest
    cross_logon.cancel()

    active = manager.get_session(target.logon_id)
    assert active is not None
    active.explorer_pid = 7777
    overwrite_digest = manager.materialization_digest()
    overwrite = manager.begin_action_cohort_materialization()
    overwrite_shell = _stage_shell(overwrite, target)
    with pytest.raises(StateError, match="overwrite a live session Explorer role"):
        _bind_shell(overwrite, target, overwrite_shell)
    assert manager.materialization_digest() == overwrite_digest
    overwrite.cancel()


def test_live_windows_shell_role_rejects_non_desktop_duplicate_close_and_terminalization() -> None:
    manager = StateManager()
    network = _live_session(
        manager,
        logon_type=3,
        session_kind="network",
    )
    digest = manager.materialization_digest()
    non_desktop = manager.begin_action_cohort_materialization()
    non_desktop_shell = _stage_shell(non_desktop, network)
    with pytest.raises(StateError, match="desktop-owning session"):
        _bind_shell(non_desktop, network, non_desktop_shell)
    assert manager.materialization_digest() == digest
    non_desktop.cancel()

    desktop = _live_session(manager, username="desktop")
    desktop_digest = manager.materialization_digest()
    duplicate = manager.begin_action_cohort_materialization()
    duplicate_shell = _stage_shell(duplicate, desktop)
    _bind_shell(duplicate, desktop, duplicate_shell)
    with pytest.raises(StateError, match="repeats a live-session process-role patch"):
        _bind_shell(duplicate, desktop, duplicate_shell)
    assert manager.materialization_digest() == desktop_digest
    duplicate.cancel()

    closing = manager.begin_action_cohort_materialization()
    closing_shell = _stage_shell(closing, desktop)
    _bind_shell(closing, desktop, closing_shell)
    closing.terminate_process(
        closing_shell.explorer,
        end_time=_START + timedelta(seconds=3),
    )
    with pytest.raises(StateError, match="cannot close a staged live-session shell role"):
        closing.seal()
    assert manager.materialization_digest() == desktop_digest
    closing.cancel()

    terminalizing = manager.begin_action_cohort_materialization()
    terminalizing_shell = _stage_shell(terminalizing, desktop)
    _bind_shell(terminalizing, desktop, terminalizing_shell)
    terminalizing.terminalize_session(
        desktop,
        end_time=_START + timedelta(seconds=5),
    )
    with pytest.raises(StateError, match="cannot terminalize a live session"):
        terminalizing.seal()
    assert manager.materialization_digest() == desktop_digest
    terminalizing.cancel()

    retained_winlogon_pid = manager.create_process(
        _HOST,
        4,
        r"C:\Windows\System32\winlogon.exe",
        "winlogon.exe",
        "SYSTEM",
        "System",
        logon_id="0x3e7",
    )
    desktop_session = manager.get_session(desktop.logon_id)
    assert desktop_session is not None
    desktop_session.session_winlogon_pid = retained_winlogon_pid
    desktop_session.process_tree_root = retained_winlogon_pid
    retained_digest = manager.materialization_digest()
    retained_close = manager.begin_action_cohort_materialization()
    retained_shell = _stage_shell(
        retained_close,
        desktop,
        live_winlogon_pid=retained_winlogon_pid,
    )
    _bind_shell(retained_close, desktop, retained_shell)
    retained_identity = manager.get_process_identity(_HOST, retained_winlogon_pid)
    assert retained_identity is not None
    retained_close.terminate_process(
        retained_identity,
        end_time=_START + timedelta(seconds=3),
    )
    with pytest.raises(StateError, match="cannot close a live-session process role"):
        retained_close.seal()
    assert manager.materialization_digest() == retained_digest
    retained_close.cancel()


def test_live_windows_shell_role_rejects_parent_close_before_child_start_without_residue() -> None:
    manager = StateManager()
    target = _live_session(manager)
    digest = manager.materialization_digest()
    version = manager.materialization_version
    builder = manager.begin_action_cohort_materialization()
    shell = _stage_shell(builder, target)
    _bind_shell(builder, target, shell)
    builder.terminate_process(
        shell.userinit,
        end_time=_START + timedelta(milliseconds=300),
    )

    with pytest.raises(StateError, match="staged parent closes before its child starts"):
        builder.seal()

    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert manager.get_process(_HOST, shell.explorer.identity.pid) is None
    builder.cancel()


def test_live_windows_shell_role_rejects_historically_active_initial_explorer() -> None:
    manager = StateManager()
    target = _live_session(manager)
    manager.set_current_time(_START - timedelta(minutes=4))
    initial_pid = manager.create_process(
        _HOST,
        4,
        r"C:\Windows\explorer.exe",
        "explorer.exe",
        target.principal,
        "Medium",
        logon_id=target.logon_id,
    )
    active = manager.get_session(target.logon_id)
    assert active is not None
    active.initial_explorer_pid = initial_pid
    active.windows_shell_bootstrapped = True
    assert manager.end_process(
        _HOST,
        initial_pid,
        end_time=_START + timedelta(seconds=2),
    )
    manager.set_current_time(_START)
    replacement_start = _START + timedelta(milliseconds=500)
    assert manager.get_process(_HOST, initial_pid) is None
    assert manager.is_process_active_at(_HOST, initial_pid, replacement_start)
    digest = manager.materialization_digest()
    version = manager.materialization_version
    builder = manager.begin_action_cohort_materialization()
    shell = _stage_shell(builder, target)

    with pytest.raises(StateError, match="initial Explorer active at replacement start"):
        _bind_shell(builder, target, shell)

    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert active.initial_explorer_pid == initial_pid
    assert active.explorer_pid is None
    builder.cancel()


def test_live_windows_shell_role_requires_windows_namespace_and_valid_target_session() -> None:
    linux_manager = StateManager()
    linux_target = _live_session(linux_manager)
    linux_digest = linux_manager.materialization_digest()
    linux_version = linux_manager.materialization_version
    linux_builder = linux_manager.begin_action_cohort_materialization()
    linux_shell = _stage_shell(linux_builder, linux_target, os_category="linux")
    with pytest.raises(StateError, match="requires an exact Windows PID"):
        _bind_shell(linux_builder, linux_target, linux_shell)
    assert linux_manager.materialization_digest() == linux_digest
    assert linux_manager.materialization_version == linux_version
    linux_builder.cancel()

    pid_manager = StateManager()
    pid_target = _live_session(pid_manager)
    pid_digest = pid_manager.materialization_digest()
    pid_version = pid_manager.materialization_version
    pid_builder = pid_manager.begin_action_cohort_materialization()
    pid_shell = _stage_shell(
        pid_builder,
        pid_target,
        fixed_pids=(4001, 4005, 4009, 4013),
    )
    with pytest.raises(StateError, match="requires an exact Windows PID"):
        _bind_shell(pid_builder, pid_target, pid_shell)
    assert pid_manager.materialization_digest() == pid_digest
    assert pid_manager.materialization_version == pid_version
    pid_builder.cancel()

    deadline_manager = StateManager()
    deadline_target = _live_session(deadline_manager)
    assert deadline_manager.plan_session_end(
        deadline_target.logon_id,
        SessionEndPlan(
            canonical_end=_START + timedelta(milliseconds=200),
            authority="action_bundle",
        ),
    )
    deadline_digest = deadline_manager.materialization_digest()
    deadline_version = deadline_manager.materialization_version
    deadline_builder = deadline_manager.begin_action_cohort_materialization()
    deadline_shell = _stage_shell(
        deadline_builder,
        deadline_target,
        require_session=False,
    )
    with pytest.raises(StateError, match="target is not valid at userinit start"):
        _bind_shell(deadline_builder, deadline_target, deadline_shell)
    assert deadline_manager.materialization_digest() == deadline_digest
    assert deadline_manager.materialization_version == deadline_version
    deadline_builder.cancel()


def test_action_cohort_staged_role_owner_is_bijective_across_session_kinds() -> None:
    staged_manager = StateManager()
    staged_manager.set_current_time(_START)
    staged_digest = staged_manager.materialization_digest()
    staged_version = staged_manager.materialization_version
    staged = staged_manager.begin_action_cohort_materialization()
    first = staged.plan_session(
        username="first",
        system=_HOST,
        logon_type=2,
        source_ip="-",
        session_kind="interactive",
        start_time=_START,
    )
    second = staged.plan_session(
        username="second",
        system=_HOST,
        logon_type=2,
        source_ip="-",
        session_kind="interactive",
        start_time=_START,
    )
    shared_winlogon = staged.plan_process(
        system=_HOST,
        parent_pid=4,
        image=r"C:\Windows\System32\winlogon.exe",
        command_line="winlogon.exe",
        username="SYSTEM",
        integrity_level="System",
        os_category="windows",
        logon_id="0x3e7",
        start_time=_START + timedelta(milliseconds=100),
    )
    staged.bind_session_processes(
        first,
        winlogon_plan=shared_winlogon,
        process_tree_root_plan=shared_winlogon,
    )
    staged.bind_session_processes(
        second,
        winlogon_plan=shared_winlogon,
        process_tree_root_plan=shared_winlogon,
    )
    with pytest.raises(StateError, match="staged process role is bound to multiple sessions"):
        staged.seal()
    assert staged_manager.materialization_digest() == staged_digest
    assert staged_manager.materialization_version == staged_version
    staged.cancel()

    cross_manager = StateManager()
    live_target = _live_session(cross_manager)
    cross_digest = cross_manager.materialization_digest()
    cross_version = cross_manager.materialization_version
    cross = cross_manager.begin_action_cohort_materialization()
    new_session = cross.plan_session(
        username="other",
        system=_HOST,
        logon_type=2,
        source_ip="-",
        session_kind="interactive",
        start_time=_START,
    )
    live_shell = _stage_shell(cross, live_target)
    cross.bind_session_processes(
        new_session,
        winlogon_plan=live_shell.winlogon,
        process_tree_root_plan=live_shell.winlogon,
    )
    _bind_shell(cross, live_target, live_shell)
    with pytest.raises(StateError, match="staged process role is bound to multiple sessions"):
        cross.seal()
    assert cross_manager.materialization_digest() == cross_digest
    assert cross_manager.materialization_version == cross_version
    cross.cancel()

    pid_owner_manager = StateManager()
    first_live = _live_session(pid_owner_manager, username="first-live")
    second_live = _live_session(pid_owner_manager, username="second-live")
    first_active = pid_owner_manager.get_session(first_live.logon_id)
    second_active = pid_owner_manager.get_session(second_live.logon_id)
    assert first_active is not None
    assert second_active is not None
    first_active.transport_pid = 64
    second_active.transport_pid = 64
    pid_owner_digest = pid_owner_manager.materialization_digest()
    pid_owner_version = pid_owner_manager.materialization_version
    shared_pid = pid_owner_manager.begin_action_cohort_materialization()
    first_shell = _stage_shell(shared_pid, first_live)
    second_shell = _stage_shell(shared_pid, second_live)
    _bind_shell(shared_pid, first_live, first_shell)
    _bind_shell(shared_pid, second_live, second_shell)
    with pytest.raises(StateError, match="process-role PID is bound to multiple sessions"):
        shared_pid.seal()
    assert pid_owner_manager.materialization_digest() == pid_owner_digest
    assert pid_owner_manager.materialization_version == pid_owner_version
    shared_pid.cancel()


def test_live_windows_shell_role_copy_tamper_foreign_stale_and_cap_reject_without_residue() -> None:
    manager = StateManager()
    target = _live_session(manager)
    plan, _shell = _live_shell_plan(manager, target)
    patch = plan.live_session_process_role_patches[0]
    copied_patch = replace(patch)
    copied_reference = replace(patch.explorer_plan)
    copied_reference_patch = replace(patch, explorer_plan=copied_reference)
    tampered_patch = replace(
        patch,
        after=replace(patch.after, explorer_pid=patch.after.explorer_pid + 4),
    )
    candidates = (
        replace(plan, _live_session_process_roles=(copied_patch,)),
        replace(plan, _live_session_process_roles=(copied_reference_patch,)),
        replace(plan, _live_session_process_roles=(tampered_patch,)),
    )
    digest = manager.materialization_digest()
    version = manager.materialization_version

    for candidate in candidates:
        assert not manager.authenticates_action_cohort_plan(candidate)
        with pytest.raises(StateError):
            manager.materialize_action_cohort(candidate)
        assert manager.materialization_digest() == digest
        assert manager.materialization_version == version

    capped = replace(
        plan,
        _live_session_process_roles=(patch,)
        * (state_manager_module._MAX_ACTION_COHORT_LIVE_SESSION_PROCESS_ROLE_PATCHES + 1),
    )
    with pytest.raises(StateError, match="role patch limit exceeded"):
        manager.materialize_action_cohort(capped)
    assert manager.materialization_digest() == digest

    foreign = StateManager()
    foreign.set_current_time(_START)
    foreign_digest = foreign.materialization_digest()
    assert not foreign.authenticates_action_cohort_plan(plan)
    with pytest.raises(StateError):
        foreign.materialize_action_cohort(plan)
    assert foreign.materialization_digest() == foreign_digest

    manager.create_session(
        "other",
        "WS-03",
        3,
        "10.0.0.3",
        start_time=_START,
    )
    stale_digest = manager.materialization_digest()
    with pytest.raises(StateError, match="stale"):
        manager.materialize_action_cohort(plan)
    assert manager.materialization_digest() == stale_digest


def test_live_windows_shell_role_before_drift_and_late_thread_failure_are_atomic() -> None:
    drifted = StateManager()
    drifted_target = _live_session(drifted)
    drifted_plan, drifted_shell = _live_shell_plan(drifted, drifted_target)
    drifted_active = drifted.get_session(drifted_target.logon_id)
    assert drifted_active is not None
    drifted_active.session_winlogon_pid = 9090
    drift_digest = drifted.materialization_digest()
    drift_version = drifted.materialization_version

    with pytest.raises(StateError, match="before-state drifted"):
        drifted.materialize_action_cohort(drifted_plan)
    assert drifted.materialization_digest() == drift_digest
    assert drifted.materialization_version == drift_version
    assert drifted.get_process(_HOST, drifted_shell.explorer.identity.pid) is None

    manager = StateManager()
    target = _live_session(manager)
    plan, shell = _live_shell_plan(manager, target)
    digest = manager.materialization_digest()
    version = manager.materialization_version
    active = manager.get_session(target.logon_id)
    assert active is not None

    with manager.prepared_action_cohort_materialization(plan) as prepared:
        with ThreadPoolExecutor(max_workers=1) as executor:
            attempted = executor.submit(prepared.commit_no_fail)
            with pytest.raises(StateError, match="claiming thread"):
                attempted.result(timeout=2)
        assert manager.materialization_digest() == digest
        assert manager.materialization_version == version
        assert active.explorer_pid is None
        result = prepared.commit_no_fail()

    assert result.committed_version == version + 1
    assert active.explorer_pid == shell.explorer.identity.pid
    assert active.session_winlogon_pid == shell.winlogon.identity.pid


def test_live_windows_shell_role_cancel_retry_is_digest_neutral_and_deterministic() -> None:
    first = StateManager()
    first_target = _live_session(first)
    digest = first.materialization_digest()
    version = first.materialization_version
    cancelled = first.begin_action_cohort_materialization()
    cancelled_shell = _stage_shell(cancelled, first_target)
    _bind_shell(cancelled, first_target, cancelled_shell)
    cancelled.cancel()
    assert first.materialization_digest() == digest
    assert first.materialization_version == version
    with pytest.raises(StateError, match="cancelled"):
        cancelled.seal()

    retry, _retry_shell = _live_shell_plan(first, first_target)
    second = StateManager()
    second_target = _live_session(second)
    equivalent, _equivalent_shell = _live_shell_plan(second, second_target)
    assert retry.semantic_id == equivalent.semantic_id
    assert retry.live_session_process_role_patches[0].before == (
        equivalent.live_session_process_role_patches[0].before
    )
    assert retry.publication_token != equivalent.publication_token
