# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Authenticated StateManager action-cohort materialization tests."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

import evidenceforge.generation.state_manager as state_manager_module
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.generation.state_manager import (
    ActionCohortMaterializationPlan,
    ActionCohortSessionMetadataState,
    StateManager,
)
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 17, 14, 0, tzinfo=UTC)


def _windows_cohort(manager: StateManager) -> ActionCohortMaterializationPlan:
    builder = manager.begin_action_cohort_materialization()
    desktop = builder.plan_session(
        username="analyst",
        system="WS-01",
        logon_type=2,
        source_ip="127.0.0.1",
        session_kind="interactive",
        start_time=_START,
        logon_guid_required=True,
    )
    type9 = builder.plan_session(
        username="analyst",
        system="WS-01",
        logon_type=9,
        source_ip="127.0.0.1",
        session_kind="new_credentials",
        start_time=_START + timedelta(seconds=1),
        logon_guid_required=True,
    )
    winlogon = builder.plan_process(
        system="WS-01",
        parent_pid=4,
        image=r"C:\Windows\System32\winlogon.exe",
        command_line="winlogon.exe",
        username="SYSTEM",
        integrity_level="System",
        os_category="windows",
        start_time=_START + timedelta(seconds=1),
    )
    userinit = builder.plan_process(
        system="WS-01",
        parent_pid=winlogon.identity.pid,
        image=r"C:\Windows\System32\userinit.exe",
        command_line="userinit.exe",
        username="analyst",
        integrity_level="Medium",
        os_category="windows",
        logon_id=desktop.identity.logon_id,
        start_time=_START + timedelta(seconds=2),
        require_session=True,
        parent_plan=winlogon,
        session_plan=desktop,
    )
    explorer = builder.plan_process(
        system="WS-01",
        parent_pid=userinit.identity.pid,
        image=r"C:\Windows\explorer.exe",
        command_line="explorer.exe",
        username="analyst",
        integrity_level="Medium",
        os_category="windows",
        logon_id=desktop.identity.logon_id,
        start_time=_START + timedelta(seconds=3),
        require_session=True,
        parent_plan=userinit,
        session_plan=desktop,
    )
    caller = builder.plan_process(
        system="WS-01",
        parent_pid=explorer.identity.pid,
        image=r"C:\Windows\System32\runas.exe",
        command_line="runas.exe /netonly /user:EXAMPLE\\admin cmd.exe",
        username="analyst",
        integrity_level="Medium",
        os_category="windows",
        logon_id=desktop.identity.logon_id,
        start_time=_START + timedelta(seconds=4),
        require_session=True,
        parent_plan=explorer,
        session_plan=desktop,
    )
    builder.bind_session_processes(
        desktop,
        winlogon_plan=winlogon,
        explorer_plan=explorer,
        process_tree_root_plan=explorer,
    )
    builder.transition_session_metadata(
        desktop,
        ActionCohortSessionMetadataState(
            source_ready_time=_START + timedelta(seconds=3),
            closure_owned_by_bundle=True,
            login_occurrence_emitted=True,
            end_plan=SessionEndPlan(
                canonical_end=_START + timedelta(hours=8),
                authority="action_bundle",
            ),
        ),
    )
    builder.patch_session_activity(desktop, _START + timedelta(seconds=8))
    builder.patch_process_activity(explorer, _START + timedelta(seconds=8))
    builder.terminate_process(
        userinit,
        end_time=_START + timedelta(seconds=5),
        parent_activity_time=_START + timedelta(seconds=5),
    )
    builder.terminate_process(
        caller,
        end_time=_START + timedelta(seconds=8),
        parent_activity_time=_START + timedelta(seconds=8),
    )
    builder.terminalize_session(type9, end_time=_START + timedelta(seconds=9))
    return builder.seal()


def test_action_cohort_commits_two_sessions_process_tree_and_staged_closes_once() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    digest = manager.materialization_digest()
    version = manager.materialization_version

    plan = _windows_cohort(manager)

    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert manager.authenticates_action_cohort_plan(plan)
    manager.validate_action_cohort_materialization(plan)
    with manager.prepared_action_cohort_materialization(plan):
        pass
    assert manager.materialization_digest() == digest

    with manager.prepared_action_cohort_materialization(plan) as prepared:
        result = prepared.commit_no_fail()

    assert result.prior_version == version
    assert result.committed_version == version + 1
    assert manager.materialization_version == version + 1
    assert manager.state.current_time == _START + timedelta(seconds=9)
    assert result.semantic_id == plan.semantic_id
    desktop, type9 = plan.sessions
    active = manager.get_session(desktop.identity.logon_id)
    assert active is not None
    assert active.session_id > 0
    assert active.windows_shell_bootstrapped
    assert active.login_occurrence_emitted
    assert active.source_ready_time == _START + timedelta(seconds=3)
    assert manager.get_session(type9.identity.logon_id) is None
    assert manager.get_session_identity(type9.identity.logon_id) == type9.identity
    assert manager.get_session_end_time(type9.identity.logon_id) == _START + timedelta(seconds=9)
    userinit = plan.processes[1]
    caller = plan.processes[3]
    for closed in (userinit, caller):
        assert manager.get_process(closed.identity.hostname, closed.identity.pid) is None
        assert (
            manager.get_process_identity_by_object_id(closed.identity.object_id) == closed.identity
        )
        primary = closed.identity.primary_thread
        assert primary is not None
        assert (
            primary.hostname,
            primary.process_object_id,
            primary.tid,
        ) not in manager.state.running_threads
    assert userinit.identity.object_id not in manager._processes_by_object_id
    assert caller.identity.object_id not in manager._processes_by_object_id


def test_action_cohort_live_process_and_session_closes_are_one_state_transition() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    logon_id = manager.create_session(
        "operator",
        "linux01",
        2,
        "-",
        start_time=_START,
        session_kind="interactive",
    )
    parent_pid = manager.create_process(
        "linux01",
        0,
        "/usr/bin/bash",
        "bash",
        "operator",
        "Medium",
        logon_id=logon_id,
    )
    child_pid = manager.create_process(
        "linux01",
        parent_pid,
        "/usr/bin/id",
        "id",
        "operator",
        "Medium",
        logon_id=logon_id,
    )
    parent = manager.get_process_identity("linux01", parent_pid)
    child = manager.get_process_identity("linux01", child_pid)
    session = manager.get_session_identity(logon_id)
    assert parent is not None and child is not None and session is not None
    version = manager.materialization_version

    builder = manager.begin_action_cohort_materialization()
    builder.terminate_process(
        child,
        end_time=_START + timedelta(seconds=5),
        parent_activity_time=_START + timedelta(seconds=5),
    )
    builder.terminate_process(parent, end_time=_START + timedelta(seconds=6))
    builder.terminalize_session(session, end_time=_START + timedelta(seconds=7))
    plan = builder.seal()
    result = manager.materialize_action_cohort(plan)

    assert result.committed_version == version + 1
    assert manager.get_process("linux01", child_pid) is None
    assert manager.get_process("linux01", parent_pid) is None
    assert manager.get_session(logon_id) is None
    assert manager.get_session_identity(logon_id) == session


def test_action_cohort_cancel_is_idempotent_and_retry_is_deterministic() -> None:
    first = StateManager()
    first.set_current_time(_START)
    digest = first.materialization_digest()
    cancelled = first.begin_action_cohort_materialization()
    cancelled.plan_session(
        username="analyst",
        system="WS-01",
        logon_type=9,
        source_ip="127.0.0.1",
        session_kind="new_credentials",
        start_time=_START,
    )
    cancelled.cancel()
    cancelled.cancel()
    assert first.materialization_digest() == digest
    with pytest.raises(StateError, match="cancelled"):
        cancelled.seal()

    retry = _windows_cohort(first)
    second = StateManager()
    second.set_current_time(_START)
    equivalent = _windows_cohort(second)
    assert retry.semantic_id == equivalent.semantic_id
    assert [session.identity for session in retry.sessions] == [
        session.identity for session in equivalent.sessions
    ]
    assert [process.identity for process in retry.processes] == [
        process.identity for process in equivalent.processes
    ]
    assert len(retry.publication_token) == 64
    assert len(equivalent.publication_token) == 64
    assert retry.publication_token != equivalent.publication_token


def test_action_cohort_tamper_copy_foreign_and_stale_reject_without_mutation() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    plan = _windows_cohort(manager)
    copied_session = replace(plan.sessions[0])
    copied_nested = replace(plan, _sessions=(copied_session, *plan.sessions[1:]))
    tampered = replace(plan, _semantic_id="0" * 64)
    foreign = StateManager()
    foreign.set_current_time(_START)
    manager_digest = manager.materialization_digest()
    foreign_digest = foreign.materialization_digest()

    assert not manager.authenticates_action_cohort_plan(copied_nested)
    assert not manager.authenticates_action_cohort_plan(tampered)
    assert not foreign.authenticates_action_cohort_plan(plan)
    for candidate in (copied_nested, tampered):
        with pytest.raises(StateError):
            manager.materialize_action_cohort(candidate)
        assert manager.materialization_digest() == manager_digest
    with pytest.raises(StateError):
        foreign.materialize_action_cohort(plan)
    assert foreign.materialization_digest() == foreign_digest

    manager.create_session(
        "other",
        "WS-02",
        3,
        "10.0.0.2",
        start_time=_START,
    )
    stale_digest = manager.materialization_digest()
    with pytest.raises(StateError, match="stale"):
        manager.materialize_action_cohort(plan)
    assert manager.materialization_digest() == stale_digest


def test_action_cohort_authenticator_is_total_for_malformed_and_evil_objects() -> None:
    manager = StateManager()

    class Evil:
        def __repr__(self) -> str:
            raise AssertionError("repr must not execute")

    class Subclass(ActionCohortMaterializationPlan):
        pass

    assert not manager.authenticates_action_cohort_plan(Evil())
    assert not manager.authenticates_action_cohort_plan(object())
    assert not manager.authenticates_action_cohort_plan(Subclass.__new__(Subclass))
    manager.set_current_time(_START)
    plan = _windows_cohort(manager)
    malformed_nested = replace(plan, _sessions=(Evil(),))
    assert not manager.authenticates_action_cohort_plan(malformed_nested)


def test_same_cohort_session_and_role_process_close_leave_only_ended_retention() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    builder = manager.begin_action_cohort_materialization()
    session = builder.plan_session(
        username="operator",
        system="linux01",
        logon_type=2,
        source_ip="-",
        session_kind="interactive",
        start_time=_START,
    )
    shell = builder.plan_process(
        system="linux01",
        parent_pid=0,
        image="/usr/bin/bash",
        command_line="bash -l",
        username="operator",
        integrity_level="Medium",
        os_category="linux",
        logon_id=session.identity.logon_id,
        start_time=_START + timedelta(seconds=1),
        require_session=True,
        session_plan=session,
    )
    builder.bind_session_processes(
        session,
        shell_plan=shell,
        process_tree_root_plan=shell,
    )
    builder.terminate_process(shell, end_time=_START + timedelta(seconds=4))
    builder.terminalize_session(session, end_time=_START + timedelta(seconds=5))
    plan = builder.seal()

    manager.materialize_action_cohort(plan)

    assert manager.get_session(session.identity.logon_id) is None
    assert manager.get_process("linux01", shell.identity.pid) is None
    assert shell.identity.object_id not in manager._processes_by_object_id
    assert ("linux01", shell.identity.pid) not in manager._process_object_ids
    assert not manager.state.running_threads
    ended = manager._ended_sessions[session.identity.logon_id][0]
    assert ended.session_shell_pid is None
    assert ended.process_tree_root is None
    assert (
        manager._ended_sessions.deadline(session.identity.logon_id)
        == (_START + timedelta(hours=48, seconds=5)).timestamp()
    )
    assert session.identity.logon_id in manager._ended_sessions_by_username_end.keys_after(
        "operator", _START
    )
    assert manager.get_process_identity_by_object_id(shell.identity.object_id) == shell.identity
    primary = shell.identity.primary_thread
    assert primary is not None
    assert (
        manager._ended_threads.get((primary.hostname, primary.process_object_id, primary.tid))
        is not None
    )


def test_action_cohort_rejects_parent_first_close_and_retries_without_residue() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    digest = manager.materialization_digest()
    builder = manager.begin_action_cohort_materialization()
    parent = builder.plan_process(
        system="linux01",
        parent_pid=0,
        image="/usr/bin/bash",
        command_line="bash",
        username="operator",
        integrity_level="Medium",
        os_category="linux",
        start_time=_START,
    )
    child = builder.plan_process(
        system="linux01",
        parent_pid=parent.identity.pid,
        image="/usr/bin/id",
        command_line="id",
        username="operator",
        integrity_level="Medium",
        os_category="linux",
        start_time=_START + timedelta(seconds=1),
        parent_plan=parent,
    )
    builder.terminate_process(parent, end_time=_START + timedelta(seconds=5))
    builder.terminate_process(child, end_time=_START + timedelta(seconds=4))

    with pytest.raises(StateError, match="child-before-parent"):
        builder.seal()
    assert manager.materialization_digest() == digest

    retry = manager.begin_action_cohort_materialization()
    retry_parent = retry.plan_process(
        system="linux01",
        parent_pid=0,
        image="/usr/bin/bash",
        command_line="bash",
        username="operator",
        integrity_level="Medium",
        os_category="linux",
        start_time=_START,
    )
    retry_child = retry.plan_process(
        system="linux01",
        parent_pid=retry_parent.identity.pid,
        image="/usr/bin/id",
        command_line="id",
        username="operator",
        integrity_level="Medium",
        os_category="linux",
        start_time=_START + timedelta(seconds=1),
        parent_plan=retry_parent,
    )
    retry.terminate_process(retry_child, end_time=_START + timedelta(seconds=4))
    retry.terminate_process(retry_parent, end_time=_START + timedelta(seconds=5))
    manager.materialize_action_cohort(retry.seal())
    assert not manager.state.running_processes


def test_action_cohort_rejects_unclosed_session_process_and_post_close_activity() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    digest = manager.materialization_digest()
    builder = manager.begin_action_cohort_materialization()
    session = builder.plan_session(
        username="operator",
        system="linux01",
        logon_type=2,
        source_ip="-",
        start_time=_START,
    )
    process = builder.plan_process(
        system="linux01",
        parent_pid=0,
        image="/usr/bin/bash",
        command_line="bash",
        username="operator",
        integrity_level="Medium",
        os_category="linux",
        logon_id=session.identity.logon_id,
        start_time=_START + timedelta(seconds=1),
        require_session=True,
        session_plan=session,
    )
    builder.patch_process_activity(process, _START + timedelta(seconds=8))
    builder.terminate_process(process, end_time=_START + timedelta(seconds=5))
    builder.terminalize_session(session, end_time=_START + timedelta(seconds=6))

    with pytest.raises(StateError, match="activity follows process close"):
        builder.seal()
    assert manager.materialization_digest() == digest

    unclosed = manager.begin_action_cohort_materialization()
    unclosed_session = unclosed.plan_session(
        username="operator",
        system="linux01",
        logon_type=2,
        source_ip="-",
        start_time=_START,
    )
    unclosed.plan_process(
        system="linux01",
        parent_pid=0,
        image="/usr/bin/bash",
        command_line="bash",
        username="operator",
        integrity_level="Medium",
        os_category="linux",
        logon_id=unclosed_session.identity.logon_id,
        start_time=_START + timedelta(seconds=1),
        require_session=True,
        session_plan=unclosed_session,
    )
    unclosed.terminalize_session(unclosed_session, end_time=_START + timedelta(seconds=6))
    with pytest.raises(StateError, match="retains a live owned process"):
        unclosed.seal()
    assert manager.materialization_digest() == digest


def test_action_cohort_rejects_cross_host_roles_metadata_and_time_drift() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    builder = manager.begin_action_cohort_materialization()
    session = builder.plan_session(
        username="analyst",
        system="WS-01",
        logon_type=2,
        source_ip="-",
        start_time=_START,
    )
    foreign_process = builder.plan_process(
        system="WS-02",
        parent_pid=4,
        image=r"C:\Windows\explorer.exe",
        command_line="explorer.exe",
        username="analyst",
        integrity_level="Medium",
        os_category="windows",
        start_time=_START + timedelta(seconds=1),
    )
    builder.bind_session_processes(session, explorer_plan=foreign_process)
    digest = manager.materialization_digest()
    with pytest.raises(StateError, match="crosses host boundaries"):
        builder.seal()
    assert manager.materialization_digest() == digest

    live_logon = manager.create_session(
        "analyst",
        "WS-03",
        2,
        "-",
        start_time=_START,
    )
    live_identity = manager.get_session_identity(live_logon)
    assert live_identity is not None
    metadata = manager.begin_action_cohort_materialization()
    metadata.transition_session_metadata(
        live_identity,
        ActionCohortSessionMetadataState(
            source_ready_time=_START + timedelta(seconds=2),
        ),
    )
    metadata_plan = metadata.seal()
    active = manager.get_session(live_logon)
    assert active is not None
    active.network_close_time = _START + timedelta(seconds=10)
    drift_digest = manager.materialization_digest()
    with pytest.raises(StateError, match="before-state drifted"):
        manager.materialize_action_cohort(metadata_plan)
    assert manager.materialization_digest() == drift_digest

    manager.state.current_time = _START + timedelta(seconds=1)
    time_digest = manager.materialization_digest()
    with pytest.raises(StateError, match="State time changed"):
        manager.materialize_action_cohort(metadata_plan)
    assert manager.materialization_digest() == time_digest


def test_prepared_action_cohort_capability_releases_after_cancel_and_commit() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    plan = _windows_cohort(manager)
    digest = manager.materialization_digest()

    with manager.prepared_action_cohort_materialization(plan) as cancelled:
        assert not cancelled.committed
    with pytest.raises(StateError, match="no longer active"):
        cancelled.commit_no_fail()
    assert manager.materialization_digest() == digest

    with manager.prepared_action_cohort_materialization(plan) as committed:
        committed.commit_no_fail()
        assert committed.committed
        with pytest.raises(StateError, match="already committed"):
            committed.commit_no_fail()
    with pytest.raises(StateError, match="no longer active"):
        committed.commit_no_fail()


def test_prepared_action_cohort_rejects_foreign_thread_before_primitive_commit() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    plan = _windows_cohort(manager)
    digest = manager.materialization_digest()
    version = manager.materialization_version

    with manager.prepared_action_cohort_materialization(plan) as prepared:
        with ThreadPoolExecutor(max_workers=1) as executor:
            foreign_commit = executor.submit(prepared.commit_no_fail)
            with pytest.raises(StateError, match="claiming thread"):
                foreign_commit.result(timeout=2)

        assert not prepared.committed
        assert manager.materialization_digest() == digest
        assert manager.materialization_version == version
        result = prepared.commit_no_fail()

    assert prepared.committed
    assert result.prior_version == version
    assert result.committed_version == version + 1


def test_action_cohort_live_closes_reject_retained_activity_without_mutation() -> None:
    process_manager = StateManager()
    process_manager.set_current_time(_START)
    process_logon_id = process_manager.create_session(
        "operator",
        "linux01",
        2,
        "-",
        start_time=_START,
        session_kind="interactive",
    )
    process_pid = process_manager.create_process(
        "linux01",
        0,
        "/usr/bin/bash",
        "bash",
        "operator",
        "Medium",
        logon_id=process_logon_id,
    )
    process_identity = process_manager.get_process_identity("linux01", process_pid)
    assert process_identity is not None
    process_builder = process_manager.begin_action_cohort_materialization()
    process_builder.terminate_process(
        process_identity,
        end_time=_START + timedelta(seconds=5),
    )
    assert process_manager.update_process_activity_time(
        "linux01",
        process_pid,
        _START + timedelta(seconds=6),
    )
    process_digest = process_manager.materialization_digest()
    process_version = process_manager.materialization_version

    with pytest.raises(StateError, match="termination materialization precedes retained activity"):
        process_builder.seal()

    assert process_manager.materialization_digest() == process_digest
    assert process_manager.materialization_version == process_version
    assert process_manager.get_process("linux01", process_pid) is not None
    process_builder.cancel()

    session_manager = StateManager()
    session_manager.set_current_time(_START)
    session_logon_id = session_manager.create_session(
        "operator",
        "linux02",
        2,
        "-",
        start_time=_START,
        session_kind="interactive",
    )
    session_identity = session_manager.get_session_identity(session_logon_id)
    assert session_identity is not None
    session_builder = session_manager.begin_action_cohort_materialization()
    session_builder.terminalize_session(
        session_identity,
        end_time=_START + timedelta(seconds=5),
    )
    assert session_manager.update_session_activity_time(
        session_logon_id,
        _START + timedelta(seconds=6),
    )
    session_digest = session_manager.materialization_digest()
    session_version = session_manager.materialization_version

    with pytest.raises(StateError, match="session close precedes retained activity"):
        session_builder.seal()

    assert session_manager.materialization_digest() == session_digest
    assert session_manager.materialization_version == session_version
    assert session_manager.get_session(session_logon_id) is not None
    session_builder.cancel()


def test_action_cohort_rejects_copied_parent_before_allocator_use_and_retries() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    builder = manager.begin_action_cohort_materialization()
    parent = builder.plan_process(
        system="linux01",
        parent_pid=0,
        image="/usr/bin/bash",
        command_line="bash",
        username="operator",
        integrity_level="Medium",
        os_category="linux",
        start_time=_START,
    )
    digest = manager.materialization_digest()

    with pytest.raises(StateError, match="parent belongs to another builder"):
        builder.plan_process(
            system="linux01",
            parent_pid=parent.identity.pid,
            image="/usr/bin/id",
            command_line="id",
            username="operator",
            integrity_level="Medium",
            os_category="linux",
            start_time=_START + timedelta(seconds=1),
            parent_plan=replace(parent),
        )

    assert manager.materialization_digest() == digest
    child = builder.plan_process(
        system="linux01",
        parent_pid=parent.identity.pid,
        image="/usr/bin/id",
        command_line="id",
        username="operator",
        integrity_level="Medium",
        os_category="linux",
        start_time=_START + timedelta(seconds=1),
        parent_plan=parent,
    )
    manager.materialize_action_cohort(builder.seal())
    assert manager.get_process("linux01", parent.identity.pid) is not None
    assert manager.get_process("linux01", child.identity.pid) is not None


def test_action_cohort_commit_publishes_allocator_successors_once() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    first = _windows_cohort(manager)
    first_result = manager.materialize_action_cohort(first)
    first_logon_ids = {session.identity.logon_id for session in first.sessions}
    first_pids = {process.identity.pid for process in first.processes}

    builder = manager.begin_action_cohort_materialization()
    session = builder.plan_session(
        username="svc.backup",
        system="WS-01",
        logon_type=3,
        source_ip="10.0.0.8",
        session_kind="network",
        start_time=_START + timedelta(seconds=10),
    )
    process = builder.plan_process(
        system="WS-01",
        parent_pid=4,
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami",
        username="svc.backup",
        integrity_level="Medium",
        os_category="windows",
        logon_id=session.identity.logon_id,
        start_time=_START + timedelta(seconds=10),
        require_session=True,
        session_plan=session,
    )
    successor = builder.seal()

    assert session.identity.logon_id not in first_logon_ids
    assert process.identity.pid not in first_pids
    result = manager.materialize_action_cohort(successor)
    assert result.prior_version == first_result.committed_version
    assert result.committed_version == first_result.committed_version + 1


def test_ended_session_retention_preserves_window_then_expires_all_indexes() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    original = manager.create_session(
        "operator",
        "linux01",
        2,
        "-",
        start_time=_START,
    )
    resolved = manager.reassign_session_logon_id(
        original,
        _START + timedelta(seconds=1),
    )
    assert resolved is not None
    end_time = _START + timedelta(seconds=2)
    assert manager.end_session(original, end_time)

    manager.set_current_time(end_time + timedelta(hours=47))
    assert manager.get_session_identity(original) is not None
    assert manager.get_session_identity(resolved) is not None
    assert manager._logon_id_aliases[original] == resolved

    manager.set_current_time(end_time + timedelta(hours=48))
    assert manager.get_session_identity(original) is None
    assert manager.get_session_identity(resolved) is None
    assert not manager._ended_sessions
    assert not manager._logon_id_aliases
    assert not manager._logon_id_aliases_by_target
    assert manager._ended_sessions_by_username_end.keys_after("operator", _START) == ()
    assert manager._ended_sessions_by_system_end.keys_after("linux01", _START) == ()


def test_ended_session_retention_hard_cap_evicts_oldest_without_live_residue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(state_manager_module, "_MAX_RETAINED_SESSION_IDENTITIES", 2)
    manager = StateManager()
    manager.set_current_time(_START)
    logon_ids = [
        manager.create_session(
            "operator",
            "linux01",
            3,
            f"10.0.0.{index + 1}",
            start_time=_START,
        )
        for index in range(3)
    ]
    for index, logon_id in enumerate(logon_ids, start=1):
        assert manager.end_session(logon_id, _START + timedelta(seconds=index))

    assert len(manager._ended_sessions) == 2
    assert manager.get_session_identity(logon_ids[0]) is None
    assert manager.get_session_identity(logon_ids[1]) is not None
    assert manager.get_session_identity(logon_ids[2]) is not None
    assert not manager.state.active_sessions
    assert set(manager._ended_sessions_by_username_end.keys_after("operator", _START)) == set(
        logon_ids[1:]
    )
    assert set(manager._ended_sessions_by_system_end.keys_after("linux01", _START)) == set(
        logon_ids[1:]
    )
