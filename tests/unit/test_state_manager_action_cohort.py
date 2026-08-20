# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Authenticated StateManager action-cohort materialization tests."""

import random
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest

import evidenceforge.generation.state_manager as state_manager_module
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
)
from evidenceforge.generation.state_manager import (
    ActionCohortMaterializationPlan,
    ActionCohortSessionMetadataState,
    SmbFileMutationJournal,
    StateManager,
)
from evidenceforge.generation.storage_world import CompiledStorageFile
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 17, 14, 0, tzinfo=UTC)


class _CallbackTrap:
    """Fail if a malformed finalizer carrier invokes caller behavior."""

    def __init__(self) -> None:
        self.calls = 0

    def _fail(self, *_args: object, **_kwargs: object) -> object:
        self.calls += 1
        raise RuntimeError("caller callback executed under State validation")

    __bool__ = _fail
    __eq__ = _fail
    __hash__ = _fail
    __iter__ = _fail
    __repr__ = _fail

    @property
    def traffic(self) -> object:
        """Fail if post-auth preparation rereads a hostile transaction field."""

        return self._fail()


class _CollidingEqualityTrap:
    """Hash like a trusted key but fail if dictionary lookup invokes equality."""

    def __init__(self, trusted_key: str) -> None:
        self._hash = hash(trusted_key)
        self.calls = 0

    def __hash__(self) -> int:
        return self._hash

    def __eq__(self, _other: object) -> bool:
        self.calls += 1
        raise RuntimeError("hostile equality callback executed")

    def __repr__(self) -> str:
        self.calls += 1
        raise RuntimeError("hostile repr callback executed")


class _ArmableCollidingEqualityTrap:
    """Permit setup, then fail if a retained-map lookup invokes equality."""

    def __init__(self, trusted_key: str) -> None:
        self._hash = hash(trusted_key)
        self.armed = False
        self.calls = 0

    def __hash__(self) -> int:
        return self._hash

    def __eq__(self, _other: object) -> bool:
        if self.armed:
            self.calls += 1
            raise RuntimeError("hostile authority-key equality callback executed")
        return False

    def __repr__(self) -> str:
        if self.armed:
            self.calls += 1
            raise RuntimeError("hostile authority-key repr callback executed")
        return "unarmed-authority-key"


def _journal_file(
    manager: StateManager,
    suffix: str,
) -> tuple[CompiledStorageFile, SmbFileMutationJournal]:
    compiled = CompiledStorageFile(
        file_id=f"file-cohort-{suffix}",
        share="FS-01.finance",
        path=f"Scratch\\cohort-{suffix}.txt",
        size_bytes=10,
        mime_type="text/plain",
    )
    manager.touch_smb_file(compiled)
    journal = manager.begin_smb_file_mutation_journal(f"operation-cohort-{suffix}")
    manager.update_smb_file(compiled.file_id, size_bytes=20, journal=journal)
    return compiled, journal


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


def test_action_cohort_smb_terminalization_rolls_back_before_canonical_finalize() -> None:
    """A provisional journal terminal remains reader-visible only until claim rollback."""

    manager = StateManager()
    manager.set_current_time(_START)
    compiled, journal = _journal_file(manager, "rollback")
    builder = manager.begin_action_cohort_materialization()
    builder.terminalize_smb_file_mutation(journal)
    plan = builder.seal()

    assert manager.smb_file_size(compiled) == 10
    with manager.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert manager.smb_file_size(compiled) == 20
        assert manager.recover_smb_file_mutation_commit(journal) is (
            prepared.expected_result.smb_file_mutation
        )
        object.__setattr__(journal, "_operation_id", "operation-public-tamper")

    assert manager.smb_file_size(compiled) == 10
    assert manager.recover_smb_file_mutation_commit(journal) is None
    manager.cancel_smb_file_mutation_journal(journal)
    summary = manager.get_state_summary()
    assert summary["smb_file_mutation_journals"] == 0
    assert summary["smb_file_mutation_retained_bytes"] == 0


def test_action_cohort_smb_terminalization_commits_once_and_returns_detached_result() -> None:
    """Reuse-operation files and State truth cross one action-cohort terminal pointer."""

    manager = StateManager()
    manager.set_current_time(_START)
    compiled, journal = _journal_file(manager, "success")
    builder = manager.begin_action_cohort_materialization()
    builder.terminalize_smb_file_mutation(journal)
    plan = builder.seal()

    result = manager.materialize_action_cohort(plan)

    assert result.smb_file_mutation is not None
    assert manager.recover_smb_file_mutation_commit(journal) is result.smb_file_mutation
    assert manager.smb_file_size(compiled) == 20
    assert manager.acknowledge_smb_file_mutation_commit(result.smb_file_mutation)
    summary = manager.get_state_summary()
    assert summary["smb_file_mutation_journals"] == 0
    assert summary["smb_file_mutation_retained_bytes"] == 0


def test_action_cohort_smb_plan_exposes_only_opaque_scalar_binding() -> None:
    """Returned plans cannot reach private preimages, terminal caps, or canonical rows."""

    manager = StateManager()
    manager.set_current_time(_START)
    _compiled, journal = _journal_file(manager, "opaque")
    builder = manager.begin_action_cohort_materialization()
    builder.terminalize_smb_file_mutation(journal)
    plan = builder.seal()
    binding = plan._smb_file_mutation_terminalization
    assert binding is not None

    assert all(
        type(getattr(binding, name)) is str
        for name in (
            "binding_id",
            "journal_id",
            "journal_publication_token",
            "operation_id",
            "expected_postimage_digest",
            "_integrity_token",
        )
    )
    assert not any(
        forbidden in repr(binding)
        for forbidden in (
            "SmbFileMutationJournalCapability",
            "SmbFileStatePreimage",
            "SmbFileState(",
        )
    )
    copied_binding = replace(binding)
    copied_plan = replace(plan, _smb_file_mutation_terminalization=copied_binding)
    assert not manager.authenticates_action_cohort_plan(copied_plan)

    object.__setattr__(binding, "operation_id", "operation-tampered")
    assert not manager.authenticates_action_cohort_plan(plan)
    manager.cancel_smb_file_mutation_journal(journal)


def _cumulative_smb_transaction(initial: NetworkTransactionPlan) -> NetworkTransactionPlan:
    return replace(
        initial,
        traffic=NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(payload_bytes=520, packets=8, ip_bytes=840),
            resp=DirectionalTrafficLedger(payload_bytes=1_480, packets=12, ip_bytes=1_960),
        ),
    )


def _pinned_smb_root(
    *,
    acknowledge_install: bool = True,
    manager: StateManager | None = None,
    owner_seed: int = 9_445,
    stable_id: str = "smb-pinned-root",
    transport_pid: int | None = None,
) -> tuple[StateManager, random.Random, object, object, NetworkTransactionPlan]:
    if manager is None:
        manager = StateManager()
        manager.set_current_time(_START)
    owner = random.Random(owner_seed)
    cursor = manager.begin_connection_planning(owner)
    identity = cursor.reserve_identity()
    pin = cursor.reserve_smb_connection_pin()
    closed_at = _START + timedelta(seconds=1.25)
    transaction = NetworkTransactionPlan(
        stable_id=stable_id,
        hostname="FS-01",
        outcome="success",
        phase_times=(("transport_start", _START), ("transport_close", closed_at)),
        started_at=_START,
        closed_at=closed_at,
        src_ip="10.0.0.10",
        src_port=50_001,
        dst_ip="10.0.0.20",
        dst_port=445,
        protocol="tcp",
        service="smb",
        zeek_uid=identity.zeek_uid,
        conn_id=identity.conn_id,
        duration=1.25,
        conn_state="SF",
        history="ShADadFf",
        traffic=NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(payload_bytes=120, packets=2, ip_bytes=200),
            resp=DirectionalTrafficLedger(payload_bytes=480, packets=3, ip_bytes=600),
        ),
    )
    batch_builder = manager.begin_materialization_batch()
    session = batch_builder.plan_session(
        username="EXAMPLE\\analyst",
        system="FS-01",
        logon_type=3,
        source_ip=transaction.src_ip,
        source_port=transaction.src_port,
        session_kind="network",
        start_time=_START + timedelta(milliseconds=50),
        logon_id=None,
        network_close_time=closed_at,
        closure_owned_by_bundle=True,
        transport_pid=transport_pid,
        end_plan=SessionEndPlan(canonical_end=closed_at, authority="action_bundle"),
        smb_principal="EXAMPLE\\analyst",
        auth_protocol="NTLMv2",
        auth_session_ref="smb-auth-root",
        account_scope="EXAMPLE",
    )
    plan = manager.finalize_connection_composite_materialization(
        cursor,
        transaction,
        source_system="WS-01",
        source_hostname="WS-01",
        hostname="FS-01",
        batch=batch_builder.seal(),
    )
    result = manager.materialize_connection_composite(plan, owner)
    receipt = result.smb_connection_pin_install
    assert receipt is not None
    if acknowledge_install:
        assert manager.acknowledge_smb_connection_pin_install(receipt)
    return manager, owner, pin, session.identity, transaction


def test_action_cohort_smb_connection_finalization_rolls_back_exact_pin_and_state() -> None:
    """The close patch is provisional with the session, row, indexes, and pin."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    connection = manager.state.open_connections[initial.conn_id]
    before_fields = dict(connection.__dict__)
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        _cumulative_smb_transaction(initial),
        session_identity,
        end_time=initial.closed_at,
    )
    plan = builder.seal()

    with manager.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert connection.traffic_ledger.orig.payload_bytes == 520
        assert manager.get_session(session_identity.logon_id) is None
        assert manager.recover_smb_connection_finalization(pin) is (
            prepared.expected_result.smb_connection_finalization
        )

    assert connection.__dict__ == before_fields
    assert manager.get_session(session_identity.logon_id) is not None
    assert manager.authenticates_smb_connection_pin(pin)
    assert manager.recover_smb_connection_finalization(pin) is None
    assert initial.conn_id not in manager._connection_expirations
    assert initial.conn_id not in manager._terminal_connection_ids


def test_action_cohort_smb_connection_finalization_commits_recovers_and_releases() -> None:
    """Final traffic/session truth commits once and remains fenced through exact ack."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    final = _cumulative_smb_transaction(initial)
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        final,
        session_identity,
        end_time=initial.closed_at,
    )
    result = manager.materialize_action_cohort(builder.seal())
    terminal = result.smb_connection_finalization
    assert terminal is not None

    connection = manager.state.open_connections[initial.conn_id]
    assert connection.traffic_ledger == final.traffic
    assert connection.bytes_sent == final.orig_bytes
    assert connection.bytes_received == final.resp_bytes
    assert manager.get_session(session_identity.logon_id) is None
    assert manager.recover_smb_connection_finalization(pin) is terminal
    assert manager.sweep_closed_connections(initial.closed_at) == 0
    assert manager.acknowledge_smb_connection_finalization(terminal)
    assert manager.recover_smb_connection_finalization(pin) is None
    assert manager.sweep_closed_connections(initial.closed_at) == 1
    assert initial.conn_id not in manager.state.open_connections


def test_action_cohort_smb_finalizer_preserves_timing_and_requires_install_ack() -> None:
    """Close planning is pre-canonical and preserves lifecycle-bound interval truth."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root(acknowledge_install=False)
    builder = manager.begin_action_cohort_materialization()
    with pytest.raises(StateError, match="install receipt must be acknowledged"):
        builder.finalize_smb_connection(
            pin,
            _cumulative_smb_transaction(initial),
            session_identity,
            end_time=initial.closed_at,
        )
    receipt = manager.recover_smb_connection_pin_install(pin)
    assert receipt is not None
    assert manager.acknowledge_smb_connection_pin_install(receipt)

    changed_interval = replace(
        _cumulative_smb_transaction(initial),
        closed_at=initial.closed_at + timedelta(seconds=1),
        duration=initial.duration + 1.0,
        phase_times=(
            initial.phase_times[0],
            ("transport_close", initial.closed_at + timedelta(seconds=1)),
        ),
    )
    with pytest.raises(StateError, match="preserve the pinned transport interval"):
        builder.finalize_smb_connection(
            pin,
            changed_interval,
            session_identity,
            end_time=changed_interval.closed_at,
        )


def _terminal_smb_connection() -> tuple[
    StateManager,
    object,
    object,
    NetworkTransactionPlan,
]:
    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        _cumulative_smb_transaction(initial),
        session_identity,
        end_time=initial.closed_at,
    )
    result = manager.materialize_action_cohort(builder.seal())
    terminal = result.smb_connection_finalization
    assert terminal is not None
    return manager, pin, terminal, initial


def _assert_no_smb_connection_pin_authority(manager: StateManager) -> None:
    """Assert every observable pin/result/ack owner has converged to zero."""

    summary = manager.get_state_summary()
    for key in (
        "smb_connection_pins_active",
        "smb_connection_pins_terminal",
        "smb_connection_pin_install_receipts",
        "smb_connection_finalization_results",
        "smb_connection_finalization_receipts",
        "smb_connection_pin_acknowledging",
        "smb_connection_pin_session_owners",
        "smb_connection_pin_protected_sessions",
        "smb_connection_pin_reserved_bytes",
        "smb_connection_pin_retained_bytes",
    ):
        assert summary[key] == 0


@pytest.mark.parametrize("watermark_method", ["set", "advance"])
def test_smb_terminal_session_survives_retention_until_final_ack(
    watermark_method: str,
) -> None:
    """Watermarks preserve the exact ended Type-3 row while the terminal pin is live."""

    manager, pin, terminal, initial = _terminal_smb_connection()
    far_future = initial.closed_at + timedelta(hours=49)
    if watermark_method == "set":
        manager.set_current_time(far_future)
    else:
        current = manager.get_current_time()
        assert current is not None
        manager.advance_time(far_future - current)

    assert manager.authenticates_smb_connection_pin(pin)
    assert manager.authenticates_smb_connection_finalization_result(terminal)
    assert manager.recover_smb_connection_finalization(pin) is terminal
    assert manager.get_session_identity(terminal.session_identity.logon_id) is not None
    assert manager._ended_sessions.protected_count() == 1
    assert manager.acknowledge_smb_connection_finalization(terminal)
    if watermark_method == "set":
        manager.set_current_time(far_future)
    else:
        manager.advance_time(timedelta(0))
    assert manager.get_session_identity(terminal.session_identity.logon_id) is None
    _assert_no_smb_connection_pin_authority(manager)


def _seed_ordinary_retained_sessions(manager: StateManager) -> tuple[str, str]:
    """Retain two ordered ordinary sessions for SMB hard-cap tests."""

    logon_ids = tuple(
        manager.create_session(
            username=f"ordinary-{index}",
            system="FS-01",
            logon_type=3,
            source_ip=f"10.0.0.{30 + index}",
            start_time=_START - timedelta(seconds=10),
        )
        for index in range(2)
    )
    for index, logon_id in enumerate(logon_ids):
        assert manager.end_session(
            logon_id,
            _START - timedelta(seconds=2 - index),
        )
    return logon_ids


def test_smb_terminal_session_displaces_oldest_ordinary_row_at_hard_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A protected Type-3 row consumes the hard cap and evicts only ordinary rows."""

    monkeypatch.setattr(state_manager_module, "_MAX_RETAINED_SESSION_IDENTITIES", 2)
    manager = StateManager()
    manager.set_current_time(_START)
    oldest, newest = _seed_ordinary_retained_sessions(manager)
    manager, _owner, pin, session_identity, initial = _pinned_smb_root(manager=manager)
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        _cumulative_smb_transaction(initial),
        session_identity,
        end_time=initial.closed_at,
    )
    result = manager.materialize_action_cohort(builder.seal())
    terminal = result.smb_connection_finalization
    assert terminal is not None

    assert len(manager._ended_sessions) == 2
    assert manager.get_session_identity(oldest) is None
    assert manager.get_session_identity(newest) is not None
    assert manager.get_session_identity(session_identity.logon_id) is not None
    assert manager._ended_sessions.protected_count() == 1
    assert manager.authenticates_smb_connection_pin(pin)
    assert manager.authenticates_smb_connection_finalization_result(terminal)
    assert manager.acknowledge_smb_connection_finalization(terminal)
    _assert_no_smb_connection_pin_authority(manager)


def test_smb_terminal_hard_cap_eviction_rolls_back_exact_retention_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provisional protected row and its ordinary victim both undo exactly."""

    monkeypatch.setattr(state_manager_module, "_MAX_RETAINED_SESSION_IDENTITIES", 2)
    manager = StateManager()
    manager.set_current_time(_START)
    oldest, newest = _seed_ordinary_retained_sessions(manager)
    manager, _owner, pin, session_identity, initial = _pinned_smb_root(manager=manager)
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        _cumulative_smb_transaction(initial),
        session_identity,
        end_time=initial.closed_at,
    )
    plan = builder.seal()
    before = manager.materialization_digest()
    retained_before = dict(manager._ended_sessions.items())
    retention_high_water_before = manager._ended_sessions._protected_high_water_mark
    retention_order_before = {
        logon_id: (
            manager._ended_sessions._deadlines[logon_id],
            manager._ended_sessions._orders[logon_id],
            manager._ended_sessions._versions[logon_id],
        )
        for logon_id in retained_before
    }

    with manager.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert manager.get_session_identity(oldest) is None
        assert manager._ended_sessions.protected_count() == 1

    assert manager.materialization_digest() == before
    assert dict(manager._ended_sessions.items()) == retained_before
    assert {
        logon_id: (
            manager._ended_sessions._deadlines[logon_id],
            manager._ended_sessions._orders[logon_id],
            manager._ended_sessions._versions[logon_id],
        )
        for logon_id in retained_before
    } == retention_order_before
    assert manager.get_session_identity(oldest) is not None
    assert manager.get_session_identity(newest) is not None
    assert manager.get_session(session_identity.logon_id) is not None
    assert manager._ended_sessions.protected_count() == 0
    assert manager._ended_sessions._protected_high_water_mark == retention_high_water_before
    assert manager.authenticates_smb_connection_pin(pin)


def test_smb_final_ack_release_allocation_failure_retains_terminal_fence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A release allocation failure leaves protection and acknowledgement retryable."""

    manager, pin, terminal, initial = _terminal_smb_connection()
    original_release = manager._ended_sessions.release
    fired = False

    def fail_release_once(logon_id: str) -> bool:
        nonlocal fired
        if not fired:
            fired = True
            raise RuntimeError("injected expiry release allocation failure")
        return original_release(logon_id)

    monkeypatch.setattr(manager._ended_sessions, "release", fail_release_once)
    with pytest.raises(RuntimeError, match="release allocation"):
        manager.acknowledge_smb_connection_finalization(terminal)
    assert fired
    assert manager._ended_sessions.protected_count() == 1
    manager.set_current_time(initial.closed_at + timedelta(hours=49))
    recovered = manager.recover_smb_connection_finalization(pin)
    assert recovered is terminal
    assert manager.authenticates_smb_connection_pin(pin)
    assert manager.authenticates_smb_connection_finalization_result(terminal)
    assert manager.acknowledge_smb_connection_finalization(recovered)
    assert manager._ended_sessions.protected_count() == 0
    _assert_no_smb_connection_pin_authority(manager)


def test_smb_final_ack_lost_successful_release_reprotects_and_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lost return after the real release restores protection before propagating."""

    manager, pin, terminal, initial = _terminal_smb_connection()
    original_release = manager._ended_sessions.release
    fired = False

    def release_then_fail(logon_id: str) -> bool:
        nonlocal fired
        released = original_release(logon_id)
        if not fired:
            fired = True
            assert released
            raise RuntimeError("lost successful retention release return")
        return released

    monkeypatch.setattr(manager._ended_sessions, "release", release_then_fail)
    with pytest.raises(RuntimeError, match="successful retention release"):
        manager.acknowledge_smb_connection_finalization(terminal)

    assert fired
    assert manager._ended_sessions.protected_count() == 1
    manager.set_current_time(initial.closed_at + timedelta(hours=49))
    recovered = manager.recover_smb_connection_finalization(pin)
    assert recovered is terminal
    assert manager.authenticates_smb_connection_pin(pin)
    assert manager.authenticates_smb_connection_finalization_result(terminal)
    monkeypatch.setattr(manager._ended_sessions, "release", original_release)
    assert manager.acknowledge_smb_connection_finalization(recovered)
    _assert_no_smb_connection_pin_authority(manager)


@pytest.mark.parametrize(
    "fault_stage",
    [
        "ack-marker",
        "ack-expiration",
        "ack-terminal-membership",
        "ack-accounting",
        "ack-authority",
        "ack-session-owner",
    ],
)
def test_smb_finalization_ack_restarts_at_every_release_stage(
    fault_stage: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lost acknowledgement return retains one exact owner and converges on retry."""

    manager, pin, terminal, initial = _terminal_smb_connection()
    fired = False

    def fail_once(stage: str) -> None:
        nonlocal fired
        if not fired and stage == fault_stage:
            fired = True
            raise RuntimeError(f"lost return at {stage}")

    monkeypatch.setattr(manager, "_smb_connection_pin_fault", fail_once)
    with pytest.raises(RuntimeError, match="lost return"):
        manager.acknowledge_smb_connection_finalization(terminal)
    assert fired

    if fault_stage == "ack-session-owner":
        manager.set_current_time(initial.closed_at + timedelta(hours=49))
    recovered = manager.recover_smb_connection_finalization(pin)
    assert recovered is terminal
    monkeypatch.setattr(manager, "_smb_connection_pin_fault", lambda _stage: None)
    assert manager.acknowledge_smb_connection_finalization(recovered)
    _assert_no_smb_connection_pin_authority(manager)


@pytest.mark.parametrize(
    "tamper_target",
    [
        "connection-row",
        "ended-session",
        "connection-forward-index",
        "connection-reverse-index",
        "session-grouped-index",
        "session-system-grouped-index",
        "session-expiry-index",
        "session-protection-index",
        "session-owner-index",
        "connection-lifecycle-index",
    ],
)
def test_smb_terminal_canonical_tamper_fails_closed_without_releasing_fence(
    tamper_target: str,
) -> None:
    """Canonical row/session/index drift is never repaired from public wrappers."""

    manager, pin, terminal, initial = _terminal_smb_connection()
    authority = manager._smb_connection_authority_by_conn_id[initial.conn_id]
    active = authority.active
    logon_id = terminal.session_identity.logon_id

    if tamper_target == "connection-row":
        prior = active.connection.bytes_sent
        active.connection.bytes_sent = prior + 1

        def restore() -> None:
            active.connection.bytes_sent = prior

    elif tamper_target == "ended-session":
        prior = active.session.auth_protocol
        active.session.auth_protocol = "Kerberos"

        def restore() -> None:
            active.session.auth_protocol = prior

    elif tamper_target == "connection-forward-index":
        forward = manager._open_connections._indexed_values[initial.conn_id]
        prior = forward["transaction_id"]
        forward["transaction_id"] = "tampered-transaction-index"

        def restore() -> None:
            forward["transaction_id"] = prior

    elif tamper_target == "connection-reverse-index":
        index_value = active.initial_snapshot.transaction_id
        bucket = manager._open_connections._indexes["transaction_id"][index_value]
        bucket.pop(initial.conn_id)

        def restore() -> None:
            bucket[initial.conn_id] = None

    elif tamper_target == "session-grouped-index":
        grouped = manager._ended_sessions_by_username_end
        prior = grouped._current.pop(logon_id)

        def restore() -> None:
            grouped._current[logon_id] = prior

    elif tamper_target == "session-system-grouped-index":
        grouped = manager._ended_sessions_by_system_end
        prior = grouped._current.pop(logon_id)

        def restore() -> None:
            grouped._current[logon_id] = prior

    elif tamper_target == "session-expiry-index":
        prior = manager._ended_sessions._deadlines[logon_id]
        manager._ended_sessions._deadlines[logon_id] = prior + 1.0

        def restore() -> None:
            manager._ended_sessions._deadlines[logon_id] = prior

    elif tamper_target == "session-protection-index":
        manager._ended_sessions._protected.remove(logon_id)

        def restore() -> None:
            manager._ended_sessions._protected.add(logon_id)

    elif tamper_target == "session-owner-index":
        prior = manager._smb_connection_conn_id_by_logon_id.pop(logon_id)

        def restore() -> None:
            manager._smb_connection_conn_id_by_logon_id[logon_id] = prior

    else:
        manager._terminal_connection_ids[initial.conn_id] = None

        def restore() -> None:
            manager._terminal_connection_ids.pop(initial.conn_id)

    assert not manager.authenticates_smb_connection_pin(pin)
    assert not manager.authenticates_smb_connection_finalization_result(terminal)
    if tamper_target in {"session-protection-index", "session-owner-index"}:
        assert manager.recover_smb_connection_finalization(pin) is None
        with pytest.raises(StateError):
            manager.get_state_summary()
    else:
        with pytest.raises(StateError):
            manager.recover_smb_connection_finalization(pin)
        summary = manager.get_state_summary()
        assert summary["smb_connection_pins_terminal"] == 1
        assert summary["smb_connection_pin_protected_sessions"] == 1

    restore()
    assert manager.authenticates_smb_connection_pin(pin)
    assert manager.authenticates_smb_connection_finalization_result(terminal)
    assert manager.acknowledge_smb_connection_finalization(terminal)
    _assert_no_smb_connection_pin_authority(manager)


@pytest.mark.parametrize("tamper_target", ["result", "receipt", "nested-transaction"])
def test_smb_terminal_public_tamper_recovers_fresh_exact_result(
    tamper_target: str,
) -> None:
    """Caller-tampered result wrappers rebuild without weakening canonical checks."""

    manager, pin, terminal, _initial = _terminal_smb_connection()
    trap: _CallbackTrap | None = None
    if tamper_target == "result":
        object.__setattr__(terminal, "conn_id", "tampered-terminal-result")
    elif tamper_target == "receipt":
        object.__setattr__(terminal.receipt, "_integrity_token", "0" * 64)
    else:
        trap = _CallbackTrap()
        object.__setattr__(terminal.final_transaction, "protocol", trap)

    assert not manager.authenticates_smb_connection_finalization_result(terminal)
    assert trap is None or trap.calls == 0
    recovered = manager.recover_smb_connection_finalization(pin)
    assert recovered is not None and recovered is not terminal
    assert trap is None or trap.calls == 0
    assert manager.authenticates_smb_connection_pin(pin)
    assert manager.authenticates_smb_connection_finalization_result(recovered)
    assert manager.acknowledge_smb_connection_finalization(recovered)
    _assert_no_smb_connection_pin_authority(manager)


def test_smb_terminal_index_validation_rejects_colliding_key_without_callbacks() -> None:
    """Reverse-index validation never hashes or compares a malformed retained key."""

    manager, pin, terminal, initial = _terminal_smb_connection()
    authority = manager._smb_connection_authority_by_conn_id[initial.conn_id]
    index_value = authority.active.initial_snapshot.transaction_id
    reverse = manager._open_connections._indexes["transaction_id"]
    bucket = reverse.pop(index_value)
    trap = _CollidingEqualityTrap(index_value)
    reverse[trap] = bucket

    assert not manager.authenticates_smb_connection_pin(pin)
    assert trap.calls == 0
    with pytest.raises(StateError):
        manager.recover_smb_connection_finalization(pin)
    assert trap.calls == 0

    reverse.pop(trap)
    reverse[index_value] = bucket
    assert manager.authenticates_smb_connection_pin(pin)
    assert manager.acknowledge_smb_connection_finalization(terminal)
    _assert_no_smb_connection_pin_authority(manager)


@pytest.mark.parametrize("operation", ["auth", "recover", "writer", "rollback", "ack"])
def test_smb_authority_lookup_rejects_colliding_key_without_callbacks(
    operation: str,
) -> None:
    """Every authority-map boundary scans exact keys before dictionary lookup."""

    if operation in {"recover", "ack"}:
        manager, pin, terminal, initial = _terminal_smb_connection()
        plan = None
    else:
        manager, _owner, pin, session_identity, initial = _pinned_smb_root()
        terminal = None
        builder = manager.begin_action_cohort_materialization()
        builder.finalize_smb_connection(
            pin,
            _cumulative_smb_transaction(initial),
            session_identity,
            end_time=initial.closed_at,
        )
        plan = builder.seal()
    authority = manager._smb_connection_authority_by_conn_id[initial.conn_id]
    trap = _ArmableCollidingEqualityTrap(initial.conn_id)
    manager._smb_connection_authority_by_conn_id.pop(initial.conn_id)
    manager._smb_connection_authority_by_conn_id[trap] = authority
    manager._smb_connection_authority_by_conn_id[initial.conn_id] = authority
    trap.calls = 0
    trap.armed = True

    try:
        if operation == "auth":
            assert not manager.authenticates_smb_connection_pin(pin)
        elif operation == "recover":
            assert manager.recover_smb_connection_finalization(pin) is None
        elif operation == "writer":
            with pytest.raises(StateError):
                manager.update_connection_bytes(initial.conn_id, 1, 1)
        elif operation == "rollback":
            assert plan is not None
            with pytest.raises(StateError):
                manager.materialize_action_cohort(plan)
        else:
            assert terminal is not None
            assert not manager.acknowledge_smb_connection_finalization(terminal)
        assert trap.calls == 0
    finally:
        trap.armed = False
        manager._smb_connection_authority_by_conn_id.pop(trap)

    assert manager.authenticates_smb_connection_pin(pin)
    if terminal is not None:
        assert manager.acknowledge_smb_connection_finalization(terminal)
        _assert_no_smb_connection_pin_authority(manager)


def test_smb_prepared_rollback_observation_rejects_colliding_authority_key() -> None:
    """The claimed preimage observer scans authority keys before dictionary equality."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        _cumulative_smb_transaction(initial),
        session_identity,
        end_time=initial.closed_at,
    )
    plan = builder.seal()
    before = manager.materialization_digest()

    with manager.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        authority = manager._smb_connection_authority_by_conn_id.pop(initial.conn_id)
        trap = _ArmableCollidingEqualityTrap(initial.conn_id)
        manager._smb_connection_authority_by_conn_id[trap] = authority
        manager._smb_connection_authority_by_conn_id[initial.conn_id] = authority
        trap.calls = 0
        trap.armed = True
        try:
            with pytest.raises(StateError):
                prepared.apply_provisional()
            assert trap.calls == 0
        finally:
            trap.armed = False
            manager._smb_connection_authority_by_conn_id.pop(trap)

    assert manager.materialization_digest() == before
    assert manager.authenticates_smb_connection_pin(pin)


@pytest.mark.parametrize(
    "authority_phase",
    [
        "active",
        "terminal",
        "ack-marker",
        "ack-expiration",
        "ack-terminal-membership",
        "ack-accounting",
        "ack-authority",
        "ack-session-owner",
    ],
)
@pytest.mark.parametrize(
    "corruption",
    [
        "alias",
        "copied-owner",
        "replacement-copy",
        "session-owner-alias",
        "aggregate-plus",
        "aggregate-minus",
        "reserve",
    ],
)
def test_smb_authority_census_rejects_every_phase_corruption(
    authority_phase: str,
    corruption: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every retained phase has one owner graph and one exact byte charge."""

    terminal = None
    if authority_phase == "active":
        manager, _owner, pin, _identity, initial = _pinned_smb_root()
    else:
        manager, pin, terminal, initial = _terminal_smb_connection()
        if authority_phase != "terminal":
            fired = False

            def fail_once(stage: str) -> None:
                nonlocal fired
                if not fired and stage == authority_phase:
                    fired = True
                    raise RuntimeError(f"lost return at {stage}")

            monkeypatch.setattr(manager, "_smb_connection_pin_fault", fail_once)
            with pytest.raises(RuntimeError, match="lost return"):
                manager.acknowledge_smb_connection_finalization(terminal)
            assert fired
            monkeypatch.setattr(manager, "_smb_connection_pin_fault", lambda _stage: None)

    healthy = manager.get_state_summary()
    primary = manager._smb_connection_authority_by_conn_id
    acknowledging = manager._smb_connection_acknowledging_by_conn_id
    locator = primary if primary else acknowledging
    authority = next(iter(locator.values()))
    active = manager._smb_connection_active_capability(authority)
    expected_retained = active.retained_bytes + (
        active.terminal_reserved_bytes if authority_phase == "active" else authority.retained_bytes
    )
    assert healthy["smb_connection_pin_retained_bytes"] == expected_retained
    assert healthy["smb_connection_pin_reserved_bytes"] == (
        active.terminal_reserved_bytes if authority_phase == "active" else 0
    )
    alias_key = f"{initial.conn_id}-alias"
    owner_alias = f"{active.session_identity.logon_id}-alias"

    if corruption == "alias":
        locator[alias_key] = authority

        def restore() -> None:
            locator.pop(alias_key)

    elif corruption == "copied-owner":
        locator[alias_key] = replace(authority)

        def restore() -> None:
            locator.pop(alias_key)

    elif corruption == "replacement-copy":
        copied = replace(authority)
        replaced_locators = []
        for retained_locator in (primary, acknowledging):
            if retained_locator.get(initial.conn_id) is authority:
                retained_locator[initial.conn_id] = copied
                replaced_locators.append(retained_locator)

        def restore() -> None:
            for retained_locator in replaced_locators:
                retained_locator[initial.conn_id] = authority

    elif corruption == "session-owner-alias":
        manager._smb_connection_conn_id_by_logon_id[owner_alias] = initial.conn_id

        def restore() -> None:
            manager._smb_connection_conn_id_by_logon_id.pop(owner_alias)

    elif corruption == "aggregate-plus":
        manager._smb_connection_retained_bytes += 1

        def restore() -> None:
            manager._smb_connection_retained_bytes -= 1

    elif corruption == "aggregate-minus":
        manager._smb_connection_retained_bytes -= 1

        def restore() -> None:
            manager._smb_connection_retained_bytes += 1

    else:
        active.terminal_reserved_bytes += 1

        def restore() -> None:
            active.terminal_reserved_bytes -= 1

    try:
        assert not manager.authenticates_smb_connection_pin(pin)
        assert manager.recover_smb_connection_finalization(pin) is None
        with pytest.raises(StateError):
            manager.get_state_summary()
    finally:
        restore()

    assert manager.get_state_summary() == healthy
    assert manager.authenticates_smb_connection_pin(pin)
    if terminal is not None:
        recovered = manager.recover_smb_connection_finalization(pin)
        assert recovered is terminal
        assert manager.acknowledge_smb_connection_finalization(recovered)
        _assert_no_smb_connection_pin_authority(manager)


def test_smb_authority_census_charges_install_receipt_and_reserved_terminal_exactly() -> None:
    """Install recovery bytes disappear once while terminal headroom stays reserved."""

    manager, _owner, pin, _identity, initial = _pinned_smb_root(acknowledge_install=False)
    active = manager._smb_connection_authority_by_conn_id[initial.conn_id]
    receipt = manager.recover_smb_connection_pin_install(pin)
    assert receipt is not None
    before = manager.get_state_summary()
    assert before["smb_connection_pin_install_receipts"] == 1
    assert before["smb_connection_pin_retained_bytes"] == (
        active.retained_bytes + active.terminal_reserved_bytes
    )
    assert before["smb_connection_pin_reserved_bytes"] == active.terminal_reserved_bytes

    receipt_charge = active.retained_bytes - manager._smb_connection_pin_retained_bytes(
        transaction=active.initial_transaction,
        session_identity=active.session_identity,
        install_receipt=False,
    )
    assert receipt_charge > 0
    assert manager.acknowledge_smb_connection_pin_install(receipt)
    after = manager.get_state_summary()
    assert after["smb_connection_pin_install_receipts"] == 0
    assert after["smb_connection_pin_retained_bytes"] == (
        before["smb_connection_pin_retained_bytes"] - receipt_charge
    )
    assert after["smb_connection_pin_reserved_bytes"] == active.terminal_reserved_bytes


def test_smb_authority_census_reconciles_mixed_active_and_terminal_charges() -> None:
    """Finalizing one of two pins consumes only that pin's terminal reservation."""

    manager = StateManager()
    manager.set_current_time(_START)
    manager, _owner, first_pin, first_identity, first_initial = _pinned_smb_root(manager=manager)
    manager, _owner, second_pin, _second_identity, second_initial = _pinned_smb_root(
        manager=manager,
        owner_seed=9_446,
        stable_id="smb-pinned-root-2",
    )
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        first_pin,
        _cumulative_smb_transaction(first_initial),
        first_identity,
        end_time=first_initial.closed_at,
    )
    result = manager.materialize_action_cohort(builder.seal())
    terminal = result.smb_connection_finalization
    assert terminal is not None
    first_authority = manager._smb_connection_authority_by_conn_id[first_initial.conn_id]
    second_authority = manager._smb_connection_authority_by_conn_id[second_initial.conn_id]

    summary = manager.get_state_summary()
    assert summary["smb_connection_pins_active"] == 1
    assert summary["smb_connection_pins_terminal"] == 1
    assert summary["smb_connection_pin_retained_bytes"] == (
        first_authority.active.retained_bytes
        + first_authority.retained_bytes
        + second_authority.retained_bytes
        + second_authority.terminal_reserved_bytes
    )
    assert summary["smb_connection_pin_reserved_bytes"] == (
        second_authority.terminal_reserved_bytes
    )
    assert manager.acknowledge_smb_connection_finalization(terminal)
    remaining = manager.get_state_summary()
    assert remaining["smb_connection_pins_active"] == 1
    assert remaining["smb_connection_pin_retained_bytes"] == (
        second_authority.retained_bytes + second_authority.terminal_reserved_bytes
    )
    assert manager.authenticates_smb_connection_pin(second_pin)


def test_smb_final_ack_fences_a_second_terminal_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One interrupted terminal release remains the exclusive acknowledgement lane."""

    manager = StateManager()
    manager.set_current_time(_START)
    manager, _owner, first_pin, first_identity, first_initial = _pinned_smb_root(manager=manager)
    manager, _owner, second_pin, second_identity, second_initial = _pinned_smb_root(
        manager=manager,
        owner_seed=9_446,
        stable_id="smb-pinned-root-2",
    )

    terminals = []
    for pin, identity, initial in (
        (first_pin, first_identity, first_initial),
        (second_pin, second_identity, second_initial),
    ):
        builder = manager.begin_action_cohort_materialization()
        builder.finalize_smb_connection(
            pin,
            _cumulative_smb_transaction(initial),
            identity,
            end_time=initial.closed_at,
        )
        terminal = manager.materialize_action_cohort(builder.seal()).smb_connection_finalization
        assert terminal is not None
        terminals.append(terminal)

    fired = False

    def fail_first_marker(stage: str) -> None:
        nonlocal fired
        if not fired and stage == "ack-marker":
            fired = True
            raise RuntimeError("lost first acknowledgement marker return")

    monkeypatch.setattr(manager, "_smb_connection_pin_fault", fail_first_marker)
    with pytest.raises(RuntimeError, match="first acknowledgement"):
        manager.acknowledge_smb_connection_finalization(terminals[0])
    assert fired
    before_second = manager.get_state_summary()
    with pytest.raises(StateError, match="another terminal release"):
        manager.acknowledge_smb_connection_finalization(terminals[1])
    assert manager.get_state_summary() == before_second
    assert manager.authenticates_smb_connection_pin(first_pin)
    assert manager.authenticates_smb_connection_pin(second_pin)

    monkeypatch.setattr(manager, "_smb_connection_pin_fault", lambda _stage: None)
    assert manager.acknowledge_smb_connection_finalization(terminals[0])
    assert manager.acknowledge_smb_connection_finalization(terminals[1])
    _assert_no_smb_connection_pin_authority(manager)


@pytest.mark.parametrize("locator_kind", ["primary", "acknowledging", "session-owner"])
def test_smb_census_rejects_colliding_keys_in_every_authority_locator(
    locator_kind: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed colliding keys cannot callback from primary, ack, or owner scans."""

    manager, pin, terminal, initial = _terminal_smb_connection()
    if locator_kind != "primary":
        fired = False

        def fail_marker(stage: str) -> None:
            nonlocal fired
            if not fired and stage == "ack-marker":
                fired = True
                raise RuntimeError("lost marker return")

        monkeypatch.setattr(manager, "_smb_connection_pin_fault", fail_marker)
        with pytest.raises(RuntimeError, match="marker"):
            manager.acknowledge_smb_connection_finalization(terminal)
        assert fired
        monkeypatch.setattr(manager, "_smb_connection_pin_fault", lambda _stage: None)

    if locator_kind == "primary":
        mapping = manager._smb_connection_authority_by_conn_id
        key = initial.conn_id
    elif locator_kind == "acknowledging":
        mapping = manager._smb_connection_acknowledging_by_conn_id
        key = initial.conn_id
    else:
        mapping = manager._smb_connection_conn_id_by_logon_id
        key = terminal.session_identity.logon_id
    retained = mapping.pop(key)
    trap = _ArmableCollidingEqualityTrap(key)
    mapping[trap] = retained
    mapping[key] = retained
    trap.calls = 0
    trap.armed = True
    try:
        assert not manager.authenticates_smb_connection_pin(pin)
        assert manager.recover_smb_connection_finalization(pin) is None
        assert not manager.acknowledge_smb_connection_finalization(terminal)
        with pytest.raises(StateError):
            manager.get_state_summary()
        assert trap.calls == 0
    finally:
        trap.armed = False
        mapping.pop(trap)
    assert manager.authenticates_smb_connection_pin(pin)
    assert manager.acknowledge_smb_connection_finalization(terminal)
    _assert_no_smb_connection_pin_authority(manager)


def test_smb_terminal_result_detaches_plan_canonical_and_session_truth() -> None:
    """Caller plan mutation cannot alias terminal recovery or canonical State."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    final = _cumulative_smb_transaction(initial)
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        final,
        session_identity,
        end_time=initial.closed_at,
    )
    plan = builder.seal()
    binding = plan._smb_connection_finalization
    assert binding is not None
    result = manager.materialize_action_cohort(plan)
    terminal = result.smb_connection_finalization
    assert terminal is not None
    authority = manager._smb_connection_authority_by_conn_id[initial.conn_id]
    canonical = manager.state.open_connections[initial.conn_id]

    assert terminal.final_transaction is not binding.final_transaction
    assert terminal.final_transaction is not authority.active.initial_transaction
    assert terminal.final_transaction.traffic is not binding.final_transaction.traffic
    assert terminal.final_transaction.traffic is not canonical.traffic_ledger
    assert terminal.final_transaction.traffic.orig is not canonical.traffic_ledger.orig
    assert terminal.final_transaction.traffic.resp is not canonical.traffic_ledger.resp
    assert terminal.session_identity is not binding.session_identity
    assert terminal.session_identity is not authority.active.session_identity
    assert terminal.receipt.session_identity is not terminal.session_identity

    canonical_before = manager._smb_connection_parent_snapshot(canonical)
    object.__setattr__(binding.final_transaction.traffic.orig, "payload_bytes", 777)
    object.__setattr__(initial.traffic.orig, "payload_bytes", 888)
    assert manager._smb_connection_parent_snapshot(canonical) == canonical_before
    assert manager.recover_smb_connection_finalization(pin) is terminal
    assert manager.authenticates_smb_connection_finalization_result(terminal)
    assert manager.acknowledge_smb_connection_finalization(terminal)
    _assert_no_smb_connection_pin_authority(manager)


def test_smb_expected_result_rejects_plan_transaction_alias() -> None:
    """Certification rejects a caller-spliced plan object before provisional writes."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        _cumulative_smb_transaction(initial),
        session_identity,
        end_time=initial.closed_at,
    )
    plan = builder.seal()
    binding = plan._smb_connection_finalization
    assert binding is not None
    digest = manager.materialization_digest()

    with manager.prepared_action_cohort_materialization(plan) as prepared:
        terminal = prepared.expected_result.smb_connection_finalization
        assert terminal is not None
        object.__setattr__(terminal, "final_transaction", binding.final_transaction)
        assert not manager.authenticates_expected_action_cohort_result(
            prepared.expected_result,
            preparation=prepared,
        )
        with pytest.raises(StateError, match="expected result"):
            prepared.certify_composite_commit(prepared.expected_result)

    assert manager.materialization_digest() == digest
    assert manager.authenticates_smb_connection_pin(pin)


def test_smb_finalizer_mid_commit_fault_restores_full_pin_preimage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure after the row patch restores the row, session, indexes, and owner."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        _cumulative_smb_transaction(initial),
        session_identity,
        end_time=initial.closed_at,
    )
    plan = builder.seal()

    def fail_terminalization(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("injected session terminalization failure")

    monkeypatch.setattr(
        manager,
        "_commit_action_cohort_session_terminalization",
        fail_terminalization,
    )
    before = manager.materialization_digest()
    with pytest.raises(RuntimeError, match="injected session"):
        manager.materialize_action_cohort(plan)

    assert manager.materialization_digest() == before
    assert manager.authenticates_smb_connection_pin(pin)
    assert manager.get_session(session_identity.logon_id) is not None


def test_smb_finalizer_fault_after_session_terminalization_restores_private_preimage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The rollback census accepts and restores the exact protected intermediate phase."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        _cumulative_smb_transaction(initial),
        session_identity,
        end_time=initial.closed_at,
    )
    plan = builder.seal()
    connection = manager.state.open_connections[initial.conn_id]
    before_fields = dict(connection.__dict__)

    def fail_after_terminalization(_prepared: object) -> None:
        assert manager.get_session(session_identity.logon_id) is None
        assert manager._ended_sessions.is_protected(session_identity.logon_id)
        raise RuntimeError("injected post-terminalization failure")

    monkeypatch.setattr(
        manager,
        "_commit_action_cohort_retention_evictions",
        fail_after_terminalization,
    )
    before = manager.materialization_digest()
    with pytest.raises(RuntimeError, match="post-terminalization"):
        manager.materialize_action_cohort(plan)

    assert manager.materialization_digest() == before
    assert connection.__dict__ == before_fields
    assert manager.get_session(session_identity.logon_id) is not None
    assert not manager._ended_sessions.is_protected(session_identity.logon_id)
    assert manager.authenticates_smb_connection_pin(pin)


def test_smb_finalizer_postcommit_observation_failure_restores_private_preimage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure before postimage publication cannot strand provisional State."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        _cumulative_smb_transaction(initial),
        session_identity,
        end_time=initial.closed_at,
    )
    plan = builder.seal()
    connection = manager.state.open_connections[initial.conn_id]
    connection_before = dict(connection.__dict__)
    original = manager._action_cohort_rollback_observation

    def fail_after_commit(journal: object) -> object:
        if connection.bytes_sent == 520:
            raise RuntimeError("injected postcommit observation failure")
        return original(journal)  # type: ignore[arg-type]

    monkeypatch.setattr(manager, "_action_cohort_rollback_observation", fail_after_commit)
    before = manager.materialization_digest()
    with pytest.raises(RuntimeError, match="postcommit observation"):
        manager.materialize_action_cohort(plan)

    assert manager.materialization_digest() == before
    assert connection.__dict__ == connection_before
    assert manager.get_session(session_identity.logon_id) is not None
    assert manager.authenticates_smb_connection_pin(pin)
    assert manager.recover_smb_connection_finalization(pin) is None


def test_pinned_smb_process_reference_rejects_direct_and_cohort_termination() -> None:
    """Neither termination path may clear a pinned Type-3 process-role pointer."""

    manager = StateManager()
    manager.set_current_time(_START)
    transport_pid = manager.create_process(
        "FS-01",
        0,
        r"C:\Windows\System32\System",
        "System",
        "SYSTEM",
        "System",
    )
    manager, _owner, pin, session_identity, _initial = _pinned_smb_root(
        manager=manager,
        transport_pid=transport_pid,
    )
    process_identity = manager.get_process_identity("FS-01", transport_pid)
    assert process_identity is not None
    session = manager.get_session(session_identity.logon_id)
    assert session is not None and session.transport_pid == transport_pid
    before = manager.materialization_digest()
    before_session = dict(session.__dict__)

    with pytest.raises(StateError, match="pinned SMB session"):
        manager.end_process("FS-01", transport_pid, _START + timedelta(seconds=2))
    assert manager.materialization_digest() == before
    assert session.__dict__ == before_session

    builder = manager.begin_action_cohort_materialization()
    with pytest.raises(StateError, match="pinned SMB session"):
        builder.terminate_process(
            process_identity,
            end_time=_START + timedelta(seconds=2),
        )
    assert manager.materialization_digest() == before
    assert session.__dict__ == before_session
    assert manager.get_process_identity("FS-01", transport_pid) == process_identity
    assert manager.authenticates_smb_connection_pin(pin)


@pytest.mark.parametrize(
    "writer",
    [
        "metadata",
        "end-plan",
        "logon-guid",
        "reassign-logon-id",
        "terminalize",
        "activity",
    ],
)
def test_pinned_smb_session_public_writer_matrix_is_digest_neutral(writer: str) -> None:
    """Every ordinary public session writer rejects before touching the Type-3 row."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    logon_id = session_identity.logon_id
    session = manager.get_session(logon_id)
    assert session is not None
    before = manager.materialization_digest()
    before_fields = dict(session.__dict__)
    before_version = manager.materialization_version

    with pytest.raises(StateError, match="pinned SMB session"):
        if writer == "metadata":
            manager.update_session_metadata(logon_id, source_ip="10.99.99.99")
        elif writer == "end-plan":
            manager.plan_session_end(
                logon_id,
                SessionEndPlan(
                    canonical_end=initial.closed_at,
                    authority="action_bundle",
                ),
            )
        elif writer == "logon-guid":
            manager.get_or_create_session_logon_guid(logon_id, "FS-01")
        elif writer == "reassign-logon-id":
            manager.reassign_session_logon_id(logon_id, initial.started_at)
        elif writer == "terminalize":
            manager.end_session(logon_id, initial.closed_at)
        else:
            manager.update_session_activity_time(logon_id, initial.closed_at)

    assert manager.materialization_digest() == before
    assert manager.materialization_version == before_version
    assert session.__dict__ == before_fields
    assert manager.get_session(logon_id) is session
    assert manager.authenticates_smb_connection_pin(pin)


@pytest.mark.parametrize("writer", ["activity", "terminalize"])
def test_pinned_smb_session_action_cohort_writer_matrix_is_precanonical(
    writer: str,
) -> None:
    """Unrelated cohorts cannot acquire a mutable pinned-session target."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    session = manager.get_session(session_identity.logon_id)
    assert session is not None
    before = manager.materialization_digest()
    before_fields = dict(session.__dict__)
    builder = manager.begin_action_cohort_materialization()
    if writer == "activity":
        builder.patch_session_activity(session_identity, initial.closed_at)
    else:
        builder.terminalize_session(session_identity, end_time=initial.closed_at)

    with pytest.raises(StateError, match="pinned SMB session"):
        builder.seal()

    assert manager.materialization_digest() == before
    assert session.__dict__ == before_fields
    assert manager.authenticates_smb_connection_pin(pin)


def test_smb_public_result_tamper_cannot_block_provisional_rollback() -> None:
    """Rollback uses private preimages even when the caller mutates its result wrapper."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        _cumulative_smb_transaction(initial),
        session_identity,
        end_time=initial.closed_at,
    )
    plan = builder.seal()
    before = manager.materialization_digest()

    with manager.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        terminal = prepared.expected_result.smb_connection_finalization
        assert terminal is not None
        object.__setattr__(terminal, "conn_id", "tampered-terminal-result")

    assert manager.materialization_digest() == before
    assert manager.authenticates_smb_connection_pin(pin)


@pytest.mark.parametrize(
    ("field", "after_certification"),
    [("_sessions", False), ("_integrity_token", False), ("_session_process_links", True)],
)
def test_smb_finalizer_claim_ignores_postclaim_public_plan_tamper(
    field: str,
    after_certification: bool,
) -> None:
    """Certification and commit consume only the manager-owned claim snapshot."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    final = _cumulative_smb_transaction(initial)
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        final,
        session_identity,
        end_time=initial.closed_at,
    )
    plan = builder.seal()
    trap = _CallbackTrap()

    with manager.prepared_action_cohort_materialization(plan) as prepared:
        assert not hasattr(prepared, "_plan")
        assert prepared._source_plan_identity == id(plan)
        if after_certification:
            prepared.certify_composite_commit(prepared.expected_result)
        object.__setattr__(plan, field, trap)
        if not after_certification:
            prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        result = prepared.finalize_no_fail()

    terminal = result.smb_connection_finalization
    assert terminal is not None
    assert terminal.final_transaction == final
    assert trap.calls == 0
    assert manager.acknowledge_smb_connection_finalization(terminal)


def test_smb_finalizer_claim_detaches_nested_binding_and_terminalization() -> None:
    """Nested caller-owned binding and terminalization carriers are not retained by a claim."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    final = _cumulative_smb_transaction(initial)
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        final,
        session_identity,
        end_time=initial.closed_at,
    )
    plan = builder.seal()
    binding = plan._smb_connection_finalization
    assert binding is not None
    terminalization = plan._session_terminalizations[0]
    transaction_trap = _CallbackTrap()
    identity_trap = _CallbackTrap()

    with manager.prepared_action_cohort_materialization(plan) as prepared:
        object.__setattr__(binding, "final_transaction", transaction_trap)
        object.__setattr__(terminalization, "target", identity_trap)
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        result = prepared.finalize_no_fail()

    terminal = result.smb_connection_finalization
    assert terminal is not None
    assert terminal.final_transaction == final
    assert result.terminalized_sessions == (terminal.session_identity,)
    assert terminal.session_identity is not session_identity
    assert transaction_trap.calls == 0
    assert identity_trap.calls == 0
    assert manager.acknowledge_smb_connection_finalization(terminal)


def test_smb_finalizer_claim_snapshot_has_no_public_graph_aliases() -> None:
    """The claim snapshot owns distinct binding, pin, traffic, identity, and close carriers."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    final = _cumulative_smb_transaction(initial)
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        final,
        session_identity,
        end_time=initial.closed_at,
    )
    plan = builder.seal()
    source_binding = plan._smb_connection_finalization
    source_terminalization = plan._session_terminalizations[0]
    assert source_binding is not None

    with manager._lock:
        snapshot, claim, source_token = manager._claim_action_cohort_plan_snapshot_locked(plan)

    assert claim is not None
    detached_binding = snapshot._smb_connection_finalization
    detached_terminalization = snapshot._session_terminalizations[0]
    assert detached_binding is claim.binding
    assert detached_binding is not source_binding
    assert detached_binding.pin is not source_binding.pin
    assert detached_binding.final_transaction is not source_binding.final_transaction
    assert (
        detached_binding.final_transaction.traffic is not source_binding.final_transaction.traffic
    )
    assert detached_binding.session_identity is not source_binding.session_identity
    assert detached_terminalization is not source_terminalization
    assert detached_terminalization.target is not source_terminalization.target
    assert source_token == plan._integrity_token
    assert snapshot._integrity_token != source_token


@pytest.mark.parametrize("hostile_replacement", [False, True])
def test_smb_finalizer_claim_detachment_closes_binding_auth_use_race(
    monkeypatch: pytest.MonkeyPatch,
    hostile_replacement: bool,
) -> None:
    """Mutation immediately after detached binding auth cannot redirect preparation."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    final = _cumulative_smb_transaction(initial)
    alternate = replace(
        final,
        traffic=NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(payload_bytes=621, packets=9, ip_bytes=941),
            resp=DirectionalTrafficLedger(payload_bytes=1_581, packets=13, ip_bytes=2_061),
        ),
    )
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        final,
        session_identity,
        end_time=initial.closed_at,
    )
    plan = builder.seal()
    binding = plan._smb_connection_finalization
    assert binding is not None
    authenticated = Event()
    mutation_complete = Event()
    trap = _CallbackTrap()
    original_validate = manager._validate_smb_connection_finalization_claim_locked
    paused = False

    def validate_then_pause(claim: object, *, binding: object | None = None) -> object:
        nonlocal paused
        active = original_validate(claim, binding=binding)  # type: ignore[arg-type]
        if not paused and binding is None:
            paused = True
            authenticated.set()
            assert mutation_complete.wait(timeout=2)
        return active

    monkeypatch.setattr(
        manager,
        "_validate_smb_connection_finalization_claim_locked",
        validate_then_pause,
    )

    def mutate_source_binding() -> None:
        assert authenticated.wait(timeout=2)
        object.__setattr__(
            binding,
            "final_transaction",
            trap if hostile_replacement else alternate,
        )
        mutation_complete.set()

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(mutate_source_binding)
        with manager.prepared_action_cohort_materialization(plan) as prepared:
            prepared.certify_composite_commit(prepared.expected_result)
            prepared.apply_provisional()
            result = prepared.finalize_no_fail()
        future.result(timeout=2)

    terminal = result.smb_connection_finalization
    assert terminal is not None
    assert terminal.final_transaction == final
    assert terminal.final_transaction.traffic.orig.payload_bytes == 520
    assert terminal.final_transaction.traffic.resp.payload_bytes == 1_480
    assert trap.calls == 0
    assert manager.acknowledge_smb_connection_finalization(terminal)


def test_smb_finalizer_claim_detachment_closes_postvalidation_terminalization_race(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation after full validation cannot alter the detached session-close projection."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    final = _cumulative_smb_transaction(initial)
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        final,
        session_identity,
        end_time=initial.closed_at,
    )
    plan = builder.seal()
    terminalization = plan._session_terminalizations[0]
    validated = Event()
    mutation_complete = Event()
    original_validate = manager.validate_action_cohort_materialization

    def validate_then_pause(
        plan_to_validate: ActionCohortMaterializationPlan,
        *,
        _smb_connection_claim: object | None = None,
    ) -> None:
        original_validate(
            plan_to_validate,
            _smb_connection_claim=_smb_connection_claim,  # type: ignore[arg-type]
        )
        validated.set()
        assert mutation_complete.wait(timeout=2)

    monkeypatch.setattr(manager, "validate_action_cohort_materialization", validate_then_pause)

    def mutate_source_terminalization() -> None:
        assert validated.wait(timeout=2)
        object.__setattr__(
            terminalization,
            "end_time",
            initial.started_at + timedelta(milliseconds=100),
        )
        mutation_complete.set()

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(mutate_source_terminalization)
        with manager.prepared_action_cohort_materialization(plan) as prepared:
            prepared.certify_composite_commit(prepared.expected_result)
            prepared.apply_provisional()
            result = prepared.finalize_no_fail()
        future.result(timeout=2)

    terminal = result.smb_connection_finalization
    assert terminal is not None
    assert manager.state.current_time == initial.closed_at
    assert manager._ended_sessions[session_identity.logon_id][1] == initial.closed_at
    assert manager.acknowledge_smb_connection_finalization(terminal)


def test_smb_finalizer_claim_survives_concurrent_public_plan_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A concurrent caller cannot redirect the no-fail tail through public plan fields."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    final = _cumulative_smb_transaction(initial)
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        final,
        session_identity,
        end_time=initial.closed_at,
    )
    plan = builder.seal()
    entered_commit = Event()
    mutation_complete = Event()
    trap = _CallbackTrap()
    original_commit = manager._commit_prevalidated_action_cohort

    def paused_commit(commit_plan: object) -> None:
        entered_commit.set()
        assert mutation_complete.wait(timeout=2)
        original_commit(commit_plan)  # type: ignore[arg-type]

    monkeypatch.setattr(manager, "_commit_prevalidated_action_cohort", paused_commit)

    def mutate_public_plan() -> None:
        assert entered_commit.wait(timeout=2)
        object.__setattr__(plan, "_session_process_links", trap)
        object.__setattr__(plan, "_final_state_time", trap)
        mutation_complete.set()

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(mutate_public_plan)
        with manager.prepared_action_cohort_materialization(plan) as prepared:
            prepared.certify_composite_commit(prepared.expected_result)
            prepared.apply_provisional()
            result = prepared.finalize_no_fail()
        future.result(timeout=2)

    terminal = result.smb_connection_finalization
    assert terminal is not None
    assert terminal.final_transaction == final
    assert trap.calls == 0
    assert manager.acknowledge_smb_connection_finalization(terminal)


@pytest.mark.parametrize("tampered_field", ["_sealed", "_boot_times"])
def test_smb_finalizer_builder_entry_rejects_hostile_shape_without_callbacks(
    tampered_field: str,
) -> None:
    """The first finalizer entry gate rejects malformed fields before truthiness."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    builder = manager.begin_action_cohort_materialization()
    original = getattr(builder, tampered_field)
    trap = _CallbackTrap()
    object.__setattr__(builder, tampered_field, trap)
    before = manager.materialization_digest()

    with pytest.raises(StateError):
        builder.finalize_smb_connection(
            pin,
            _cumulative_smb_transaction(initial),
            session_identity,
            end_time=initial.closed_at,
        )

    assert trap.calls == 0
    assert manager.materialization_digest() == before
    assert manager.authenticates_smb_connection_pin(pin)
    object.__setattr__(builder, tampered_field, original)
    builder.cancel()


def test_smb_finalizer_builder_seal_rejects_hostile_members_without_callbacks() -> None:
    """Seal gates every forbidden member before generic traversal or semantic HMAC."""

    manager, _owner, pin, session_identity, initial = _pinned_smb_root()
    builder = manager.begin_action_cohort_materialization()
    builder.finalize_smb_connection(
        pin,
        _cumulative_smb_transaction(initial),
        session_identity,
        end_time=initial.closed_at,
    )
    original = builder._process_activity_patches
    trap = _CallbackTrap()
    object.__setattr__(builder, "_process_activity_patches", trap)
    before = manager.materialization_digest()

    with pytest.raises(StateError, match="process activity"):
        builder.seal()

    assert trap.calls == 0
    assert manager.materialization_digest() == before
    assert manager.authenticates_smb_connection_pin(pin)
    object.__setattr__(builder, "_process_activity_patches", original)
    builder.cancel()
