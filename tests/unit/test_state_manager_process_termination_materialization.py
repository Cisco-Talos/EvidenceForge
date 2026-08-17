# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Atomic StateManager process-termination materialization tests."""

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.generation.state_manager import (
    ProcessTerminationMaterializationPlan,
    StateManager,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.state import ActiveSession, RunningProcess

_START = datetime(2026, 8, 17, 9, 0, tzinfo=UTC)
_END = _START + timedelta(seconds=8)
_SESSION_REFERENCE_FIELDS = (
    "explorer_pid",
    "session_user_manager_pid",
    "session_winlogon_pid",
    "session_shell_pid",
    "process_tree_root",
    "transport_pid",
)


def _manager_with_process() -> tuple[
    StateManager,
    RunningProcess,
    RunningProcess,
    ActiveSession,
    int,
]:
    manager = StateManager()
    manager.set_current_time(_START)
    logon_id = manager.create_session(
        "analyst",
        "WS-01",
        2,
        "10.0.0.5",
        start_time=_START,
    )
    parent_pid = manager.create_process(
        "WS-01",
        0,
        r"C:\Windows\explorer.exe",
        "explorer.exe",
        "analyst",
        "Medium",
    )
    child_pid = manager.create_process(
        "WS-01",
        parent_pid,
        r"C:\Windows\System32\cmd.exe",
        "cmd.exe /c whoami",
        "analyst",
        "Medium",
    )
    parent = manager.get_process("WS-01", parent_pid)
    child = manager.get_process("WS-01", child_pid)
    session = manager.get_session(logon_id)
    assert parent is not None
    assert child is not None
    assert session is not None
    worker = manager.create_thread(
        "WS-01",
        child.ecar_object_id,
        kind="worker",
        start_time=_START + timedelta(seconds=1),
    )
    for name in _SESSION_REFERENCE_FIELDS:
        setattr(session, name, child_pid)
    session.initial_explorer_pid = child_pid
    return manager, parent, child, session, worker.tid


def _plan(manager: StateManager, child: RunningProcess) -> ProcessTerminationMaterializationPlan:
    return manager.plan_process_termination_materialization(
        system=child.system,
        pid=child.pid,
        end_time=_END,
        parent_activity_time=_END,
    )


def test_process_termination_plan_is_allocation_free_and_authenticates_exact_fields() -> None:
    manager, _parent, child, _session, _worker_tid = _manager_with_process()
    expected_identity = manager.get_process_identity(child.system, child.pid)
    digest = manager.materialization_digest()
    version = manager.materialization_version

    plan = _plan(manager, child)

    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert plan.expected_version == version
    assert plan.identity == expected_identity
    assert plan.end_time == _END
    assert plan.parent_activity_time == _END
    assert len(plan.publication_token) == 64
    assert manager.authenticates_process_termination_plan(plan)
    assert manager.authenticates_materialization_plan(plan)
    manager.validate_process_termination_materialization(plan)
    with manager.materialization_guard(plan):
        manager.validate_process_termination_materialization(plan)
    assert manager.materialization_digest() == digest


def test_process_termination_guard_commits_exact_process_threads_indexes_and_references() -> None:
    manager, parent, child, session, worker_tid = _manager_with_process()
    plan = _plan(manager, child)
    primary_thread = plan.identity.primary_thread
    assert primary_thread is not None
    version = manager.materialization_version

    with manager.process_termination_materialization_guard(plan):
        receipt_identity = manager._commit_prevalidated_process_termination_materialization(plan)

    assert receipt_identity == plan.identity
    assert manager.materialization_version == version + 1
    assert manager.get_process(child.system, child.pid) is None
    assert manager.get_process_identity(child.system, child.pid) == plan.identity
    assert manager.get_process_identity_by_object_id(child.ecar_object_id) == plan.identity
    assert manager.get_process_object_id(child.system, child.pid) == child.ecar_object_id
    assert child.end_time == _END
    assert parent.last_activity_time == _END
    assert (child.system, child.pid) not in manager._process_object_ids
    assert child.ecar_object_id not in manager._processes_by_object_id
    assert manager._active_pid_reservation_counts[child.system] == 1
    for tid in (primary_thread.tid, worker_tid):
        key = (child.system, child.ecar_object_id, tid)
        assert key not in manager.state.running_threads
        ended_thread = manager._ended_threads.get(key)
        assert ended_thread is not None
        assert ended_thread.end_time == _END
    for name in _SESSION_REFERENCE_FIELDS:
        assert getattr(session, name) is None
    assert session.initial_explorer_pid == child.pid

    committed_digest = manager.materialization_digest()
    with pytest.raises(StateError, match="stale"):
        manager.materialize_process_termination(plan)
    assert manager.materialization_digest() == committed_digest


Tamper = Callable[
    [ProcessTerminationMaterializationPlan],
    ProcessTerminationMaterializationPlan,
]


@pytest.mark.parametrize(
    "tamper",
    (
        lambda plan: replace(
            plan,
            _identity=replace(plan.identity, image=r"C:\tampered.exe"),
        ),
        lambda plan: replace(
            plan,
            _payload=replace(plan._payload, end_time=_END + timedelta(seconds=1)),
        ),
        lambda plan: replace(
            plan,
            _payload=replace(
                plan._payload,
                parent_activity_time=_END + timedelta(seconds=1),
            ),
        ),
        lambda plan: replace(
            plan,
            _payload=replace(plan._payload, threads=plan._payload.threads[:-1]),
        ),
        lambda plan: replace(
            plan,
            _payload=replace(plan._payload, session_references=()),
        ),
        lambda plan: replace(plan, _integrity_token="0" * 64),
    ),
)
def test_process_termination_plan_tampering_is_zero_mutation(tamper: Tamper) -> None:
    manager, _parent, child, _session, _worker_tid = _manager_with_process()
    plan = _plan(manager, child)
    tampered = tamper(plan)
    digest = manager.materialization_digest()

    assert not manager.authenticates_process_termination_plan(tampered)
    assert not manager.authenticates_materialization_plan(tampered)
    with pytest.raises(StateError, match="integrity validation failed"):
        manager.materialize_process_termination(tampered)

    assert manager.materialization_digest() == digest
    assert manager.get_process(child.system, child.pid) is child


def test_process_termination_plan_rejects_foreign_authority_and_stale_version() -> None:
    manager, _parent, child, _session, _worker_tid = _manager_with_process()
    plan = _plan(manager, child)
    foreign = StateManager()
    foreign_digest = foreign.materialization_digest()

    assert not foreign.authenticates_process_termination_plan(plan)
    with pytest.raises(StateError, match="integrity validation failed"):
        foreign.materialize_process_termination(plan)
    assert foreign.materialization_digest() == foreign_digest

    manager.create_process(
        "WS-01",
        0,
        r"C:\Windows\System32\notepad.exe",
        "notepad.exe",
        "analyst",
        "Medium",
    )
    stale_digest = manager.materialization_digest()
    assert manager.authenticates_process_termination_plan(plan)
    with pytest.raises(StateError, match="stale"):
        manager.materialize_process_termination(plan)
    assert manager.materialization_digest() == stale_digest
    assert manager.get_process(child.system, child.pid) is child


def test_process_termination_plan_rejects_identity_thread_and_session_reference_drift() -> None:
    manager, _parent, child, session, worker_tid = _manager_with_process()
    plan = _plan(manager, child)
    version = manager.materialization_version
    assert manager.assign_process_to_session(child.system, child.pid, session.logon_id)
    assert manager.materialization_version == version
    identity_drift_digest = manager.materialization_digest()

    with pytest.raises(StateError, match="target identity drifted"):
        manager.validate_process_termination_materialization(plan)
    assert manager.materialization_digest() == identity_drift_digest

    manager, _parent, child, _session, worker_tid = _manager_with_process()
    plan = _plan(manager, child)
    version = manager.materialization_version
    assert manager.end_thread(child.system, child.ecar_object_id, worker_tid, _END)
    assert manager.materialization_version == version
    thread_drift_digest = manager.materialization_digest()

    with pytest.raises(StateError, match="live threads drifted"):
        manager.validate_process_termination_materialization(plan)
    assert manager.materialization_digest() == thread_drift_digest

    manager, _parent, child, session, _worker_tid = _manager_with_process()
    plan = _plan(manager, child)
    version = manager.materialization_version
    session.transport_pid = None
    assert manager.materialization_version == version
    reference_drift_digest = manager.materialization_digest()

    with pytest.raises(StateError, match="active-session references drifted"):
        manager.validate_process_termination_materialization(plan)
    assert manager.materialization_digest() == reference_drift_digest


def test_end_process_compatibility_uses_one_authenticated_versioned_commit() -> None:
    manager, _parent, child, _session, _worker_tid = _manager_with_process()
    version = manager.materialization_version

    assert manager.end_process(child.system, child.pid, _END)
    assert manager.materialization_version == version + 1
    assert manager.get_process(child.system, child.pid) is None
    assert manager.get_process_identity(child.system, child.pid) is not None

    committed_digest = manager.materialization_digest()
    assert not manager.end_process(child.system, child.pid, _END + timedelta(seconds=1))
    assert manager.materialization_digest() == committed_digest
