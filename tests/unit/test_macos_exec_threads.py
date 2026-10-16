# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Independently authored Mac task replacement and transactional thread contracts."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_process_execution_state import _START, _execute, _process


def test_exec_replaces_every_thread_and_preserves_historical_snapshots() -> None:
    manager, before = _process()
    workers = tuple(
        manager.create_thread(before.hostname, before.object_id, start_time=_START)
        for _ in range(3)
    )
    assert before.primary_thread is not None
    prior = (before.primary_thread, *workers)
    after = _execute(manager, before)
    assert after.primary_thread is not None
    assert after.primary_thread.tid not in {thread.tid for thread in prior}
    for thread in prior:
        assert manager.get_thread(*thread.canonical_key) is None
        retained = manager._ended_threads.get(thread.canonical_key)
        assert retained is not None
        assert retained.end_time == after.execution_started_at
        assert manager._thread_identity(retained) == thread
    live = manager._running_threads.find("process_object_id", before.object_id)
    assert len(live) == 1
    assert manager._thread_identity(live[0]) == after.primary_thread
    assert manager.get_process_identity_at(before.hostname, before.pid, _START) == before
    manager.end_process(before.hostname, before.pid, _START + timedelta(seconds=2))
    assert not manager._running_threads.find("process_object_id", before.object_id)
    assert manager._ended_threads.get(after.primary_thread.canonical_key).end_time == (
        _START + timedelta(seconds=2)
    )
    assert all(
        manager._ended_threads.get(thread.canonical_key).end_time == after.execution_started_at
        for thread in prior
    )


def test_exec_thread_abort_restores_objects_indexes_and_counter_then_retries() -> None:
    manager, before = _process()
    worker = manager.create_thread(before.hostname, before.object_id, start_time=_START)
    original_rows = dict(manager.state.running_threads)
    digest = manager.materialization_digest()
    builder = manager.begin_action_cohort_materialization()
    after = builder.execute_process(
        before, image="/usr/bin/id", command_line="id", executed_at=_START + timedelta(seconds=1)
    )
    plan = builder.seal()
    assert manager.materialization_digest() == digest
    with manager.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert manager.get_thread(*worker.canonical_key) is None
        assert manager.get_primary_thread(before.hostname, before.pid) == after.primary_thread
    assert manager.materialization_digest() == digest
    assert dict(manager.state.running_threads) == original_rows
    for key, row in original_rows.items():
        assert manager.state.running_threads[key] is row
        assert row.end_time is None
    manager.materialize_action_cohort(plan)
    assert manager.get_primary_thread(before.hostname, before.pid) == after.primary_thread


def test_exec_thread_checkpoint_preserves_retirements_and_next_allocations() -> None:
    manager, before = _process()
    worker = manager.create_thread(before.hostname, before.object_id, start_time=_START)
    after = _execute(manager, before)
    restored = StateManager()
    _restore_head(restored, _capture_head(manager))
    assert restored._ended_threads.get(worker.canonical_key) == manager._ended_threads.get(
        worker.canonical_key
    )
    assert restored.get_primary_thread(before.hostname, before.pid) == after.primary_thread
    assert _execute(restored, after, 2) == _execute(manager, after, 2)
    assert restored.materialization_digest() == manager.materialization_digest()


@pytest.mark.parametrize("exec_first", [True, False])
def test_exec_and_unrelated_spawn_reserve_distinct_threads_in_one_cohort(exec_first: bool) -> None:
    manager, before = _process()
    builder = manager.begin_action_cohort_materialization()

    def execute() -> ProcessIdentity:
        return builder.execute_process(
            before,
            image="/usr/bin/id",
            command_line="id",
            executed_at=_START + timedelta(seconds=1),
        )

    if exec_first:
        after = execute()
    child = builder.plan_process(
        system=before.hostname,
        parent_pid=0,
        image="/bin/zsh",
        command_line="zsh",
        username=before.principal,
        integrity_level="Medium",
        os_category="macos",
        start_time=_START + timedelta(seconds=1),
    )
    if not exec_first:
        after = execute()
    manager.materialize_action_cohort(builder.seal())
    assert after.primary_thread is not None and child.identity.primary_thread is not None
    assert after.primary_thread.tid != child.identity.primary_thread.tid
    later = manager.create_thread(before.hostname, before.object_id)
    assert later.tid > max(after.primary_thread.tid, child.identity.primary_thread.tid)


@pytest.mark.parametrize("tamper", ["retired", "counter", "replacement"])
def test_exec_thread_plan_tampering_is_rejected(tamper: str) -> None:
    manager, before = _process()
    builder = manager.begin_action_cohort_materialization()
    after = builder.execute_process(
        before, image="/usr/bin/id", command_line="id", executed_at=_START + timedelta(seconds=1)
    )
    plan = builder.seal()
    execution = plan.process_executions[0]
    if tamper == "retired":
        execution = replace(execution, retired_threads=())
    elif tamper == "counter":
        execution = replace(execution, thread_counter=(before.hostname, 1))
    else:
        execution = replace(execution, after=replace(after, primary_thread=before.primary_thread))
    digest = manager.materialization_digest()
    with pytest.raises(StateError):
        manager.materialize_action_cohort(replace(plan, _process_executions=(execution,)))
    assert manager.materialization_digest() == digest


def test_exec_cannot_close_a_thread_before_it_started() -> None:
    manager, before = _process()
    manager.create_thread(
        before.hostname, before.object_id, start_time=_START + timedelta(seconds=2)
    )
    digest = manager.materialization_digest()
    with pytest.raises(StateError, match="thread preimage"):
        _execute(manager, before)
    assert manager.materialization_digest() == digest


def test_exec_retention_eviction_is_reversible(monkeypatch: pytest.MonkeyPatch) -> None:
    manager, before = _process()
    manager.create_thread(before.hostname, before.object_id, start_time=_START)
    first = _execute(manager, before)
    monkeypatch.setattr("evidenceforge.generation.state_manager._MAX_RETAINED_THREAD_IDENTITIES", 1)
    digest = manager.materialization_digest()
    builder = manager.begin_action_cohort_materialization()
    builder.execute_process(
        first, image="/usr/bin/true", command_line="true", executed_at=_START + timedelta(seconds=2)
    )
    plan = builder.seal()
    with manager.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert len(manager._ended_threads) <= 1
    assert manager.materialization_digest() == digest
    manager.materialize_action_cohort(plan)
    assert len(manager._ended_threads) <= 1
