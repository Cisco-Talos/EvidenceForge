# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented ordered process chains share one canonical commit and rollback."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_descriptor_state import _table
from tests.unit.test_macos_process_relationship_projection import _family
from tests.unit.test_posix_job_control import _START


@pytest.mark.parametrize("fork", [False, True])
@pytest.mark.parametrize("close", [False, True])
@pytest.mark.parametrize("restored", [False, True])
def test_ordered_execution_preserves_each_epoch_and_one_atomic_result(
    fork: bool, close: bool, restored: bool
) -> None:
    state, _, _, parent = _family()
    table = replace(_table(), hostname=parent.hostname, observed_at=_START + timedelta(seconds=5))
    builder = state.begin_action_cohort_materialization()
    builder.record_macos_descriptors(parent, table=table)
    state.materialize_action_cohort(builder.seal())
    if restored:
        recovered = StateManager()
        _restore_head(recovered, _capture_head(state))
        state = recovered
    before = state.materialization_digest()
    builder = state.begin_action_cohort_materialization()
    birth = builder.fork_process(parent, forked_at=_START + timedelta(seconds=10)) if fork else None
    subject = birth.identity if birth else parent
    after = builder.execute_process(
        birth if birth else parent,
        image="/usr/bin/invented-worker",
        command_line="invented-worker",
        executed_at=_START + timedelta(seconds=11),
    )
    if close:
        builder.terminate_process(
            after,
            end_time=_START + timedelta(seconds=12),
            exit_outcome=PosixProcessExit(exit_code=7),
        )
    cohort = builder.seal()
    assert state.materialization_digest() == before
    source = state.observe_planned_execution_relationships(cohort, source=True)
    target = state.observe_planned_execution_relationships(cohort)
    assert source.parent.process == subject
    assert target.parent.process == after
    if close:
        terminal = state.observe_planned_termination_relationships(cohort)
        assert terminal.parent.process == after
    with state.prepared_action_cohort_materialization(cohort) as prepared:
        result = prepared.expected_result
        prepared.certify_composite_commit(result)
        prepared.apply_provisional()
        if close:
            assert (after.hostname, after.pid) not in state.state.running_processes
        else:
            assert state.get_process_identity(after.hostname, after.pid) == after
    assert state.materialization_digest() == before
    assert state.observe_planned_execution_relationships(cohort) == target
    result = state.materialize_action_cohort(cohort)
    assert result.executed_processes == (after,)
    assert result.terminated_processes == ((after,) if close else ())
    assert result.committed_version == result.prior_version + 1
    if birth:
        assert result.started_processes == (subject,)
        assert (
            state.get_process_identity_at(subject.hostname, subject.pid, subject.started_at)
            == subject
        )
        assert (
            state.process_descriptors_at(subject, event_time=subject.started_at).bindings
            == table.bindings
        )
    assert (
        state.get_process_identity_at(after.hostname, after.pid, after.execution_started_at)
        == after
    )
    assert state.process_descriptors_at(
        after, event_time=after.execution_started_at
    ) == table.after_exec(after.execution_started_at)
    recovered = StateManager()
    _restore_head(recovered, _capture_head(state))
    assert (
        recovered.get_process_identity_at(after.hostname, after.pid, after.execution_started_at)
        == after
    )
    assert recovered.materialization_digest() == state.materialization_digest()
    with pytest.raises(StateError, match="stale"):
        state.materialize_action_cohort(cohort)


@pytest.mark.parametrize("offset", [-1, 0])
def test_ordered_close_requires_strictly_later_exact_execution(offset: int) -> None:
    state, _, _, parent = _family()
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        parent, image="/bin/true", command_line="true", executed_at=_START + timedelta(seconds=10)
    )
    with pytest.raises(StateError, match="follow its exact execution"):
        builder.terminate_process(after, end_time=_START + timedelta(seconds=10 + offset))


def test_staged_exec_rejects_nonfork_birth_and_foreign_member() -> None:
    state, _, _, parent = _family()
    builder = state.begin_action_cohort_materialization()
    birth = builder.plan_process(
        system=parent.hostname,
        parent_pid=parent.pid,
        image="/bin/sh",
        command_line="sh",
        username=parent.principal,
        integrity_level="Medium",
        os_category="macos",
        start_time=_START + timedelta(seconds=10),
    )
    with pytest.raises(StateError, match="authenticated fork"):
        builder.execute_process(
            birth,
            image="/bin/true",
            command_line="true",
            executed_at=_START + timedelta(seconds=11),
        )
    other = state.begin_action_cohort_materialization()
    fork = other.fork_process(parent, forked_at=_START + timedelta(seconds=10))
    with pytest.raises(StateError, match="another builder"):
        builder.execute_process(
            fork, image="/bin/true", command_line="true", executed_at=_START + timedelta(seconds=11)
        )


def test_close_cannot_select_preexec_identity_for_ordered_lifetime() -> None:
    state, _, _, parent = _family()
    builder = state.begin_action_cohort_materialization()
    builder.execute_process(
        parent, image="/bin/true", command_line="true", executed_at=_START + timedelta(seconds=10)
    )
    builder.terminate_process(parent, end_time=_START + timedelta(seconds=11))
    with pytest.raises(StateError, match="separate cohort"):
        state.validate_action_cohort_materialization(builder.seal())


@pytest.mark.parametrize("operation", ["exec", "close"])
def test_failure_after_primitive_write_restores_full_chain(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    state, _, _, parent = _family()
    builder = state.begin_action_cohort_materialization()
    birth = builder.fork_process(parent, forked_at=_START + timedelta(seconds=10))
    after = builder.execute_process(
        birth, image="/bin/true", command_line="true", executed_at=_START + timedelta(seconds=11)
    )
    builder.terminate_process(after, end_time=_START + timedelta(seconds=12))
    plan = builder.seal()
    before = state.materialization_digest()
    method_name = (
        "_commit_prevalidated_process_termination_materialization"
        if operation == "close"
        else "_commit_prevalidated_action_cohort"
    )
    original = getattr(StateManager, method_name)

    def fail(*args: object, **kwargs: object) -> object:
        original(*args, **kwargs)
        raise RuntimeError("invented failure after write")

    with monkeypatch.context() as patch:
        patch.setattr(StateManager, method_name, fail)
        with pytest.raises(RuntimeError, match="invented failure"):
            state.materialize_action_cohort(plan)
    assert state.materialization_digest() == before
    state.materialize_action_cohort(plan)
    assert (
        state.get_process_identity_at(after.hostname, after.pid, after.execution_started_at)
        == after
    )


def test_two_ordered_children_keep_independent_execution_and_thread_owners() -> None:
    state, _, _, parent = _family()
    builder = state.begin_action_cohort_materialization()
    children = []
    for second in (10, 20):
        birth = builder.fork_process(parent, forked_at=_START + timedelta(seconds=second))
        after = builder.execute_process(
            birth,
            image="/bin/true",
            command_line="true",
            executed_at=_START + timedelta(seconds=second + 1),
        )
        builder.terminate_process(after, end_time=_START + timedelta(seconds=second + 2))
        children.append((birth.identity, after))
    cohort = builder.seal()
    snapshots = [
        state.observe_planned_termination_relationships(cohort, process=after)
        for _, after in children
    ]
    assert len({identity.primary_thread.tid for pair in children for identity in pair}) == 4
    assert len({identity.audit_pid_version for pair in children for identity in pair}) == 4
    result = state.materialize_action_cohort(cohort)
    assert result.terminated_processes == tuple(after for _, after in children)
    for (birth, after), snapshot in zip(children, snapshots, strict=True):
        assert state.get_process_identity_at(birth.hostname, birth.pid, birth.started_at) == birth
        historical = state.observe_process_relationships(
            after, observed_at=after.execution_started_at
        )
        assert historical.parent.parent == snapshot.parent.parent
        assert historical.responsibility.responsible == snapshot.responsibility.responsible


def test_changed_postexec_close_snapshot_cannot_reuse_sealed_cohort() -> None:
    state, _, _, parent = _family()
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        parent, image="/bin/true", command_line="true", executed_at=_START + timedelta(seconds=10)
    )
    builder.terminate_process(after, end_time=_START + timedelta(seconds=11))
    cohort = builder.seal()
    changed = replace(
        cohort,
        _process_terminations=(replace(cohort.process_terminations[0], post_execution=parent),),
    )
    before = state.materialization_digest()
    with pytest.raises(StateError, match="integrity|semantic|exact earlier execution"):
        state.materialize_action_cohort(changed)
    assert state.materialization_digest() == before
