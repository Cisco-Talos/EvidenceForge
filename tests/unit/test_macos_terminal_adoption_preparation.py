# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Exit preparation composes with authenticated surviving-child adoption."""

from datetime import timedelta

import pytest

from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.events.responsibility import ProcessResponsibility
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.actions.macos_launch_item import (
    macos_system_job_unload_completion_plan,
)
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import StateManager
from tests.unit.test_macos_es_exit_preparation import _fixture, _prepare
from tests.unit.test_macos_launch_activation import _activation, _process, _setup
from tests.unit.test_macos_process_relationship_projection import _family
from tests.unit.test_posix_job_control import _START
from tests.unit.test_process_responsibility import _launch, _reference


def test_production_job_group_cleanup_can_freeze_exit_with_surviving_child_adoption() -> None:
    state, registry, authority, adapter, job = _setup()
    process = _process(
        state, job, new_posix_session=True, responsibility=ProcessResponsibility(None)
    )
    authority.materialize_process_service_composite(
        process, adapter.prepare_service_publication(_activation(registry, authority, job, process))
    )
    parent = process.identity
    child_plan = _process(
        state,
        job,
        parent_pid=parent.pid,
        new_posix_session=True,
        start_time=parent.started_at + timedelta(seconds=2),
    )
    authority.materialize_process(child_plan)
    child = child_plan.identity
    descendant_plan = _process(
        state,
        job,
        parent_pid=child.pid,
        start_time=parent.started_at + timedelta(seconds=3),
    )
    authority.materialize_process(descendant_plan)
    descendant = descendant_plan.identity
    plan = macos_system_job_unload_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=parent.started_at + timedelta(seconds=10),
        action_id="native-adopting-unload",
    )
    before = state.materialization_digest()
    observed = state.observe_planned_termination_relationships(plan.cohort, process=parent)
    assert observed.parent.process == parent
    assert observed.parent.parent.pid == 1
    assert state.materialization_digest() == before
    assert state.get_process_identity_by_object_id(child.object_id) == child
    authority.materialize_process_group_service_closure_composite(
        plan.cohort, plan.group, adapter.prepare_service_process_closure(plan.closure)
    )
    assert state.get_process_identity_by_object_id(child.object_id).parent_pid == 1
    assert state.get_process_identity_by_object_id(descendant.object_id) == descendant
    assert observed.parent.process == parent
    assert registry.get_service_instance(job.instance_identity.object_id).closed_at is not None


@pytest.mark.parametrize("offset", [0, 1])
@pytest.mark.parametrize("restore", [False, True])
def test_exit_observes_parent_and_responsible_adoption_only_before_terminal_boundary(
    offset: int, restore: bool
) -> None:
    state, ancestor, _, _ = _family()
    middle = _launch(state, ancestor, second=5)
    subject = _launch(state, middle, second=6, responsibility=_reference(middle))
    at = _START + timedelta(seconds=7)
    if restore:
        restored = StateManager()
        _restore_head(restored, _capture_head(state))
        state = restored
    root = state.get_process_identity(subject.hostname, 1)
    builder = state.begin_action_cohort_materialization()
    adopted = builder.adopt_process_after_parent_exit(middle, adopter=root, changed_at=at)
    # The family's original child also survives this ancestor's exit.
    for child in state.get_posix_group_members(ancestor.job_control):
        if child.parent_pid == ancestor.pid and child != middle:
            builder.adopt_process_after_parent_exit(child, adopter=root, changed_at=at)
    builder.terminate_process(ancestor, end_time=at)
    builder.terminate_process(subject, end_time=at + timedelta(seconds=offset))
    cohort = builder.seal()
    before = state.materialization_digest()
    observed = state.observe_planned_termination_relationships(cohort, process=subject)
    expected = adopted if offset else middle
    assert observed.parent.parent == expected
    assert observed.responsibility.responsible == expected
    assert observed.parent.process == subject
    assert state.materialization_digest() == before
    state.materialize_action_cohort(cohort)
    assert state.get_process_identity_by_object_id(middle.object_id) == adopted
    assert observed.parent.parent == expected


@pytest.mark.parametrize("installed", [False, True])
@pytest.mark.parametrize("filtered", [False, True])
def test_native_exit_freezes_with_surviving_fork_and_retains_exact_retry_bytes(
    installed: bool, filtered: bool
) -> None:
    fixture = _fixture(installed=installed, status="filtered" if filtered else "visible")
    state = fixture.owner.state
    subject = fixture.process.process
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(
        subject, forked_at=subject.execution_started_at + timedelta(seconds=1)
    )
    state.materialize_action_cohort(builder.seal())
    builder = state.begin_action_cohort_materialization()
    adopted = builder.adopt_process_after_parent_exit(
        child.identity,
        adopter=state.get_process_identity(subject.hostname, 1),
        changed_at=fixture.process.observed_at,
    )
    builder.terminate_process(
        subject, end_time=fixture.process.observed_at, exit_outcome=PosixProcessExit(exit_code=0)
    )
    fixture.cohort = builder.seal()
    before = state.materialization_digest()
    with _prepare(fixture) as prepared:
        frozen = prepared.ndjson
        assert decode_endpoint_security_record(frozen).process.audit_token.pid == subject.pid
    assert state.materialization_digest() == before
    with _prepare(fixture) as prepared:
        assert prepared.ndjson == frozen
        prepared.collector.commit_no_fail()
    state.materialize_action_cohort(fixture.cohort)
    assert state.get_process_identity_by_object_id(child.identity.object_id) == adopted
    assert fixture.owner.collectors.retained_native_projection(fixture.delivery) == frozen


def test_terminal_preparation_accepts_unrelated_activity_bookkeeping() -> None:
    state, _, owner, subject = _family()
    at = subject.started_at + timedelta(seconds=3)
    builder = state.begin_action_cohort_materialization()
    builder.patch_process_activity(owner, activity_time=at)
    builder.terminate_process(subject, end_time=at)
    cohort = builder.seal()
    before = state.materialization_digest()
    observed = state.observe_planned_termination_relationships(cohort, process=subject)
    assert observed == state.observe_process_relationships(subject, observed_at=at)
    assert state.materialization_digest() == before


@pytest.mark.parametrize("installed", [False, True])
def test_native_exit_batch_preserves_surviving_descendant_without_extra_exit(
    installed: bool,
) -> None:
    from tests.unit.test_macos_es_exit_batch_preparation import _group
    from tests.unit.test_macos_es_exit_batch_preparation import _prepare as prepare_group

    group = _group(installed)
    state = group.owner.state
    first = group.records[0].process.process
    builder = state.begin_action_cohort_materialization()
    survivor = builder.fork_process(first, forked_at=first.started_at + timedelta(seconds=0.1))
    state.materialize_action_cohort(builder.seal())
    builder = state.begin_action_cohort_materialization()
    adopted = builder.adopt_process_after_parent_exit(
        survivor.identity,
        adopter=state.get_process_identity(first.hostname, 1),
        changed_at=group.records[0].process.observed_at,
    )
    for terminal in group.cohort.process_terminations:
        builder.terminate_process(
            terminal.identity, end_time=terminal.end_time, exit_outcome=terminal.exit_outcome
        )
    group.cohort = builder.seal()
    before = state.materialization_digest()
    with prepare_group(group) as prepared:
        frozen = prepared.ndjson
        rows = tuple(decode_endpoint_security_record(line) for line in frozen)
        assert len(rows) == 3
        assert survivor.identity.pid not in {row.process.audit_token.pid for row in rows}
        assert state.materialization_digest() == before
        prepared.collector.commit_no_fail()
    state.materialize_action_cohort(group.cohort)
    assert state.get_process_identity_by_object_id(survivor.identity.object_id) == adopted
    assert group.owner.collectors.retained_native_batch_projection(group.delivery) == frozen
