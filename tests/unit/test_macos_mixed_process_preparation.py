# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mixed source preparation reads canonical intent without temporary publication."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.responsibility import ProcessResponsibility
from evidenceforge.formats.macos_endpoint_security import (
    ESAuditToken,
    decode_endpoint_security_record,
)
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_es_exec_preparation import _fixture, _prepare
from tests.unit.test_macos_process_relationship_projection import _family
from tests.unit.test_posix_job_control import _START


@pytest.mark.parametrize("terminal", [False, True])
def test_selected_second_birth_uses_authenticated_new_host_namespace(terminal: bool) -> None:
    state = StateManager()
    state.set_current_time(_START)
    builder = state.begin_action_cohort_materialization()
    root = builder.plan_process(
        system="new-mac",
        parent_pid=0,
        image="/sbin/launchd",
        command_line="launchd",
        username="root",
        integrity_level="System",
        os_category="macos",
        responsibility=ProcessResponsibility(None),
    )
    child = builder.plan_process(
        system="new-mac",
        parent_pid=root.identity.pid,
        parent_plan=root,
        image="/bin/sh",
        command_line="sh",
        username="casey",
        integrity_level="Medium",
        os_category="macos",
        start_time=_START + timedelta(seconds=1),
        responsibility=ProcessResponsibility(None),
    )
    if terminal:
        builder.terminate_process(child, end_time=_START + timedelta(seconds=2))
    cohort = builder.seal()
    before = state.materialization_digest()
    observed = (
        state.observe_planned_termination_relationships(cohort, process=child.identity)
        if terminal
        else state.observe_planned_process_relationships(cohort, process=child.identity)
    )
    assert observed.parent.parent == root.identity
    assert observed.parent.process == child.identity
    assert state.materialization_digest() == before


@pytest.mark.parametrize("offset", [-1, 0, 1])
@pytest.mark.parametrize("close", [False, True])
@pytest.mark.parametrize("restored", [False, True])
def test_fork_source_and_child_share_strictly_earlier_responsible_transition(
    offset: int, close: bool, restored: bool
) -> None:
    state, _, owner, subject = _family()
    if restored:
        recovered = StateManager()
        _restore_head(recovered, _capture_head(state))
        state = recovered
    at = _START + timedelta(seconds=10)
    builder = state.begin_action_cohort_materialization()
    if close:
        builder.terminate_process(owner, end_time=at + timedelta(seconds=offset))
        expected_owner = owner
    else:
        expected_owner = builder.execute_process(
            owner,
            image="/usr/bin/true",
            command_line="true",
            executed_at=at + timedelta(seconds=offset),
        )
    child = builder.fork_process(subject, forked_at=at)
    cohort = builder.seal()
    before = state.materialization_digest()
    source = state.observe_planned_fork_parent_relationships(cohort, child=child.identity)
    target = state.observe_planned_process_relationships(cohort, process=child.identity)
    assert source.parent.process == subject and target.parent.parent == subject
    for observed in (source, target):
        if close and offset < 0:
            assert observed.responsibility.reason == "exited"
            assert observed.responsibility.responsible == observed.parent.process
        else:
            assert observed.responsibility.responsible == (expected_owner if offset < 0 else owner)
    assert state.materialization_digest() == before
    assert state.get_process_identity_by_object_id(child.identity.object_id) is None
    with state.prepared_action_cohort_materialization(cohort) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
    assert state.materialization_digest() == before
    assert state.observe_planned_process_relationships(cohort, process=child.identity) == target
    state.materialize_action_cohort(cohort)
    if offset != 0:
        assert state.observe_process_relationships(child.identity, observed_at=at) == target
    with pytest.raises(StateError, match="stale"):
        state.observe_planned_process_relationships(cohort, process=child.identity)


@pytest.mark.parametrize("offset", [-1, 0, 1])
@pytest.mark.parametrize("reverse", [False, True])
def test_selected_exec_source_target_and_exit_observe_related_execution_at_same_boundary(
    offset: int, reverse: bool
) -> None:
    state, parent, owner, subject = _family()
    at = _START + timedelta(seconds=10)
    builder = state.begin_action_cohort_materialization()
    after = {}
    rows = [(owner, at + timedelta(seconds=offset)), (subject, at)]
    for identity, when in reversed(rows) if reverse else rows:
        after[identity.object_id] = builder.execute_process(
            identity,
            image="/usr/bin/true",
            command_line="true",
            executed_at=when,
        )
    builder.terminate_process(parent, end_time=at + timedelta(seconds=3))
    cohort = builder.seal()
    before = state.materialization_digest()
    with pytest.raises(StateError, match="selected execution"):
        state.observe_planned_execution_relationships(cohort)
    source = state.observe_planned_execution_relationships(cohort, process=subject, source=True)
    target = state.observe_planned_execution_relationships(cohort, process=after[subject.object_id])
    expected = after[owner.object_id] if offset < 0 else owner
    assert source.parent.process == subject
    assert target.parent.process == after[subject.object_id]
    assert source.responsibility.responsible == target.responsibility.responsible == expected
    # An unrelated terminal member with unknown responsibility stays unknown.
    with pytest.raises(StateError, match="known process facts"):
        state.observe_planned_termination_relationships(cohort, process=parent)
    assert state.materialization_digest() == before


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_exit_uses_related_parent_and_responsible_execution_only_when_earlier(offset: int) -> None:
    state, parent, owner, subject = _family()
    at = _START + timedelta(seconds=10)
    builder = state.begin_action_cohort_materialization()
    parents = {}
    for identity in (parent, owner):
        parents[identity.object_id] = builder.execute_process(
            identity,
            image="/usr/bin/true",
            command_line="true",
            executed_at=at + timedelta(seconds=offset),
        )
    builder.terminate_process(subject, end_time=at)
    cohort = builder.seal()
    before = state.materialization_digest()
    observed = state.observe_planned_termination_relationships(cohort, process=subject)
    assert observed.parent.parent == (parents[parent.object_id] if offset < 0 else parent)
    assert observed.responsibility.responsible == (
        parents[owner.object_id] if offset < 0 else owner
    )
    assert state.materialization_digest() == before
    state.materialize_action_cohort(cohort)
    assert observed.parent.process == subject


def test_related_service_drop_changes_responsible_credentials_in_exit_view() -> None:
    from tests.unit.test_macos_service_drop import _account, _child
    from tests.unit.test_process_responsibility import _launch, _reference

    state, owner = _child()
    root = state.get_process_identity(owner.hostname, owner.parent_pid)
    subject = _launch(state, root, second=4, responsibility=_reference(owner))
    builder = state.begin_action_cohort_materialization()
    after = builder.drop_macos_service_child_privileges(
        owner, service_account=_account(), dropped_at=_START + timedelta(seconds=5)
    )
    builder.terminate_process(subject, end_time=_START + timedelta(seconds=6))
    cohort = builder.seal()
    before = state.materialization_digest()
    observed = state.observe_planned_termination_relationships(cohort, process=subject)
    assert observed.responsibility.responsible == after
    assert observed.responsibility.responsible.principal == "_sshd"
    assert state.materialization_digest() == before


@pytest.mark.parametrize("providers", ["rr", "ii", "ri", "ir"])
def test_native_exec_freezes_mixed_relationships_with_identical_counter_retry(
    providers: str,
) -> None:
    fixture = _fixture(providers=providers)
    state = fixture.owner.state
    original = fixture.cohort.process_executions[0]
    owner = state.get_process_identity_by_object_id(
        original.target.responsibility.responsible.object_id
    )
    builder = state.begin_action_cohort_materialization()
    related = builder.execute_process(
        owner,
        image="/usr/bin/true",
        command_line="true",
        executed_at=original.after.execution_started_at - timedelta(microseconds=1),
    )
    after = builder.execute_process(
        original.target,
        image=original.after.image,
        command_line=original.after.command_line,
        executed_at=original.after.execution_started_at,
        arguments=original.after.arguments,
        environment=original.after.environment,
        image_security=original.after.image_security,
        exec_image=original.after.exec_image,
        exec_script=original.after.exec_script,
        executable_version=original.after.executable_version,
        execution_directory=original.after.execution_directory,
    )
    fixture.cohort = builder.seal()
    fixture.after = replace(fixture.after, process=after)
    before = state.materialization_digest()
    with _prepare(fixture) as prepared:
        frozen = prepared.ndjson
        native = decode_endpoint_security_record(frozen)
        assert native.process.responsible_audit_token.pidversion == related.audit_pid_version
        assert (
            native.event.exec.target.responsible_audit_token
            == native.process.responsible_audit_token
        )
    assert state.materialization_digest() == before
    with _prepare(fixture) as prepared:
        assert prepared.ndjson == frozen
        prepared.collector.commit_no_fail()
    state.materialize_action_cohort(fixture.cohort)
    assert fixture.owner.collectors.retained_native_projection(fixture.delivery) == frozen


def test_mixed_native_preparation_rejects_transitioning_its_observing_collector() -> None:
    fixture = _fixture()
    state = fixture.owner.state
    original = fixture.cohort.process_executions[0]
    builder = state.begin_action_cohort_materialization()
    builder.execute_process(
        fixture.collector,
        image="/usr/bin/true",
        command_line="true",
        executed_at=original.after.execution_started_at + timedelta(seconds=1),
    )
    after = builder.execute_process(
        original.target,
        image=original.after.image,
        command_line=original.after.command_line,
        executed_at=original.after.execution_started_at,
        executable_version=original.after.executable_version,
    )
    fixture.cohort = builder.seal()
    fixture.after = replace(fixture.after, process=after)
    before = state.materialization_digest()
    with pytest.raises(StateError, match="observing collector"):
        with _prepare(fixture):
            pass
    assert state.materialization_digest() == before
    assert fixture.owner.collectors.retained_native_projection(fixture.delivery) is None


def test_mixed_preparation_preserves_canonical_exec_dependency_rejection() -> None:
    state, _, _, subject = _family()
    builder = state.begin_action_cohort_materialization()
    builder.execute_process(
        subject,
        image="/usr/bin/true",
        command_line="true",
        executed_at=_START + timedelta(seconds=8),
    )
    builder.fork_process(subject, forked_at=_START + timedelta(seconds=9))
    before = state.materialization_digest()
    with pytest.raises(StateError, match="separate cohort"):
        builder.seal()
    assert state.materialization_digest() == before


@pytest.mark.parametrize("installed", [False, True])
@pytest.mark.parametrize("filtered", [False, True])
def test_native_fork_source_and_child_use_same_mixed_responsible_snapshot(
    installed: bool, filtered: bool
) -> None:
    from tests.unit.test_macos_es_fork_preparation import _fixture as fork_fixture
    from tests.unit.test_macos_es_fork_preparation import _prepare as prepare_fork

    fixture = fork_fixture(installed=installed, status="filtered" if filtered else "visible")
    state = fixture.owner.state
    owner = state.get_process_identity_by_object_id(
        fixture.parent.process.responsibility.responsible.object_id
    )
    builder = state.begin_action_cohort_materialization()
    related = builder.execute_process(
        owner,
        image="/usr/bin/true",
        command_line="true",
        executed_at=fixture.child.observed_at - timedelta(microseconds=1),
    )
    child = builder.fork_process(fixture.parent.process, forked_at=fixture.child.observed_at)
    fixture.cohort = builder.seal()
    fixture.child = replace(fixture.child, process=child.identity)
    before = state.materialization_digest()
    with prepare_fork(fixture) as prepared:
        native = decode_endpoint_security_record(prepared.ndjson)
        assert (
            native.process.responsible_audit_token
            == ESAuditToken.from_process_identity(related).as_native_array()
        )
        assert (
            native.event.fork.child.responsible_audit_token
            == native.process.responsible_audit_token
        )
    assert state.materialization_digest() == before
    fixture.owner.collectors.cancel(fixture.delivery)


@pytest.mark.parametrize("installed", [False, True])
@pytest.mark.parametrize("filtered", [False, True])
def test_native_exit_uses_mixed_owner_exec_without_extra_native_row(
    installed: bool, filtered: bool
) -> None:
    from tests.unit.test_macos_es_exit_preparation import _fixture as exit_fixture
    from tests.unit.test_macos_es_exit_preparation import _prepare as prepare_exit

    fixture = exit_fixture(installed=installed, status="filtered" if filtered else "visible")
    state = fixture.owner.state
    owner = state.get_process_identity_by_object_id(
        fixture.process.process.responsibility.responsible.object_id
    )
    builder = state.begin_action_cohort_materialization()
    related = builder.execute_process(
        owner,
        image="/usr/bin/true",
        command_line="true",
        executed_at=fixture.process.observed_at - timedelta(microseconds=1),
    )
    terminal = fixture.cohort.process_terminations[0]
    builder.terminate_process(
        terminal.identity, end_time=terminal.end_time, exit_outcome=terminal.exit_outcome
    )
    fixture.cohort = builder.seal()
    before = state.materialization_digest()
    with prepare_exit(fixture) as prepared:
        native = decode_endpoint_security_record(prepared.ndjson)
        assert native.process.responsible_audit_token.pidversion == related.audit_pid_version
        assert prepared.ndjson.count("\n") == 1
    assert state.materialization_digest() == before
    fixture.owner.collectors.cancel(fixture.delivery)
