# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""State-to-lifecycle action-cohort projection and binding tests."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.lifecycle import (
    LifecycleTransition,
    SessionEndPlan,
)
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import (
    LifecycleActionCohortAdmissionToken,
    LifecycleActionCohortReceipt,
    LifecycleProcessStartRequest,
    LifecycleRegistry,
    LifecycleSessionStartRequest,
    LifecycleSubjectClosureControl,
)
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import (
    ActionCohortMaterializationPlan,
    ActionCohortSessionMetadataState,
    StateManager,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import stable_uuid

_START = datetime(2026, 8, 17, 14, 0, tzinfo=UTC)


def _authority(
    state: StateManager,
    registry: LifecycleRegistry | None = None,
) -> tuple[GeneratorLifecycleAuthority, LifecycleRegistry]:
    resolved_registry = registry or LifecycleRegistry(shard_count=4)
    return (
        GeneratorLifecycleAuthority(
            state,
            LifecycleShadow(state, resolved_registry),
            shard_count=4,
        ),
        resolved_registry,
    )


def _closed_staged_cohort(state: StateManager) -> ActionCohortMaterializationPlan:
    state.set_current_time(_START)
    builder = state.begin_action_cohort_materialization()
    session = builder.plan_session(
        username="operator",
        system="LINUX-01",
        logon_type=2,
        source_ip="-",
        session_kind="interactive",
        start_time=_START,
    )
    parent = builder.plan_process(
        system="LINUX-01",
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
    child = builder.plan_process(
        system="LINUX-01",
        parent_pid=parent.identity.pid,
        image="/usr/bin/id",
        command_line="id",
        username="operator",
        integrity_level="Medium",
        os_category="linux",
        logon_id=session.identity.logon_id,
        start_time=_START + timedelta(seconds=2),
        require_session=True,
        parent_plan=parent,
        session_plan=session,
        parent_activity_time=_START + timedelta(seconds=2),
    )
    builder.bind_session_processes(
        session,
        shell_plan=parent,
        process_tree_root_plan=parent,
    )
    builder.transition_session_metadata(
        session,
        ActionCohortSessionMetadataState(
            source_ready_time=_START + timedelta(seconds=3),
            closure_owned_by_bundle=True,
            login_occurrence_emitted=True,
            end_plan=SessionEndPlan(
                canonical_end=_START + timedelta(seconds=20),
                authority="action_bundle",
            ),
        ),
    )
    builder.patch_process_activity(child, _START + timedelta(seconds=4))
    builder.patch_session_activity(session, _START + timedelta(seconds=4))
    builder.terminate_process(
        child,
        end_time=_START + timedelta(seconds=5),
        parent_activity_time=_START + timedelta(seconds=5),
    )
    builder.terminate_process(parent, end_time=_START + timedelta(seconds=6))
    builder.terminalize_session(session, end_time=_START + timedelta(seconds=7))
    return builder.seal()


def _semantic_id(
    plan: ActionCohortMaterializationPlan,
    category: str,
    source_ordinal: int,
    object_id: str,
    role: str,
) -> str:
    return stable_uuid(
        "lifecycle-authority-action-cohort",
        plan.semantic_id,
        category,
        source_ordinal,
        object_id,
        role,
    )


def test_action_cohort_projects_exact_ordered_state_members_and_read_only_patches() -> None:
    state = StateManager()
    authority, registry = _authority(state)
    plan = _closed_staged_cohort(state)
    state_digest = state.materialization_digest()
    registry_census = registry.census()

    assert plan.session_metadata_patches is plan._session_metadata
    assert plan.process_activity_patches is plan._process_activity
    assert plan.session_activity_patches is plan._session_activity
    assert plan.session_metadata_patches[0].after.end_plan is not None

    request = authority.action_cohort_request(plan)
    session, parent, child = plan.sessions[0], plan.processes[0], plan.processes[1]

    assert request.state_publication_token == plan.publication_token
    assert len(request.operations) == 11
    assert [type(operation) for operation in request.operations] == [
        LifecycleSessionStartRequest,
        LifecycleProcessStartRequest,
        LifecycleProcessStartRequest,
        LifecycleTransition,
        LifecycleTransition,
        LifecycleTransition,
        LifecycleTransition,
        LifecycleTransition,
        LifecycleSubjectClosureControl,
        LifecycleSubjectClosureControl,
        LifecycleSubjectClosureControl,
    ]
    assert [
        operation.identity.object_id
        for operation in request.operations[:3]
        if isinstance(operation, (LifecycleSessionStartRequest, LifecycleProcessStartRequest))
    ] == [
        session.identity.object_id,
        parent.identity.object_id,
        child.identity.object_id,
    ]
    process_start = request.operations[2]
    assert isinstance(process_start, LifecycleProcessStartRequest)
    assert process_start.identity.parent_object_id == parent.identity.object_id
    assert process_start.membership.session_object_id == session.identity.object_id

    dependents = request.operations[3:8]
    assert [
        (operation.subject.kind, operation.subject.object_id, operation.canonical_time)
        for operation in dependents
        if isinstance(operation, LifecycleTransition)
    ] == [
        ("process", parent.identity.object_id, _START + timedelta(seconds=2)),
        ("session", session.identity.object_id, _START + timedelta(seconds=3)),
        ("process", child.identity.object_id, _START + timedelta(seconds=4)),
        ("session", session.identity.object_id, _START + timedelta(seconds=4)),
        ("process", parent.identity.object_id, _START + timedelta(seconds=5)),
    ]
    metadata = request.operations[4]
    assert isinstance(metadata, LifecycleTransition)
    assert metadata.canonical_time != _START + timedelta(seconds=20)
    assert metadata.transition_id == _semantic_id(
        plan,
        "session-metadata",
        0,
        session.identity.object_id,
        "transition",
    )

    closures = request.operations[8:]
    assert [
        (operation.barrier.subject.kind, operation.barrier.subject.object_id)
        for operation in closures
        if isinstance(operation, LifecycleSubjectClosureControl)
    ] == [
        ("process", child.identity.object_id),
        ("process", parent.identity.object_id),
        ("session", session.identity.object_id),
    ]
    assert authority.action_cohort_request(plan) == request
    assert state.materialization_digest() == state_digest
    assert registry.census() == registry_census


def test_action_cohort_preparation_and_binding_reject_foreign_tamper_and_reorder() -> None:
    state = StateManager()
    authority, registry = _authority(state)
    plan = _closed_staged_cohort(state)
    request = authority.action_cohort_request(plan)
    state_digest = state.materialization_digest()
    registry_census = registry.census()

    token = authority.prepare_action_cohort(plan)
    assert type(token) is LifecycleActionCohortAdmissionToken
    assert token.request == request
    assert authority.authenticates_action_cohort_binding(plan, token)
    assert state.materialization_digest() == state_digest
    assert registry.census() == registry_census

    foreign_authority, _foreign_registry = _authority(state)
    foreign_state = StateManager()
    foreign_state.set_current_time(_START)
    cross_owner, _cross_registry = _authority(foreign_state)
    assert not foreign_authority.authenticates_action_cohort_binding(plan, token)
    assert not cross_owner.authenticates_action_cohort_binding(plan, token)
    assert not authority.authenticates_action_cohort_binding(
        replace(plan, _semantic_id="0" * 64),
        token,
    )
    assert not authority.authenticates_action_cohort_binding(
        plan,
        replace(
            token,
            request=replace(token.request, state_publication_token="foreign-state-token"),
        ),
    )
    reordered = replace(
        plan,
        _process_terminations=tuple(reversed(plan.process_terminations)),
    )
    with pytest.raises(StateError, match="integrity"):
        authority.action_cohort_request(reordered)

    with registry.claimed_action_cohort(token) as prepared:
        receipt = prepared.commit_no_fail()
    assert type(receipt) is LifecycleActionCohortReceipt
    assert authority.authenticates_action_cohort_binding(plan, receipt)
    assert not foreign_authority.authenticates_action_cohort_binding(plan, receipt)
    assert not authority.authenticates_action_cohort_binding(
        plan,
        replace(receipt, plan_digest="0" * 64),
    )


def test_action_cohort_staged_start_requires_exact_live_parent_and_session_owners() -> None:
    state = StateManager()
    state.set_current_time(_START)
    logon_id = state.create_session(
        "operator",
        "LINUX-02",
        2,
        "-",
        start_time=_START,
        session_kind="interactive",
    )
    state.set_current_time(_START + timedelta(seconds=1))
    parent_pid = state.create_process(
        "LINUX-02",
        0,
        "/usr/bin/bash",
        "bash -l",
        "operator",
        "Medium",
        logon_id=logon_id,
    )
    session = state.get_session_identity(logon_id)
    parent = state.get_process_identity("LINUX-02", parent_pid)
    assert session is not None and parent is not None

    authority, _registry = _authority(state)
    authority.bootstrap_active_state()
    builder = state.begin_action_cohort_materialization()
    child = builder.plan_process(
        system="LINUX-02",
        parent_pid=parent_pid,
        image="/usr/bin/id",
        command_line="id",
        username="operator",
        integrity_level="Medium",
        os_category="linux",
        logon_id=logon_id,
        start_time=_START + timedelta(seconds=2),
        require_session=True,
    )
    builder.patch_process_activity(parent, _START + timedelta(seconds=3))
    builder.patch_session_activity(session, _START + timedelta(seconds=3))
    builder.terminate_process(
        child,
        end_time=_START + timedelta(seconds=4),
        parent_activity_time=_START + timedelta(seconds=4),
    )
    plan = builder.seal()

    request = authority.action_cohort_request(plan)
    start = request.operations[0]
    assert isinstance(start, LifecycleProcessStartRequest)
    assert start.identity.object_id == child.identity.object_id
    assert start.identity.parent_object_id == parent.object_id
    assert start.membership.session_object_id == session.object_id
    assert [
        operation.subject.object_id
        for operation in request.operations[1:4]
        if isinstance(operation, LifecycleTransition)
    ] == [parent.object_id, session.object_id, parent.object_id]

    missing_owner_authority, _missing_registry = _authority(state)
    with pytest.raises(StateError, match="registered|registry|lifecycle"):
        missing_owner_authority.action_cohort_request(plan)


def test_action_cohort_projection_enforces_256_operation_cap_without_mutation() -> None:
    state = StateManager()
    state.set_current_time(_START)
    authority, registry = _authority(state)
    state_digest = state.materialization_digest()
    registry_census = registry.census()

    def cohort(process_count: int) -> ActionCohortMaterializationPlan:
        builder = state.begin_action_cohort_materialization()
        for ordinal in range(process_count):
            process = builder.plan_process(
                system="LINUX-CAP",
                parent_pid=0,
                image="/usr/bin/true",
                command_line="true",
                username="root",
                integrity_level="High",
                os_category="linux",
                start_time=_START + timedelta(microseconds=ordinal),
                fixed_pid=20_000 + ordinal,
            )
            builder.patch_process_activity(
                process,
                _START + timedelta(seconds=1, microseconds=ordinal),
            )
        return builder.seal()

    accepted = authority.action_cohort_request(cohort(128))
    assert len(accepted.operations) == 256
    with pytest.raises(StateError, match="too many lifecycle operations"):
        authority.action_cohort_request(cohort(129))

    assert state.materialization_digest() == state_digest
    assert registry.census() == registry_census


def test_action_cohort_binding_authenticator_is_total_for_untrusted_objects() -> None:
    state = StateManager()
    authority, _registry = _authority(state)
    plan = _closed_staged_cohort(state)

    class Evil:
        def __getattribute__(self, name: str) -> object:
            raise AssertionError(f"untrusted attribute access: {name}")

        def __repr__(self) -> str:
            raise AssertionError("untrusted repr")

    assert not authority.authenticates_action_cohort_binding(Evil(), Evil())
    assert not authority.authenticates_action_cohort_binding(plan, Evil())
