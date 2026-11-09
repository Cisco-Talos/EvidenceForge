# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit unload completion uses shared closure ownership without deleting files."""

from datetime import timedelta

import pytest

from evidenceforge.generation.actions.macos_launch_item import (
    macos_system_job_unload_completion_plan,
)
from evidenceforge.generation.checkpoints.lifecycle_head import _capture, _restore
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_launch_activation import _activation, _process, _setup
from tests.unit.test_macos_launch_file import _manager
from tests.unit.test_macos_launch_registration import _START


def test_dormant_unload_preserves_file_and_allocates_no_process() -> None:
    runtime = _manager()
    state, registry, _authority, adapter, job = _setup(runtime)
    before = state.materialization_digest()
    at = _START + timedelta(seconds=10)
    plan = macos_system_job_unload_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=at,
        action_id="unload-worker",
    )
    assert plan.process is None
    assert state.materialization_digest() == before
    token = adapter.prepare_service_process_closure(plan.closure)
    with adapter.claimed_service_process_closure(token) as prepared:
        prepared.commit_no_fail()
    assert registry.get_service_instance(job.instance_identity.object_id).closed_at == at
    assert state.materialization_digest() == before
    plist = job.instance_identity.launchd_job.plist
    assert runtime.resolve_record(plist.hostname, plist.principal, plist.native_path, "macos")
    del prepared
    restored = LifecycleRegistry(shard_count=8)
    _restore(restored, _capture(registry))
    assert restored.get_service_instance(job.instance_identity.object_id).closed_at == at


@pytest.mark.parametrize("removed", [False, True])
def test_active_unload_closes_exact_job_process_and_rejects_later_activation(removed: bool) -> None:
    runtime = _manager()
    state, registry, authority, adapter, job = _setup(runtime)
    process = _process(state, job)
    activation = _activation(registry, authority, job, process)
    authority.materialize_process_service_composite(
        process, adapter.prepare_service_publication(activation)
    )
    plist = job.instance_identity.launchd_job.plist
    if removed:
        runtime.registry.withdraw_execution_path(
            runtime.resolve_record(plist.hostname, plist.principal, plist.native_path, "macos"),
            _START + timedelta(seconds=2),
        )
    at = _START + timedelta(seconds=10)
    plan = macos_system_job_unload_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=at,
        action_id="unload-worker",
    )
    assert plan.process.identity.object_id == process.identity.object_id
    authority.materialize_process_service_closure_composite(
        plan.process, adapter.prepare_service_process_closure(plan.closure)
    )
    assert state.get_process("MAC-A", process.identity.pid) is None
    assert registry.get_process(process.identity.object_id).closed_at == at
    assert registry.get_service_instance(job.instance_identity.object_id).closed_at == at
    assert (
        registry.service_process_binding(activation.process_bindings[0].binding_id).closed_at == at
    )
    assert (
        bool(runtime.resolve_record(plist.hostname, plist.principal, plist.native_path, "macos"))
        is not removed
    )
    assert state.get_process("MAC-A", 1) is not None
    state.set_current_time(at + timedelta(seconds=1))
    with pytest.raises(StateError, match="unloaded job"):
        _activation(registry, authority, job, _process(state, job))


def test_unload_after_process_exit_uses_only_dormant_service_closure() -> None:
    from tests.unit.test_process_service_lifecycle_authority import _closure_request

    state, registry, authority, adapter, job = _setup()
    process = _process(state, job)
    activation = _activation(registry, authority, job, process)
    authority.materialize_process_service_composite(
        process, adapter.prepare_service_publication(activation)
    )
    exit_at = _START + timedelta(seconds=5)
    termination = state.plan_process_termination_materialization(
        system="MAC-A", pid=process.identity.pid, end_time=exit_at
    )
    closure = _closure_request(
        activation, process_object_id=process.identity.object_id, at=exit_at, close_service=False
    )
    authority.materialize_process_service_closure_composite(
        termination, adapter.prepare_service_process_closure(closure)
    )
    plan = macos_system_job_unload_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=exit_at + timedelta(seconds=1),
        action_id="unload-after-exit",
    )
    assert plan.process is None and not plan.closure.process_closures
    token = adapter.prepare_service_process_closure(plan.closure)
    with adapter.claimed_service_process_closure(token) as prepared:
        prepared.commit_no_fail()
    assert registry.get_process(process.identity.object_id).closed_at == exit_at


def test_unload_refuses_to_infer_child_process_group_membership() -> None:
    state, registry, authority, adapter, job = _setup()
    process = _process(state, job)
    activation = _activation(registry, authority, job, process)
    authority.materialize_process_service_composite(
        process, adapter.prepare_service_publication(activation)
    )
    state.set_current_time(_START + timedelta(seconds=2))
    child = _process(state, job, parent_pid=process.identity.pid)
    authority.materialize_process(child)
    before = state.materialization_digest()
    with pytest.raises(StateError, match="process-group ownership"):
        macos_system_job_unload_completion_plan(
            lifecycle_registry=registry,
            state_manager=state,
            service_object_id=job.instance_identity.object_id,
            completed_at=_START + timedelta(seconds=10),
            action_id="unload-worker",
        )
    assert state.materialization_digest() == before
    assert registry.get_service_instance(job.instance_identity.object_id).close_barrier is None


@pytest.mark.parametrize("action", ["", " wrong "])
def test_unload_requires_an_exact_action_id(action: str) -> None:
    state, registry, _authority, _adapter, job = _setup()
    with pytest.raises(ValueError, match="exact action ID"):
        macos_system_job_unload_completion_plan(
            lifecycle_registry=registry,
            state_manager=state,
            service_object_id=job.instance_identity.object_id,
            completed_at=_START,
            action_id=action,
        )


def test_unload_cannot_precede_bootstrap() -> None:
    state, registry, _authority, _adapter, job = _setup()
    with pytest.raises(StateError, match="precede bootstrap"):
        macos_system_job_unload_completion_plan(
            lifecycle_registry=registry,
            state_manager=state,
            service_object_id=job.instance_identity.object_id,
            completed_at=_START - timedelta(seconds=1),
            action_id="too-early",
        )


def test_failed_unload_commit_leaves_job_and_process_live_then_retry_closes_both() -> None:
    state, registry, authority, adapter, job = _setup()
    process = _process(state, job)
    activation = _activation(registry, authority, job, process)
    authority.materialize_process_service_composite(
        process, adapter.prepare_service_publication(activation)
    )
    plan = macos_system_job_unload_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=_START + timedelta(seconds=10),
        action_id="unload-worker",
    )
    before = state.materialization_digest()

    def reject() -> None:
        raise StateError("injected unload precommit failure")

    authority._materialization_precommit_hook = reject
    with pytest.raises(StateError, match="injected unload"):
        authority.materialize_process_service_closure_composite(
            plan.process, adapter.prepare_service_process_closure(plan.closure)
        )
    assert state.materialization_digest() == before
    assert registry.get_service_instance(job.instance_identity.object_id).closed_at is None
    assert registry.get_process(process.identity.object_id).closed_at is None
    assert adapter.service_preparation_census().closure_reservations == 0
    authority._materialization_precommit_hook = None
    authority.materialize_process_service_closure_composite(
        plan.process, adapter.prepare_service_process_closure(plan.closure)
    )
    assert (
        registry.get_service_instance(job.instance_identity.object_id).closed_at
        == plan.process.end_time
    )


def test_new_child_after_unload_planning_prevents_stale_closure() -> None:
    state, registry, authority, adapter, job = _setup()
    process = _process(state, job)
    activation = _activation(registry, authority, job, process)
    authority.materialize_process_service_composite(
        process, adapter.prepare_service_publication(activation)
    )
    plan = macos_system_job_unload_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=_START + timedelta(seconds=10),
        action_id="unload-worker",
    )
    state.set_current_time(_START + timedelta(seconds=2))
    child = _process(state, job, parent_pid=process.identity.pid)
    authority.materialize_process(child)
    before = state.materialization_digest()
    with pytest.raises(StateError):
        authority.materialize_process_service_closure_composite(
            plan.process, adapter.prepare_service_process_closure(plan.closure)
        )
    assert state.materialization_digest() == before
    assert state.get_process("MAC-A", child.identity.pid) is not None
    assert registry.get_service_instance(job.instance_identity.object_id).closed_at is None


def test_unload_after_authenticated_exec_terminates_current_execution_of_same_lifetime() -> None:
    from evidenceforge.events.contexts import HostContext
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.generation.actions.command_effects import ExecutionEffectAuditCounter
    from evidenceforge.generation.actions.posix_process import process_exec_occurrence
    from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
    from tests.unit.test_process_exit_projection import _prepare

    state, registry, authority, adapter, job = _setup()
    process = _process(state, job)
    activation = _activation(registry, authority, job, process)
    authority.materialize_process_service_composite(
        process, adapter.prepare_service_publication(activation)
    )
    dispatcher = EventDispatcher(
        state,
        {},
        lifecycle_shadow=LifecycleShadow(state, registry),
        enforce_lifecycle_authority=True,
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        process.identity,
        image="/usr/local/libexec/worker-stage-two",
        command_line="worker-stage-two --quiet",
        executed_at=_START + timedelta(seconds=2),
    )
    event = process_exec_occurrence(
        host=HostContext(
            hostname="MAC-A",
            ip="192.0.2.20",
            os="macOS 26",
            os_category="macos",
            system_type="workstation",
        ),
        before=process.identity,
        after=after,
        integrity_level="root",
    )
    dispatcher.publish_prepared_action_cohort_batch(
        _prepare(
            dispatcher, builder.seal(), event, exact=True, root=f"process-exec:{after.execution_id}"
        )
    )
    plan = macos_system_job_unload_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=_START + timedelta(seconds=10),
        action_id="unload-after-exec",
    )
    assert plan.process.identity == after
    authority.materialize_process_service_closure_composite(
        plan.process, adapter.prepare_service_process_closure(plan.closure)
    )
    assert (
        registry.get_service_instance(job.instance_identity.object_id).closed_at
        == plan.process.end_time
    )
    assert state.get_process("MAC-A", after.pid) is None


@pytest.mark.parametrize("restore", [False, True])
def test_group_unload_closes_exact_members_in_child_first_order(restore: bool) -> None:
    from evidenceforge.generation.actions.macos_launch_item import MacosSystemJobGroupUnloadPlan
    from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
    from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
    from evidenceforge.generation.lifecycle_production_adapters import LifecycleProductionAdapter
    from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
    from evidenceforge.generation.state_manager import StateManager

    state, registry, authority, adapter, job = _setup()
    process = _process(state, job, new_posix_session=True)
    authority.materialize_process_service_composite(
        process, adapter.prepare_service_publication(_activation(registry, authority, job, process))
    )
    child = _process(
        state, job, parent_pid=process.identity.pid, start_time=_START + timedelta(seconds=2)
    )
    authority.materialize_process(child)
    grandchild = _process(
        state, job, parent_pid=child.identity.pid, start_time=_START + timedelta(seconds=3)
    )
    authority.materialize_process(grandchild)
    if restore:
        restored_state = StateManager()
        _restore_head(restored_state, _capture_head(state))
        restored_registry = LifecycleRegistry(shard_count=8)
        _restore(restored_registry, _capture(registry))
        state, registry = restored_state, restored_registry
        authority = GeneratorLifecycleAuthority(
            state, LifecycleShadow(state, registry), shard_count=8
        )
        adapter = LifecycleProductionAdapter(registry)
    at = _START + timedelta(seconds=10)
    plan = macos_system_job_unload_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=at,
        action_id="group-unload",
    )
    assert isinstance(plan, MacosSystemJobGroupUnloadPlan)
    assert tuple(row.identity.object_id for row in plan.cohort.process_terminations) == (
        grandchild.identity.object_id,
        child.identity.object_id,
        process.identity.object_id,
    )
    version = state.materialization_version
    proof = authority.materialize_process_group_service_closure_composite(
        plan.cohort, plan.group, adapter.prepare_service_process_closure(plan.closure)
    )
    assert state.materialization_version == version + 1
    assert state.get_posix_group_members(plan.group) == ()
    assert state.get_process("MAC-A", 1) is not None
    assert registry.get_service_instance(job.instance_identity.object_id).closed_at == at
    for close in plan.cohort.process_terminations:
        assert authority.authenticates_process_service_closure_composite_receipt(
            close.target, proof
        )
        assert registry.get_process(close.identity.object_id).closed_at == at


@pytest.mark.parametrize("separate_group", [False, True])
def test_group_unload_rejects_membership_drift_but_adopts_external_descendants(
    separate_group: bool,
) -> None:
    state, registry, authority, adapter, job = _setup()
    process = _process(state, job, new_posix_session=True)
    authority.materialize_process_service_composite(
        process, adapter.prepare_service_publication(_activation(registry, authority, job, process))
    )
    plan = macos_system_job_unload_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=_START + timedelta(seconds=10),
        action_id="group-unload",
    )
    child = _process(
        state,
        job,
        parent_pid=process.identity.pid,
        new_posix_session=separate_group,
        start_time=_START + timedelta(seconds=2),
    )
    authority.materialize_process(child)
    if separate_group:
        plan = macos_system_job_unload_completion_plan(
            lifecycle_registry=registry,
            state_manager=state,
            service_object_id=job.instance_identity.object_id,
            completed_at=_START + timedelta(seconds=10),
            action_id="group-unload",
        )
    before = state.materialization_digest()
    if separate_group:
        authority.materialize_process_group_service_closure_composite(
            plan.cohort, plan.group, adapter.prepare_service_process_closure(plan.closure)
        )
        surviving = state.get_process_identity_by_object_id(child.identity.object_id)
        assert surviving.parent_pid == 1
        assert surviving.parentage.original == child.identity.parentage.original
        assert surviving.job_control == child.identity.job_control
        assert registry.get_service_instance(job.instance_identity.object_id).closed_at is not None
    else:
        with pytest.raises(StateError):
            authority.materialize_process_group_service_closure_composite(
                plan.cohort, plan.group, adapter.prepare_service_process_closure(plan.closure)
            )
        assert state.materialization_digest() == before
        assert registry.get_service_instance(job.instance_identity.object_id).closed_at is None
    assert registry.get_process(child.identity.object_id).closed_at is None
    assert adapter.service_preparation_census().reserved_keys == 0
