# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Loaded jobs activate and exit through shared atomic process/service owners."""

import shlex
from datetime import timedelta
from typing import Any

import pytest

from evidenceforge.events.identity import PosixProcessCredentials
from evidenceforge.generation.actions.macos_launch_item import macos_system_job_activation_plan
from evidenceforge.generation.checkpoints.lifecycle_head import _capture, _restore
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_production_adapters import (
    LifecycleProductionAdapter,
    ServiceLifecyclePublicationPlan,
)
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
from evidenceforge.generation.state_manager import ProcessMaterializationPlan, StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_lifecycle_service_preparation import _publish
from tests.unit.test_macos_launch_registration import _START, _plan
from tests.unit.test_process_service_lifecycle_authority import _closure_request


def _setup(
    runtime_content: RuntimeContentIdentityManager | None = None,
) -> tuple[
    StateManager,
    LifecycleRegistry,
    GeneratorLifecycleAuthority,
    LifecycleProductionAdapter,
    ServiceLifecyclePublicationPlan,
]:
    state = StateManager()
    registry = LifecycleRegistry(shard_count=8)
    authority = GeneratorLifecycleAuthority(state, LifecycleShadow(state, registry), shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    boot = _START - timedelta(hours=1)
    state.set_current_time(boot)
    state.register_boot_time("MAC-A", boot)
    parent = state.plan_process_materialization(
        system="MAC-A",
        parent_pid=0,
        fixed_pid=1,
        image="/sbin/launchd",
        command_line="/sbin/launchd",
        username="root",
        integrity_level="root",
        os_category="macos",
        start_time=boot,
        credentials=PosixProcessCredentials(0, 0, 0, 0),
    )
    authority.materialize_process(parent)
    job = _plan(**({"runtime_content": runtime_content} if runtime_content is not None else {}))
    _publish(adapter, job)
    state.set_current_time(_START + timedelta(seconds=1))
    return state, registry, authority, adapter, job


def _process(
    state: StateManager, job: ServiceLifecyclePublicationPlan, **changes: Any
) -> ProcessMaterializationPlan:
    definition = job.instance_identity.launchd_job
    values = dict(
        system="MAC-A",
        parent_pid=1,
        image=definition.program,
        command_line=shlex.join(definition.arguments),
        username=definition.principal,
        integrity_level="root",
        os_category="macos",
        credentials=PosixProcessCredentials(0, 0, 0, 0),
    )
    return state.plan_process_materialization(**(values | changes))


def _activation(
    registry: LifecycleRegistry,
    authority: GeneratorLifecycleAuthority,
    job: ServiceLifecyclePublicationPlan,
    process: ProcessMaterializationPlan,
) -> ServiceLifecyclePublicationPlan:
    return macos_system_job_activation_plan(
        lifecycle_registry=registry,
        lifecycle_authority=authority,
        service_object_id=job.instance_identity.object_id,
        process_plan=process,
        action_id="activate-example-job",
    )


def test_activation_publishes_exact_process_binding_and_preserves_loaded_job() -> None:
    state, registry, authority, adapter, job = _setup()
    process = _process(state, job)
    before = state.materialization_digest()
    activation = _activation(registry, authority, job, process)
    assert state.materialization_digest() == before
    assert registry.get_process(process.identity.object_id) is None
    result = authority.materialize_process_service_composite(
        process, adapter.prepare_service_publication(activation)
    )
    assert authority.authenticates_process_service_composite_receipt(process, result.receipt)
    assert result.process.parent_pid == 1
    assert result.process.ecar_object_id == process.identity.object_id
    assert (
        registry.get_service_instance(job.instance_identity.object_id).identity
        == job.instance_identity
    )
    assert (
        registry.service_process_binding(activation.process_bindings[0].binding_id).closed_at
        is None
    )


def test_second_activation_is_rejected_until_process_exits_then_job_can_run_again() -> None:
    state, registry, authority, adapter, job = _setup()
    first = _process(state, job)
    activation = _activation(registry, authority, job, first)
    authority.materialize_process_service_composite(
        first, adapter.prepare_service_publication(activation)
    )
    state.set_current_time(_START + timedelta(seconds=2))
    second = _process(state, job)
    before = state.materialization_digest()
    with pytest.raises(StateError, match="active process binding"):
        adapter.prepare_service_publication(_activation(registry, authority, job, second))
    assert state.materialization_digest() == before
    at = _START + timedelta(seconds=3)
    close = state.plan_process_termination_materialization(
        system="MAC-A", pid=first.identity.pid, end_time=at
    )
    request = _closure_request(
        activation, process_object_id=first.identity.object_id, at=at, close_service=False
    )
    authority.materialize_process_service_closure_composite(
        close, adapter.prepare_service_process_closure(request)
    )
    assert registry.get_process(first.identity.object_id).closed_at == at
    assert registry.get_service_instance(job.instance_identity.object_id).closed_at is None
    state.set_current_time(at + timedelta(seconds=1))
    third = _process(state, job)
    authority.materialize_process_service_composite(
        third, adapter.prepare_service_publication(_activation(registry, authority, job, third))
    )
    restored = LifecycleRegistry(shard_count=8)
    _restore(restored, _capture(registry))
    assert (
        restored.get_service_instance(job.instance_identity.object_id).identity
        == job.instance_identity
    )
    assert restored.get_process(first.identity.object_id).closed_at == at
    assert restored.get_process(third.identity.object_id).closed_at is None


@pytest.mark.parametrize(
    "changes",
    [
        {"image": "/bin/sh"},
        {"command_line": "different --arguments"},
        {"username": "alice"},
        {"credentials": PosixProcessCredentials(501, 501, 20, 20)},
        {"parent_pid": 4},
    ],
)
def test_activation_rejects_substituted_process_facts_without_state_changes(
    changes: dict[str, object],
) -> None:
    state, registry, authority, adapter, job = _setup()
    process = _process(state, job, **changes)
    before = state.materialization_digest()
    with pytest.raises(StateError, match="Launchd"):
        _activation(registry, authority, job, process)
    assert state.materialization_digest() == before


def test_precommit_failure_releases_activation_reservation_without_partial_process() -> None:
    state, registry, authority, adapter, job = _setup()
    process = _process(state, job)
    activation = _activation(registry, authority, job, process)
    before = state.materialization_digest()

    def fail() -> None:
        raise StateError("injected launch failure")

    authority._materialization_precommit_hook = fail
    with pytest.raises(StateError, match="injected"):
        authority.materialize_process_service_composite(
            process, adapter.prepare_service_publication(activation)
        )
    assert state.materialization_digest() == before
    assert registry.get_process(process.identity.object_id) is None
    assert adapter.service_preparation_census().publication_reservations == 0
    authority._materialization_precommit_hook = None
    authority.materialize_process_service_composite(
        process, adapter.prepare_service_publication(activation)
    )


def test_unload_closes_process_binding_and_job_then_rejects_activation() -> None:
    state, registry, authority, adapter, job = _setup()
    process = _process(state, job)
    activation = _activation(registry, authority, job, process)
    authority.materialize_process_service_composite(
        process, adapter.prepare_service_publication(activation)
    )
    at = _START + timedelta(seconds=20)
    close = state.plan_process_termination_materialization(
        system="MAC-A", pid=process.identity.pid, end_time=at
    )
    request = _closure_request(
        activation, process_object_id=process.identity.object_id, at=at, close_service=True
    )
    authority.materialize_process_service_closure_composite(
        close, adapter.prepare_service_process_closure(request)
    )
    assert state.get_process("MAC-A", process.identity.pid) is None
    assert registry.get_service_instance(job.instance_identity.object_id).closed_at == at
    assert (
        registry.service_process_binding(activation.process_bindings[0].binding_id).closed_at == at
    )
    state.set_current_time(at + timedelta(seconds=1))
    with pytest.raises(StateError, match="unloaded job"):
        _activation(registry, authority, job, _process(state, job))


def test_restored_state_and_job_can_exit_and_activate_again() -> None:
    from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head

    state, registry, authority, adapter, job = _setup()
    process = _process(state, job)
    activation = _activation(registry, authority, job, process)
    authority.materialize_process_service_composite(
        process, adapter.prepare_service_publication(activation)
    )
    restored_state = StateManager()
    _restore_head(restored_state, _capture_head(state))
    restored_registry = LifecycleRegistry(shard_count=8)
    _restore(restored_registry, _capture(registry))
    restored_authority = GeneratorLifecycleAuthority(
        restored_state, LifecycleShadow(restored_state, restored_registry), shard_count=8
    )
    restored_adapter = LifecycleProductionAdapter(restored_registry)
    at = _START + timedelta(seconds=5)
    close = restored_state.plan_process_termination_materialization(
        system="MAC-A", pid=process.identity.pid, end_time=at
    )
    request = _closure_request(
        activation, process_object_id=process.identity.object_id, at=at, close_service=False
    )
    restored_authority.materialize_process_service_closure_composite(
        close, restored_adapter.prepare_service_process_closure(request)
    )
    restored_state.set_current_time(at + timedelta(seconds=1))
    fresh = _process(restored_state, job)
    new_activation = _activation(restored_registry, restored_authority, job, fresh)
    result = restored_authority.materialize_process_service_composite(
        fresh, restored_adapter.prepare_service_publication(new_activation)
    )
    assert result.process.ecar_object_id != process.identity.object_id
    assert new_activation.instance_identity == job.instance_identity


def test_backward_activation_time_cannot_overlap_a_closed_binding() -> None:
    state, registry, authority, adapter, job = _setup()
    process = _process(state, job)
    activation = _activation(registry, authority, job, process)
    authority.materialize_process_service_composite(
        process, adapter.prepare_service_publication(activation)
    )
    at = _START + timedelta(seconds=20)
    close = state.plan_process_termination_materialization(
        system="MAC-A", pid=process.identity.pid, end_time=at
    )
    request = _closure_request(
        activation, process_object_id=process.identity.object_id, at=at, close_service=False
    )
    authority.materialize_process_service_closure_composite(
        close, adapter.prepare_service_process_closure(request)
    )
    state.set_current_time(at - timedelta(seconds=1))
    overlapping = _process(state, job)
    with pytest.raises(StateError, match="overlap its preceding"):
        adapter.prepare_service_publication(_activation(registry, authority, job, overlapping))


def test_one_prepared_activation_reserves_the_job_against_another() -> None:
    state, registry, authority, adapter, job = _setup()
    process = _process(state, job)
    activation = _activation(registry, authority, job, process)
    token = adapter.prepare_service_publication(activation)
    try:
        with pytest.raises(StateError, match="already in progress"):
            adapter.prepare_service_publication(activation)
    finally:
        adapter.cancel_service_publication(token)
    assert adapter.service_preparation_census().publication_reservations == 0
