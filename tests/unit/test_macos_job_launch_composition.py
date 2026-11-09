# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Loaded job activation consumes its definition and owns a separate lifetime."""

from datetime import timedelta

import pytest

from evidenceforge.generation.actions.macos_launch_item import (
    macos_system_job_launch_plan,
    macos_system_job_leader_exit_completion_plan,
    macos_system_job_unload_completion_plan,
)
from evidenceforge.generation.checkpoints.lifecycle_head import _capture, _restore
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_production_adapters import LifecycleProductionAdapter
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_launch_activation import _process, _setup
from tests.unit.test_macos_launch_registration import _START


@pytest.mark.parametrize("known_boot", [False, True])
@pytest.mark.parametrize("restore", [False, True])
def test_loaded_job_launch_descendant_exit_and_unload_preserve_exact_group(
    known_boot: bool, restore: bool
) -> None:
    state, registry, authority, adapter, job = _setup(known_boot_group=known_boot)
    before = state.materialization_digest()
    plan = macos_system_job_launch_plan(
        lifecycle_registry=registry,
        lifecycle_authority=authority,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        started_at=_START + timedelta(seconds=1),
        action_id="launch-explicitly",
    )
    assert state.materialization_digest() == before
    process = plan.process.identity
    assert process.arguments == job.instance_identity.launchd_job.arguments
    assert process.environment is None
    assert process.job_control.pgid == process.job_control.session.sid == process.pid
    assert process.job_control != plan.process.parent_identity.job_control
    authority.materialize_process_service_composite(
        plan.process, adapter.prepare_service_publication(plan.activation)
    )
    child = _process(state, job, parent_pid=process.pid, start_time=_START + timedelta(seconds=2))
    authority.materialize_process(child)
    if restore:
        fresh_state, fresh_registry = StateManager(), LifecycleRegistry()
        _restore_head(fresh_state, _capture_head(state))
        _restore(fresh_registry, _capture(registry))
        state, registry = fresh_state, fresh_registry
        authority = GeneratorLifecycleAuthority(state, LifecycleShadow(state, registry))
        adapter = LifecycleProductionAdapter(registry)
    exit_plan = macos_system_job_leader_exit_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=_START + timedelta(seconds=3),
        action_id="job-exit",
    )
    authority.materialize_process_group_leader_exit_composite(
        exit_plan.cohort,
        exit_plan.group,
        adapter.prepare_service_process_closure(exit_plan.closure),
    )
    assert state.get_process_identity_by_object_id(child.identity.object_id).parent_pid == 1
    assert registry.get_service_instance(job.instance_identity.object_id).closed_at is None
    replacement = macos_system_job_launch_plan(
        lifecycle_registry=registry,
        lifecycle_authority=authority,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        started_at=_START + timedelta(seconds=4),
        action_id="overlapping-activation",
    )
    before = state.materialization_digest()
    with pytest.raises(StateError, match="live members"):
        authority.materialize_process_service_composite(
            replacement.process, adapter.prepare_service_publication(replacement.activation)
        )
    assert state.materialization_digest() == before
    unload = macos_system_job_unload_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=_START + timedelta(seconds=5),
        action_id="job-unload",
    )
    authority.materialize_process_group_service_closure_composite(
        unload.cohort, unload.group, adapter.prepare_service_process_closure(unload.closure)
    )
    assert not state.get_posix_group_members(process.job_control)
    assert state.get_process("MAC-A", 1) is not None
    before = state.materialization_digest()
    with pytest.raises(StateError, match="unloaded"):
        macos_system_job_launch_plan(
            lifecycle_registry=registry,
            lifecycle_authority=authority,
            state_manager=state,
            service_object_id=job.instance_identity.object_id,
            started_at=_START + timedelta(seconds=6),
            action_id="invalid-restart",
        )
    assert state.materialization_digest() == before


@pytest.mark.parametrize("damage", ["missing", "naive", "early", "parent", "action"])
def test_job_launch_rejects_missing_or_inconsistent_owners_without_allocating(damage: str) -> None:
    state, registry, authority, _, job = _setup()
    service = job.instance_identity.object_id
    at = _START + timedelta(seconds=1)
    if damage == "missing":
        service = "missing-service"
    elif damage == "naive":
        at = at.replace(tzinfo=None)
    elif damage == "early":
        at = _START - timedelta(seconds=1)
    elif damage == "parent":
        state.get_process("MAC-A", 1).image = "/usr/bin/other"
    before = state.materialization_digest()
    with pytest.raises((StateError, ValueError)):
        macos_system_job_launch_plan(
            lifecycle_registry=registry,
            lifecycle_authority=authority,
            state_manager=state,
            service_object_id=service,
            started_at=at,
            action_id="" if damage == "action" else "launch-explicitly",
        )
    assert state.materialization_digest() == before
