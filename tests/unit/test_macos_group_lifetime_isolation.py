# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Job unload cannot claim an unrelated reuse of its former leader's numeric IDs."""

from datetime import timedelta

import pytest

from evidenceforge.generation.actions.macos_launch_item import (
    MacosSystemJobUnloadPlan,
    macos_system_job_unload_completion_plan,
)
from evidenceforge.generation.checkpoints.lifecycle_head import _capture, _restore
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.lifecycle_production_adapters import LifecycleProductionAdapter
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.state_manager import StateManager
from tests.unit.test_macos_launch_activation import _activation, _process, _setup
from tests.unit.test_macos_launch_registration import _START
from tests.unit.test_process_service_lifecycle_authority import _closure_request


@pytest.mark.parametrize("restore", [False, True])
def test_unload_after_group_id_reuse_preserves_the_unrelated_lifetime(restore: bool) -> None:
    state, registry, authority, adapter, job = _setup()
    leader = _process(state, job, new_posix_session=True)
    activation = _activation(registry, authority, job, leader)
    authority.materialize_process_service_composite(
        leader, adapter.prepare_service_publication(activation)
    )
    at = _START + timedelta(seconds=2)
    termination = state.plan_process_termination_materialization(
        system="MAC-A", pid=leader.identity.pid, end_time=at
    )
    authority.materialize_process_service_closure_composite(
        termination,
        adapter.prepare_service_process_closure(
            _closure_request(
                activation, process_object_id=leader.identity.object_id, at=at, close_service=False
            )
        ),
    )
    unrelated = _process(
        state,
        job,
        fixed_pid=leader.identity.pid,
        new_posix_session=True,
        start_time=at + timedelta(seconds=1),
    )
    authority.materialize_process(unrelated)
    old_group, new_group = leader.identity.job_control, unrelated.identity.job_control
    assert old_group.pgid == new_group.pgid
    assert old_group.session.sid == new_group.session.sid
    assert old_group != new_group
    assert state.get_posix_group_members(old_group) == ()
    if restore:
        fresh_state = StateManager()
        _restore_head(fresh_state, _capture_head(state))
        fresh_registry = LifecycleRegistry(shard_count=8)
        _restore(fresh_registry, _capture(registry))
        state, registry = fresh_state, fresh_registry
        adapter = LifecycleProductionAdapter(registry)
    before = state.materialization_digest()
    plan = macos_system_job_unload_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=at + timedelta(seconds=2),
        action_id="unload-old-group-only",
    )
    assert isinstance(plan, MacosSystemJobUnloadPlan)
    assert plan.process is None
    with adapter.claimed_service_process_closure(
        adapter.prepare_service_process_closure(plan.closure)
    ) as prepared:
        prepared.commit_no_fail()
    assert state.materialization_digest() == before
    assert state.get_posix_group_members(new_group) == (unrelated.identity,)
    assert registry.get_process(unrelated.identity.object_id).closed_at is None
    assert registry.get_service_instance(job.instance_identity.object_id).closed_at is not None
