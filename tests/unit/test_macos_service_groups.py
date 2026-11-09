# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""A loaded job retains its exact group even after its leader and binding retire."""

from datetime import timedelta

import pytest

from evidenceforge.generation.actions.macos_launch_item import (
    MacosSystemJobGroupUnloadPlan,
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
from tests.unit.test_macos_launch_activation import _activation, _process, _setup
from tests.unit.test_macos_launch_registration import _START
from tests.unit.test_process_service_lifecycle_authority import _closure_request


@pytest.mark.parametrize("restore", [False, True])
def test_leaderless_group_retains_job_ownership_and_closes_adopted_member(restore: bool) -> None:
    state, registry, authority, adapter, job = _setup(known_boot_group=True)
    leader = _process(state, job, new_posix_group=True)
    activation = _activation(registry, authority, job, leader)
    authority.materialize_process_service_composite(
        leader, adapter.prepare_service_publication(activation)
    )
    sibling = _process(state, job, parent_pid=1, start_time=_START + timedelta(seconds=2))
    authority.materialize_process(sibling)
    builder = state.begin_action_cohort_materialization()
    adopted = builder.change_posix_job_control(
        sibling.identity,
        operation="setpgid",
        changed_at=_START + timedelta(seconds=3),
        group=leader.identity.job_control,
    )
    state.materialize_action_cohort(builder.seal())
    at = _START + timedelta(seconds=4)
    close = state.plan_process_termination_materialization(
        system="MAC-A", pid=leader.identity.pid, end_time=at
    )
    authority.materialize_process_service_closure_composite(
        close,
        adapter.prepare_service_process_closure(
            _closure_request(
                activation, process_object_id=leader.identity.object_id, at=at, close_service=False
            )
        ),
    )
    assert (
        registry.get_service_instance(job.instance_identity.object_id).process_group
        == leader.identity.job_control
    )
    assert not registry.service_process_binding_page(
        service_object_id=job.instance_identity.object_id, limit=2
    )[0]
    state.set_current_time(at + timedelta(seconds=1))
    new_launch = _process(state, job, new_posix_group=True)
    with pytest.raises(StateError, match="live members"):
        authority.materialize_process_service_composite(
            new_launch,
            adapter.prepare_service_publication(_activation(registry, authority, job, new_launch)),
        )
    registry.advance_watermark(_START + registry.closed_retention + timedelta(seconds=10))
    assert registry.get_process(leader.identity.object_id) is None
    assert registry.service_process_binding(activation.process_bindings[0].binding_id) is None
    if restore:
        recovered_state = StateManager()
        _restore_head(recovered_state, _capture_head(state))
        recovered_registry = LifecycleRegistry(shard_count=8)
        _restore(recovered_registry, _capture(registry))
        state, registry = recovered_state, recovered_registry
        authority = GeneratorLifecycleAuthority(
            state, LifecycleShadow(state, registry), shard_count=8
        )
        adapter = LifecycleProductionAdapter(registry)
    plan = macos_system_job_unload_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=_START + registry.closed_retention + timedelta(seconds=11),
        action_id="leaderless-job-unload",
    )
    assert isinstance(plan, MacosSystemJobGroupUnloadPlan)
    assert not plan.closure.binding_closures
    assert [row.identity for row in plan.cohort.process_terminations] == [adopted]
    authority.materialize_process_group_service_closure_composite(
        plan.cohort, plan.group, adapter.prepare_service_process_closure(plan.closure)
    )
    assert state.get_posix_group_members(plan.group) == ()
    assert state.get_process("MAC-A", 1) is not None
    assert registry.get_service_instance(job.instance_identity.object_id).closed_at is not None


@pytest.mark.parametrize("damage", ["host", "early", "non_job", "boolean_pid", "leader", "pid"])
def test_corrupted_retained_group_cannot_replace_registry(damage: str) -> None:
    from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
    from evidenceforge.generation.checkpoints.packed import dumps, loads

    state, registry, authority, adapter, job = _setup()
    leader = _process(state, job, new_posix_session=True)
    authority.materialize_process_service_composite(
        leader, adapter.prepare_service_publication(_activation(registry, authority, job, leader))
    )
    document = loads(_capture(registry))
    row = next(row for part in document["partitions"] for row in part[2])
    if damage == "host":
        row[3][0] = "another-host"
    elif damage == "early":
        row[3][6] = (_START - timedelta(hours=1)).isoformat()
    elif damage == "non_job":
        row[1][7] = None
    elif damage == "leader":
        row[3][5] = "different-process"
    elif damage == "pid":
        row[3][4] += 1
    else:
        row[3][4] = True
    fresh = LifecycleRegistry(shard_count=8)
    before = _capture(fresh)
    with pytest.raises(CheckpointCorruptionError):
        _restore(fresh, dumps(document))
    assert _capture(fresh) == before


def test_group_owner_replacement_is_bounded_and_rejects_forged_membership() -> None:
    from dataclasses import replace

    state, registry, authority, adapter, job = _setup()
    first_group = None
    for index in range(3):
        state.set_current_time(_START + timedelta(seconds=index * 10 + 1))
        leader = _process(state, job, new_posix_session=True)
        activation = _activation(registry, authority, job, leader)
        if first_group is not None:
            with pytest.raises(ValueError, match="exact staged"):
                adapter.prepare_service_publication(replace(activation, process_group=first_group))
        authority.materialize_process_service_composite(
            leader, adapter.prepare_service_publication(activation)
        )
        first_group = first_group or leader.identity.job_control
        at = _START + timedelta(seconds=index * 10 + 2)
        close = state.plan_process_termination_materialization(
            system="MAC-A", pid=leader.identity.pid, end_time=at
        )
        authority.materialize_process_service_closure_composite(
            close,
            adapter.prepare_service_process_closure(
                _closure_request(
                    activation,
                    process_object_id=leader.identity.object_id,
                    at=at,
                    close_service=False,
                )
            ),
        )
        partition = registry._partitions[registry._partition_id("MAC-A")]
        assert len(partition._services._process_groups) == 1
        assert (
            registry.get_service_instance(job.instance_identity.object_id).process_group
            == leader.identity.job_control
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"new_posix_group": True},
        {"new_posix_group": "yes"},
        {"new_posix_group": True, "new_posix_session": True},
        {"new_posix_group": True, "os_category": "windows"},
    ],
)
def test_invalid_or_unknown_parent_group_launch_rejects_before_allocation(
    changes: dict[str, object],
) -> None:
    state, _, _, _, job = _setup()
    before = state.materialization_digest()
    with pytest.raises(StateError):
        _process(state, job, **changes)
    assert state.materialization_digest() == before
