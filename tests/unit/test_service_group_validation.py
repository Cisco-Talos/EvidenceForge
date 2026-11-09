# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Source coordinators reuse exact State/service ownership without taking claims."""

from dataclasses import replace

import pytest

from evidenceforge.models.exceptions import StateError
from tests.unit.test_service_group_closure import _owned_group


def test_service_group_validation_has_no_state_lifecycle_or_reservation_effects() -> None:
    state, registry, authority, adapter, group, plan, request = _owned_group()
    before = state.materialization_digest()
    snapshots = tuple(
        registry.get_process(item.identity.object_id) for item in plan.process_terminations
    )
    census = adapter.service_preparation_census()
    for _ in range(2):
        result = authority.validate_process_group_service_closure(
            plan, group, request, close_group=True
        )
        assert result == tuple(item.target for item in plan.process_terminations)
    assert state.materialization_digest() == before
    assert (
        tuple(registry.get_process(item.identity.object_id) for item in plan.process_terminations)
        == snapshots
    )
    assert adapter.service_preparation_census() == census
    authority.materialize_process_group_service_closure_composite(
        plan, group, adapter.prepare_service_process_closure(request)
    )
    assert state.get_posix_group_members(group) == ()


@pytest.mark.parametrize(
    "damage", ["order", "missing_control", "mode", "foreign_group", "foreign_plan"]
)
def test_service_group_validation_rejects_mismatched_contract_without_reserving(
    damage: str,
) -> None:
    state, _, authority, adapter, group, plan, request = _owned_group()
    before = state.materialization_digest()
    if damage == "order":
        request = replace(request, process_closures=tuple(reversed(request.process_closures)))
    elif damage == "missing_control":
        request = replace(request, process_closures=request.process_closures[1:])
    elif damage == "foreign_group":
        group = replace(group, leader_object_id="different-leader")
    elif damage == "foreign_plan":
        plan = _owned_group()[5]
    with pytest.raises(StateError):
        authority.validate_process_group_service_closure(
            plan, group, request, close_group=damage != "mode"
        )
    assert state.materialization_digest() == before
    assert adapter.service_preparation_census().reserved_keys == 0


def test_service_group_validation_rejects_authenticated_plan_omitting_live_member() -> None:
    state, _, authority, adapter, group, complete, request = _owned_group()
    child = complete.process_terminations[0]
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(child.identity, end_time=child.end_time)
    partial = builder.seal()
    request = replace(request, binding_closures=(), process_closures=request.process_closures[:1])
    before = state.materialization_digest()
    with pytest.raises(StateError, match="retained service owner"):
        authority.validate_process_group_service_closure(partial, group, request, close_group=True)
    assert state.materialization_digest() == before
    assert adapter.service_preparation_census().reserved_keys == 0


def test_service_group_validation_rechecks_state_after_canonical_completion() -> None:
    state, _, authority, adapter, group, plan, request = _owned_group()
    authority.validate_process_group_service_closure(plan, group, request, close_group=True)
    authority.materialize_process_group_service_closure_composite(
        plan, group, adapter.prepare_service_process_closure(request)
    )
    before = state.materialization_digest()
    with pytest.raises(StateError):
        authority.validate_process_group_service_closure(plan, group, request, close_group=True)
    assert state.materialization_digest() == before
    assert adapter.service_preparation_census().reserved_keys == 0
