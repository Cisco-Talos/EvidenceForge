# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Service closure admits only an exact child-before-parent terminal graph."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.job_control import PosixGroupIdentity
from evidenceforge.events.lifecycle import LifecycleMembership, ProcessTokenIdentity
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_production_adapters import LifecycleProductionAdapter
from evidenceforge.generation.lifecycle_registry import (
    LifecycleRegistry,
    LifecycleServiceProcessClosureRequest,
    _PreparedServiceClosureCommitPlan,
)
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan, StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_lifecycle_service_preparation import (
    _START,
    _binding_close,
    _control,
    _plan,
    _process,
    _publish,
)
from tests.unit.test_posix_job_control import _change, _fork, _root


def _tree() -> tuple[
    LifecycleRegistry, LifecycleProductionAdapter, LifecycleServiceProcessClosureRequest
]:
    registry = LifecycleRegistry(shard_count=4)
    adapter = LifecycleProductionAdapter(registry)
    parent = _process(registry, hostname="MAC-GROUP", object_id="parent", pid=10)
    child = replace(parent, object_id="child", pid=11, parent_object_id=parent.object_id)
    registry.register_process(
        child,
        token=ProcessTokenIdentity(principal="root", logon_id=""),
        membership=LifecycleMembership(owner_kind="boot", owner_object_id="boot:MAC-GROUP"),
        action_id="start:child",
        transition_id="transition:start:child",
    )
    publication = _publish(adapter, _plan(hostname="MAC-GROUP", logical_id="job", process=parent))
    at = _START + timedelta(seconds=10)
    request = LifecycleServiceProcessClosureRequest(
        binding_closures=(_binding_close(publication.bindings[0].identity, at=at),),
        process_closures=(
            _control("process", "child", at=at),
            _control("process", "parent", at=at),
        ),
        service_closures=(_control("service", publication.service.identity.object_id, at=at),),
    )
    return registry, adapter, request


def test_service_group_closes_children_before_parent_and_exact_retry_is_idempotent() -> None:
    registry, adapter, request = _tree()
    for _ in range(2):
        token = adapter.prepare_service_process_closure(request)
        with adapter.claimed_service_process_closure(token) as prepared:
            receipt = prepared.commit_no_fail()
        assert [row.identity.object_id for row in receipt.processes] == ["child", "parent"]
        assert all(row.closed_at == _START + timedelta(seconds=10) for row in receipt.processes)
    assert registry.get_process("parent").closed_at == registry.get_process("child").closed_at
    assert adapter.service_preparation_census().reserved_keys == 0


def _owned_group() -> tuple[
    StateManager,
    LifecycleRegistry,
    GeneratorLifecycleAuthority,
    LifecycleProductionAdapter,
    PosixGroupIdentity,
    ActionCohortMaterializationPlan,
    LifecycleServiceProcessClosureRequest,
]:
    state, root = _root()
    root = _change(state, root, "bootstrap", 0)
    leader = _fork(state, root, 1)
    leader = _change(state, leader, "setsid", 2)
    child = _fork(state, leader, 3)
    registry = LifecycleRegistry(shard_count=4)
    authority = GeneratorLifecycleAuthority(state, LifecycleShadow(state, registry), shard_count=4)
    authority.bootstrap_active_state()
    adapter = LifecycleProductionAdapter(registry)
    service_plan = _plan(
        hostname=leader.hostname,
        logical_id="group-job",
        process=registry.get_process(leader.object_id).identity,
    )
    service_plan = replace(
        service_plan,
        process_bindings=tuple(
            replace(binding, bound_at=leader.started_at)
            for binding in service_plan.process_bindings
        ),
    )
    service = _publish(adapter, service_plan)
    at = leader.started_at + timedelta(seconds=20)
    builder = state.begin_action_cohort_materialization()
    for process in (child, leader):
        builder.terminate_process(process, end_time=at)
    plan = builder.seal()
    request = LifecycleServiceProcessClosureRequest(
        binding_closures=(_binding_close(service.bindings[0].identity, at=at),),
        process_closures=tuple(
            _control("process", row.object_id, at=at) for row in (child, leader)
        ),
        service_closures=(_control("service", service.service.identity.object_id, at=at),),
    )
    return state, registry, authority, adapter, leader.job_control, plan, request


def test_group_composite_closes_all_owners_in_one_state_version_and_authenticates_each_source_plan() -> (
    None
):
    state, registry, authority, adapter, group, plan, request = _owned_group()
    before = state.materialization_version
    proof = authority.materialize_process_group_service_closure_composite(
        plan, group, adapter.prepare_service_process_closure(request)
    )
    assert state.materialization_version == before + 1
    assert state.get_posix_group_members(group) == ()
    for close in plan.process_terminations:
        assert registry.get_process(close.identity.object_id).closed_at == close.end_time
        assert authority.authenticates_process_service_closure_composite_receipt(
            close.target, proof
        )
        assert not authority.authenticates_process_service_closure_composite_receipt(
            close.target, replace(proof, processes=())
        )
    assert adapter.service_preparation_census().reserved_keys == 0


def test_group_composite_precommit_rejection_preserves_both_owners() -> None:
    state, registry, authority, adapter, group, plan, request = _owned_group()
    before = state.materialization_digest()

    def reject() -> None:
        raise StateError("injected group precommit rejection")

    authority._materialization_precommit_hook = reject
    with pytest.raises(StateError, match="injected group"):
        authority.materialize_process_group_service_closure_composite(
            plan, group, adapter.prepare_service_process_closure(request)
        )
    assert state.materialization_digest() == before
    assert all(
        registry.get_process(row.identity.object_id).closed_at is None
        for row in plan.process_terminations
    )
    assert adapter.service_preparation_census().reserved_keys == 0


def test_group_composite_lost_registry_return_finishes_state_and_retains_authenticated_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, registry, authority, adapter, group, plan, request = _owned_group()
    original = registry._service_closure_receipt_locked

    def lose_return(commit_plan: _PreparedServiceClosureCommitPlan) -> None:
        original(commit_plan)
        raise RuntimeError("injected group registry lost return")

    monkeypatch.setattr(registry, "_service_closure_receipt_locked", lose_return)
    with pytest.raises(RuntimeError, match="lost return") as caught:
        authority.materialize_process_group_service_closure_composite(
            plan, group, adapter.prepare_service_process_closure(request)
        )
    proof = caught.value.process_group_service_receipt
    assert state.get_posix_group_members(group) == ()
    for close in plan.process_terminations:
        assert registry.get_process(close.identity.object_id).closed_at == close.end_time
        assert authority.authenticates_process_service_closure_composite_receipt(
            close.target, proof
        )
    assert adapter.service_preparation_census().reserved_keys == 0


@pytest.mark.parametrize("damage", ["missing", "order", "late"])
def test_group_close_rejects_missing_reversed_or_late_children_without_mutation(
    damage: str,
) -> None:
    registry, adapter, request = _tree()
    if damage == "missing":
        request = replace(request, process_closures=request.process_closures[1:])
    elif damage == "order":
        request = replace(request, process_closures=tuple(reversed(request.process_closures)))
    else:
        request = replace(
            request,
            process_closures=(
                _control("process", "child", at=_START + timedelta(seconds=11)),
                request.process_closures[1],
            ),
        )
    with pytest.raises(StateError, match="child processes"):
        adapter.prepare_service_process_closure(request)
    assert registry.get_process("parent").closed_at is None
    assert registry.get_process("child").closed_at is None
    assert adapter.service_preparation_census().reserved_keys == 0


def test_group_close_rejects_hold_shift_before_either_owner_mutates() -> None:
    from evidenceforge.events.lifecycle import LifecycleEntityRef, LifecycleHold

    state, registry, authority, adapter, group, plan, request = _owned_group()
    at = plan.process_terminations[0].end_time
    registry.add_hold(
        LifecycleHold(
            hold_id="group-test-hold",
            subject=LifecycleEntityRef("process", plan.process_terminations[0].identity.object_id),
            acquired_at=at - timedelta(seconds=1),
            hold_until=at + timedelta(seconds=1),
            action_id="held-transport",
            reason="transport_close",
        )
    )
    before = state.materialization_digest()
    with pytest.raises(StateError):
        authority.materialize_process_group_service_closure_composite(
            plan, group, adapter.prepare_service_process_closure(request)
        )
    assert state.materialization_digest() == before
    assert registry.get_process(plan.process_terminations[0].identity.object_id).closed_at is None
    assert adapter.service_preparation_census().reserved_keys == 0


def test_group_receipt_publishes_each_exact_close_without_reapplying_state(tmp_path: Path) -> None:
    import json

    from evidenceforge.events.contexts import HostContext
    from evidenceforge.events.dispatcher import EventDispatcher, PreparedDispatchStateIntent
    from evidenceforge.formats.loader import load_format
    from evidenceforge.generation.actions.posix_process import process_exit_occurrence
    from evidenceforge.generation.emitters.ecar import EcarEmitter

    state, registry, authority, adapter, group, plan, request = _owned_group()
    output = tmp_path / "group.json"
    emitter = EcarEmitter(load_format("ecar"), output)
    dispatcher = EventDispatcher(
        state,
        {"ecar": emitter},
        lifecycle_shadow=LifecycleShadow(state, registry),
        enforce_lifecycle_authority=True,
    )
    dispatcher.bind_lifecycle_authority(authority)
    prepared = []
    for close in plan.process_terminations:
        occurrence = process_exit_occurrence(
            host=HostContext(
                hostname=close.identity.hostname,
                ip="192.0.2.20",
                os="macOS 26",
                os_category="macos",
                system_type="workstation",
            ),
            process=close.identity,
            timestamp=close.end_time,
            integrity_level=state.get_process(
                close.identity.hostname, close.identity.pid
            ).integrity_level,
        )
        prepared.append(
            dispatcher.prepare_builder(
                occurrence,
                state_intent=PreparedDispatchStateIntent.EXTERNAL_MATERIALIZED_CLOSE,
                lifecycle_ticket=close.target,
            )
        )
    proof = authority.materialize_process_group_service_closure_composite(
        plan, group, adapter.prepare_service_process_closure(request)
    )
    version = state.materialization_version
    for event in prepared:
        dispatcher.publish_prepared(event, materialization_receipt=proof)
    emitter.close()
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert [row["objectID"] for row in rows] == [
        p.identity.object_id for p in plan.process_terminations
    ]
    assert all(row["object"] == "PROCESS" and row["action"] == "TERMINATE" for row in rows)
    assert state.materialization_version == version
