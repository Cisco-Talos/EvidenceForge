# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Surviving outside-group children retain exact ownership across unload failures."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.lifecycle import LifecycleHold
from evidenceforge.generation.actions.macos_launch_item import (
    MacosSystemJobGroupUnloadPlan,
    macos_system_job_unload_completion_plan,
)
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.lifecycle_head import _capture, _restore
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_production_adapters import (
    LifecycleProductionAdapter,
    ServiceLifecyclePublicationPlan,
)
from evidenceforge.generation.lifecycle_registry import (
    LifecycleRegistry,
    _PreparedServiceClosureCommitPlan,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_launch_activation import _activation, _process, _setup
from tests.unit.test_macos_launch_registration import _START


def _family() -> tuple[
    StateManager,
    LifecycleRegistry,
    GeneratorLifecycleAuthority,
    LifecycleProductionAdapter,
    ServiceLifecyclePublicationPlan,
    ProcessIdentity,
    ProcessIdentity,
    ProcessIdentity,
    MacosSystemJobGroupUnloadPlan,
]:
    state, registry, authority, adapter, job = _setup()
    parent = _process(state, job, new_posix_session=True)
    authority.materialize_process_service_composite(
        parent, adapter.prepare_service_publication(_activation(registry, authority, job, parent))
    )
    child = _process(
        state,
        job,
        parent_pid=parent.identity.pid,
        new_posix_session=True,
        start_time=_START + timedelta(seconds=2),
    )
    authority.materialize_process(child)
    descendant = _process(
        state, job, parent_pid=child.identity.pid, start_time=_START + timedelta(seconds=3)
    )
    authority.materialize_process(descendant)
    plan = macos_system_job_unload_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=_START + timedelta(seconds=10),
        action_id="adopting-unload",
    )
    assert isinstance(plan, MacosSystemJobGroupUnloadPlan)
    return (
        state,
        registry,
        authority,
        adapter,
        job,
        parent.identity,
        child.identity,
        descendant.identity,
        plan,
    )


@pytest.mark.parametrize("retire_parent", [False, True])
def test_group_unload_preserves_external_subtree_and_restores_current_parent(
    retire_parent: bool,
) -> None:
    state, registry, authority, adapter, job, parent, child, descendant, plan = _family()
    authority.materialize_process_group_service_closure_composite(
        plan.cohort, plan.group, adapter.prepare_service_process_closure(plan.closure)
    )
    adopted = state.get_process_identity_by_object_id(child.object_id)
    assert adopted.parentage.original == child.parentage.original
    assert adopted.parentage.current.pid == 1
    assert (adopted.credentials, adopted.job_control, adopted.execution_id) == (
        child.credentials,
        child.job_control,
        child.execution_id,
    )
    assert state.get_process_identity_by_object_id(descendant.object_id) == descendant
    assert state.get_process_identity_at(child.hostname, child.pid, child.started_at) == child
    assert (
        registry.get_process(child.object_id).membership
        == registry.get_process(descendant.object_id).membership
    )
    if retire_parent:
        registry.advance_watermark(_START + timedelta(days=3))
        assert registry.get_process(parent.object_id) is None
    recovered = LifecycleRegistry()
    _restore(recovered, _capture(registry))
    assert recovered.get_process(child.object_id) == registry.get_process(child.object_id)
    assert (
        recovered.get_process(child.object_id).current_parent_object_id
        == adopted.parentage.current.object_id
    )
    assert [
        row.identity.object_id
        for row in recovered.live_child_process_page(child.object_id, limit=10)[0]
    ] == [descendant.object_id]
    recovered_state = StateManager()
    _restore_head(recovered_state, _capture_head(state))
    assert recovered_state.get_process_identity_by_object_id(child.object_id) == adopted
    assert (
        recovered_state.get_process_identity_at(child.hostname, child.pid, child.started_at)
        == child
    )


@pytest.mark.parametrize(
    "fault", ["precommit", "lost-return", "omit-adoption", "parent-hold", "new-child"]
)
def test_adoption_and_group_close_have_one_failure_boundary(
    fault: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, registry, authority, adapter, job, parent, child, descendant, plan = _family()
    before = state.materialization_digest()
    if fault == "precommit":

        def reject() -> None:
            raise StateError("injected precommit failure")

        authority._materialization_precommit_hook = reject
    elif fault == "lost-return":
        original = registry._service_closure_receipt_locked

        def lose_return(commit: _PreparedServiceClosureCommitPlan) -> None:
            original(commit)
            raise RuntimeError("injected lost return")

        monkeypatch.setattr(registry, "_service_closure_receipt_locked", lose_return)
    elif fault == "omit-adoption":
        plan = replace(plan, closure=replace(plan.closure, parent_adoptions=()))
    elif fault == "parent-hold":
        registry.add_hold(
            LifecycleHold(
                hold_id="retained-parent",
                subject=registry.get_process(parent.object_id).identity.ref,
                acquired_at=_START + timedelta(seconds=4),
                hold_until=_START + timedelta(seconds=20),
                action_id="parent-hold",
                reason="modeled dependency",
            )
        )
    elif fault == "new-child":
        authority.materialize_process(
            _process(
                state,
                job,
                parent_pid=parent.pid,
                new_posix_session=True,
                start_time=_START + timedelta(seconds=4),
            )
        )
        before = state.materialization_digest()
    with pytest.raises((StateError, RuntimeError)) as caught:
        authority.materialize_process_group_service_closure_composite(
            plan.cohort, plan.group, adapter.prepare_service_process_closure(plan.closure)
        )
    if fault == "lost-return":
        proof = caught.value.process_group_service_receipt
        assert authority.authenticates_process_service_closure_composite_receipt(
            plan.cohort.process_terminations[0].target, proof
        )
        assert state.get_process_identity_by_object_id(child.object_id).parent_pid == 1
        assert registry.get_process(parent.object_id).closed_at is not None
        assert (
            registry.get_process(child.object_id).current_parent_object_id
            == state.get_process_identity(child.hostname, 1).object_id
        )
    else:
        assert state.materialization_digest() == before
        assert registry.get_process(parent.object_id).closed_at is None
        assert registry.get_process(child.object_id).current_parent_object_id == parent.object_id
    assert adapter.service_preparation_census().reserved_keys == 0


def test_service_adoption_exact_retry_does_not_move_relationship_twice() -> None:
    state, registry, authority, adapter, job, parent, child, descendant, plan = _family()
    authority.materialize_process_group_service_closure_composite(
        plan.cohort, plan.group, adapter.prepare_service_process_closure(plan.closure)
    )
    for _ in range(2):
        token = adapter.prepare_service_process_closure(plan.closure)
        with adapter.claimed_service_process_closure(token) as prepared:
            prepared.commit_no_fail()
    root = state.get_process_identity(child.hostname, 1)
    assert [
        row.identity.object_id
        for row in registry.live_child_process_page(root.object_id, limit=10)[0]
    ] == [child.object_id]


@pytest.mark.parametrize(
    "damage", ["parent-pid", "parent-exit", "adopter-pid", "adopter-host", "missing-frontier"]
)
def test_corrupt_adoption_checkpoint_cannot_replace_live_registry(damage: str) -> None:
    state, registry, authority, adapter, job, parent, child, descendant, plan = _family()
    authority.materialize_process_group_service_closure_composite(
        plan.cohort, plan.group, adapter.prepare_service_process_closure(plan.closure)
    )
    document = loads(_capture(registry))
    rows = {row[0][1]: row for part in document["partitions"] for row in part[0]}
    # Locate by the typed identity's stable serialized object ID.
    child_row = next(row for row in rows.values() if row[0][1] == child.object_id)
    if damage == "parent-pid":
        child_row[5][0][1][2] += 1
    elif damage == "adopter-pid":
        child_row[5][1][1][2] = 99
    elif damage == "adopter-host":
        child_row[5][1][1][0] = "FOREIGN"
    elif damage == "missing-frontier":
        child_row[5] = None
    else:
        child_row[5][2] = (_START + timedelta(seconds=9)).isoformat()
    target = LifecycleRegistry()
    before = _capture(target)
    with pytest.raises((CheckpointCorruptionError, ValueError)):
        _restore(target, dumps(document))
    assert _capture(target) == before


def test_adoption_reservation_excludes_old_parent_child_and_adopter_mutations() -> None:
    state, registry, authority, adapter, job, parent, child, descendant, plan = _family()
    token = adapter.prepare_service_process_closure(plan.closure)
    root = state.get_process_identity(child.hostname, 1)
    try:
        for identity in (parent, child, root):
            with pytest.raises(StateError, match="reserved|prepar"):
                registry.record_dependent(
                    registry.get_process(identity.object_id).identity.ref,
                    transition_id="conflict:" + identity.object_id,
                    canonical_time=_START + timedelta(seconds=5),
                    action_id="conflict",
                    reason="conflicting activity",
                )
    finally:
        adapter.cancel_service_process_closure(token)


@pytest.mark.parametrize("target", ["adopter", "old-parent", "child"])
def test_stale_adoption_refuses_to_reinterpret_live_identity(target: str) -> None:
    state, registry, authority, adapter, job, parent, child, descendant, plan = _family()
    # A newer canonical activity on the surviving child makes a backdated
    # relationship update inadmissible even when State has not observed it.
    identity = (
        child
        if target == "child"
        else parent
        if target == "old-parent"
        else state.get_process_identity(child.hostname, 1)
    )
    at = _START + timedelta(seconds=11)
    registry.record_dependent(
        registry.get_process(identity.object_id).identity.ref,
        transition_id="later:" + identity.object_id,
        canonical_time=at,
        action_id="later",
        reason="newer canonical activity",
    )
    if target == "adopter":
        # Root activity does not prevent an earlier child from becoming attached.
        token = adapter.prepare_service_process_closure(plan.closure)
        adapter.cancel_service_process_closure(token)
    else:
        before = state.materialization_digest()
        with pytest.raises(StateError):
            adapter.prepare_service_process_closure(plan.closure)
        assert state.materialization_digest() == before


def test_later_child_close_releases_current_parent_and_restores_closed_history() -> None:
    from evidenceforge.generation.lifecycle_registry import LifecycleServiceProcessClosureRequest
    from tests.unit.test_lifecycle_service_preparation import _control

    state, registry, authority, adapter, job, parent, child, descendant, plan = _family()
    authority.materialize_process_group_service_closure_composite(
        plan.cohort, plan.group, adapter.prepare_service_process_closure(plan.closure)
    )
    at = _START + timedelta(seconds=20)
    request = LifecycleServiceProcessClosureRequest(
        binding_closures=(),
        process_closures=tuple(
            _control("process", identity.object_id, at=at) for identity in (descendant, child)
        ),
    )
    token = adapter.prepare_service_process_closure(request)
    with adapter.claimed_service_process_closure(token) as prepared:
        prepared.commit_no_fail()
    del prepared
    root = state.get_process_identity(child.hostname, 1)
    assert registry.live_child_process_page(root.object_id, limit=10)[0] == ()
    recovered = LifecycleRegistry()
    _restore(recovered, _capture(registry))
    assert recovered.get_process(child.object_id) == registry.get_process(child.object_id)
    assert recovered.live_child_process_page(root.object_id, limit=10)[0] == ()
