# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Leader exit preserves a loaded job and group until an explicit later unload."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.generation.actions.macos_launch_item import (
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
from tests.unit.test_macos_launch_activation import _activation, _process, _setup
from tests.unit.test_macos_launch_registration import _START


@pytest.mark.parametrize("restore", [False, True])
@pytest.mark.parametrize("separate_group", [False, True])
def test_bound_leader_exit_adopts_children_and_later_unload_respects_group(
    restore: bool, separate_group: bool
) -> None:
    state, registry, authority, adapter, job = _setup()
    leader = _process(state, job, new_posix_session=True)
    authority.materialize_process_service_composite(
        leader, adapter.prepare_service_publication(_activation(registry, authority, job, leader))
    )
    child = _process(
        state,
        job,
        parent_pid=leader.identity.pid,
        new_posix_session=separate_group,
        start_time=_START + timedelta(seconds=2),
    )
    authority.materialize_process(child)
    exit_at = _START + timedelta(seconds=10)
    plan = macos_system_job_leader_exit_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=exit_at,
        action_id="completed-leader",
        exit_outcome=PosixProcessExit(exit_code=7),
    )
    proof = authority.materialize_process_group_leader_exit_composite(
        plan.cohort, plan.group, adapter.prepare_service_process_closure(plan.closure)
    )
    assert authority.authenticates_process_service_closure_composite_receipt(
        plan.cohort.process_terminations[0].target, proof
    )
    assert not plan.closure.service_closures
    assert registry.get_service_instance(job.instance_identity.object_id).closed_at is None
    assert registry.get_process(leader.identity.object_id).closed_at == exit_at
    assert state.get_process_identity_by_object_id(child.identity.object_id).parent_pid == 1
    assert (
        state.get_process_identity_by_object_id(child.identity.object_id).job_control
        == child.identity.job_control
    )
    assert state._ended_processes_by_object_id.get(
        leader.identity.object_id
    ).exit_outcome == PosixProcessExit(exit_code=7)
    if not separate_group:
        replacement = _process(
            state, job, start_time=exit_at + timedelta(seconds=1), new_posix_session=True
        )
        with pytest.raises(StateError, match="live members"):
            authority.materialize_process_service_composite(
                replacement,
                adapter.prepare_service_publication(
                    _activation(registry, authority, job, replacement)
                ),
            )
    del proof
    if restore:
        registry.advance_watermark(_START + timedelta(days=3))
        assert registry.get_process(leader.identity.object_id) is None
        new_state, new_registry = StateManager(), LifecycleRegistry()
        _restore_head(new_state, _capture_head(state))
        _restore(new_registry, _capture(registry))
        state, registry = new_state, new_registry
        authority = GeneratorLifecycleAuthority(
            state, LifecycleShadow(state, registry), shard_count=8
        )
        adapter = LifecycleProductionAdapter(registry)
    unload_at = _START + timedelta(days=3, seconds=1) if restore else exit_at + timedelta(seconds=1)
    unload = macos_system_job_unload_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=unload_at,
        action_id="later-unload",
    )
    if separate_group:
        with adapter.claimed_service_process_closure(
            adapter.prepare_service_process_closure(unload.closure)
        ) as prepared:
            prepared.commit_no_fail()
        assert state.get_process_identity_by_object_id(child.identity.object_id) is not None
    else:
        authority.materialize_process_group_service_closure_composite(
            unload.cohort, unload.group, adapter.prepare_service_process_closure(unload.closure)
        )
        assert state.get_process(child.identity.hostname, child.identity.pid) is None
    assert registry.get_service_instance(job.instance_identity.object_id).closed_at == unload_at


@pytest.mark.parametrize(
    "damage",
    ["unknown-group", "foreign-group", "unload-request", "missing-adoption", "stale-state"],
)
def test_leader_exit_rejects_changed_ownership_without_partial_commit(damage: str) -> None:
    from tests.unit.test_macos_group_adoption import _family

    state, registry, authority, adapter, job, parent, child, descendant, unload = _family()
    at = _START + timedelta(seconds=10)
    if damage == "unknown-group":
        # An unknown-membership service still uses the existing narrower exit API.
        other_state, other_registry, other_authority, other_adapter, other_job = _setup()
        unknown = _process(other_state, other_job)
        other_authority.materialize_process_service_composite(
            unknown,
            other_adapter.prepare_service_publication(
                _activation(other_registry, other_authority, other_job, unknown)
            ),
        )
        with pytest.raises(StateError, match="known group"):
            macos_system_job_leader_exit_completion_plan(
                lifecycle_registry=other_registry,
                state_manager=other_state,
                service_object_id=other_job.instance_identity.object_id,
                completed_at=at,
                action_id="unknown",
            )
        return
    plan = macos_system_job_leader_exit_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=at,
        action_id="leader",
    )
    if damage == "foreign-group":
        plan = replace(plan, group=child.job_control)
    elif damage == "unload-request":
        plan = replace(
            plan, closure=replace(plan.closure, service_closures=unload.closure.service_closures)
        )
    elif damage == "missing-adoption":
        plan = replace(plan, closure=replace(plan.closure, parent_adoptions=()))
    else:
        authority.materialize_process(
            _process(state, job, start_time=_START + timedelta(seconds=4))
        )
    before = state.materialization_digest()
    with pytest.raises(StateError):
        authority.materialize_process_group_leader_exit_composite(
            plan.cohort, plan.group, adapter.prepare_service_process_closure(plan.closure)
        )
    assert state.materialization_digest() == before
    assert registry.get_process(parent.object_id).closed_at is None
    assert registry.get_service_instance(job.instance_identity.object_id).closed_at is None
    assert adapter.service_preparation_census().reserved_keys == 0


@pytest.mark.parametrize("collected", [False, True])
def test_leader_exit_projection_preserves_survivor_and_loaded_job(
    tmp_path: Path, collected: bool
) -> None:
    import json

    from evidenceforge.events.contexts import HostContext
    from evidenceforge.events.dispatcher import EventDispatcher, PreparedDispatchStateIntent
    from evidenceforge.formats.loader import load_format
    from evidenceforge.generation.actions.posix_process import process_exit_occurrence
    from evidenceforge.generation.emitters.ecar import EcarEmitter
    from tests.unit.test_macos_group_adoption import _family

    state, registry, authority, adapter, job, parent, child, descendant, _ = _family()
    plan = macos_system_job_leader_exit_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=_START + timedelta(seconds=10),
        action_id="source-leader-exit",
        exit_outcome=PosixProcessExit(exit_code=7),
    )
    close = plan.cohort.process_terminations[0]
    output = tmp_path / "leader.json"
    emitter = EcarEmitter(load_format("ecar"), output)
    dispatcher = EventDispatcher(
        state,
        {"ecar": emitter} if collected else {},
        lifecycle_shadow=LifecycleShadow(state, registry),
        enforce_lifecycle_authority=True,
    )
    dispatcher.bind_lifecycle_authority(authority)
    event = process_exit_occurrence(
        host=HostContext(
            hostname=parent.hostname,
            ip="192.0.2.25",
            os="macOS 26",
            os_category="macos",
            system_type="workstation",
        ),
        process=parent,
        timestamp=close.end_time,
        integrity_level="root",
    )
    event.process.exit_outcome = close.target.exit_outcome
    prepared = dispatcher.prepare_builder(
        event,
        state_intent=PreparedDispatchStateIntent.EXTERNAL_MATERIALIZED_CLOSE,
        lifecycle_ticket=close.target,
    )
    proof = authority.materialize_process_group_leader_exit_composite(
        plan.cohort, plan.group, adapter.prepare_service_process_closure(plan.closure)
    )
    dispatcher.publish_prepared(prepared, materialization_receipt=proof)
    emitter.close()
    rows = [json.loads(row) for row in output.read_text().splitlines()] if output.exists() else []
    assert len(rows) == int(collected)
    if collected:
        assert rows[0]["objectID"] == parent.object_id
        assert rows[0]["action"] == "TERMINATE"
    assert registry.get_service_instance(job.instance_identity.object_id).closed_at is None
    assert state.get_process_identity_by_object_id(child.object_id).parent_pid == 1
    assert state.get_process_identity_by_object_id(descendant.object_id) == descendant


def test_leader_exit_lost_commit_return_preserves_loaded_job_and_adoption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.generation.lifecycle_registry import _PreparedServiceClosureCommitPlan
    from tests.unit.test_macos_group_adoption import _family

    state, registry, authority, adapter, job, parent, child, descendant, _ = _family()
    plan = macos_system_job_leader_exit_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=_START + timedelta(seconds=10),
        action_id="lost-leader-exit",
    )
    original = registry._service_closure_receipt_locked

    def lose_return(commit: _PreparedServiceClosureCommitPlan) -> None:
        original(commit)
        raise RuntimeError("lost leader commit return")

    monkeypatch.setattr(registry, "_service_closure_receipt_locked", lose_return)
    with pytest.raises(RuntimeError, match="lost leader") as caught:
        authority.materialize_process_group_leader_exit_composite(
            plan.cohort, plan.group, adapter.prepare_service_process_closure(plan.closure)
        )
    assert authority.authenticates_process_service_closure_composite_receipt(
        plan.cohort.process_terminations[0].target, caught.value.process_group_service_receipt
    )
    assert state.get_process_identity_by_object_id(child.object_id).parent_pid == 1
    assert registry.get_process(parent.object_id).closed_at is not None
    assert registry.get_service_instance(job.instance_identity.object_id).closed_at is None
    assert adapter.service_preparation_census().reserved_keys == 0


@pytest.mark.parametrize(
    "damage", ["outcome", "time", "image", "integrity", "platform", "plan-token"]
)
def test_leader_exit_source_cannot_change_terminal_facts(damage: str) -> None:
    from evidenceforge.events.contexts import HostContext
    from evidenceforge.events.dispatcher import EventDispatcher, PreparedDispatchStateIntent
    from evidenceforge.generation.actions.posix_process import process_exit_occurrence
    from evidenceforge.models.exceptions import EventContractError
    from tests.unit.test_macos_group_adoption import _family

    state, registry, authority, adapter, job, parent, child, descendant, _ = _family()
    plan = macos_system_job_leader_exit_completion_plan(
        lifecycle_registry=registry,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        completed_at=_START + timedelta(seconds=10),
        action_id="exact-source",
        exit_outcome=PosixProcessExit(exit_code=7),
    )
    close = plan.cohort.process_terminations[0].target
    event = process_exit_occurrence(
        host=HostContext(
            hostname=parent.hostname,
            ip="192.0.2.25",
            os="macOS 26",
            os_category="macos",
            system_type="workstation",
        ),
        process=parent,
        timestamp=close.end_time,
        integrity_level="root",
    )
    event.process.exit_outcome = close.exit_outcome
    if damage == "outcome":
        event.process.exit_outcome = PosixProcessExit(exit_code=0)
    elif damage == "time":
        event.timestamp += timedelta(seconds=1)
    elif damage == "image":
        event.process.image = "/bin/other"
    elif damage == "integrity":
        event.process.integrity_level = "Medium"
    elif damage == "platform":
        event.src_host.os_category = "linux"
    else:
        close = replace(
            close, _payload=replace(close._payload, exit_outcome=PosixProcessExit(exit_code=0))
        )
    dispatcher = EventDispatcher(
        state,
        {},
        lifecycle_shadow=LifecycleShadow(state, registry),
        enforce_lifecycle_authority=True,
    )
    dispatcher.bind_lifecycle_authority(authority)
    before = state.materialization_digest()
    with pytest.raises((EventContractError, ValueError)):
        dispatcher.prepare_builder(
            event,
            state_intent=PreparedDispatchStateIntent.EXTERNAL_MATERIALIZED_CLOSE,
            lifecycle_ticket=close,
        )
    assert state.materialization_digest() == before
    assert registry.get_process(parent.object_id).closed_at is None


@pytest.mark.slow
def test_leader_exit_source_is_stable_across_fresh_process_hash_seeds(tmp_path: Path) -> None:
    import os
    import subprocess
    import sys

    script = """
from pathlib import Path
import sys
from tests.unit.test_macos_launch_leader_exit import test_leader_exit_projection_preserves_survivor_and_loaded_job
out = Path(sys.argv[1]); out.mkdir()
test_leader_exit_projection_preserves_survivor_and_loaded_job(out, True)
"""
    for seed in ("17", "9876"):
        result = subprocess.run(
            [sys.executable, "-c", script, str(tmp_path / seed)],
            env=os.environ | {"PYTHONHASHSEED": seed},
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / "17" / "leader.json").read_bytes() == (
        tmp_path / "9876" / "leader.json"
    ).read_bytes()
