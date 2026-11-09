# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Kernel parent adoption composes with exact parent exit and preserves origin."""

from datetime import timedelta

import pytest

from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_posix_job_control import _START, _fork, _root


def test_adoption_and_parent_exit_share_state_commit_and_preserve_history() -> None:
    state, root = _root()
    parent = _fork(state, root, 1)
    child = _fork(state, parent, 2)
    at = _START + timedelta(seconds=3)
    builder = state.begin_action_cohort_materialization()
    adopted = builder.adopt_process_after_parent_exit(child, adopter=root, changed_at=at)
    builder.terminate_process(parent, end_time=at)
    plan = builder.seal()
    before = state.materialization_digest()
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert state.get_process_identity(child.hostname, child.pid) == adopted
    assert state.materialization_digest() == before
    state.materialize_action_cohort(plan)
    assert state.get_process_identity(child.hostname, child.pid) == adopted
    assert adopted.parentage.original == child.parentage.original
    assert adopted.parent_pid == root.pid
    assert adopted.execution_id == child.execution_id
    assert adopted.credentials == child.credentials
    assert adopted.job_control == child.job_control
    assert state.get_process_identity_at(child.hostname, child.pid, child.started_at) == child
    assert state.get_process(parent.hostname, parent.pid) is None
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_process_identity(child.hostname, child.pid) == adopted
    assert restored.get_process_identity_at(child.hostname, child.pid, child.started_at) == child


def test_adoption_without_its_parent_exit_is_not_a_standalone_state_mutation() -> None:
    state, root = _root()
    parent = _fork(state, root, 1)
    child = _fork(state, parent, 2)
    builder = state.begin_action_cohort_materialization()
    builder.adopt_process_after_parent_exit(
        child, adopter=root, changed_at=_START + timedelta(seconds=3)
    )
    before = state.materialization_digest()
    with pytest.raises(StateError, match="exact cohort exit"):
        state.materialize_action_cohort(builder.seal())
    assert state.materialization_digest() == before


def test_parent_exit_dispatch_atomically_adopts_the_surviving_child() -> None:
    from evidenceforge.events.contexts import HostContext
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.generation.actions.posix_process import process_exit_occurrence
    from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
    from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
    from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
    from tests.unit.test_process_exit_projection import _prepare

    state, root = _root()
    parent = _fork(state, root, 1)
    child = _fork(state, parent, 2)
    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    authority.bootstrap_active_state()
    dispatcher = EventDispatcher(
        state, {}, lifecycle_shadow=shadow, enforce_lifecycle_authority=True
    )
    from evidenceforge.generation.actions.command_effects import ExecutionEffectAuditCounter

    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    at = _START + timedelta(seconds=3)
    builder = state.begin_action_cohort_materialization()
    adopted = builder.adopt_process_after_parent_exit(child, adopter=root, changed_at=at)
    builder.terminate_process(parent, end_time=at)
    event = process_exit_occurrence(
        host=HostContext(
            hostname=parent.hostname,
            ip="192.0.2.50",
            os="macOS 26",
            os_category="macos",
            system_type="workstation",
        ),
        process=parent,
        timestamp=at,
        integrity_level="System",
    )
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, builder.seal(), event))
    assert state.get_process_identity(child.hostname, child.pid) == adopted
    import gc

    from evidenceforge.generation.checkpoints.lifecycle_head import _capture, _restore

    del dispatcher
    gc.collect()
    registry.prune_action_cohort_receipt_authorities()
    restored_registry = LifecycleRegistry()
    _restore(restored_registry, _capture(registry))
    registry = restored_registry
    assert registry.get_process(parent.object_id).closed_at == at
    snapshot = registry.get_process(child.object_id)
    assert snapshot.identity.parent_object_id == parent.object_id
    assert snapshot.current_parent_object_id == root.object_id
    assert snapshot.closed_at is None
    assert registry.live_child_process_page(parent.object_id, limit=10)[0] == ()
    assert tuple(
        row.identity.object_id
        for row in registry.live_child_process_page(root.object_id, limit=10)[0]
    ) == (child.object_id,)


@pytest.mark.parametrize(
    "damage", ["non-root", "foreign-host", "unknown-parent", "parent-reuse", "backdated"]
)
def test_state_adoption_rejects_invalid_parent_authority(damage: str) -> None:
    from dataclasses import replace

    state, root = _root()
    parent = _fork(state, root, 1)
    child = _fork(state, parent, 2)
    at = _START + timedelta(seconds=3)
    if damage == "non-root":
        root = replace(root, principal="user")
    elif damage == "foreign-host":
        root = replace(root, hostname="FOREIGN", primary_thread=None)
    elif damage == "unknown-parent":
        child = replace(child, parentage=None)
    elif damage == "parent-reuse":
        child = replace(
            child,
            parentage=replace(
                child.parentage,
                current=replace(child.parentage.current, object_id="other-lifetime"),
            ),
        )
    else:
        at = _START + timedelta(seconds=1)
    before = state.materialization_digest()
    builder = state.begin_action_cohort_materialization()
    with pytest.raises((StateError, ValueError)):
        builder.adopt_process_after_parent_exit(child, adopter=root, changed_at=at)
    assert state.materialization_digest() == before


def test_previous_process_record_reads_unknown_adoption_history() -> None:
    from evidenceforge.generation.checkpoints.state_values import (
        decode_state_value,
        encode_state_value,
    )

    state, root = _root()
    child = _fork(state, root, 1)
    running = state.get_process(child.hostname, child.pid)
    encoded = encode_state_value(running)
    legacy = [encoded[0], "running-process-v12", encoded[2][:36]]
    recovered = decode_state_value(legacy)
    assert recovered.parentage == running.parentage
    assert recovered.parentage_history == ()


def test_parent_history_is_independent_of_later_exec() -> None:
    state, root = _root()
    parent = _fork(state, root, 1)
    child = _fork(state, parent, 2)
    builder = state.begin_action_cohort_materialization()
    adopted = builder.adopt_process_after_parent_exit(
        child, adopter=root, changed_at=_START + timedelta(seconds=3)
    )
    builder.terminate_process(parent, end_time=_START + timedelta(seconds=3))
    state.materialize_action_cohort(builder.seal())
    builder = state.begin_action_cohort_materialization()
    executed = builder.execute_process(
        adopted, image="/bin/true", command_line="true", executed_at=_START + timedelta(seconds=4)
    )
    state.materialize_action_cohort(builder.seal())
    assert executed.parentage == adopted.parentage
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_process_identity_at(child.hostname, child.pid, child.started_at) == child
    assert (
        restored.get_process_identity_at(child.hostname, child.pid, _START + timedelta(seconds=3))
        == adopted
    )
    assert (
        restored.get_process_identity_at(child.hostname, child.pid, _START + timedelta(seconds=4))
        == executed
    )
