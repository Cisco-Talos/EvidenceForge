# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Synthetic execution epochs through the canonical atomic State owner."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.lifecycle import LifecycleTransition
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.lifecycle_authority import (
    GeneratorLifecycleAuthority,
    _process_identity_payload,
)
from evidenceforge.generation.lifecycle_registry import (
    LifecycleRegistry,
    LifecycleSubjectClosureControl,
)
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import EventContractError, StateError
from evidenceforge.models.state import RunningProcess

_START = datetime(2026, 10, 15, 12, tzinfo=UTC)


def _process(platform: str = "macos") -> tuple[StateManager, ProcessIdentity]:
    manager = StateManager()
    manager.set_current_time(_START)
    plan = manager.plan_process_materialization(
        system="workstation-test",
        parent_pid=0,
        image="/bin/zsh",
        command_line="-zsh",
        username="alex",
        integrity_level="Medium",
        os_category=platform,
        start_time=_START,
    )
    manager.materialize_process(plan)
    return manager, plan.identity


def _execute(manager: StateManager, before: ProcessIdentity, seconds: int = 1) -> ProcessIdentity:
    builder = manager.begin_action_cohort_materialization()
    after = builder.execute_process(
        before,
        image="/usr/bin/id",
        command_line="id -u",
        executed_at=_START + timedelta(seconds=seconds),
    )
    result = manager.materialize_action_cohort(builder.seal())
    assert result.executed_processes == (after,)
    assert result.started_processes == result.terminated_processes == ()
    return after


@pytest.mark.parametrize("platform", ["macos", "linux"])
def test_exec_preserves_lifetime_and_historical_observations(platform: str) -> None:
    manager, before = _process(platform)
    counters = (dict(manager._pid_counters), dict(manager._thread_id_counters))
    after = _execute(manager, before)
    assert after.object_id == before.object_id
    assert after.pid == before.pid
    assert after.started_at == before.started_at
    assert after.lifecycle_group_id == before.lifecycle_group_id
    if platform == "macos":
        assert after.primary_thread != before.primary_thread
        assert after.primary_thread is not None
        assert after.primary_thread.started_at == after.execution_started_at
        assert manager.get_primary_thread(before.hostname, before.pid) == after.primary_thread
    else:
        assert after.primary_thread == before.primary_thread
    assert after.execution_id != before.execution_id
    assert after.execution_ordinal == 1
    assert before.image == "/bin/zsh"
    assert after.image == "/usr/bin/id"
    assert after.initial_image == before.image
    assert manager.get_process_identity(before.hostname, before.pid) == after
    assert manager.get_process_identity_at(before.hostname, before.pid, _START) == before
    assert (
        manager.get_process_identity_at(before.hostname, before.pid, after.execution_started_at)
        == after
    )
    assert manager._pid_counters == counters[0]
    if platform == "linux":
        assert manager._thread_id_counters == counters[1]
    assert len(manager.state.running_processes) == 1


def test_exec_planning_is_pure_and_provisional_abort_restores_exact_preimage() -> None:
    manager, before = _process()
    digest = manager.materialization_digest()
    builder = manager.begin_action_cohort_materialization()
    after = builder.execute_process(
        before, image="/usr/bin/id", command_line="id", executed_at=_START + timedelta(seconds=1)
    )
    plan = builder.seal()
    assert manager.materialization_digest() == digest
    with manager.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert manager.get_process_identity(before.hostname, before.pid) == after
    assert manager.materialization_digest() == digest
    assert manager.get_process_identity(before.hostname, before.pid) == before
    process = manager.get_process(before.hostname, before.pid)
    assert process is not None and process.prior_executions == ()
    # The original transaction may be retried with exactly the same semantic identity.
    manager.materialize_action_cohort(plan)
    assert manager.get_process_identity(before.hostname, before.pid) == after


def test_execution_checkpoint_restores_history_and_continues_same_epoch_sequence() -> None:
    manager, before = _process()
    first = _execute(manager, before)
    restored = StateManager()
    _restore_head(restored, _capture_head(manager))
    assert restored.get_process_identity_at(before.hostname, before.pid, _START) == before
    assert restored.get_process_identity(before.hostname, before.pid) == first
    expected = _execute(manager, first, seconds=2)
    actual = _execute(restored, first, seconds=2)
    assert expected == actual
    assert manager.materialization_digest() == restored.materialization_digest()


def test_exact_post_exec_frontier_is_atomic_and_survives_checkpoint() -> None:
    manager, before = _process()
    digest = manager.materialization_digest()
    builder = manager.begin_action_cohort_materialization()
    after = builder.execute_process(
        before, image="/usr/bin/id", command_line="id", executed_at=_START + timedelta(seconds=1)
    )
    at = _START + timedelta(seconds=2)
    builder.patch_process_activity(after, at)
    plan = builder.seal()
    with manager.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert manager.get_process(before.hostname, before.pid).last_activity_time == at
    assert manager.materialization_digest() == digest
    manager.materialize_action_cohort(plan)
    restored = StateManager()
    _restore_head(restored, _capture_head(manager))
    assert restored.get_process(before.hostname, before.pid).last_activity_time == at


@pytest.mark.parametrize("damage", ["time", "identity"])
def test_post_exec_frontier_rejects_backdating_or_unowned_future_identity(damage: str) -> None:
    manager, before = _process()
    digest = manager.materialization_digest()
    builder = manager.begin_action_cohort_materialization()
    after = builder.execute_process(
        before, image="/usr/bin/id", command_line="id", executed_at=_START + timedelta(seconds=1)
    )
    if damage == "identity":
        with pytest.raises(StateError, match="absent or drifted"):
            builder.patch_process_activity(
                replace(after, image="/usr/bin/other"), _START + timedelta(seconds=2)
            )
    else:
        builder.patch_process_activity(after, _START)
        with pytest.raises(StateError, match="Post-exec activity"):
            builder.seal()
    assert manager.materialization_digest() == digest


def test_exit_retains_last_execution_and_original_lifetime() -> None:
    manager, before = _process()
    after = _execute(manager, before)
    builder = manager.begin_action_cohort_materialization()
    builder.terminate_process(after, end_time=_START + timedelta(seconds=3))
    result = manager.materialize_action_cohort(builder.seal())
    assert result.terminated_processes == (after,)
    assert manager.get_process(before.hostname, before.pid) is None
    assert manager.get_process_identity_by_object_id(before.object_id) == after
    assert manager.get_process_identity_at(before.hostname, before.pid, _START) == before
    assert (
        manager.get_process_identity_at(before.hostname, before.pid, _START + timedelta(seconds=3))
        is None
    )


def test_exec_rejects_stale_identity_and_backdated_activity_without_mutation() -> None:
    manager, before = _process()
    after = _execute(manager, before)
    digest = manager.materialization_digest()
    with pytest.raises(StateError, match="identity|drift"):
        _execute(manager, before, seconds=2)
    manager.update_process_activity_time(before.hostname, before.pid, _START + timedelta(seconds=4))
    updated = manager.materialization_digest()
    with pytest.raises(StateError, match="committed activity"):
        _execute(manager, after, seconds=3)
    assert manager.materialization_digest() == updated
    assert updated != digest


@pytest.mark.parametrize("member", ["activity", "close"])
def test_exec_rejects_ambiguous_same_cohort_dependents(member: str) -> None:
    manager, before = _process()
    digest = manager.materialization_digest()
    builder = manager.begin_action_cohort_materialization()
    builder.execute_process(
        before, image="/usr/bin/id", command_line="id", executed_at=_START + timedelta(seconds=1)
    )
    if member == "activity":
        builder.patch_process_activity(before, _START + timedelta(seconds=2))
    else:
        builder.terminate_process(before, end_time=_START + timedelta(seconds=2))
    with pytest.raises(StateError, match="separate cohort"):
        builder.seal()
    assert manager.materialization_digest() == digest


def test_windows_processes_cannot_receive_posix_exec_transition() -> None:
    manager, before = _process("windows")
    digest = manager.materialization_digest()
    with pytest.raises(StateError, match="POSIX PID namespace"):
        _execute(manager, before)
    assert manager.materialization_digest() == digest


def test_tampered_execution_plan_is_rejected_before_commit() -> None:
    manager, before = _process()
    builder = manager.begin_action_cohort_materialization()
    after = builder.execute_process(
        before, image="/usr/bin/id", command_line="id", executed_at=_START + timedelta(seconds=1)
    )
    plan = builder.seal()
    altered = replace(plan.process_executions[0], after=replace(after, principal="root"))
    with pytest.raises(StateError, match="semantic identity"):
        manager.materialize_action_cohort(replace(plan, _process_executions=(altered,)))
    assert manager.get_process_identity(before.hostname, before.pid) == before


def test_retained_exec_history_is_bounded_and_never_substitutes_current_image() -> None:
    manager, before = _process()
    current = before
    for seconds in range(1, 70):
        current = _execute(manager, current, seconds)
    process = manager.get_process(before.hostname, before.pid)
    assert process is not None and len(process.prior_executions) == 64
    assert manager.get_process_identity_at(before.hostname, before.pid, _START) is None
    assert (
        manager.get_process_identity_at(
            before.hostname, before.pid, _START + timedelta(seconds=68)
        ).execution_ordinal
        == 68
    )


@pytest.mark.parametrize("kind", ["identity", "process"])
def test_legacy_checkpoint_values_upgrade_without_inventing_an_exec(kind: str) -> None:
    manager, identity = _process()
    original = (
        identity if kind == "identity" else manager.get_process(identity.hostname, identity.pid)
    )
    encoded = encode_state_value(original)
    assert isinstance(encoded, list)
    old_tag, field_count = (
        ("process-identity", 12) if kind == "identity" else ("running-process", 21)
    )
    encoded[1] = old_tag
    encoded[2] = encoded[2][:field_count]
    restored = decode_state_value(encoded)
    assert isinstance(restored, (RunningProcess, ProcessIdentity))
    assert restored.execution_ordinal == 0 and restored.executed_at is None
    assert restored == replace(original, audit_pid_version=None, parentage=None)


@pytest.mark.parametrize("platform", ["macos", "linux"])
def test_fork_inherits_current_execution_then_child_exec_keeps_new_lifetime(platform: str) -> None:
    manager, original = _process(platform)
    parent = _execute(manager, original)
    builder = manager.begin_action_cohort_materialization()
    child = builder.fork_process(parent, forked_at=_START + timedelta(seconds=2))
    assert child.parent_identity == parent
    assert child.identity.pid != parent.pid
    assert child.identity.object_id != parent.object_id
    assert child.identity.image == parent.image
    assert child.identity.command_line == parent.command_line
    assert child.identity.principal == parent.principal
    assert child.identity.logon_id == parent.logon_id
    result = manager.materialize_action_cohort(builder.seal())
    assert result.started_processes == (child.identity,)
    executed = _execute(manager, child.identity, seconds=3)
    assert executed.pid == child.identity.pid
    assert executed.object_id == child.identity.object_id
    assert manager.get_process_identity(parent.hostname, parent.pid) == parent


def test_child_parent_snapshot_resolves_execution_at_child_start() -> None:
    manager, before = _process()
    _execute(manager, before, seconds=2)
    builder = manager.begin_action_cohort_materialization()
    child = builder.plan_process(
        system=before.hostname,
        parent_pid=before.pid,
        image="/usr/bin/true",
        command_line="true",
        username=before.principal,
        integrity_level="Medium",
        os_category="macos",
        start_time=_START + timedelta(seconds=1),
    )
    assert child.parent_identity == before
    manager.materialize_action_cohort(builder.seal())
    assert manager.get_process_identity(before.hostname, child.identity.pid) == child.identity


def test_linux_exec_with_worker_threads_still_requires_platform_replacement_semantics() -> None:
    manager, before = _process("linux")
    worker = manager.create_thread(before.hostname, before.object_id, start_time=_START)
    digest = manager.materialization_digest()
    with pytest.raises(StateError, match="worker threads"):
        _execute(manager, before)
    assert manager.materialization_digest() == digest
    assert manager.get_thread(before.hostname, before.object_id, worker.tid) == worker


@pytest.mark.parametrize("platform", ["macos", "linux"])
def test_exec_retains_registered_lifetime_and_advances_dependent_frontier(platform: str) -> None:
    manager, before = _process(platform)
    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(manager, registry)
    authority = GeneratorLifecycleAuthority(manager, shadow, shard_count=4)
    authority.bootstrap_active_state()
    initial = registry.get_process(before.object_id)
    assert initial is not None
    builder = manager.begin_action_cohort_materialization()
    after = builder.execute_process(
        before, image="/usr/bin/id", command_line="id", executed_at=_START + timedelta(seconds=1)
    )
    plan = builder.seal()
    token = authority.prepare_action_cohort(plan)
    assert len(token.request.operations) == 1
    transition = token.request.operations[0]
    assert isinstance(transition, LifecycleTransition)
    assert transition.kind == "dependent"
    assert transition.subject == initial.identity.ref
    assert transition.canonical_time == after.execution_started_at
    with manager.prepared_action_cohort_materialization(plan) as state_claim:
        with registry.claimed_action_cohort(token) as registry_claim:
            state_claim.certify_composite_commit(state_claim.expected_result)
            state_claim.apply_provisional()
            registry_claim.commit_no_fail()
            state_claim.finalize_no_fail()
    current = registry.get_process(before.object_id)
    assert current is not None
    assert current.identity == initial.identity
    assert current.membership == initial.membership
    assert current.token == initial.token
    assert current.latest_dependent_at == after.execution_started_at
    assert current.current_view.execution_ordinal == after.execution_ordinal
    assert current.current_view.image == after.image
    assert current.current_view.changed_at == after.execution_started_at
    assert current.current_view.token == initial.token
    assert transition.process_change.after == current.current_view
    assert shadow.ensure_process(after, session=None) == initial.identity
    # A later close still binds the original lifetime while carrying the new image.
    close = manager.begin_action_cohort_materialization()
    close.terminate_process(after, end_time=_START + timedelta(seconds=2))
    close_plan = close.seal()
    close_token = authority.prepare_action_cohort(close_plan)
    assert len(close_token.request.operations) == 1
    closure = close_token.request.operations[0]
    assert isinstance(closure, LifecycleSubjectClosureControl)
    assert closure.barrier.subject == initial.identity.ref


def test_execution_requires_an_existing_registered_lifetime() -> None:
    manager, before = _process()
    registry = LifecycleRegistry(shard_count=4)
    authority = GeneratorLifecycleAuthority(
        manager, LifecycleShadow(manager, registry), shard_count=4
    )
    builder = manager.begin_action_cohort_materialization()
    builder.execute_process(
        before, image="/usr/bin/id", command_line="id", executed_at=_START + timedelta(seconds=1)
    )
    with pytest.raises(StateError, match="not registered"):
        authority.prepare_action_cohort(builder.seal())


def test_execution_payload_binds_epoch_and_immutable_lifetime_image() -> None:
    manager, before = _process()
    after = _execute(manager, before)
    assert _process_identity_payload(before) != _process_identity_payload(after)
    assert _process_identity_payload(after) != _process_identity_payload(
        replace(after, lifetime_image="/bin/bash")
    )
    assert _process_identity_payload(after) != _process_identity_payload(
        replace(after, execution_ordinal=2)
    )


def test_initial_execution_cannot_claim_a_different_lifetime_image() -> None:
    _manager, before = _process()
    with pytest.raises(ValueError, match="Initial process execution"):
        replace(before, lifetime_image="/bin/bash")


def test_execution_cannot_publish_without_a_canonical_source_projection() -> None:
    manager, before = _process()
    builder = manager.begin_action_cohort_materialization()
    builder.execute_process(
        before, image="/usr/bin/id", command_line="id", executed_at=_START + timedelta(seconds=1)
    )
    dispatcher = EventDispatcher(manager, {})
    digest = manager.materialization_digest()
    with pytest.raises(EventContractError, match="ordered dispatch tuple"):
        dispatcher.prepare_action_cohort_batch("exec-test", builder.seal(), (), (), (), ())
    assert manager.materialization_digest() == digest


def test_exec_history_does_not_cross_reused_pid_lifetimes(monkeypatch: pytest.MonkeyPatch) -> None:
    manager, original = _process()
    executed = _execute(manager, original)
    manager.end_process(original.hostname, original.pid, _START + timedelta(seconds=3))
    preview = manager._preview_linux_pid

    def reused_pid(**kwargs: object) -> tuple:
        _pid, position, patch, candidates = preview(**kwargs)
        return original.pid, position, patch, candidates

    monkeypatch.setattr(manager, "_preview_linux_pid", reused_pid)
    replacement = manager.plan_process_materialization(
        system=original.hostname,
        parent_pid=0,
        image="/bin/cat",
        command_line="cat /tmp/example.txt",
        username="alex",
        integrity_level="Medium",
        os_category="macos",
        start_time=_START + timedelta(seconds=10),
    )
    manager.materialize_process(replacement)
    assert replacement.identity.pid == original.pid
    assert replacement.identity.object_id != original.object_id
    assert replacement.identity.execution_ordinal == 0
    # PID-only lookup deliberately forgets the retired incarnation at reuse.
    # Delayed observations must carry the durable object ID to recover history.
    assert manager.get_process_identity_at(original.hostname, original.pid, _START) is None
    assert (
        manager.get_process_identity_at(
            original.hostname, original.pid, _START + timedelta(seconds=2)
        )
        is None
    )
    assert (
        manager.get_process_identity_at(
            original.hostname, original.pid, _START + timedelta(seconds=5)
        )
        is None
    )
    assert (
        manager.get_process_identity_by_object_id(original.object_id, event_time=_START) == original
    )
    assert (
        manager.get_process_identity_by_object_id(
            original.object_id, event_time=_START + timedelta(seconds=2)
        )
        == executed
    )
    assert manager.get_process_identity(original.hostname, original.pid) == replacement.identity
