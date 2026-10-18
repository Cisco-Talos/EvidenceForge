# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Authenticated audit adoption preserves the privileged receiver and its history."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.identity import PosixProcessCredentials, ProcessIdentity
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_audit_sessions import _START, _commit, _plan, _start


def _receiver() -> tuple[StateManager, ProcessIdentity]:
    manager = StateManager()
    _start(manager)
    builder, session = _plan(manager)
    process = builder.plan_process(
        system="MAC-A",
        parent_pid=0,
        image="/usr/libexec/sshd-session",
        command_line="sshd-session: casey [priv]",
        username="root",
        integrity_level="System",
        os_category="macos",
        logon_id=session.identity.logon_id,
        session_plan=session,
        require_session=True,
        start_time=_START + timedelta(milliseconds=200),
        credentials=PosixProcessCredentials(0, 0, 0, 0),
    )
    builder.bind_session_processes(session, transport_plan=process, process_tree_root_plan=process)
    _commit(manager, builder)
    return manager, process.identity


def _bind(manager: StateManager, before: ProcessIdentity) -> ProcessIdentity:
    builder = manager.begin_action_cohort_materialization()
    after = builder.bind_macos_process_audit_origin(before, bound_at=_START + timedelta(seconds=1))
    manager.materialize_action_cohort(builder.seal())
    return after


def test_audit_adoption_preserves_root_task_execution_and_historical_credentials() -> None:
    manager, before = _receiver()
    after = _bind(manager, before)
    assert replace(after, credentials=before.credentials) == before
    assert after.credentials == PosixProcessCredentials(0, 0, 0, 0, 501, 100_000)
    assert manager.get_process_identity("MAC-A", before.pid) == after
    assert (
        manager.get_process_identity_at("MAC-A", before.pid, _START + timedelta(milliseconds=500))
        == before
    )
    assert (
        manager.get_process_identity_at("MAC-A", before.pid, _START + timedelta(seconds=1)) == after
    )
    assert manager.get_primary_thread("MAC-A", before.pid) == before.primary_thread


def test_audit_adoption_rollback_restores_exact_process_and_retries() -> None:
    manager, before = _receiver()
    row = manager.get_process("MAC-A", before.pid)
    digest = manager.materialization_digest()
    builder = manager.begin_action_cohort_materialization()
    after = builder.bind_macos_process_audit_origin(before, bound_at=_START + timedelta(seconds=1))
    plan = builder.seal()
    assert manager.materialization_digest() == digest
    with manager.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert row.credentials == after.credentials
    assert manager.get_process("MAC-A", before.pid) is row
    assert row.audit_binding is None
    assert manager.materialization_digest() == digest
    manager.materialize_action_cohort(plan)
    assert manager.get_process_identity("MAC-A", before.pid) == after


def test_audit_origin_is_inherited_by_fork_without_reallocating_session_or_pid_version() -> None:
    manager, before = _receiver()
    after = _bind(manager, before)
    builder = manager.begin_action_cohort_materialization()
    child = builder.fork_process(after, forked_at=_START + timedelta(seconds=2))
    manager.materialize_action_cohort(builder.seal())
    assert child.identity.credentials == after.credentials
    assert child.identity.audit_pid_version != after.audit_pid_version
    assert manager.get_process("MAC-A", child.identity.pid).audit_binding is None
    assert manager._macos_audit_session_counters == {"MAC-A": 100_000}


def test_audit_adoption_history_survives_exec_exit_and_checkpoint() -> None:
    manager, before = _receiver()
    after = _bind(manager, before)
    builder = manager.begin_action_cohort_materialization()
    executed = builder.execute_process(
        after, image="/bin/zsh", command_line="-zsh", executed_at=_START + timedelta(seconds=2)
    )
    manager.materialize_action_cohort(builder.seal())
    manager.end_process("MAC-A", before.pid, _START + timedelta(seconds=3))
    restored = StateManager()
    _restore_head(restored, _capture_head(manager))
    for owner in (manager, restored):
        assert (
            owner.get_process_identity_by_object_id(
                before.object_id, event_time=_START + timedelta(milliseconds=500)
            )
            == before
        )
        assert (
            owner.get_process_identity_by_object_id(
                before.object_id, event_time=_START + timedelta(seconds=1)
            )
            == after
        )
        assert (
            owner.get_process_identity_by_object_id(
                before.object_id, event_time=_START + timedelta(seconds=2)
            )
            == executed
        )


@pytest.mark.parametrize("seconds", [0, 300, 301])
def test_adoption_rejects_time_outside_authenticated_transport(seconds: int) -> None:
    manager, before = _receiver()
    builder = manager.begin_action_cohort_materialization()
    with pytest.raises((StateError, ValueError)):
        builder.bind_macos_process_audit_origin(
            before, bound_at=_START + timedelta(seconds=seconds)
        )


def test_adoption_cannot_replace_existing_origin_or_accept_stale_identity() -> None:
    manager, before = _receiver()
    after = _bind(manager, before)
    for target in (before, after):
        builder = manager.begin_action_cohort_materialization()
        with pytest.raises((StateError, ValueError)):
            builder.bind_macos_process_audit_origin(target, bound_at=_START + timedelta(seconds=2))


def test_adoption_and_dependent_fork_require_separate_cohorts() -> None:
    manager, before = _receiver()
    builder = manager.begin_action_cohort_materialization()
    builder.bind_macos_process_audit_origin(before, bound_at=_START + timedelta(seconds=1))
    builder.fork_process(before, forked_at=_START + timedelta(seconds=2))
    with pytest.raises(StateError, match="separate cohort"):
        builder.seal()


def test_checkpoint_rejects_current_credentials_inconsistent_with_bound_origin() -> None:
    manager, before = _receiver()
    _bind(manager, before)
    manager.get_process("MAC-A", before.pid).credentials = before.credentials
    with pytest.raises(CheckpointCorruptionError, match="audit-origin binding"):
        _restore_head(StateManager(), _capture_head(manager))


def test_adoption_requires_exact_receiver_role_not_another_privileged_session_process() -> None:
    manager, before = _receiver()
    manager.get_session(before.logon_id).transport_pid = 0
    with pytest.raises(StateError, match="session authority"):
        _bind(manager, before)


def test_adoption_preserves_lifecycle_identity_and_advances_its_activity_frontier() -> None:
    from evidenceforge.events.lifecycle import LifecycleTransition
    from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
    from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
    from evidenceforge.generation.lifecycle_shadow import LifecycleShadow

    manager, before = _receiver()
    registry = LifecycleRegistry(shard_count=4)
    authority = GeneratorLifecycleAuthority(
        manager, LifecycleShadow(manager, registry), shard_count=4
    )
    authority.bootstrap_active_state()
    initial = registry.get_process(before.object_id)
    builder = manager.begin_action_cohort_materialization()
    after = builder.bind_macos_process_audit_origin(before, bound_at=_START + timedelta(seconds=1))
    plan = builder.seal()
    token = authority.prepare_action_cohort(plan)
    assert len(token.request.operations) == 1
    transition = token.request.operations[0]
    assert isinstance(transition, LifecycleTransition)
    assert transition.subject == initial.identity.ref
    assert transition.reason == "State process audit-origin adoption"
    with manager.prepared_action_cohort_materialization(plan) as state_claim:
        with registry.claimed_action_cohort(token) as registry_claim:
            state_claim.certify_composite_commit(state_claim.expected_result)
            state_claim.apply_provisional()
            registry_claim.commit_no_fail()
            state_claim.finalize_no_fail()
    assert manager.get_process_identity("MAC-A", before.pid) == after
    assert registry.get_process(before.object_id).identity == initial.identity
    assert registry.get_process(before.object_id).latest_dependent_at == transition.canonical_time


def test_adoption_requires_an_explicit_source_member() -> None:
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.models.exceptions import EventContractError

    manager, before = _receiver()
    builder = manager.begin_action_cohort_materialization()
    builder.bind_macos_process_audit_origin(before, bound_at=_START + timedelta(seconds=1))
    plan = builder.seal()
    dispatcher = EventDispatcher(manager, {})
    with pytest.raises(EventContractError, match="ordered dispatch tuple"):
        dispatcher.prepare_action_cohort_batch("audit-origin-test", plan, (), (), (), ())


def test_legacy_process_record_decodes_with_absent_audit_binding() -> None:
    from evidenceforge.generation.checkpoints.state_values import (
        decode_state_value,
        encode_state_value,
    )

    manager, before = _receiver()
    row = manager.get_process("MAC-A", before.pid)
    encoded = encode_state_value(row)
    assert encoded[1] == "running-process-v10"
    encoded[1] = "running-process-v4"
    encoded[2] = encoded[2][:27]
    assert decode_state_value(encoded) == row


@pytest.mark.parametrize("field", ["before", "after", "origin", "bound_at"])
def test_tampered_audit_binding_is_rejected_before_state_mutation(field: str) -> None:
    manager, before = _receiver()
    builder = manager.begin_action_cohort_materialization()
    builder.bind_macos_process_audit_origin(before, bound_at=_START + timedelta(seconds=1))
    plan = builder.seal()
    digest = manager.materialization_digest()
    binding = plan.process_activity_patches[0].audit_binding
    value = {
        "before": PosixProcessCredentials(0, 0, 1, 1),
        "after": PosixProcessCredentials(0, 0, 0, 0, 999, 100_001),
        "origin": replace(binding.origin, audit_uid=999),
        "bound_at": _START + timedelta(seconds=4),
    }[field]
    object.__setattr__(binding, field, value)
    with pytest.raises((StateError, ValueError)):
        manager.materialize_action_cohort(plan)
    assert manager.materialization_digest() == digest
    assert manager.get_process_identity("MAC-A", before.pid) == before
