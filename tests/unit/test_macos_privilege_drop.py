# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Authenticated Mac SSH child credentials change without creating an execution."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.identity import PosixProcessCredentials, ProcessIdentity
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_audit_sessions import _START, _commit, _start


def _child(*, known_ids: bool = True) -> tuple[StateManager, ProcessIdentity]:
    manager = StateManager()
    _start(manager)
    builder = manager.begin_materialization_batch()
    session = builder.plan_session(
        username="casey",
        system="MAC-A",
        logon_type=10,
        source_ip="192.0.2.10",
        session_kind="ssh",
        auth_protocol="ssh",
        start_time=_START,
        source_ready_time=_START + timedelta(seconds=2),
        network_close_time=_START + timedelta(minutes=5),
        effective_uid=501 if known_ids else None,
        effective_gid=20 if known_ids else None,
    )
    session = builder.enrich_macos_audit_session(
        session, audit_uid=501, authenticated_at=_START + timedelta(seconds=1)
    )
    receiver = builder.plan_process(
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
    builder.bind_session_processes(
        session, transport_plan=receiver, process_tree_root_plan=receiver
    )
    _commit(manager, builder)
    changes = manager.begin_action_cohort_materialization()
    parent = changes.bind_macos_process_audit_origin(
        receiver.identity, bound_at=_START + timedelta(seconds=1)
    )
    manager.materialize_action_cohort(changes.seal())
    changes = manager.begin_action_cohort_materialization()
    child = changes.fork_process(parent, forked_at=_START + timedelta(seconds=2))
    manager.materialize_action_cohort(changes.seal())
    return manager, child.identity


def _drop(manager: StateManager, before: ProcessIdentity) -> ProcessIdentity:
    builder = manager.begin_action_cohort_materialization()
    after = builder.drop_macos_ssh_child_privileges(
        before, dropped_at=_START + timedelta(seconds=3)
    )
    manager.materialize_action_cohort(builder.seal())
    return after


def test_drop_changes_credentials_and_username_index_without_exec_or_pid_change() -> None:
    manager, before = _child()
    after = _drop(manager, before)
    assert replace(after, principal=before.principal, credentials=before.credentials) == before
    assert after.principal == "casey"
    assert after.credentials == PosixProcessCredentials(501, 501, 20, 20, 501, 100_000)
    process = manager.get_process("MAC-A", before.pid)
    assert process.integrity_level == "Medium" and process.privilege_drop is not None
    assert not process.prior_executions
    assert process in manager._running_processes.find("username", "casey")
    assert process not in manager._running_processes.find("username", "root")
    assert (
        manager.get_process_identity_at("MAC-A", before.pid, _START + timedelta(seconds=2))
        == before
    )
    assert (
        manager.get_process_identity_at("MAC-A", before.pid, _START + timedelta(seconds=3)) == after
    )


def test_provisional_drop_rolls_back_same_object_and_username_index_then_retries() -> None:
    manager, before = _child()
    process = manager.get_process("MAC-A", before.pid)
    digest = manager.materialization_digest()
    builder = manager.begin_action_cohort_materialization()
    after = builder.drop_macos_ssh_child_privileges(
        before, dropped_at=_START + timedelta(seconds=3)
    )
    plan = builder.seal()
    assert manager.materialization_digest() == digest
    with manager.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert process.username == "casey"
        assert process in manager._running_processes.find("username", "casey")
    assert manager.get_process("MAC-A", before.pid) is process
    assert process.username == "root" and process.privilege_drop is None
    assert process in manager._running_processes.find("username", "root")
    assert process not in manager._running_processes.find("username", "casey")
    assert manager.materialization_digest() == digest
    manager.materialize_action_cohort(plan)
    assert manager.get_process_identity("MAC-A", before.pid) == after


def test_drop_history_survives_exec_exit_and_checkpoint() -> None:
    manager, before = _child()
    dropped = _drop(manager, before)
    builder = manager.begin_action_cohort_materialization()
    executed = builder.execute_process(
        dropped, image="/bin/zsh", command_line="-zsh", executed_at=_START + timedelta(seconds=4)
    )
    manager.materialize_action_cohort(builder.seal())
    manager.end_process("MAC-A", before.pid, _START + timedelta(seconds=5))
    restored = StateManager()
    _restore_head(restored, _capture_head(manager))
    for owner in (manager, restored):
        for seconds, identity in ((2, before), (3, dropped), (4, executed)):
            assert (
                owner.get_process_identity_by_object_id(
                    before.object_id, event_time=_START + timedelta(seconds=seconds)
                )
                == identity
            )
        assert (
            owner.get_process_identity_by_object_id(
                before.object_id, event_time=_START + timedelta(seconds=5)
            )
            is None
        )


def test_fork_after_drop_inherits_user_without_copying_parent_transition() -> None:
    manager, before = _child()
    dropped = _drop(manager, before)
    builder = manager.begin_action_cohort_materialization()
    child = builder.fork_process(dropped, forked_at=_START + timedelta(seconds=4))
    manager.materialize_action_cohort(builder.seal())
    assert child.identity.credentials == dropped.credentials
    assert child.identity.principal == dropped.principal
    assert manager.get_process("MAC-A", child.identity.pid).privilege_drop is None


@pytest.mark.parametrize("seconds", [1, 2, 300, 301])
def test_drop_rejects_outside_child_lifetime(seconds: int) -> None:
    manager, before = _child()
    with pytest.raises((StateError, ValueError)):
        manager.begin_action_cohort_materialization().drop_macos_ssh_child_privileges(
            before, dropped_at=_START + timedelta(seconds=seconds)
        )


def test_drop_requires_known_ids_and_cannot_replace_an_existing_drop() -> None:
    manager, before = _child(known_ids=False)
    with pytest.raises(StateError, match="UID/GID"):
        _drop(manager, before)
    manager, before = _child()
    after = _drop(manager, before)
    with pytest.raises((StateError, ValueError)):
        _drop(manager, after)
    with pytest.raises(StateError):
        _drop(manager, before)


def test_monitor_and_unrelated_process_cannot_adopt_child_credentials() -> None:
    manager, before = _child()
    parent = manager.get_process_identity("MAC-A", before.parent_pid)
    with pytest.raises(StateError, match="child authority"):
        _drop(manager, parent)
    manager.get_session(before.logon_id).transport_pid = 0
    with pytest.raises(StateError, match="child authority"):
        _drop(manager, before)


def test_tampered_drop_plan_fails_without_mutating_state() -> None:
    manager, before = _child()
    builder = manager.begin_action_cohort_materialization()
    builder.drop_macos_ssh_child_privileges(before, dropped_at=_START + timedelta(seconds=3))
    plan = builder.seal()
    patch = plan.process_activity_patches[0]
    altered = replace(patch, privilege_drop=replace(patch.privilege_drop, after_principal="other"))
    with pytest.raises(StateError):
        manager.materialize_action_cohort(replace(plan, _process_activity=(altered,)))
    assert manager.get_process_identity("MAC-A", before.pid) == before


def test_drop_updates_lifecycle_current_token_preserving_original_identity() -> None:
    manager, before = _child()
    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(manager, registry)
    authority = GeneratorLifecycleAuthority(manager, shadow, shard_count=4)
    authority.bootstrap_active_state()
    initial = registry.get_process(before.object_id)
    builder = manager.begin_action_cohort_materialization()
    after = builder.drop_macos_ssh_child_privileges(
        before, dropped_at=_START + timedelta(seconds=3)
    )
    plan = builder.seal()
    token = authority.prepare_action_cohort(plan)
    with manager.prepared_action_cohort_materialization(plan) as state_claim:
        with registry.claimed_action_cohort(token) as registry_claim:
            state_claim.certify_composite_commit(state_claim.expected_result)
            state_claim.apply_provisional()
            registry_claim.commit_no_fail()
            state_claim.finalize_no_fail()
    current = registry.get_process(before.object_id)
    assert current.identity == initial.identity and current.token == initial.token
    assert current.current_view.token.principal == "casey"
    assert current.current_view.token.integrity_level == "Medium"
    assert current.current_view.execution_ordinal == 0
    assert (
        shadow.ensure_process(after, session=manager.get_session_identity(after.logon_id))
        == initial.identity
    )


def test_corrupt_drop_history_is_rejected_before_checkpoint_restore() -> None:
    manager, before = _child()
    _drop(manager, before)
    manager.get_process("MAC-A", before.pid).username = "root"
    with pytest.raises(CheckpointCorruptionError, match="privilege-drop"):
        _restore_head(StateManager(), _capture_head(manager))


@pytest.mark.parametrize("family", ["exec", "fork", "terminate"])
def test_privilege_drop_is_separate_from_dependent_lifecycle_transitions(family: str) -> None:
    manager, before = _child()
    builder = manager.begin_action_cohort_materialization()
    builder.drop_macos_ssh_child_privileges(before, dropped_at=_START + timedelta(seconds=3))
    at = _START + timedelta(seconds=4)
    if family == "exec":
        builder.execute_process(before, image="/bin/zsh", command_line="-zsh", executed_at=at)
    elif family == "fork":
        builder.fork_process(before, forked_at=at)
    else:
        builder.terminate_process(before, end_time=at)
    with pytest.raises(StateError, match="separate cohort"):
        builder.seal()


@pytest.mark.parametrize("platform", ["linux", "windows", "unknown"])
def test_privilege_drop_rejects_other_platform_namespaces(platform: str) -> None:
    manager, before = _child()
    manager._pid_os[before.hostname] = platform
    with pytest.raises(StateError, match="Mac child authority"):
        _drop(manager, before)


def test_privilege_drop_rejects_later_dependent_frontier_and_retired_parent() -> None:
    manager, before = _child()
    manager.update_process_activity_time("MAC-A", before.pid, _START + timedelta(seconds=4))
    with pytest.raises(StateError, match="live child interval"):
        _drop(manager, before)
    manager, before = _child()
    manager.end_process("MAC-A", before.parent_pid, _START + timedelta(milliseconds=2500))
    with pytest.raises(StateError, match="child authority"):
        _drop(manager, before)


def test_privilege_drop_requires_an_explicit_source_member() -> None:
    from evidenceforge.events.dispatcher import EventContractError, EventDispatcher

    manager, before = _child()
    builder = manager.begin_action_cohort_materialization()
    builder.drop_macos_ssh_child_privileges(before, dropped_at=_START + timedelta(seconds=3))
    dispatcher = EventDispatcher(manager, {})
    with pytest.raises(EventContractError, match="ordered dispatch tuple"):
        dispatcher.prepare_action_cohort_batch("drop-test", builder.seal(), (), (), (), ())


def test_legacy_process_record_upgrades_with_absent_privilege_drop() -> None:
    from evidenceforge.generation.checkpoints.state_values import (
        decode_state_value,
        encode_state_value,
    )

    manager, before = _child()
    process = manager.get_process("MAC-A", before.pid)
    encoded = encode_state_value(process)
    encoded[1] = "running-process-v5"
    encoded[2] = encoded[2][:28]
    restored = decode_state_value(encoded)
    assert restored == replace(process, parentage=None)
    assert restored.privilege_drop is None


def test_bootstrap_cannot_reinterpret_post_drop_credentials_as_initial_identity() -> None:
    manager, before = _child()
    _drop(manager, before)
    registry = LifecycleRegistry()
    authority = GeneratorLifecycleAuthority(manager, LifecycleShadow(manager, registry))
    with pytest.raises(StateError, match="Cannot bootstrap.*privilege drop"):
        authority.bootstrap_active_state()
    assert registry.get_process(before.object_id) is None


def test_lifecycle_exec_after_drop_preserves_new_token_and_initial_root_identity() -> None:
    manager, before = _child()
    registry = LifecycleRegistry()
    shadow = LifecycleShadow(manager, registry)
    authority = GeneratorLifecycleAuthority(manager, shadow)
    authority.bootstrap_active_state()
    initial = registry.get_process(before.object_id)
    for kind, seconds in (("credentials", 3), ("exec", 4)):
        builder = manager.begin_action_cohort_materialization()
        current = manager.get_process_identity("MAC-A", before.pid)
        if kind == "credentials":
            builder.drop_macos_ssh_child_privileges(
                current, dropped_at=_START + timedelta(seconds=seconds)
            )
        else:
            builder.execute_process(
                current,
                image="/bin/zsh",
                command_line="-zsh",
                executed_at=_START + timedelta(seconds=seconds),
            )
        plan = builder.seal()
        token = authority.prepare_action_cohort(plan)
        with manager.prepared_action_cohort_materialization(plan) as state_claim:
            with registry.claimed_action_cohort(token) as registry_claim:
                state_claim.certify_composite_commit(state_claim.expected_result)
                state_claim.apply_provisional()
                registry_claim.commit_no_fail()
                state_claim.finalize_no_fail()
    snapshot = registry.get_process(before.object_id)
    assert snapshot.identity == initial.identity and snapshot.token.principal == "root"
    assert snapshot.current_view.token.principal == "casey"
    assert snapshot.current_view.role == "shell"
    assert snapshot.current_view.execution_ordinal == 1
    assert authority.foreground_owner("MAC-A", before.pid).principal == "casey"
    # Both canonical owners must restore together; a State-only bootstrap is rejected above.
    from evidenceforge.generation.checkpoints.lifecycle_head import _capture, _restore

    del registry_claim, state_claim, token
    registry.prune_action_cohort_receipt_authorities()
    restored_state = StateManager()
    _restore_head(restored_state, _capture_head(manager))
    restored_registry = LifecycleRegistry()
    _restore(restored_registry, _capture(registry))
    restored_authority = GeneratorLifecycleAuthority(
        restored_state, LifecycleShadow(restored_state, restored_registry)
    )
    assert restored_authority.foreground_owner("MAC-A", before.pid).principal == "casey"
    assert restored_registry.get_process(before.object_id) == snapshot
    assert (
        restored_state.get_process_identity_at("MAC-A", before.pid, _START + timedelta(seconds=2))
        == before
    )
