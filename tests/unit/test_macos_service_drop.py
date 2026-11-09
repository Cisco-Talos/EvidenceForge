# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Pre-authentication service credentials remain separate from user authentication."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.identity import PosixProcessCredentials, ProcessIdentity
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.identity import MacAccount
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_audit_identity import _START
from tests.unit.test_macos_service_identity import _directory


def _account() -> MacAccount:
    account = _directory().macos_account("_sshd", "MAC-A")
    assert account is not None
    return account


def _child(
    platform: str = "macos", *, execute: bool = True
) -> tuple[StateManager, ProcessIdentity]:
    manager = StateManager()
    parent = manager.plan_process_materialization(
        system="MAC-A",
        parent_pid=0,
        image="/usr/libexec/sshd-session",
        command_line="/usr/libexec/sshd-session -i -R",
        username="root",
        integrity_level="System",
        os_category=platform,
        start_time=_START,
        credentials=PosixProcessCredentials(0, 0, 0, 0),
    )
    manager.materialize_process(parent)
    builder = manager.begin_action_cohort_materialization()
    child = builder.fork_process(parent.identity, forked_at=_START + timedelta(seconds=1))
    manager.materialize_action_cohort(builder.seal())
    if not execute:
        return manager, child.identity
    builder = manager.begin_action_cohort_materialization()
    executed = builder.execute_process(
        child.identity,
        image="/usr/libexec/sshd-auth",
        command_line="/usr/libexec/sshd-auth -i -R",
        executed_at=_START + timedelta(seconds=2),
    )
    manager.materialize_action_cohort(builder.seal())
    return manager, executed


def _drop(manager: StateManager, before: ProcessIdentity) -> ProcessIdentity:
    builder = manager.begin_action_cohort_materialization()
    after = builder.drop_macos_service_child_privileges(
        before,
        service_account=_account(),
        dropped_at=_START + timedelta(seconds=3),
    )
    manager.materialize_action_cohort(builder.seal())
    return after


def test_service_drop_changes_principal_without_creating_authenticated_audit_origin() -> None:
    manager, before = _child()
    after = _drop(manager, before)
    assert replace(after, credentials=before.credentials, principal=before.principal) == before
    assert after.credentials == PosixProcessCredentials(75, 75, 75, 75)
    assert after.principal == "_sshd"
    process = manager.get_process("MAC-A", before.pid)
    assert process.service_drop is not None
    assert process.privilege_drop is None and process.audit_binding is None
    assert process in manager._running_processes.find("username", "_sshd")
    assert process not in manager._running_processes.find("username", "root")
    assert (
        manager.get_process_identity_at("MAC-A", before.pid, before.execution_started_at) == before
    )
    assert (
        manager.get_process_identity_at("MAC-A", before.pid, _START + timedelta(seconds=3)) == after
    )
    assert not manager._macos_audit_session_counters


def test_service_drop_provisional_rollback_restores_indexes_and_exact_history() -> None:
    manager, before = _child()
    process = manager.get_process("MAC-A", before.pid)
    digest = manager.materialization_digest()
    builder = manager.begin_action_cohort_materialization()
    after = builder.drop_macos_service_child_privileges(
        before,
        service_account=_account(),
        dropped_at=_START + timedelta(seconds=3),
    )
    plan = builder.seal()
    with manager.prepared_action_cohort_materialization(plan) as claim:
        claim.certify_composite_commit(claim.expected_result)
        claim.apply_provisional()
        assert process in manager._running_processes.find("username", "_sshd")
    assert manager.materialization_digest() == digest
    assert manager.get_process("MAC-A", before.pid) is process
    assert process.service_drop is None and process.username == "root"
    assert process not in manager._running_processes.find("username", "_sshd")
    manager.materialize_action_cohort(plan)
    assert manager.get_process_identity("MAC-A", before.pid) == after


def test_service_drop_survives_exec_exit_and_checkpoint_with_historical_credentials() -> None:
    manager, before = _child()
    after = _drop(manager, before)
    builder = manager.begin_action_cohort_materialization()
    executed = builder.execute_process(
        after,
        image="/usr/bin/true",
        command_line="/usr/bin/true",
        executed_at=_START + timedelta(seconds=4),
    )
    manager.materialize_action_cohort(builder.seal())
    manager.end_process("MAC-A", after.pid, _START + timedelta(seconds=5))
    restored = StateManager()
    _restore_head(restored, _capture_head(manager))
    for state in (manager, restored):
        for seconds, identity in ((2, before), (3, after), (4, executed)):
            assert (
                state.get_process_identity_by_object_id(
                    before.object_id,
                    event_time=_START + timedelta(seconds=seconds),
                )
                == identity
            )
        assert (
            state.get_process_identity_by_object_id(
                before.object_id,
                event_time=_START + timedelta(seconds=5),
            )
            is None
        )


@pytest.mark.parametrize("seconds", [0, 1, 2])
def test_service_drop_cannot_precede_its_current_execution(seconds: int) -> None:
    manager, before = _child()
    with pytest.raises(StateError, match="live child interval"):
        manager.begin_action_cohort_materialization().drop_macos_service_child_privileges(
            before,
            service_account=_account(),
            dropped_at=_START + timedelta(seconds=seconds),
        )


@pytest.mark.parametrize(
    "change", [{"host": "MAC-B"}, {"uid": 0}, {"scope": "local"}, {"account_name": "casey"}]
)
def test_service_drop_rejects_wrong_service_account(change: dict[str, object]) -> None:
    manager, before = _child()
    with pytest.raises(StateError, match="host-local SSH service account"):
        manager.begin_action_cohort_materialization().drop_macos_service_child_privileges(
            before,
            service_account=replace(_account(), **change),
            dropped_at=_START + timedelta(seconds=3),
        )


def test_service_drop_rejects_linux_and_authenticated_children() -> None:
    manager, before = _child("linux")
    with pytest.raises(StateError, match="unauthenticated Mac child"):
        _drop(manager, before)
    from tests.unit.test_macos_privilege_drop import _child as authenticated_child

    manager, before = authenticated_child()
    with pytest.raises(ValueError, match="without authenticated origin"):
        _drop(manager, before)


@pytest.mark.parametrize("change", ["exit", "exec", "activity"])
def test_service_drop_rejects_retired_or_changed_parent_and_late_child_activity(
    change: str,
) -> None:
    manager, before = _child()
    if change == "exit":
        manager.end_process("MAC-A", before.parent_pid, _START + timedelta(seconds=2))
    else:
        builder = manager.begin_action_cohort_materialization()
        if change == "exec":
            parent = manager.get_process_identity("MAC-A", before.parent_pid)
            builder.execute_process(
                parent,
                image="/bin/zsh",
                command_line="zsh",
                executed_at=_START + timedelta(seconds=2),
            )
        else:
            builder.patch_process_activity(before, activity_time=_START + timedelta(seconds=4))
        manager.materialize_action_cohort(builder.seal())
    with pytest.raises(StateError):
        _drop(manager, before)


def test_service_drop_is_once_only_and_cannot_be_used_as_authenticated_child_drop() -> None:
    manager, before = _child()
    after = _drop(manager, before)
    with pytest.raises((StateError, ValueError)):
        _drop(manager, after)
    with pytest.raises(StateError, match="authenticated session"):
        manager.begin_action_cohort_materialization().drop_macos_ssh_child_privileges(
            after,
            dropped_at=_START + timedelta(seconds=4),
        )


@pytest.mark.parametrize("field", ["username", "credentials", "integrity_level"])
def test_checkpoint_rejects_inconsistent_service_drop_history(field: str) -> None:
    manager, before = _child()
    _drop(manager, before)
    process = manager.get_process("MAC-A", before.pid)
    setattr(
        process,
        field,
        {"username": "root", "credentials": before.credentials, "integrity_level": "System"}[field],
    )
    with pytest.raises(CheckpointCorruptionError, match="service privilege-drop"):
        _restore_head(StateManager(), _capture_head(manager))


def test_legacy_process_record_has_no_invented_service_drop() -> None:
    manager, before = _child()
    process = manager.get_process("MAC-A", before.pid)
    encoded = encode_state_value(process)
    encoded[1] = "running-process-v6"
    encoded[2] = encoded[2][:29]
    restored = decode_state_value(encoded)
    assert restored == replace(process, parentage=None) and restored.service_drop is None


def test_post_drop_bootstrap_cannot_reinterpret_original_token() -> None:
    manager, before = _child(execute=False)
    _drop(manager, before)
    registry = LifecycleRegistry()
    authority = GeneratorLifecycleAuthority(manager, LifecycleShadow(manager, registry))
    with pytest.raises(StateError, match="Cannot bootstrap.*privilege drop"):
        authority.bootstrap_active_state()


def test_service_drop_advances_current_lifecycle_token_and_restores_both_owners() -> None:
    from evidenceforge.generation.checkpoints.lifecycle_head import (
        _capture as capture_lifecycle,
    )
    from evidenceforge.generation.checkpoints.lifecycle_head import (
        _restore as restore_lifecycle,
    )

    manager, before = _child(execute=False)
    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(manager, registry)
    authority = GeneratorLifecycleAuthority(manager, shadow, shard_count=4)
    authority.bootstrap_active_state()
    initial = registry.get_process(before.object_id)
    builder = manager.begin_action_cohort_materialization()
    before = builder.execute_process(
        before,
        image="/usr/libexec/sshd-auth",
        command_line="sshd-auth -i -R",
        executed_at=_START + timedelta(seconds=2),
    )
    execution_plan = builder.seal()
    execution_token = authority.prepare_action_cohort(execution_plan)
    with manager.prepared_action_cohort_materialization(execution_plan) as state_claim:
        with registry.claimed_action_cohort(execution_token) as registry_claim:
            state_claim.certify_composite_commit(state_claim.expected_result)
            state_claim.apply_provisional()
            registry_claim.commit_no_fail()
            state_claim.finalize_no_fail()
    builder = manager.begin_action_cohort_materialization()
    after = builder.drop_macos_service_child_privileges(
        before,
        service_account=_account(),
        dropped_at=_START + timedelta(seconds=3),
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
    assert current.current_view.token.principal == "_sshd"
    assert current.current_view.token.integrity_level == "Medium"
    assert current.current_view.execution_ordinal == before.execution_ordinal
    assert shadow.ensure_process(after) == initial.identity
    del registry_claim, state_claim, token, execution_token
    registry.prune_action_cohort_receipt_authorities()
    restored_state = StateManager()
    _restore_head(restored_state, _capture_head(manager))
    restored_registry = LifecycleRegistry(shard_count=4)
    restore_lifecycle(restored_registry, capture_lifecycle(registry))
    assert restored_registry.get_process(before.object_id) == current
    assert (
        LifecycleShadow(restored_state, restored_registry).ensure_process(after) == initial.identity
    )


@pytest.mark.parametrize("family", ["exec", "fork", "terminate"])
def test_service_drop_requires_separate_cohort_from_dependent_transitions(family: str) -> None:
    manager, before = _child()
    builder = manager.begin_action_cohort_materialization()
    builder.drop_macos_service_child_privileges(
        before,
        service_account=_account(),
        dropped_at=_START + timedelta(seconds=3),
    )
    if family == "exec":
        builder.execute_process(
            before, image="/bin/zsh", command_line="zsh", executed_at=_START + timedelta(seconds=4)
        )
    elif family == "fork":
        builder.fork_process(before, forked_at=_START + timedelta(seconds=4))
    else:
        builder.terminate_process(before, end_time=_START + timedelta(seconds=4))
    with pytest.raises(StateError, match="separate cohort"):
        builder.seal()


def test_tampered_service_drop_plan_fails_before_mutation() -> None:
    manager, before = _child()
    builder = manager.begin_action_cohort_materialization()
    builder.drop_macos_service_child_privileges(
        before,
        service_account=_account(),
        dropped_at=_START + timedelta(seconds=3),
    )
    plan = builder.seal()
    digest = manager.materialization_digest()
    drop = plan.process_activity_patches[0].service_drop
    object.__setattr__(drop, "parent_object_id", "other-parent")
    with pytest.raises(StateError):
        manager.materialize_action_cohort(plan)
    assert manager.materialization_digest() == digest


def test_historical_exec_credentials_are_not_replaced_by_later_service_drop() -> None:
    manager, before = _child()
    builder = manager.begin_action_cohort_materialization()
    privileged = builder.execute_process(
        before,
        image="/usr/libexec/sshd-auth",
        command_line="helper",
        credentials=PosixProcessCredentials(0, 0, 0, 20),
        executed_at=_START + timedelta(milliseconds=2200),
    )
    manager.materialize_action_cohort(builder.seal())
    builder = manager.begin_action_cohort_materialization()
    ready = builder.execute_process(
        privileged,
        image="/usr/libexec/sshd-auth",
        command_line="helper",
        credentials=before.credentials,
        executed_at=_START + timedelta(milliseconds=2400),
    )
    manager.materialize_action_cohort(builder.seal())
    _drop(manager, ready)
    assert (
        manager.get_process_identity_at(
            "MAC-A",
            before.pid,
            _START + timedelta(milliseconds=2300),
        )
        == privileged
    )
    assert (
        manager.get_process_identity_at(
            "MAC-A",
            before.pid,
            _START + timedelta(milliseconds=2500),
        )
        == ready
    )


def test_post_exec_bootstrap_cannot_reset_the_current_execution() -> None:
    manager, before = _child()
    registry = LifecycleRegistry()
    authority = GeneratorLifecycleAuthority(manager, LifecycleShadow(manager, registry))
    with pytest.raises(StateError, match="Cannot bootstrap.*exec"):
        authority.bootstrap_active_state()
    assert registry.get_process(before.object_id) is None


def test_fork_inherits_service_credentials_without_copying_parent_transition() -> None:
    manager, before = _child()
    after = _drop(manager, before)
    builder = manager.begin_action_cohort_materialization()
    child = builder.fork_process(after, forked_at=_START + timedelta(seconds=4))
    manager.materialize_action_cohort(builder.seal())
    assert child.identity.credentials == after.credentials
    assert child.identity.principal == "_sshd"
    assert manager.get_process("MAC-A", child.identity.pid).service_drop is None


def test_parent_pid_reuse_cannot_authorize_old_service_child() -> None:
    manager, before = _child()
    manager.end_process("MAC-A", before.parent_pid, _START + timedelta(seconds=2))
    replacement = manager.plan_process_materialization(
        system="MAC-A",
        parent_pid=0,
        image="/usr/libexec/sshd-session",
        command_line="/usr/libexec/sshd-session -i -R",
        username="root",
        integrity_level="System",
        os_category="macos",
        fixed_pid=before.parent_pid,
        start_time=_START + timedelta(milliseconds=2500),
        credentials=PosixProcessCredentials(0, 0, 0, 0),
    )
    manager.materialize_process(replacement)
    with pytest.raises(StateError, match="unauthenticated Mac child"):
        _drop(manager, before)


@pytest.mark.parametrize("seconds", [1, 2])
def test_service_drop_cannot_happen_after_authenticated_origin_exists(seconds: int) -> None:
    from tests.unit.test_macos_process_audit_binding import _receiver

    manager, parent = _receiver()
    builder = manager.begin_action_cohort_materialization()
    child = builder.fork_process(parent, forked_at=_START + timedelta(milliseconds=500))
    manager.materialize_action_cohort(builder.seal())
    with pytest.raises(StateError, match="precede authentication"):
        manager.begin_action_cohort_materialization().drop_macos_service_child_privileges(
            child.identity,
            service_account=_account(),
            dropped_at=_START + timedelta(seconds=seconds),
        )
