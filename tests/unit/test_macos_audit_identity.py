# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Native audit versions belong to canonical allocation, not an ES serializer."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.lifecycle_authority import _process_identity_payload
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 10, 15, 12, tzinfo=UTC)


def _start(manager: StateManager, host: str = "MAC-A", platform: str = "macos") -> ProcessIdentity:
    plan = manager.plan_process_materialization(
        system=host,
        parent_pid=0,
        image="/bin/zsh",
        command_line="zsh",
        username="casey",
        integrity_level="Medium",
        os_category=platform,
        start_time=_START,
    )
    manager.materialize_process(plan)
    return plan.identity


def test_versions_are_host_scoped_and_not_allocated_for_other_platforms() -> None:
    manager = StateManager()
    first = _start(manager)
    second = _start(manager)
    other = _start(manager, "MAC-B")
    assert (first.audit_pid_version, second.audit_pid_version, other.audit_pid_version) == (1, 2, 1)
    assert _start(manager, "LINUX", "linux").audit_pid_version is None
    assert _start(manager, "WINDOWS", "windows").audit_pid_version is None
    assert set(manager._macos_audit_pid_versions) == {"MAC-A", "MAC-B"}


def test_fork_and_exec_reserve_versions_without_mutating_state_and_abort_can_retry() -> None:
    manager = StateManager()
    parent = _start(manager)
    digest = manager.materialization_digest()
    builder = manager.begin_action_cohort_materialization()
    child = builder.fork_process(parent, forked_at=_START + timedelta(seconds=1))
    plan = builder.seal()
    assert child.identity.audit_pid_version == 2
    assert child.parent_identity.audit_pid_version == 1
    assert manager.materialization_digest() == digest
    with manager.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert manager._macos_audit_pid_versions == {"MAC-A": 2}
    assert manager.materialization_digest() == digest
    manager.materialize_action_cohort(plan)
    builder = manager.begin_action_cohort_materialization()
    after = builder.execute_process(
        child.identity,
        image="/usr/bin/id",
        command_line="id",
        executed_at=_START + timedelta(seconds=2),
    )
    assert after.audit_pid_version == 3
    assert after.object_id == child.identity.object_id and after.pid == child.identity.pid
    plan = builder.seal()
    digest = manager.materialization_digest()
    with manager.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert manager._macos_audit_pid_versions == {"MAC-A": 3}
    assert manager.materialization_digest() == digest
    manager.materialize_action_cohort(plan)
    assert manager.get_process_identity(parent.hostname, parent.pid) == parent
    assert (
        manager.get_process_identity_at(parent.hostname, after.pid, child.identity.started_at)
        == child.identity
    )
    assert manager.get_process_identity(parent.hostname, after.pid) == after


def test_interleaved_cohort_allocations_and_exec_share_one_version_namespace() -> None:
    manager = StateManager()
    original = _start(manager)
    builder = manager.begin_action_cohort_materialization()
    first = builder.plan_process(
        system="MAC-A",
        parent_pid=0,
        image="/bin/zsh",
        command_line="zsh",
        username="casey",
        integrity_level="Medium",
        os_category="macos",
        start_time=_START,
    )
    after = builder.execute_process(
        original, image="/usr/bin/id", command_line="id", executed_at=_START + timedelta(seconds=1)
    )
    last = builder.plan_process(
        system="MAC-A",
        parent_pid=0,
        image="/bin/zsh",
        command_line="zsh",
        username="casey",
        integrity_level="Medium",
        os_category="macos",
        start_time=_START,
    )
    manager.materialize_action_cohort(builder.seal())
    assert (
        first.identity.audit_pid_version,
        after.audit_pid_version,
        last.identity.audit_pid_version,
    ) == (2, 3, 4)
    assert _start(manager).audit_pid_version == 5


def test_checkpoint_restores_counter_history_and_future_allocations_exactly() -> None:
    manager = StateManager()
    first = _start(manager)
    builder = manager.begin_action_cohort_materialization()
    after = builder.execute_process(
        first, image="/usr/bin/id", command_line="id", executed_at=_START + timedelta(seconds=1)
    )
    manager.materialize_action_cohort(builder.seal())
    restored = StateManager()
    _restore_head(restored, _capture_head(manager))
    assert restored.get_process_identity(first.hostname, first.pid) == after
    assert restored.get_process_identity_at(first.hostname, first.pid, _START) == first
    assert _start(restored) == _start(manager)
    assert restored.materialization_digest() == manager.materialization_digest()


@pytest.mark.parametrize("value", [True, 0, -1, 2**32, "1"])
def test_invalid_native_versions_are_rejected_at_identity_boundary(value: object) -> None:
    identity = _start(StateManager())
    with pytest.raises(ValueError, match="Audit PID version"):
        replace(identity, audit_pid_version=value)


def test_version_namespace_exhaustion_fails_without_wrapping_or_mutating() -> None:
    manager = StateManager()
    _start(manager)
    manager._macos_audit_pid_versions["MAC-A"] = 2**32 - 1
    digest = manager.materialization_digest()
    with pytest.raises(StateError, match="exhausted"):
        _start(manager)
    assert manager.materialization_digest() == digest


def test_v3_identity_upgrade_preserves_unknown_version_and_authentication_binds_new_fact() -> None:
    original = _start(StateManager())
    old = encode_state_value(original)
    old[1] = "process-identity-v3"
    # v3 has exactly 16 fields, regardless of later optional identity extensions.
    old[2] = old[2][:16]
    restored = decode_state_value(old)
    assert restored == replace(original, audit_pid_version=None)
    assert _process_identity_payload(restored) != _process_identity_payload(original)


@pytest.mark.parametrize("value", [True, 0, 2**32])
def test_checkpoint_rejects_invalid_counter_before_publishing_state(value: object) -> None:
    manager = StateManager()
    _start(manager)
    document = loads(_capture_head(manager))
    document["simple"]["_macos_audit_pid_versions"] = encode_state_value({"MAC-A": value})
    restored = StateManager()
    digest = restored.materialization_digest()
    with pytest.raises(CheckpointCorruptionError, match="audit PID"):
        _restore_head(restored, dumps(document))
    assert restored.materialization_digest() == digest


def test_old_head_cannot_silently_restore_without_native_version_counter() -> None:
    manager = StateManager()
    _start(manager)
    document = loads(_capture_head(manager))
    document["schema_version"] = "1"
    del document["simple"]["_macos_audit_pid_versions"]
    with pytest.raises(CheckpointCorruptionError, match="head schema"):
        _restore_head(StateManager(), dumps(document))


def test_reused_pid_gets_new_audit_version_and_keeps_prior_identity() -> None:
    manager = StateManager()
    first = _start(manager)
    builder = manager.begin_action_cohort_materialization()
    builder.terminate_process(first, end_time=_START + timedelta(seconds=1))
    manager.materialize_action_cohort(builder.seal())
    plan = manager.plan_process_materialization(
        system=first.hostname,
        parent_pid=0,
        image="/usr/bin/id",
        command_line="id",
        username="casey",
        integrity_level="Medium",
        os_category="macos",
        start_time=_START + timedelta(seconds=2),
        fixed_pid=first.pid,
    )
    manager.materialize_process(plan)
    assert plan.identity.pid == first.pid
    assert plan.identity.audit_pid_version > first.audit_pid_version
    assert manager.get_process_identity_by_object_id(first.object_id) == first


def test_es_token_projection_requires_explicit_audit_facts_and_preserves_word_order() -> None:
    from evidenceforge.events.identity import PosixProcessCredentials
    from evidenceforge.formats.macos_endpoint_security import ESAuditToken

    identity = _start(StateManager())
    with pytest.raises(ValueError, match="explicit credentials"):
        ESAuditToken.from_process_identity(identity)
    known = replace(identity, credentials=PosixProcessCredentials(501, 0, 20, 0, 501, 100001))
    token = ESAuditToken.from_process_identity(known)
    assert token.as_native_array() == (
        501,
        0,
        0,
        501,
        20,
        identity.pid,
        100001,
        identity.audit_pid_version,
    )
    for field_name in ("audit_uid", "audit_session_id"):
        unknown = replace(known, credentials=replace(known.credentials, **{field_name: None}))
        with pytest.raises(ValueError, match="explicit credentials"):
            ESAuditToken.from_process_identity(unknown)
    with pytest.raises(ValueError, match="explicit credentials"):
        ESAuditToken.from_process_identity(replace(known, audit_pid_version=None))
