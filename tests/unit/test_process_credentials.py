# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented credential snapshots through atomic process lifetime transitions."""

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.identity import PosixProcessCredentials, ProcessIdentity
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.lifecycle_authority import _process_identity_payload
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 10, 15, 12, tzinfo=UTC)
_USER = PosixProcessCredentials(501, 501, 20, 20, audit_uid=501, audit_session_id=110007)


def _create(
    platform: str = "macos",
    *,
    batched: bool = False,
    credentials: PosixProcessCredentials | None = _USER,
) -> tuple[StateManager, ProcessIdentity]:
    manager = StateManager()
    manager.set_current_time(_START)
    builder = manager.begin_action_cohort_materialization() if batched else None
    planner = builder.plan_process if builder else manager.plan_process_materialization
    plan = planner(
        system="MAC-TEST",
        parent_pid=0,
        image="/bin/zsh",
        command_line="-zsh",
        username="casey",
        integrity_level="Medium",
        os_category=platform,
        start_time=_START,
        credentials=credentials,
    )
    if builder:
        manager.materialize_action_cohort(builder.seal())
    else:
        manager.materialize_process(plan)
    return manager, plan.identity


def _exec(
    manager: StateManager,
    before: ProcessIdentity,
    credentials: PosixProcessCredentials | None,
    *,
    seconds: int = 1,
) -> ProcessIdentity:
    builder = manager.begin_action_cohort_materialization()
    after = builder.execute_process(
        before,
        image="/usr/bin/id",
        command_line="id",
        executed_at=_START + timedelta(seconds=seconds),
        credentials=credentials,
    )
    manager.materialize_action_cohort(builder.seal())
    return after


@pytest.mark.parametrize("platform", ["linux", "macos"])
@pytest.mark.parametrize("batched", [False, True])
def test_explicit_process_credentials_survive_all_allocation_paths(
    platform: str, batched: bool
) -> None:
    manager, identity = _create(platform, batched=batched)
    assert identity.credentials == _USER
    assert manager.get_process_identity(identity.hostname, identity.pid) == identity
    assert manager.get_process(identity.hostname, identity.pid).credentials == _USER


@pytest.mark.parametrize("platform", ["linux", "macos"])
def test_exec_changes_effective_ids_without_changing_audit_origin_or_login_principal(
    platform: str,
) -> None:
    manager, before = _create(platform)
    privileged = replace(_USER, effective_uid=0, effective_gid=0)
    after = _exec(manager, before, privileged)
    assert after.credentials == privileged
    assert after.credentials.origin == before.credentials.origin
    assert after.principal == before.principal == "casey"
    assert after.pid == before.pid and after.object_id == before.object_id
    assert after.logon_id == before.logon_id
    assert manager.get_process_identity_at(before.hostname, before.pid, _START) == before
    assert before.credentials == _USER
    # Omitting credentials explicitly preserves the previous execution's effective IDs.
    inherited = _exec(manager, after, None, seconds=2)
    assert inherited.credentials == privileged
    dropped = _exec(manager, inherited, _USER, seconds=3)
    assert dropped.credentials == _USER
    assert manager.get_process_identity_at(before.hostname, before.pid, after.executed_at) == after


def test_fork_inherits_effective_credentials_and_audit_origin_without_mutating_parent() -> None:
    manager, original = _create()
    parent = _exec(manager, original, replace(_USER, effective_uid=0))
    builder = manager.begin_action_cohort_materialization()
    child = builder.fork_process(parent, forked_at=_START + timedelta(seconds=2))
    assert child.identity.credentials == parent.credentials
    assert child.parent_identity == parent
    manager.materialize_action_cohort(builder.seal())
    changed = _exec(manager, child.identity, _USER, seconds=3)
    assert changed.credentials.effective_uid == 501
    assert manager.get_process_identity(parent.hostname, parent.pid) == parent


@pytest.mark.parametrize("field", ["real_uid", "real_gid", "audit_uid", "audit_session_id"])
def test_exec_cannot_rewrite_real_or_audit_origin(field: str) -> None:
    manager, before = _create()
    digest = manager.materialization_digest()
    with pytest.raises(StateError, match="preserve known real and audit credentials"):
        _exec(manager, before, replace(_USER, **{field: 0}))
    assert manager.materialization_digest() == digest


def test_unknown_credentials_remain_unknown_and_cannot_be_retroactively_inferred() -> None:
    manager, before = _create(credentials=None)
    assert _exec(manager, before, None).credentials is None
    current = manager.get_process_identity(before.hostname, before.pid)
    digest = manager.materialization_digest()
    with pytest.raises(StateError, match="preserve known real and audit credentials"):
        _exec(manager, current, _USER, seconds=2)
    assert manager.materialization_digest() == digest


def test_credential_exec_abort_restores_runtime_history_and_can_retry() -> None:
    manager, before = _create()
    digest = manager.materialization_digest()
    builder = manager.begin_action_cohort_materialization()
    after = builder.execute_process(
        before,
        image="/usr/bin/id",
        command_line="id",
        executed_at=_START + timedelta(seconds=1),
        credentials=replace(_USER, effective_uid=0),
    )
    plan = builder.seal()
    assert manager.materialization_digest() == digest
    with manager.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert manager.get_process_identity(before.hostname, before.pid) == after
    assert manager.materialization_digest() == digest
    assert manager.get_process_identity(before.hostname, before.pid) == before
    manager.materialize_action_cohort(plan)
    assert manager.get_process_identity(before.hostname, before.pid) == after


def test_credentials_and_execution_history_survive_checkpoint_and_exit() -> None:
    manager, before = _create()
    after = _exec(manager, before, replace(_USER, effective_uid=0))
    restored = StateManager()
    _restore_head(restored, _capture_head(manager))
    assert restored.get_process_identity(before.hostname, before.pid) == after
    assert restored.get_process_identity_at(before.hostname, before.pid, _START) == before
    expected = _exec(manager, after, _USER, seconds=2)
    actual = _exec(restored, after, _USER, seconds=2)
    assert actual == expected
    for state in (manager, restored):
        builder = state.begin_action_cohort_materialization()
        builder.terminate_process(expected, end_time=_START + timedelta(seconds=3))
        state.materialize_action_cohort(builder.seal())
        assert state.get_process_identity_by_object_id(before.object_id) == expected
    assert manager.materialization_digest() == restored.materialization_digest()


@pytest.mark.parametrize("kind", ["process", "identity"])
def test_v2_checkpoint_upgrade_preserves_exec_without_inventing_credentials(kind: str) -> None:
    manager, before = _create(credentials=None)
    after = _exec(manager, before, None)
    original = after if kind == "identity" else manager.get_process(before.hostname, before.pid)
    encoded = encode_state_value(original)
    encoded[1] = "process-identity-v2" if kind == "identity" else "running-process-v2"
    encoded[2] = encoded[2][:-2]
    restored = decode_state_value(encoded)
    assert restored == replace(original, audit_pid_version=None)
    assert restored.credentials is None and restored.execution_ordinal == 1


@pytest.mark.parametrize("batched", [False, True])
def test_windows_rejects_posix_credentials_before_allocation(batched: bool) -> None:
    with pytest.raises(StateError, match="POSIX platform"):
        _create("windows", batched=batched)


@pytest.mark.parametrize(
    "field",
    ["real_uid", "effective_uid", "real_gid", "effective_gid", "audit_uid", "audit_session_id"],
)
@pytest.mark.parametrize("value", [True, -1, 2**32, "501"])
def test_native_credential_ids_are_strict_and_bounded(field: str, value: object) -> None:
    with pytest.raises(ValueError, match="integer IDs"):
        replace(_USER, **{field: value})


def test_audit_absence_is_distinct_from_the_explicit_native_unset_sentinel() -> None:
    unknown = replace(_USER, audit_uid=None, audit_session_id=None)
    unset = replace(_USER, audit_uid=2**32 - 1, audit_session_id=2**32 - 1)
    assert unknown != unset
    assert decode_state_value(encode_state_value(unknown)) == unknown
    assert decode_state_value(encode_state_value(unset)) == unset
    with pytest.raises(FrozenInstanceError):
        unknown.effective_uid = 0


def test_credential_payload_is_bound_to_lifecycle_authority_and_sealed_plan() -> None:
    manager, before = _create()
    changed = replace(before, credentials=replace(_USER, effective_uid=0))
    assert _process_identity_payload(before) != _process_identity_payload(changed)
    with pytest.raises(StateError, match="identity|drift"):
        _exec(manager, changed, None)
    builder = manager.begin_action_cohort_materialization()
    after = builder.execute_process(
        before, image="/usr/bin/id", command_line="id", executed_at=_START + timedelta(seconds=1)
    )
    plan = builder.seal()
    altered = replace(
        plan.process_executions[0], after=replace(after, credentials=changed.credentials)
    )
    digest = manager.materialization_digest()
    with pytest.raises(StateError, match="semantic identity"):
        manager.materialize_action_cohort(replace(plan, _process_executions=(altered,)))
    assert manager.materialization_digest() == digest


def test_checkpoint_rejects_invalid_credential_record_instead_of_coercing() -> None:
    encoded = encode_state_value(_USER)
    encoded[2][0] = True
    with pytest.raises(CheckpointCorruptionError, match="record is invalid"):
        decode_state_value(encoded)


def test_mac_launch_resolves_host_accounts_and_historical_parent_credentials() -> None:
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.generation.activity import ActivityGenerator
    from evidenceforge.generation.identity import IdentityDirectory, MacAccount
    from evidenceforge.models.scenario import System

    manager, before = _create()
    directory = IdentityDirectory("example.test", "", False)
    directory.macos_accounts[("casey", "mac-test")] = MacAccount(
        "casey", "casey", 501, 20, "MAC-TEST", "/Users/casey"
    )
    directory.macos_accounts[("root", "mac-test")] = MacAccount(
        "root", "root", 0, 0, "MAC-TEST", "/var/root"
    )
    generator = ActivityGenerator(
        manager, {}, dispatcher=EventDispatcher(manager, {}), identity_directory=directory
    )
    system = System(hostname="MAC-TEST", ip="192.0.2.10", os="macOS 26", type="workstation")
    original = generator._process_credentials(system, "casey", 0, _START)
    assert original == PosixProcessCredentials(501, 501, 20, 20)
    assert original.audit_uid is None and original.audit_session_id is None
    assert generator._process_credentials(system, "root", 0, _START).effective_uid == 0
    assert generator._process_credentials(system, "unresolved", 0, _START) is None
    privileged = replace(_USER, effective_uid=0)
    _exec(manager, before, privileged)
    digest = manager.materialization_digest()
    assert generator._process_credentials(system, "casey", before.pid, _START) == _USER
    assert (
        generator._process_credentials(system, "casey", before.pid, _START + timedelta(seconds=2))
        == privileged
    )
    # A new explicit actor does not inherit another user's effective or audit IDs.
    root = generator._process_credentials(system, "root", before.pid, _START + timedelta(seconds=2))
    assert root == PosixProcessCredentials(0, 0, 0, 0)
    assert manager.materialization_digest() == digest
    for os_name in ("Windows 11", "Ubuntu 24.04", "FreeBSD"):
        assert (
            generator._process_credentials(
                system.model_copy(update={"os": os_name}), "casey", 0, _START
            )
            is None
        )
    other = system.model_copy(update={"hostname": "UNMODELED"})
    assert generator._process_credentials(other, "casey", 0, _START) is None
    generator.identity_directory = None
    assert generator._process_credentials(system, "casey", 0, _START) is None
