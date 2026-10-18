# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented POSIX job-control lifetimes through the atomic canonical State owner."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.identity import PosixProcessCredentials, ProcessIdentity
from evidenceforge.events.job_control import PosixGroupIdentity
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.lifecycle_authority import _process_identity_payload
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_process_execution_state import _START


def _root(platform: str = "macos") -> tuple[StateManager, ProcessIdentity]:
    state = StateManager()
    state.set_current_time(_START)
    plan = state.plan_process_materialization(
        system="workstation-test",
        parent_pid=0,
        image="/sbin/launchd",
        command_line="launchd",
        username="root",
        integrity_level="System",
        os_category=platform,
        fixed_pid=1,
        credentials=PosixProcessCredentials(0, 0, 0, 0),
    )
    state.materialize_process(plan)
    return state, plan.identity


def _change(
    state: StateManager,
    target: ProcessIdentity,
    operation: str,
    seconds: int,
    *,
    group: PosixGroupIdentity | None = None,
    actor: ProcessIdentity | None = None,
) -> ProcessIdentity:
    builder = state.begin_action_cohort_materialization()
    after = builder.change_posix_job_control(
        target,
        operation=operation,
        changed_at=_START + timedelta(seconds=seconds),
        group=group,
        actor=actor,
    )
    state.materialize_action_cohort(builder.seal())
    assert state.get_process_identity(target.hostname, target.pid) == after
    return after


def _fork(state: StateManager, parent: ProcessIdentity, seconds: int) -> ProcessIdentity:
    builder = state.begin_action_cohort_materialization()
    plan = builder.fork_process(parent, forked_at=_START + timedelta(seconds=seconds))
    state.materialize_action_cohort(builder.seal())
    return plan.identity


def _close(state: StateManager, identity: ProcessIdentity, seconds: int) -> None:
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(identity, end_time=_START + timedelta(seconds=seconds))
    state.materialize_action_cohort(builder.seal())


@pytest.mark.parametrize("platform", ["linux", "macos"])
def test_fork_exec_and_history_preserve_separate_job_control(platform: str) -> None:
    state, root = _root(platform)
    root = _change(state, root, "bootstrap", 0)
    child = _fork(state, root, 1)
    assert child.job_control == root.job_control
    session_leader = _change(state, child, "setsid", 2)
    assert session_leader.job_control.pgid == child.pid
    assert session_leader.job_control.session.sid == child.pid
    assert session_leader.execution_id == child.execution_id
    assert session_leader.logon_id == child.logon_id
    assert state.get_process_identity_at(child.hostname, child.pid, child.started_at) == child
    builder = state.begin_action_cohort_materialization()
    executed = builder.execute_process(
        session_leader,
        image="/bin/zsh",
        command_line="zsh",
        executed_at=_START + timedelta(seconds=3),
    )
    state.materialize_action_cohort(builder.seal())
    assert executed.job_control == session_leader.job_control
    assert (
        state.get_process_identity_at(child.hostname, child.pid, _START + timedelta(seconds=2))
        == session_leader
    )
    assert _process_identity_payload(executed)[-1][0] == "posix-job-control-v1"


def test_leader_exit_preserves_group_session_and_numeric_id_until_last_member() -> None:
    state, root = _root()
    root = _change(state, root, "bootstrap", 0)
    leader = _change(state, _fork(state, root, 1), "setsid", 2)
    member = _fork(state, leader, 3)
    group = leader.job_control
    _close(state, leader, 4)
    assert state.get_posix_group_members(group) == (member,)
    assert state._pid_is_reserved(leader.hostname, leader.pid, _START + timedelta(seconds=5), None)
    # Move the last member into its own group: the old session still survives.
    member = _change(state, member, "setpgid", 5)
    assert state.get_posix_group_members(group) == ()
    assert member.job_control.session == group.session
    assert state._pid_is_reserved(leader.hostname, leader.pid, _START + timedelta(seconds=6), None)
    _close(state, member, 6)
    assert not state._pid_is_reserved(
        leader.hostname, leader.pid, _START + timedelta(seconds=7), None
    )
    assert state._pid_is_reserved(leader.hostname, leader.pid, _START + timedelta(seconds=4), None)
    state.advance_pid_allocation_watermark(_START + timedelta(seconds=7))
    assert ("session", leader.hostname, leader.pid) not in state._posix_job_control_reservations


def test_parent_can_group_child_only_before_exec_and_destination_can_outlive_leader() -> None:
    state, root = _root()
    root = _change(state, root, "bootstrap", 0)
    first = _fork(state, root, 1)
    first = _change(state, first, "setpgid", 2, actor=root)
    second = _fork(state, root, 3)
    second = _change(state, second, "setpgid", 4, group=first.job_control, actor=root)
    _close(state, first, 5)
    third = _fork(state, root, 6)
    third = _change(state, third, "setpgid", 7, group=second.job_control, actor=root)
    assert set(state.get_posix_group_members(second.job_control)) == {second, third}
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        third, image="/bin/zsh", command_line="zsh", executed_at=_START + timedelta(seconds=8)
    )
    state.materialize_action_cohort(builder.seal())
    before = state.materialization_digest()
    with pytest.raises(StateError, match="has not executed"):
        _change(state, after, "setpgid", 9, actor=root)
    assert state.materialization_digest() == before


@pytest.mark.parametrize("operation", ["setsid", "setpgid"])
def test_session_leader_cannot_change_group_or_create_another_session(operation: str) -> None:
    state, root = _root()
    root = _change(state, root, "bootstrap", 0)
    with pytest.raises(StateError):
        _change(state, root, operation, 1)


def test_group_changes_reject_cross_session_stale_and_backdated_membership() -> None:
    state, root = _root()
    root = _change(state, root, "bootstrap", 0)
    child = _fork(state, root, 1)
    leader = _change(state, child, "setsid", 2)
    sibling = _fork(state, root, 3)
    before = state.materialization_digest()
    for target, group, seconds in (
        (sibling, leader.job_control, 4),
        (child, None, 4),
        (sibling, None, 2),
    ):
        with pytest.raises(StateError):
            _change(state, target, "setpgid", seconds, group=group)
        assert state.materialization_digest() == before


def test_provisional_abort_restores_group_indices_counts_and_historical_identity() -> None:
    state, root = _root()
    root = _change(state, root, "bootstrap", 0)
    child = _fork(state, root, 1)
    builder = state.begin_action_cohort_materialization()
    after = builder.change_posix_job_control(
        child, operation="setsid", changed_at=_START + timedelta(seconds=2)
    )
    plan = builder.seal()
    before = state.materialization_digest()
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert state.get_posix_group_members(after.job_control) == (after,)
    assert state.materialization_digest() == before
    assert state.get_posix_group_members(after.job_control) == ()
    state.materialize_action_cohort(plan)
    assert state.get_posix_group_members(after.job_control) == (after,)


def test_checkpoint_resume_preserves_leaderless_groups_and_history() -> None:
    state, root = _root()
    root = _change(state, root, "bootstrap", 0)
    leader = _change(state, _fork(state, root, 1), "setsid", 2)
    child = _fork(state, leader, 3)
    _close(state, leader, 4)
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_posix_group_members(child.job_control) == (child,)
    assert decode_state_value(encode_state_value(child)) == child
    assert _change(state, child, "setpgid", 5) == _change(restored, child, "setpgid", 5)
    assert _capture_head(state) == _capture_head(restored)


@pytest.mark.parametrize("corruption", ["counts", "membership", "history", "legacy"])
def test_checkpoint_rejects_inconsistent_job_control_before_publishing(corruption: str) -> None:
    state, root = _root()
    root = _change(state, root, "bootstrap", 0)
    document = loads(_capture_head(state))
    if corruption == "counts":
        document["simple"]["_posix_job_control_reservation_counts"] = encode_state_value({})
    elif corruption == "membership":
        document["simple"]["_posix_job_control_reservations"] = encode_state_value({})
    elif corruption == "history":
        state.get_process(root.hostname, root.pid).job_control_history = (
            replace(
                state.get_process(root.hostname, root.pid).job_control_history[0],
                changed_at=_START + timedelta(seconds=1),
            ),
        )
        document = loads(_capture_head(state))
    else:
        document["schema_version"] = "6"
        for name in ("_posix_job_control_reservations", "_posix_job_control_reservation_counts"):
            del document["simple"][name]
    restored = StateManager()
    before = restored.materialization_digest()
    with pytest.raises(CheckpointCorruptionError):
        _restore_head(restored, dumps(document))
    assert restored.materialization_digest() == before


def test_legacy_head_and_records_keep_unknown_membership() -> None:
    state, identity = _root()
    document = loads(_capture_head(state))
    document["schema_version"] = "6"
    for name in ("_posix_job_control_reservations", "_posix_job_control_reservation_counts"):
        del document["simple"][name]
    restored = StateManager()
    _restore_head(restored, dumps(document))
    assert restored.get_process_identity(identity.hostname, identity.pid).job_control is None
    fields = encode_state_value(identity)[2]
    assert decode_state_value(["record", "process-identity-v5", fields[:18]]).job_control is None
    fields = encode_state_value(state.get_process(identity.hostname, identity.pid))[2]
    assert (
        decode_state_value(["record", "running-process-v9", fields[:32]]).job_control_history == ()
    )


@pytest.mark.parametrize("operation", ["bootstrap", "setsid", "setpgid"])
def test_unknown_membership_is_not_inferred_from_login_or_audit_identity(operation: str) -> None:
    state, root = _root()
    child = _fork(state, root, 1)
    before = state.materialization_digest()
    with pytest.raises((StateError, ValueError)):
        _change(state, child, operation, 2)
    assert state.materialization_digest() == before
    assert child.job_control is None


def test_bootstrap_requires_the_initial_state_frontier() -> None:
    state, root = _root()
    _fork(state, root, 1)
    with pytest.raises(StateError):
        _change(state, root, "bootstrap", 0)


def test_close_rollback_restores_membership_and_retirement_counts() -> None:
    state, root = _root()
    root = _change(state, root, "bootstrap", 0)
    child = _change(state, _fork(state, root, 1), "setsid", 2)
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(child, end_time=_START + timedelta(seconds=3))
    plan = builder.seal()
    before = state.materialization_digest()
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert state.get_posix_group_members(child.job_control) == ()
    assert state.materialization_digest() == before
    assert state.get_posix_group_members(child.job_control) == (child,)
    state.materialize_action_cohort(plan)
    assert state.get_posix_group_members(child.job_control) == ()


def test_cohort_multiple_closes_retire_only_after_final_member() -> None:
    state, root = _root()
    root = _change(state, root, "bootstrap", 0)
    leader = _change(state, _fork(state, root, 1), "setsid", 2)
    member = _fork(state, leader, 3)
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(member, end_time=_START + timedelta(seconds=4))
    builder.terminate_process(leader, end_time=_START + timedelta(seconds=5))
    state.materialize_action_cohort(builder.seal())
    for kind in ("group", "session"):
        rows = state._posix_job_control_reservations[(kind, leader.hostname, leader.pid)]
        assert rows[-1].members == 0
        assert rows[-1].ended_at == _START + timedelta(seconds=5)


def test_process_starts_inherit_exact_group_and_fail_before_writes_when_backdated() -> None:
    state, root = _root()
    root = _change(state, root, "bootstrap", 0)
    _fork(state, root, 4)
    before = state.materialization_digest()
    with pytest.raises(StateError, match="backdated"):
        _fork(state, root, 3)
    assert state.materialization_digest() == before


def test_separate_hosts_can_own_same_numeric_groups() -> None:
    state, root = _root()
    root = _change(state, root, "bootstrap", 0)
    plan = state.plan_process_materialization(
        system="second-workstation",
        parent_pid=0,
        image="/sbin/launchd",
        command_line="launchd",
        username="root",
        integrity_level="System",
        os_category="macos",
        fixed_pid=1,
        credentials=PosixProcessCredentials(0, 0, 0, 0),
        start_time=_START,
    )
    state.materialize_process(plan)
    other = _change(state, plan.identity, "bootstrap", 0)
    assert other.job_control != root.job_control
    assert state.get_posix_group_members(other.job_control) == (other,)
    assert state.get_posix_group_members(root.job_control) == (root,)


def test_membership_change_cannot_share_cohort_with_unrelated_activity() -> None:
    state, root = _root()
    root = _change(state, root, "bootstrap", 0)
    child = _fork(state, root, 1)
    builder = state.begin_action_cohort_materialization()
    builder.change_posix_job_control(
        child, operation="setsid", changed_at=_START + timedelta(seconds=2)
    )
    builder.plan_process(
        system=root.hostname,
        parent_pid=0,
        image="/bin/true",
        command_line="true",
        username="root",
        integrity_level="System",
        os_category="macos",
        start_time=_START + timedelta(seconds=3),
    )
    before = state.materialization_digest()
    with pytest.raises(StateError, match="own process cohort"):
        state.materialize_action_cohort(builder.seal())
    assert state.materialization_digest() == before


def test_reused_numeric_group_and_session_ids_have_distinct_lifetime_identity() -> None:
    state, root = _root()
    root = _change(state, root, "bootstrap", 0)
    original = _change(state, _fork(state, root, 1), "setsid", 2)
    _close(state, original, 3)
    plan = state.plan_process_materialization(
        system=root.hostname,
        parent_pid=root.pid,
        image="/bin/zsh",
        command_line="zsh",
        username="root",
        integrity_level="System",
        os_category="macos",
        fixed_pid=original.pid,
        credentials=root.credentials,
        start_time=_START + timedelta(seconds=4),
    )
    state.materialize_process(plan)
    replacement = _change(state, plan.identity, "setsid", 5)
    assert replacement.job_control.pgid == original.job_control.pgid
    assert replacement.job_control.session.sid == original.job_control.session.sid
    assert replacement.job_control != original.job_control
    assert state.get_posix_group_members(original.job_control) == ()
    assert state.get_posix_group_members(replacement.job_control) == (replacement,)
    assert (
        state.get_process_identity_by_object_id(
            original.object_id, event_time=_START + timedelta(seconds=2)
        )
        == original
    )
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_posix_group_members(replacement.job_control) == (replacement,)


def test_parent_controlled_change_rollback_restores_both_process_frontiers() -> None:
    state, root = _root()
    root = _change(state, root, "bootstrap", 0)
    child = _fork(state, root, 1)
    builder = state.begin_action_cohort_materialization()
    builder.change_posix_job_control(
        child, operation="setpgid", changed_at=_START + timedelta(seconds=2), actor=root
    )
    plan = builder.seal()
    before = state.materialization_digest()
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert state.get_process(root.hostname, root.pid).last_activity_time == _START + timedelta(
            seconds=2
        )
    assert state.materialization_digest() == before


def test_membership_history_budget_rejects_before_partial_mutation() -> None:
    from evidenceforge.generation.posix_job_control import MAX_MEMBERSHIP_CHANGES

    state, root = _root()
    root = _change(state, root, "bootstrap", 0)
    child = _fork(state, root, 1)
    for index in range(MAX_MEMBERSHIP_CHANGES):
        child = _change(
            state, child, "setpgid", index + 2, group=root.job_control if index % 2 else None
        )
    before = state.materialization_digest()
    with pytest.raises(StateError, match="oversized"):
        _change(state, child, "setpgid", MAX_MEMBERSHIP_CHANGES + 2)
    assert state.materialization_digest() == before
