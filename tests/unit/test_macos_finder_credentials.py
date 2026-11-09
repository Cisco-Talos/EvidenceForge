# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented Finder child credentials retain one execution before GUI audit adoption."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.identity import ProcessIdentity, SessionIdentity
from evidenceforge.events.process import process_credential_identities
from evidenceforge.generation.actions.posix_process import process_credential_occurrence
from evidenceforge.generation.checkpoints.state_manager_head import StateManagerParticipant
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_gui_exec_adoption import _APP, _HOST, _setup
from tests.unit.test_process_execution_state import _START


def _root_launcher() -> tuple[StateManager, ProcessIdentity, SessionIdentity]:
    state, _, owner = _setup()
    parent = state.get_process_identity(_HOST.hostname, 1)
    builder = state.begin_action_cohort_materialization()
    birth = builder.fork_process(parent, forked_at=_START + timedelta(seconds=3))
    launcher = builder.execute_process(
        birth,
        image="/usr/libexec/xpcproxy",
        command_line="xpcproxy invented.service",
        arguments=("xpcproxy", "invented.service"),
        environment=("XPC_FLAGS=0",),
        executed_at=_START + timedelta(seconds=4),
    )
    state.materialize_action_cohort(builder.seal())
    return state, launcher, owner


def test_gui_account_binding_is_atomic_historical_and_preserves_execution() -> None:
    state, before, owner = _root_launcher()
    at = _START + timedelta(seconds=5)
    builder = state.begin_action_cohort_materialization()
    after = builder.drop_macos_gui_launcher_credentials(before, session=owner, dropped_at=at)
    plan = builder.seal()
    event = process_credential_occurrence(
        host=_HOST,
        before=before,
        after=after,
        timestamp=at,
        kind="process_service_drop",
        integrity_level="Medium",
        session=owner,
    )
    assert process_credential_identities(event) == (before, after)
    assert before.principal == "root" and before.credentials.real_uid == 0
    assert after.principal == "alex" and after.credentials.real_uid == 501
    assert after.logon_id == owner.logon_id
    assert after.credentials.audit_uid == before.credentials.audit_uid == 2**32 - 1
    assert after.credentials.audit_session_id == before.credentials.audit_session_id == 0
    assert (
        after.execution_id == before.execution_id
        and after.audit_pid_version == before.audit_pid_version
    )
    digest = state.materialization_digest()
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert state.get_process_identity(_HOST.hostname, before.pid) == after
    assert state.materialization_digest() == digest
    state.materialize_action_cohort(plan)
    assert (
        state.get_process_identity_at(_HOST.hostname, before.pid, at - timedelta(microseconds=1))
        == before
    )
    assert state.get_process_identity_at(_HOST.hostname, before.pid, at) == after
    assert state.get_processes_for_session(owner.logon_id)
    builder = state.begin_action_cohort_materialization()
    app = builder.execute_process(
        after,
        image=_APP,
        command_line=_APP,
        arguments=(_APP,),
        executed_at=at + timedelta(seconds=1),
        macos_gui_session=owner,
    )
    state.materialize_action_cohort(builder.seal())
    assert app.credentials.audit_uid == 501 and app.execution_ordinal == 2
    seal = StateManagerParticipant(state).prepare_checkpoint(1)
    restored = StateManager()
    StateManagerParticipant(restored).restore_checkpoint(seal.head.payload, ())
    assert restored.get_process_identity(_HOST.hostname, before.pid) == app
    assert (
        restored.get_process_identity_at(_HOST.hostname, before.pid, at - timedelta(microseconds=1))
        == before
    )
    assert restored.get_process_identity_at(_HOST.hostname, before.pid, at) == after


@pytest.mark.parametrize("damage", ["owner", "host", "kind", "time"])
def test_gui_account_binding_rejects_foreign_or_expired_authority(damage: str) -> None:
    state, before, owner = _root_launcher()
    if damage == "owner":
        owner = replace(owner, principal="other")
    elif damage == "host":
        owner = replace(owner, hostname="OTHER")
    elif damage == "kind":
        owner = replace(owner, session_kind="ssh")
    at = _START + timedelta(seconds=3 if damage == "time" else 5)
    digest = state.materialization_digest()
    with pytest.raises((StateError, ValueError)):
        state.begin_action_cohort_materialization().drop_macos_gui_launcher_credentials(
            before, session=owner, dropped_at=at
        )
    assert state.materialization_digest() == digest


def test_gui_service_drop_checkpoint_preserves_exact_session_authority() -> None:
    state, before, owner = _root_launcher()
    builder = state.begin_action_cohort_materialization()
    builder.drop_macos_gui_launcher_credentials(
        before, session=owner, dropped_at=_START + timedelta(seconds=5)
    )
    drop = builder.seal().process_activity_patches[0].service_drop
    assert decode_state_value(encode_state_value(drop)) == drop


def test_prior_service_drop_checkpoint_width_remains_readable() -> None:
    from tests.unit.test_macos_service_drop import _child, _drop

    state, before = _child()
    _drop(state, before)
    drop = state.get_process(before.hostname, before.pid).service_drop
    encoded = encode_state_value(drop)
    assert encoded[0] == "record" and encoded[1] == "macos-process-service-drop-v2"
    encoded[1] = "macos-process-service-drop-v1"
    encoded[2] = encoded[2][:10]
    assert decode_state_value(encoded) == drop


def test_gui_exec_allows_independent_boot_group_lookahead_without_retiring_it_early() -> None:
    state, before, owner = _root_launcher()
    builder = state.begin_action_cohort_materialization()
    after = builder.drop_macos_gui_launcher_credentials(
        before,
        session=owner,
        dropped_at=_START + timedelta(seconds=5),
    )
    state.materialize_action_cohort(builder.seal())
    root = state.get_process_identity(before.hostname, 1)
    builder = state.begin_action_cohort_materialization()
    later = builder.fork_process(root, forked_at=_START + timedelta(seconds=10))
    state.materialize_action_cohort(builder.seal())
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(later.identity, end_time=_START + timedelta(seconds=20))
    state.materialize_action_cohort(builder.seal())
    builder = state.begin_action_cohort_materialization()
    app = builder.execute_process(
        after,
        image=_APP,
        command_line=_APP,
        arguments=(_APP,),
        executed_at=_START + timedelta(seconds=6),
        macos_gui_session=owner,
    )
    state.materialize_action_cohort(builder.seal())
    assert state.get_posix_group_members(app.job_control) == (app,)
    # The boot group still contains the fixture's other member. Remove it, then
    # prove that the last member cannot retire before the later observed activity.
    other = next(p for p in state.get_posix_group_members(root.job_control) if p.pid != 1)
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(other, end_time=_START + timedelta(seconds=21))
    state.materialize_action_cohort(builder.seal())
    digest = state.materialization_digest()
    builder = state.begin_action_cohort_materialization()
    with pytest.raises(StateError, match="backdated"):
        builder.terminate_process(root, end_time=_START + timedelta(seconds=19))
        state.materialize_action_cohort(builder.seal())
    assert state.materialization_digest() == digest
