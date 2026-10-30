# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Assigned boot origins share the canonical audit namespace without authenticating a user."""

from datetime import timedelta

import pytest

from evidenceforge.events.identity import PosixProcessCredentials, ProcessIdentity
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import MaterializationBatchBuilder, StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_audit_sessions import _commit, _plan
from tests.unit.test_process_execution_state import _START


def _boot(builder: MaterializationBatchBuilder) -> ProcessIdentity:
    return builder.plan_process(
        system="MAC-A",
        parent_pid=0,
        fixed_pid=1,
        image="/sbin/launchd",
        command_line="/sbin/launchd",
        username="root",
        integrity_level="System",
        os_category="macos",
        new_posix_session=True,
        credentials=PosixProcessCredentials(0, 0, 0, 0, 2**32 - 1, 0),
        macos_boot_audit_session=True,
        start_time=_START - timedelta(seconds=1),
    ).identity


@pytest.mark.parametrize("cohort", [False, True])
def test_boot_assignment_rolls_back_and_gui_namespace_cannot_collide(cohort: bool) -> None:
    state = StateManager()
    state.set_current_time(_START)
    builder = (
        state.begin_action_cohort_materialization()
        if cohort
        else state.begin_materialization_batch()
    )
    boot = _boot(builder)
    plan = builder.seal()
    digest = state.materialization_digest()
    assert boot.credentials.audit_session_id == 100_000
    assert boot.credentials.is_unattributed_root
    assert not state._macos_audit_session_counters
    if cohort:
        with state.prepared_action_cohort_materialization(plan) as prepared:
            prepared.certify_composite_commit(prepared.expected_result)
            prepared.apply_provisional()
            assert state._macos_audit_session_counters == {"MAC-A": 100_000}
    else:
        with state.prepared_materialization_batch(plan) as prepared:
            prepared.apply_provisional()
            assert state._macos_audit_session_counters == {"MAC-A": 100_000}
    assert state.materialization_digest() == digest
    # An aborted generic batch retires its fence; the retry reserves the same value.
    retry = state.begin_materialization_batch()
    assert _boot(retry) == boot
    _commit(state, retry)
    login, session = _plan(state)
    assert session.audit_origin.audit_session_id == 100_001
    _commit(state, login)
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_process_identity("MAC-A", 1) == boot
    assert restored._macos_audit_session_counters == {"MAC-A": 100_001}


@pytest.mark.parametrize(
    "damage", ["host_os", "pid", "image", "principal", "authenticated", "bool"]
)
def test_boot_assignment_requires_explicit_unattributed_launchd(damage: str) -> None:
    state = StateManager()
    state.set_current_time(_START)
    arguments: dict = {
        "system": "MAC-A",
        "parent_pid": 0,
        "fixed_pid": 1,
        "image": "/sbin/launchd",
        "command_line": "/sbin/launchd",
        "username": "root",
        "integrity_level": "System",
        "os_category": "macos",
        "new_posix_session": True,
        "macos_boot_audit_session": True,
        "credentials": PosixProcessCredentials(0, 0, 0, 0, 2**32 - 1, 0),
    }
    if damage == "host_os":
        arguments["os_category"] = "linux"
    elif damage == "pid":
        arguments["fixed_pid"] = 2
    elif damage == "image":
        arguments["image"] = "/bin/zsh"
    elif damage == "principal":
        arguments["username"] = "other"
    elif damage == "authenticated":
        arguments["credentials"] = PosixProcessCredentials(0, 0, 0, 0, 501, 100_000)
    else:
        arguments["macos_boot_audit_session"] = 1
    digest = state.materialization_digest()
    with pytest.raises(StateError):
        state.plan_process_materialization(**arguments)
    assert state.materialization_digest() == digest
