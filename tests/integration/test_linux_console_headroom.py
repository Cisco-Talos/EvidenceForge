# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""New getty admission covers source readiness and the whole occupied interval."""

from datetime import timedelta

import pytest

from evidenceforge.generation.actions.linux_console import plan_linux_console_login
from evidenceforge.generation.activity.system_processes import linux_console_policy
from evidenceforge.models.scenario import User
from tests.unit.test_sudo_logon_id_ownership import _SCENARIO_START, _sudo_generator


def test_new_console_getty_reserves_creation_headroom_before_short_idle_lead(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generator, state, system = _sudo_generator()
    original = generator._sample_profile_activity_gap

    def short_getty_lead(key: str, **kwargs: object) -> timedelta:
        if key == "linux.console.getty_before_login":
            return timedelta(milliseconds=400)
        return original(key, **kwargs)

    monkeypatch.setattr(generator, "_sample_profile_activity_gap", short_getty_lead)
    user = User(username="console-user", full_name="Console User", email="console@example.test")
    logon_id = generator.generate_logon(
        user,
        system,
        _SCENARIO_START + timedelta(minutes=10),
        emit_network_evidence=False,
        allow_local_session_reuse=False,
    )
    session = state.get_session(logon_id)
    assert session is not None
    identity = state.get_process_identity(system.hostname, session.process_tree_root)
    assert identity is not None and identity.image == "/bin/login"
    running = state.get_process(system.hostname, identity.pid)
    assert running is not None
    getty = running.prior_executions[0]
    bound = generator._process_create_source_bound(system=system, canonical_time=getty.started_at)
    assert bound < identity.execution_started_at < session.start_time


@pytest.mark.parametrize("restore", [False, True])
def test_new_getty_cannot_overlap_a_recently_closed_terminal_lifetime(restore: bool) -> None:
    from evidenceforge.generation.state_manager import StateManager
    from tests.support.state_checkpoint import capture_complete_state, restore_complete_state

    generator, state, system = _sudo_generator()
    at = _SCENARIO_START + timedelta(minutes=10)
    pid = generator.generate_system_process(
        system,
        at - timedelta(minutes=1),
        "/sbin/agetty",
        "/sbin/agetty --noclear tty1 linux",
        username="root",
        emit_linux_syslog=False,
    )
    generator.generate_system_process_termination(
        system,
        at - timedelta(milliseconds=200),
        pid,
        "/sbin/agetty",
        username="root",
    )
    if restore:
        restored = StateManager()
        restore_complete_state(restored, capture_complete_state(state))
        state = restored
    policy = linux_console_policy()
    assert policy is not None
    assert plan_linux_console_login(state, system, at, policy).terminal == "tty1"
    reserved = plan_linux_console_login(
        state,
        system,
        at,
        policy,
        occupied_since=at - timedelta(seconds=2),
    )
    assert reserved.terminal == "tty2" and reserved.existing_getty is None
