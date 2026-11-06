# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""A sudo bootstrap cannot reuse a session rejected for command coverage."""

from datetime import timedelta
from unittest.mock import patch

from evidenceforge.events.lifecycle import SessionEndPlan
from tests.unit.test_sudo_logon_id_ownership import (
    _SCENARIO_START,
    _generate_sudo_processes,
    _sudo_generator,
)


def test_bootstrap_allocates_session_after_existing_terminal_fails_full_coverage() -> None:
    generator, state, system = _sudo_generator()
    first_at = _SCENARIO_START + timedelta(minutes=15)
    first_pid, _, _, first_tty = _generate_sudo_processes(
        generator, system, sudo_time=first_at, lifecycle_group_id="first", tty="pts/1"
    )
    assert first_pid > 0
    first = state.get_sessions_for_user("testuser")[0]
    second_at = _SCENARIO_START + timedelta(hours=1)
    assert state.plan_session_end(
        first.logon_id,
        SessionEndPlan(
            canonical_end=second_at + timedelta(seconds=1),
            authority="explicit_storyline",
            storyline_event_id="old-session-close",
        ),
    )
    with patch.object(generator, "generate_logon", wraps=generator.generate_logon) as bootstrap:
        second_pid, _, _, second_tty = _generate_sudo_processes(
            generator, system, sudo_time=second_at, lifecycle_group_id="second", tty="pts/2"
        )
    assert second_pid > 0
    assert second_tty != first_tty
    assert bootstrap.call_count == 1
    assert bootstrap.call_args.kwargs["allow_local_session_reuse"] is False
    second = state.get_session(state.get_process(system.hostname, second_pid).logon_id)
    assert second is not None and second.logon_id != first.logon_id
    assert generator._linux_sudo_terminal_for_session(first.logon_id) == first_tty
    assert generator._linux_sudo_terminal_for_session(second.logon_id) == second_tty
