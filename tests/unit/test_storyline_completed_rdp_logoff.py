"""Authored RDP closes acknowledge only exact lifecycle-owned completion."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.generation.engine.typed_handlers.authentication import handle_logoff
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import LogoffEventSpec, System, User


@pytest.mark.parametrize("early", [False, True])
def test_paired_rdp_logoff_requires_exact_existing_terminal_state(early: bool) -> None:
    start = datetime(2026, 11, 2, 13, tzinfo=UTC)
    deadline = start + timedelta(hours=2)
    plan = SessionEndPlan(deadline, "explicit_storyline", "close-desktop")
    state = StateManager()
    state.set_current_time(start)
    logon_id = state.create_session(
        username="analyst",
        system="CLIENT",
        logon_type=10,
        source_ip="192.0.2.1",
        session_kind="rdp",
    )
    state.plan_session_end(logon_id, plan)
    state.end_session(logon_id, deadline - timedelta(seconds=1) if early else deadline)
    runtime = SimpleNamespace(
        state_manager=state,
        _session_end_plan_for_current_logoff=lambda: (logon_id, plan),
        activity_generator=Mock(),
    )
    context = SimpleNamespace(
        actor=User(username="analyst", full_name="Analyst", email="analyst@example.test"),
        system=System(hostname="CLIENT", ip="192.0.2.2", os="Windows 11", type="workstation"),
        time=deadline,
        malicious_event={},
    )
    if early:
        with pytest.raises(StateError, match="lost its paired session"):
            handle_logoff(runtime, LogoffEventSpec(), context)
    else:
        result = handle_logoff(runtime, LogoffEventSpec(), context)
        assert result["logon_id"] == logon_id
    runtime.activity_generator.generate_logoff.assert_not_called()
