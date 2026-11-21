"""An exact previously closed RDP session completes its authored close intent."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.generation.engine.typed_handlers.authentication import handle_logoff
from evidenceforge.generation.ground_truth_ledger import GroundTruthLedger
from evidenceforge.generation.intent_ledger import (
    AuthoredIntent,
    AuthoredIntentLedger,
    IntentSection,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import LogoffEventSpec, System, User


def test_exact_completed_rdp_logoff_finishes_real_authored_intent_without_duplicate() -> None:
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
    state.end_session(logon_id, deadline)
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
    intent = AuthoredIntent(
        intent_id="close-intent",
        section=IntentSection.STORYLINE,
        step_id="close-desktop",
        event_type="logoff",
        semantic_instance_key="close:0",
        authored_time=deadline.isoformat(),
        actor="analyst",
        system="CLIENT",
        activity="Close desktop",
    )
    ledger = GroundTruthLedger(AuthoredIntentLedger("exact-close", (intent,)))
    try:
        result = handle_logoff(runtime, LogoffEventSpec(), context)
        ledger.finish_intent(intent.intent_id, result, "logoff")
        assert ledger.intent_results()[intent.intent_id] == {
            "status": "modeled_outcome",
            "reason": None,
            "outcome": "already_completed",
        }
        runtime.activity_generator.generate_logoff.assert_not_called()
    finally:
        ledger.close()
