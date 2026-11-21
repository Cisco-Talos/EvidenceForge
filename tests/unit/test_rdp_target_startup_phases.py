"""Canonical RDP startup work, replay, and admission contracts."""

from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.generation import rdp_target_timing
from evidenceforge.generation.actions import rdp_session
from evidenceforge.generation.activity.timing_profiles import TimingWindow
from evidenceforge.generation.baseline_timing import BaselineTimingPlanner
from evidenceforge.generation.rdp_target_timing import (
    RdpTargetPhasePlan,
    plan_rdp_target_bootstrap,
)
from evidenceforge.models.exceptions import StateError

_OPEN = datetime(2026, 11, 2, 13, tzinfo=UTC)


def _plan(key: str, *, manager: bool = True, close_seconds: int = 60) -> RdpTargetPhasePlan:
    return plan_rdp_target_bootstrap(
        timing=BaselineTimingPlanner.compatibility(_OPEN),
        transport_open=_OPEN,
        logon_time=_OPEN + timedelta(seconds=2),
        transport_close=_OPEN + timedelta(seconds=close_seconds),
        session_deadline=_OPEN + timedelta(minutes=2),
        stable_id=key,
        hostname="RDP-TARGET",
        has_session_manager=manager,
    )


def test_readiness_does_not_erase_scoped_startup_work() -> None:
    plans = [_plan(f"session-{index}") for index in range(32)]
    assert plans == [_plan(f"session-{index}") for index in range(32)]
    manager_gaps: set[timedelta] = set()
    auth_gaps: set[timedelta] = set()
    for plan in plans:
        assert plan.session_manager is not None
        assert _OPEN + timedelta(seconds=5) < plan.session_manager < plan.winlogon
        assert plan.winlogon < plan.authentication < plan.user_manager < plan.desktop
        assert plan.desktop < plan.user_manager_exit < _OPEN + timedelta(seconds=60)
        manager_gaps.add(plan.winlogon - plan.session_manager)
        auth_gaps.add(plan.authentication - plan.winlogon)
    assert len(manager_gaps) > 24
    assert len(auth_gaps) > 24
    assert all(
        timedelta(milliseconds=120) <= gap <= timedelta(milliseconds=1500) for gap in manager_gaps
    )


def test_existing_manager_does_not_create_a_second_manager() -> None:
    plan = _plan("existing-manager", manager=False)
    assert plan.session_manager is None
    assert _OPEN + timedelta(seconds=2) < plan.winlogon < plan.authentication


def test_transport_too_short_for_startup_is_rejected() -> None:
    with pytest.raises(StateError, match="closes before target bootstrap"):
        _plan("short-transport", close_seconds=6)


def test_deadline_support_uses_the_same_configured_phase_maxima(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    windows = rdp_target_timing.rdp_target_phase_windows()
    expanded = windows.model_copy(
        update={
            "authentication": TimingWindow(
                min_ms=80000,
                max_ms=90000,
                position="after",
                relationship_class="causal_prerequisite",
            )
        }
    )
    monkeypatch.setattr(rdp_target_timing, "rdp_target_phase_windows", lambda: expanded)
    monkeypatch.setattr(rdp_session, "rdp_target_phase_windows", lambda: expanded)
    reserved = rdp_session.rdp_action_deadline_transport_headroom_seconds()
    assert reserved > 5 + rdp_target_timing.rdp_target_work_max_seconds(expanded)
    plan = _plan("expanded-work", close_seconds=115)
    assert timedelta(seconds=80) <= plan.authentication - plan.winlogon <= timedelta(seconds=90)
    assert plan.user_manager_exit < _OPEN + timedelta(seconds=reserved)
