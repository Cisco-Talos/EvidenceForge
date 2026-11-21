# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical RDP startup phases separate admission readiness from sampled work."""

from __future__ import annotations

from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.generation.activity.timing_profiles import TimingWindow, get_timing_window
from evidenceforge.generation.baseline_timing import BaselineTimingPlanner
from evidenceforge.generation.timing import TemporalConstraintGraph, TimingScope
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.time import ensure_utc

RDP_SESSION_MANAGER_READINESS_SECONDS = 5.0


class RdpTargetPhaseWindows(BaseModel):
    """One effective configuration snapshot for RDP target startup work."""

    negotiation: TimingWindow
    session_manager_lead: TimingWindow
    session_manager_spawn: TimingWindow
    winlogon_spawn: TimingWindow
    authentication: TimingWindow
    userinit_exit: TimingWindow
    model_config = ConfigDict(extra="forbid", frozen=True)


def rdp_target_phase_windows() -> RdpTargetPhaseWindows:
    """Read configured phase support with compatible code defaults."""
    return RdpTargetPhaseWindows(
        negotiation=get_timing_window(
            "rdp.target_logon_after_transport",
            default_min_ms=900,
            default_max_ms=1600,
            default_position="after",
            default_class="causal_prerequisite",
        ),
        session_manager_lead=get_timing_window(
            "rdp.session_manager_lead_before_logon",
            default_min_ms=1500,
            default_max_ms=8000,
            default_position="before",
            default_class="causal_prerequisite",
        ),
        session_manager_spawn=get_timing_window(
            "rdp.session_manager_spawn_after_ready",
            default_min_ms=80,
            default_max_ms=800,
            default_position="after",
            default_class="causal_prerequisite",
        ),
        winlogon_spawn=get_timing_window(
            "rdp.winlogon_spawn_after_ready",
            default_min_ms=120,
            default_max_ms=1500,
            default_position="after",
            default_class="causal_prerequisite",
        ),
        authentication=get_timing_window(
            "rdp.authentication_after_winlogon",
            default_min_ms=350,
            default_max_ms=2400,
            default_position="after",
            default_class="causal_prerequisite",
        ),
        userinit_exit=get_timing_window(
            "rdp.userinit_after_desktop_ready",
            default_min_ms=650,
            default_max_ms=4900,
            default_position="after",
            default_class="teardown",
        ),
    )


class RdpTargetPhasePlan(BaseModel):
    """Canonical phase times consumed unchanged by State and source projection."""

    session_manager: datetime | None = Field(description="Optional per-session smss birth")
    winlogon: datetime = Field(description="Winlogon birth after its launch work")
    authentication: datetime = Field(description="Target authentication source readiness")
    user_manager: datetime = Field(description="Userinit birth after authentication")
    desktop: datetime = Field(description="Explorer birth after userinit readiness")
    user_manager_exit: datetime = Field(description="Userinit handoff termination")
    model_config = ConfigDict(extra="forbid", frozen=True)


def _maximum_work_seconds(window: TimingWindow) -> float:
    # Immediate causal work still occupies one internal clock quantum.
    return max(0.000001, window.max_ms / 1000)


def rdp_target_work_max_seconds(windows: RdpTargetPhaseWindows | None = None) -> float:
    """Return the same configured work support used by physical phase planning."""
    windows = windows or rdp_target_phase_windows()
    return sum(
        _maximum_work_seconds(w)
        for w in (
            windows.session_manager_spawn,
            windows.winlogon_spawn,
            windows.authentication,
            windows.userinit_exit,
        )
    ) + BaselineTimingPlanner.windows_session_bootstrap_max_seconds(remote=True)


def plan_rdp_target_bootstrap(
    *,
    timing: BaselineTimingPlanner,
    transport_open: datetime,
    logon_time: datetime,
    transport_close: datetime,
    session_deadline: datetime,
    stable_id: str,
    hostname: str,
    has_session_manager: bool,
) -> RdpTargetPhasePlan:
    """Plan the whole target bootstrap before allocating canonical actors.

    Bounds are modeled support, not empirical Windows kernel calibration. The
    existing session-manager readiness fence remains a separate admission bound.
    """
    opened, requested = ensure_utc(transport_open), ensure_utc(logon_time)
    closed, deadline = ensure_utc(transport_close), ensure_utc(session_deadline)
    if not opened < closed < deadline or requested >= closed:
        raise StateError("Exact RDP target startup requires an open transport before its deadline")
    windows = rdp_target_phase_windows()

    def work(key: str, window: TimingWindow) -> timedelta:
        sampled = timing.triangular_seconds(
            relationship_key=key,
            stable_id=stable_id,
            minimum=window.min_ms / 1000,
            mode=(window.min_ms + 0.35 * (window.max_ms - window.min_ms)) / 1000,
            maximum=window.max_ms / 1000,
            host=hostname,
            lifecycle_id=stable_id,
            sample_key="target_phase_work",
        )
        return max(timedelta(microseconds=1), timedelta(seconds=sampled))

    manager_time: datetime | None = None
    manager_ready = requested
    manager_work = timedelta(0)
    if has_session_manager:
        lead = work("rdp.session_manager_lead_before_logon", windows.session_manager_lead)
        manager_ready = max(
            requested - lead, opened + timedelta(seconds=RDP_SESSION_MANAGER_READINESS_SECONDS)
        )
        manager_work = work("rdp.session_manager_spawn_after_ready", windows.session_manager_spawn)
        manager_time = manager_ready + manager_work
    winlogon_ready = max(requested, manager_time or requested)
    winlogon_work = work("rdp.winlogon_spawn_after_ready", windows.winlogon_spawn)
    winlogon_time = winlogon_ready + winlogon_work
    auth_work = work("rdp.authentication_after_winlogon", windows.authentication)
    auth_time = winlogon_time + auth_work
    user_delay, desktop_delay = timing.windows_session_bootstrap_delays(
        stable_id=stable_id,
        host=hostname,
        lifecycle_id=stable_id,
        remote=True,
    )
    user_time = auth_time + timedelta(seconds=user_delay)
    desktop_time = user_time + timedelta(seconds=desktop_delay)
    exit_work = work("rdp.userinit_after_desktop_ready", windows.userinit_exit)
    exit_time = desktop_time + exit_work

    graph = TemporalConstraintGraph(
        timing_runtime=timing.runtime,
        scope=TimingScope(
            stable_id=stable_id, host=hostname, source="rdp_session", lifecycle_id=stable_id
        ),
        relationship_key="rdp.target_startup.constraints",
    )
    graph.add_node("transport_open", opened, not_before=opened, not_after=opened)
    graph.add_node("session_request", requested, not_before=requested, not_after=requested)
    if has_session_manager:
        graph.add_node("manager_ready", manager_ready)
        graph.constrain_after(
            "manager_ready",
            "transport_open",
            min_gap=timedelta(seconds=RDP_SESSION_MANAGER_READINESS_SECONDS),
        )
        graph.add_node("manager", manager_time)
        graph.constrain_after("manager", "manager_ready", min_gap=manager_work)
    graph.add_node("winlogon_ready", winlogon_ready)
    graph.constrain_after("winlogon_ready", "session_request", min_gap=timedelta(0))
    if has_session_manager:
        graph.constrain_after("winlogon_ready", "manager", min_gap=timedelta(0))
    graph.add_node("winlogon", winlogon_time)
    graph.constrain_after("winlogon", "winlogon_ready", min_gap=winlogon_work)
    graph.add_node("authentication", auth_time)
    graph.constrain_after("authentication", "winlogon", min_gap=auth_work)
    graph.add_node("user_manager", user_time)
    graph.constrain_after("user_manager", "authentication", min_gap=timedelta(seconds=user_delay))
    graph.add_node("desktop", desktop_time)
    graph.constrain_after("desktop", "user_manager", min_gap=timedelta(seconds=desktop_delay))
    graph.add_node("user_manager_exit", exit_time)
    graph.constrain_after("user_manager_exit", "desktop", min_gap=exit_work)
    # Fail before State reservations rather than moving the authored transport.
    if exit_time >= closed:
        raise StateError(
            "Exact RDP transport closes before target bootstrap and userinit handoff complete"
        )
    graph.add_node("transport_close", closed, not_before=closed, not_after=closed)
    graph.constrain_after("transport_close", "user_manager_exit", min_gap=timedelta(microseconds=1))
    graph.add_node("session_deadline", deadline, not_before=deadline, not_after=deadline)
    graph.constrain_after("session_deadline", "transport_close", min_gap=timedelta(microseconds=1))
    values = graph.resolve()
    return RdpTargetPhasePlan(
        session_manager=values.get("manager"),
        winlogon=values["winlogon"],
        authentication=values["authentication"],
        user_manager=values["user_manager"],
        desktop=values["desktop"],
        user_manager_exit=values["user_manager_exit"],
    )
