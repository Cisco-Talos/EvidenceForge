# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical workspace request and native writer projection remain distinct."""

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import HostContext
from evidenceforge.events.contracts import shadow_seal
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.identity import EventIdentityPlan
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.events.observation import ObservationPolicy
from evidenceforge.formats.loader import load_format
from evidenceforge.formats.macos_unified_log import decode_unified_log_record
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.emitters.macos_unified_log import MacosUnifiedLogEmitter
from evidenceforge.generation.macos_logging import prepare_workspace_request
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from tests.unit.test_macos_foundations import _TIME, _seed_launchd, _system, _user
from tests.unit.test_macos_unified_projection import _START, _owned_writer


def _request_event(
    scenarios_dir: Path, *, missing_image: bool = False, os_name: str = "macOS 26"
) -> tuple[StateManager, OccurrenceBuilder]:
    manager, registry, writer = _owned_writer(scenarios_dir)
    manager.set_current_time(_START + timedelta(seconds=10))
    logon = manager.create_session(
        "casey", writer.hostname, logon_type=2, source_ip=None, session_kind="interactive"
    )
    session = manager.get_session_identity(logon)
    request = prepare_workspace_request(
        manager,
        None if missing_image else registry,
        session=session,
        writer_pid=writer.pid,
        requested_at=_START + timedelta(seconds=11),
        os_name=os_name,
    )
    return manager, OccurrenceBuilder(
        timestamp=request.requested_at,
        event_type="macos_workspace_request",
        src_host=HostContext(
            hostname=writer.hostname,
            fqdn="mac-fixture.example.test",
            ip="192.0.2.10",
            os="macOS 26",
            os_category="macos",
            system_type="workstation",
        ),
        macos_workspace=request,
        identity_plan=EventIdentityPlan(subject=session, session=session, actor=writer),
        lifecycle=ActionLifecycleContext(
            group_id=session.lifecycle_group_id,
            canonical_start=session.started_at,
            phase="dependent",
        ),
    )


@pytest.mark.parametrize("threaded", [False, True])
def test_workspace_request_uses_native_host_writer_and_retains_session_subject(
    scenarios_dir: Path, tmp_path: Path, threaded: bool
) -> None:
    manager, event = _request_event(scenarios_dir)
    emitter = MacosUnifiedLogEmitter(load_format("macos_unified_log"), tmp_path, threaded=threaded)
    dispatcher = EventDispatcher(manager, {"macos_unified_log": emitter})
    try:
        dispatcher.dispatch_builder(event)
    finally:
        emitter.close()
    path = tmp_path / "mac-fixture.example.test" / "macos_unified_log.ndjson"
    rows = path.read_text().splitlines()
    assert len(rows) == 1
    record = decode_unified_log_record(rows[0])
    request = event.macos_workspace
    assert record.event_message == "-[Login1 launchWorkspace] | enter"
    assert record.user_id == 0 and request.session.principal == "casey"
    assert event.identity_plan.subject == request.session
    assert record.process_id == request.writer.pid
    assert record.thread_id == request.writer.primary_thread.tid
    assert record.mach_timestamp == request.native.mach_timestamp
    assert "session" not in json.loads(rows[0])
    assert manager.get_session(request.session.logon_id) is not None


def test_missing_native_image_does_not_remove_or_close_canonical_request(
    scenarios_dir: Path, tmp_path: Path
) -> None:
    manager, event = _request_event(scenarios_dir, missing_image=True)
    emitter = MacosUnifiedLogEmitter(load_format("macos_unified_log"), tmp_path)
    try:
        EventDispatcher(manager, {"macos_unified_log": emitter}).dispatch_builder(event)
    finally:
        emitter.close()
    assert event.macos_workspace.unavailable_reason == "native_image_unavailable"
    assert manager.get_session(event.macos_workspace.session.logon_id) is not None
    assert not list(tmp_path.rglob("*.ndjson"))


@pytest.mark.parametrize(
    "os_name,available",
    [
        ("macOS 26", True),
        ("macOS 26.0.1", True),
        ("Darwin 25.0", True),
        ("macOS 15", False),
        ("macOS", False),
        ("Mac OS X", False),
        ("Darwin 24", False),
        ("macOS 260", False),
        ("Windows 26", False),
    ],
)
def test_native_workspace_profile_requires_explicit_supported_version(
    scenarios_dir: Path, os_name: str, available: bool
) -> None:
    _, event = _request_event(scenarios_dir, os_name=os_name)
    assert (event.macos_workspace.native is not None) == available
    if not available:
        assert event.macos_workspace.unavailable_reason == "profile_unavailable"


@pytest.mark.parametrize("damage", ["host", "platform", "time", "subject", "actor", "lifecycle"])
def test_workspace_contract_rejects_changed_canonical_ownership(
    scenarios_dir: Path, damage: str
) -> None:
    _, event = _request_event(scenarios_dir)
    if damage == "host":
        event.src_host.hostname = "another-mac"
    elif damage == "platform":
        event.src_host.os_category = "linux"
    elif damage == "time":
        event.timestamp += timedelta(seconds=1)
    elif damage == "subject":
        event.identity_plan = replace(event.identity_plan, subject=event.macos_workspace.writer)
    elif damage == "actor":
        event.identity_plan = replace(event.identity_plan, actor=event.macos_workspace.session)
    else:
        event.lifecycle = replace(event.lifecycle, phase="start")
    assert not shadow_seal(event).valid


@pytest.mark.parametrize("missingness,delay_ms", [(1.0, 0), (0.0, 275)])
def test_workspace_collection_does_not_change_session_or_uptime(
    scenarios_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missingness: float,
    delay_ms: int,
) -> None:
    manager, event = _request_event(scenarios_dir)
    monkeypatch.setattr(
        "evidenceforge.events.observation.get_observation_profile",
        lambda _name: {
            "default": {
                "missingness": missingness,
                "delay_ms": {"min_ms": delay_ms, "max_ms": delay_ms},
                "host_missingness_multiplier": {"min": 1.0, "max": 1.0},
            }
        },
    )
    emitter = MacosUnifiedLogEmitter(load_format("macos_unified_log"), tmp_path)
    dispatcher = EventDispatcher(
        manager,
        {"macos_unified_log": emitter},
        observation_policy=ObservationPolicy("workspace_test"),
    )
    when = event.timestamp
    session = event.macos_workspace.session
    try:
        dispatcher.dispatch_builder(event)
    finally:
        emitter.close()
    assert event.timestamp == when
    assert manager.get_session_identity(session.logon_id) == session
    paths = list(tmp_path.rglob("*.ndjson"))
    if missingness:
        assert not paths
    else:
        record = decode_unified_log_record(paths[0].read_text().strip())
        assert record.mach_timestamp == event.macos_workspace.native.mach_timestamp
        assert record.timestamp.startswith(
            (when + timedelta(milliseconds=delay_ms)).strftime("%Y-%m-%d %H:%M:%S.%f")
        )


def test_workspace_wall_clock_skew_does_not_rebase_native_uptime(scenarios_dir: Path) -> None:
    _, event = _request_event(scenarios_dir)
    planner = SourceTimingPlanner(clock_profile_name="enterprise_standard")
    delta = planner.endpoint_clock_adjustment_for_host(
        timestamp=event.timestamp, hostname=event.src_host.hostname, os_category="macos"
    )
    projected = planner.plan_event(
        event, "macos_unified_log", observation_delay=timedelta(seconds=2)
    )
    assert projected.timestamp == event.timestamp + delta + timedelta(seconds=2)
    assert delta != timedelta(0)
    assert projected.macos_workspace.native == event.macos_workspace.native


def test_shared_login_owner_emits_one_workspace_stage_for_reused_local_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = StateManager()
    _seed_launchd(manager)
    dispatcher = EventDispatcher(manager, {})
    generator = ActivityGenerator(manager, {}, dispatcher=dispatcher)
    recorded: list[OccurrenceBuilder] = []
    dispatch = dispatcher.dispatch_builder

    def capture(event: OccurrenceBuilder) -> dict[str, str]:
        recorded.append(event)
        return dispatch(event)

    monkeypatch.setattr(dispatcher, "dispatch_builder", capture)
    user, system = _user(), _system()
    generator.generate_failed_logon(user, system, _TIME, logon_type=2)
    generator.generate_logon(user, system, _TIME + timedelta(seconds=1), logon_type=5)
    assert not any(event.macos_workspace for event in recorded)
    first = generator.generate_logon(user, system, _TIME + timedelta(seconds=10))
    assert first == generator.generate_logon(
        user, system, _TIME + timedelta(minutes=1), logon_id=first
    )
    assert first == generator.generate_logon(user, system, _TIME + timedelta(minutes=2))
    requests = [event for event in recorded if event.macos_workspace is not None]
    assert len(requests) == 1
    assert requests[0].macos_workspace.session.logon_id == first
    assert requests[0].macos_workspace.native is None
    assert manager.get_session(first).login_occurrence_emitted
