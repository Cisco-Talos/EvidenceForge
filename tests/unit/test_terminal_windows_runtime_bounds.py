# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused regression tests for terminal Windows runtime admission."""

import math
import random
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from evidenceforge.config.schemas import (
    WindowsRemoteAuthDurationProfile,
    WindowsRemoteAuthOutcomeProfiles,
    WindowsRemoteAuthTransportConfig,
)
from evidenceforge.generation.actions.file_transfer import (
    http_response_parent_duration_floor,
)
from evidenceforge.generation.actions.windows_remote_authentication import (
    WindowsRemoteAuthenticationPlanner,
    WindowsRemoteAuthenticationRequest,
)
from evidenceforge.generation.activity import (
    ActivityGenerator,
    system_processes,
    windows_auth_realism,
)
from evidenceforge.generation.activity.http_multipart import (
    build_http_multipart_context,
)
from evidenceforge.generation.activity.timing_profiles import EndpointClockTiming
from evidenceforge.generation.engine import baseline as baseline_module
from evidenceforge.generation.engine.baseline import (
    _BASELINE_BROWSER_CLOSE_HEADROOM,
    BaselineMixin,
)
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models import System, User
from evidenceforge.models.scenario import (
    WebRequestProfile,
    WebRouteProfile,
    WeightedHttpMethodProfile,
)

_START = datetime(2024, 3, 18, 12, tzinfo=UTC)


def _windows_system() -> System:
    return System(
        hostname="WKS-01",
        ip="10.0.10.10",
        os="Windows 11",
        type="workstation",
    )


def _user() -> User:
    return User(
        username="alice",
        full_name="Alice Example",
        email="alice@example.test",
    )


def _activity_generator() -> tuple[ActivityGenerator, StateManager, dict[str, Mock]]:
    state = StateManager()
    emitters = {
        "windows_event_security": Mock(),
        "windows_event_sysmon": Mock(),
        "ecar": Mock(),
        "zeek_conn": Mock(),
        "syslog": Mock(),
    }
    generator = ActivityGenerator(
        state,
        emitters,
        generation_window_start=_START,
        generation_window_end=_START + timedelta(hours=1),
    )
    return generator, state, emitters


def _process_create_admission_times(
    planner: SourceTimingPlanner,
    emitters: dict[str, Mock],
    pid: int,
) -> list[datetime]:
    """Return actual admitted source times for one process-create identity."""

    return [
        planner.admission_time(call.args[0], format_name)
        for format_name, emitter in emitters.items()
        for call in emitter.emit.call_args_list
        if call.args
        and call.args[0].event_type
        in {
            "process_create",
            "session_process_create",
            "system_process_create",
        }
        and call.args[0].process is not None
        and call.args[0].process.pid == pid
    ]


def test_machine_auth_close_bound_has_success_overlay_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid tiny overlay cannot understate the success auth-to-close tail."""

    tiny = WindowsRemoteAuthDurationProfile(
        distribution="lognormal",
        minimum_seconds=0.05,
        median_seconds=0.075,
        maximum_seconds=0.10,
        sigma=0.5,
    )
    outcomes = WindowsRemoteAuthOutcomeProfiles(success="tiny", failure="tiny")
    config = WindowsRemoteAuthTransportConfig(
        profiles={"tiny": tiny},
        defaults=outcomes,
        sources={"machine_account_logon": outcomes},
    )
    monkeypatch.setattr(windows_auth_realism, "remote_auth_transport_config", lambda: config)

    bound = windows_auth_realism.remote_auth_transport_max_duration_seconds(
        source="machine_account_logon",
        outcome="success",
    )
    runtime = TimingRuntime(reference_time=_START, namespace="machine-auth-overlay-floor")
    request = WindowsRemoteAuthenticationRequest(
        target_system=System(
            hostname="DC-01",
            ip="10.0.20.10",
            os="Windows Server 2022",
            type="domain_controller",
        ),
        time=_START,
        source_ip="10.0.10.10",
        source_port=55000,
        logon_type=3,
        auth_protocol="Kerberos",
        outcome="success",
        destination_port=389,
        source_system=_windows_system(),
        source="machine_account_logon",
    )
    network_request = WindowsRemoteAuthenticationPlanner(
        SimpleNamespace(timing_runtime=runtime)
    )._network_request(request)
    close_time = network_request.time + timedelta(seconds=network_request.duration)

    assert bound == 0.25
    assert close_time <= request.time + timedelta(seconds=bound)


def test_windows_scheduled_task_plan_is_policy_state_neutral_until_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Planning consumes selection RNG but not the task cap or cooldown."""

    entry = {
        "id": "bounded-task",
        "image": r"C:\Windows\System32\gpupdate.exe",
        "weight": 1,
        "max_per_host_window": 1,
        "cooldown_seconds": 3600,
        "command_templates": ["gpupdate.exe /force"],
        "parent": "taskeng",
    }
    monkeypatch.setattr(system_processes, "get_scheduled_task_entries", lambda _host: [entry])
    engine = BaselineMixin()

    plan = engine._plan_windows_scheduled_task(
        system=_windows_system(),
        rng=random.Random(7),
        time=_START,
    )

    assert plan is not None
    assert not hasattr(engine, "_windows_scheduled_task_counts")
    assert not hasattr(engine, "_windows_scheduled_task_last_seen")

    engine._commit_windows_scheduled_task(plan)

    assert engine._windows_scheduled_task_counts[plan.state_key] == 1
    assert engine._windows_scheduled_task_last_seen[plan.state_key] == _START
    assert (
        engine._plan_windows_scheduled_task(
            system=_windows_system(),
            rng=random.Random(7),
            time=_START + timedelta(hours=2),
        )
        is None
    )


def test_profiled_system_process_forwards_source_visible_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The profiled-worker early return forwards the deadline to manager and worker."""

    monkeypatch.setattr(
        "evidenceforge.generation.source_timing.endpoint_clock_timing",
        lambda _profile, _os: EndpointClockTiming(7800, 7800, 0, 0),
    )
    runtime = TimingRuntime(reference_time=_START, namespace="terminal-process-deadline")
    planner = SourceTimingPlanner(clock_profile_name="messy_collection", timing_runtime=runtime)
    state = StateManager()
    emitters = {
        "windows_event_security": Mock(),
        "windows_event_sysmon": Mock(),
        "ecar": Mock(),
        "syslog": Mock(),
    }
    generator = ActivityGenerator(
        state,
        emitters,
        timing_runtime=runtime,
        source_timing_planner=planner,
        generation_window_start=_START,
        generation_window_end=_START + timedelta(hours=1),
    )
    system = System(
        hostname="MAIL-01",
        ip="10.0.20.25",
        os="Windows Server 2022",
        type="server",
        services=["owa", "exchange"],
        roles=["mail_server"],
    )
    create_time = _START + timedelta(seconds=10)
    source_bound = create_time + planner.process_create_positive_headroom(
        create_time,
        "windows",
    )
    state.set_current_time(create_time - timedelta(hours=1))
    state.register_process(
        system=system.hostname,
        pid=4,
        parent_pid=0,
        image="System",
        command_line="",
        username="SYSTEM",
        integrity_level="System",
        os_category="windows",
    )
    state.register_process(
        system=system.hostname,
        pid=500,
        parent_pid=4,
        image=r"C:\Windows\System32\services.exe",
        command_line="services.exe",
        username="SYSTEM",
        integrity_level="System",
        os_category="windows",
    )
    generator._system_pids = {system.hostname: {"system": 4, "services": 500}}
    processes_before = tuple(state.get_processes_on_system(system.hostname))
    frontier_before = state.get_current_time()

    rejected_pid = generator.generate_system_process(
        system=system,
        time=create_time,
        process_name=r"C:\Windows\System32\inetsrv\w3wp.exe",
        command_line=r'C:\Windows\System32\inetsrv\w3wp.exe -ap "MSExchangeOWAAppPool"',
        parent_pid=500,
        username="SYSTEM",
        source_visible_by=source_bound - timedelta(microseconds=1),
    )

    assert rejected_pid == 0
    assert state.get_current_time() == frontier_before
    assert tuple(state.get_processes_on_system(system.hostname)) == processes_before
    assert all(not emitter.emit.called for emitter in emitters.values())

    pid = generator.generate_system_process(
        system=system,
        time=create_time,
        process_name=r"C:\Windows\System32\inetsrv\w3wp.exe",
        command_line=r'C:\Windows\System32\inetsrv\w3wp.exe -ap "MSExchangeOWAAppPool"',
        parent_pid=500,
        username="SYSTEM",
        source_visible_by=source_bound,
    )
    visible_create = generator.process_source_create_time(system.hostname, pid)
    worker = state.get_process(system.hostname, pid)
    assert worker is not None
    manager_visible_create = generator.process_source_create_time(
        system.hostname,
        worker.parent_pid,
    )
    assert visible_create is not None
    assert manager_visible_create is not None
    worker_source_times = _process_create_admission_times(planner, emitters, pid)
    manager_source_times = _process_create_admission_times(planner, emitters, worker.parent_pid)
    assert worker_source_times
    assert manager_source_times
    assert visible_create == max(worker_source_times)
    assert manager_visible_create == max(manager_source_times)
    assert manager_visible_create <= source_bound - timedelta(milliseconds=1)
    assert visible_create <= source_bound


def test_source_visible_create_deadline_preserves_requested_process_termination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Late endpoint clocks cannot push a bounded termination past its owner deadline."""

    monkeypatch.setattr(
        "evidenceforge.generation.source_timing.endpoint_clock_timing",
        lambda _profile, _os: EndpointClockTiming(7800, 7800, 0, 0),
    )
    runtime = TimingRuntime(reference_time=_START, namespace="terminal-process-termination")
    planner = SourceTimingPlanner(clock_profile_name="messy_collection", timing_runtime=runtime)
    state = StateManager()
    emitters = {
        "windows_event_security": Mock(),
        "windows_event_sysmon": Mock(),
        "ecar": Mock(),
        "syslog": Mock(),
    }
    generator = ActivityGenerator(
        state,
        emitters,
        timing_runtime=runtime,
        source_timing_planner=planner,
        generation_window_start=_START,
        generation_window_end=_START + timedelta(hours=1),
    )
    system = _windows_system()
    create_time = _START + timedelta(seconds=10)
    state.set_current_time(create_time - timedelta(seconds=1))
    parent_pid = state.create_process(
        system=system.hostname,
        parent_pid=4,
        image=r"C:\Windows\System32\services.exe",
        command_line="services.exe",
        username="SYSTEM",
        integrity_level="System",
    )
    state.set_current_time(create_time)
    parent_source_time = generator._process_source_frontier_or_bound(
        system=system,
        pid=parent_pid,
    )
    source_bound = generator._process_create_source_bound(
        system=system,
        canonical_time=create_time,
        parent_source_time=parent_source_time,
    )
    terminate_time = source_bound + timedelta(microseconds=1)

    pid = generator.generate_system_process(
        system=system,
        time=create_time,
        process_name=r"C:\Windows\System32\gpupdate.exe",
        command_line="gpupdate.exe /force",
        parent_pid=parent_pid,
        username="SYSTEM",
        source_visible_by=source_bound,
    )
    visible_create = generator.process_source_create_time(system.hostname, pid)
    state.set_current_time(terminate_time)
    generator.generate_system_process_termination(
        system=system,
        time=terminate_time,
        pid=pid,
        process_name=r"C:\Windows\System32\gpupdate.exe",
        parent_pid=parent_pid,
        username="SYSTEM",
    )

    assert visible_create is not None
    process_source_times = _process_create_admission_times(planner, emitters, pid)
    assert process_source_times
    assert visible_create == max(process_source_times)
    assert visible_create <= source_bound
    terminate_events = [
        call.args[0]
        for call in emitters["ecar"].emit.call_args_list
        if call.args[0].event_type == "process_terminate"
    ]
    assert len(terminate_events) == 1
    assert terminate_events[0].timestamp == terminate_time


def test_service_delegation_rejects_bounded_caller_before_state_frontier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller whose sampled termination escapes the pass leaves no state mutation."""

    engine = BaselineMixin()
    engine.start_time = _START - timedelta(hours=1)
    engine.state_manager = StateManager()
    engine.activity_generator = Mock()
    engine._service_account_delegation_choices = {
        "svc_ops": {
            "image": r"C:\Program Files\Meridian\OpsAgent\ops-agent.exe",
            "command_line": (r'"C:\Program Files\Meridian\OpsAgent\ops-agent.exe" check --once'),
            "parent_key": "services",
        }
    }
    engine.state_manager.set_current_time(_START - timedelta(minutes=5))
    prior_frontier = engine.state_manager.get_current_time()
    set_current_time = Mock(wraps=engine.state_manager.set_current_time)
    monkeypatch.setattr(engine.state_manager, "set_current_time", set_current_time)

    result = engine._ensure_service_account_delegation_process(
        system=_windows_system(),
        svc_name="svc_ops",
        time=_START,
        sys_pids={"services": 700},
        rng=random.Random(11),
        exclusive_end=_START + timedelta(seconds=1),
    )

    assert result is None
    assert engine.state_manager.get_current_time() == prior_frontier
    set_current_time.assert_not_called()
    engine.activity_generator.generate_system_process.assert_not_called()
    engine.activity_generator.generate_system_process_termination.assert_not_called()


def test_web_affinity_headroom_includes_exact_multipart_serialization_bound() -> None:
    """Multipart framing and the largest client boundary family affect close admission."""

    multipart = {
        "media_type": "multipart/form-data",
        "parts": [
            {
                "name": "archive",
                "body_len": 1_000_000_000,
                "filename": "archive.bin",
                "detected_mime_type": "application/octet-stream",
            }
        ],
    }
    profile = WebRequestProfile(
        routes=[
            WebRouteProfile(
                path="/upload",
                methods={"POST": WeightedHttpMethodProfile(request_multipart=multipart)},
            )
        ]
    )
    spec = profile.routes[0].methods["POST"].request_multipart
    assert spec is not None
    body_bound = max(
        build_http_multipart_context(
            spec,
            stable_key="baseline-affinity-headroom",
            client_family=family,
        ).body_len
        for family in ("browser", "curl", "generic")
    )
    expected = max(
        _BASELINE_BROWSER_CLOSE_HEADROOM.total_seconds(),
        math.ceil(http_response_parent_duration_floor(body_bound) + 12.0),
    )

    assert BaselineMixin._baseline_multipart_profile_body_bound(spec) == body_bound
    assert BaselineMixin._baseline_web_affinity_headroom_seconds(profile) == expected
    assert expected > _BASELINE_BROWSER_CLOSE_HEADROOM.total_seconds()


def test_failed_logon_owner_rejects_post_normalization_cutoff_without_mutation() -> None:
    """Interactive cadence normalization cannot leak an event at the exclusive end."""

    generator, state, emitters = _activity_generator()
    system = _windows_system()
    user = _user()
    generator.generate_failed_logon(user, system, _START, logon_type=2)
    generator.generate_failed_logon(
        user,
        system,
        _START + timedelta(seconds=3),
        logon_type=2,
    )
    before_frontier = state.get_current_time()
    before_events = len(emitters["windows_event_security"].emit.call_args_list)

    generator.generate_failed_logon(
        user,
        system,
        _START + timedelta(seconds=4),
        logon_type=2,
        exclusive_end=_START + timedelta(seconds=5),
    )

    key = (system.hostname.lower(), user.username, 2, "-")
    assert generator._failed_logon_attempt_times.get(key) == (
        _START,
        _START + timedelta(seconds=3),
    )
    assert generator._failed_logon_attempt_pending == {}
    assert state.get_current_time() == before_frontier
    assert len(emitters["windows_event_security"].emit.call_args_list) == before_events


def test_terminal_failed_logon_burst_keeps_later_nonmonotonic_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An out-of-window middle candidate cannot terminate a nonmonotonic burst scan."""

    user = _user()
    system = _windows_system()
    engine = BaselineMixin()
    engine.start_time = _START
    engine.end_time = _START + timedelta(seconds=10)
    engine.activity_generator = SimpleNamespace(
        timing_runtime=object(),
        generate_failed_logon=Mock(),
        generate_logon=Mock(),
    )
    engine.scenario = SimpleNamespace(
        baseline_activity=SimpleNamespace(suspicious_noise="high"),
        environment=SimpleNamespace(
            users=[user],
            systems=[system],
            domain="example.test",
        ),
        personas=[],
    )
    rng = SimpleNamespace(randint=Mock(side_effect=[2, 8, 2, 3]))
    monkeypatch.setattr(baseline_module, "_get_rng", lambda: rng)
    monkeypatch.setattr(baseline_module, "get_suspicious_event_count", lambda *_args: 1)
    monkeypatch.setattr(
        baseline_module,
        "pick_suspicious_pattern",
        lambda *_args: {"type": "failed_logon_burst"},
    )
    monkeypatch.setattr(
        baseline_module,
        "generate_failed_logon_burst",
        lambda *_args: {
            "user": user,
            "system": system,
            "time": _START + timedelta(seconds=5),
            "num_failures": 3,
        },
    )

    engine._generate_suspicious_noise(_START)

    fail_calls = engine.activity_generator.generate_failed_logon.call_args_list
    assert [call.kwargs["time"] for call in fail_calls] == [
        _START + timedelta(seconds=5),
        _START + timedelta(seconds=9),
    ]
    assert all(call.kwargs["exclusive_end"] == engine.end_time for call in fail_calls)
    assert rng.randint.call_count == 4
