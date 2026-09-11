# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused generator regressions for terminal lifecycle admission."""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

import evidenceforge.generation.activity.generator as generator_module
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.observation import ObservationPolicy
from evidenceforge.generation.actions.auth_session import (
    FailedLogonRequest,
    MachineAccountLogonRequest,
)
from evidenceforge.generation.actions.linux_sudo_session import LinuxSudoSessionRequest
from evidenceforge.generation.actions.process_execution import (
    ProcessExecutionActionBundle,
    ProcessExecutionRequest,
)
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.windows_auth_realism import (
    machine_account_authentication_close_bound_seconds,
    remote_auth_transport_max_duration_seconds,
)
from evidenceforge.generation.emitters.cisco_asa import CiscoAsaEmitter
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.syslog import SyslogEmitter
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
from evidenceforge.generation.emitters.windows import WindowsEventEmitter
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models import System, User

_START = datetime(2024, 3, 18, 12, tzinfo=UTC)


def _user(username: str = "alice") -> User:
    return User(
        username=username,
        full_name=username.title(),
        email=f"{username}@example.test",
    )


def _windows_system(hostname: str = "WKS-01", ip: str = "10.0.10.10") -> System:
    return System(
        hostname=hostname,
        ip=ip,
        os="Windows 11",
        type="workstation",
    )


def _linux_system(hostname: str = "LNX-01", ip: str = "10.0.20.10") -> System:
    return System(
        hostname=hostname,
        ip=ip,
        os="Ubuntu 24.04",
        type="workstation",
    )


def _mail_system() -> System:
    return System(
        hostname="MAIL-01",
        ip="10.0.20.25",
        os="Windows Server 2022",
        type="server",
        services=["owa", "exchange"],
        roles=["mail_server"],
    )


def _generator(
    *,
    profile: str = "complete",
    reference_time: datetime | None = None,
) -> tuple[ActivityGenerator, StateManager, dict[str, Mock]]:
    state = StateManager()
    emitters = {
        name: Mock()
        for name in (
            "windows_event_security",
            "windows_event_sysmon",
            "ecar",
            "zeek_conn",
            "cisco_asa",
            "syslog",
        )
    }
    emitter_types = {
        "windows_event_security": WindowsEventEmitter,
        "windows_event_sysmon": SysmonEventEmitter,
        "ecar": EcarEmitter,
        "zeek_conn": ZeekEmitter,
        "cisco_asa": CiscoAsaEmitter,
        "syslog": SyslogEmitter,
    }
    for name, emitter in emitters.items():
        real_emitter = object.__new__(emitter_types[name])
        emitter.can_handle.side_effect = real_emitter.can_handle
    timing_runtime = TimingRuntime(reference_time=reference_time or _START)
    source_timing_planner = SourceTimingPlanner(
        clock_profile_name=profile,
        timing_runtime=timing_runtime,
    )
    dispatcher = EventDispatcher(
        state_manager=state,
        emitters=emitters,
        observation_policy=ObservationPolicy(profile),
        timing_runtime=timing_runtime,
        source_timing_planner=source_timing_planner,
    )
    generator = ActivityGenerator(
        state,
        emitters,
        dispatcher=dispatcher,
        timing_runtime=timing_runtime,
        source_timing_planner=source_timing_planner,
        generation_window_start=_START - timedelta(hours=1),
        generation_window_end=_START + timedelta(hours=1),
    )
    return generator, state, emitters


def _failed_logon_headroom(
    generator: ActivityGenerator,
    *,
    user: User,
    system: System,
    logon_type: int,
    source_ip: str | None,
    dc_system: System | None = None,
) -> timedelta:
    request = FailedLogonRequest(
        user=user,
        system=system,
        time=_START,
        logon_type=logon_type,
        source_ip=source_ip,
        dc_system=dc_system,
    )
    local_logon = logon_type in (2, 5, 7, 11) or source_ip == system.ip
    normalized_source = "-" if local_logon else source_ip or system.ip
    return generator._failed_logon_completion_headroom(
        request=request,
        source_ip=normalized_source,
        auth_source_ip=normalized_source,
    )


def _machine_account_headroom(
    generator: ActivityGenerator,
    *,
    source_ip: str,
    dc_ip: str,
) -> timedelta:
    transport = timedelta(
        seconds=remote_auth_transport_max_duration_seconds(
            source="machine_account_logon",
            outcome="success",
        ),
    )
    endpoint_clock = generator._source_timing_planner.endpoint_clock_positive_headroom(
        _START + timedelta(seconds=30),
        "windows",
    )
    sensor = generator._network_sensor_close_positive_headroom(
        canonical_time=_START + transport,
        src_ip=source_ip,
        dst_ip=dc_ip,
        protocol="tcp",
        conn_states=("SF",),
        payload_bytes=1,
    )
    return timedelta(
        seconds=machine_account_authentication_close_bound_seconds(
            endpoint_clock_headroom_seconds=endpoint_clock.total_seconds(),
            network_sensor_headroom_seconds=sensor.total_seconds(),
        ),
    )


def _emitted_source_times(
    generator: ActivityGenerator,
    emitters: dict[str, Mock],
) -> list[datetime]:
    times: list[datetime] = []
    for format_name, emitter in emitters.items():
        for call in emitter.emit.call_args_list:
            if not call.args:
                continue
            event = call.args[0]
            times.append(generator._source_timing_planner.admission_time(event, format_name))
    return times


def _emitted_process_create_source_times(
    generator: ActivityGenerator,
    emitters: dict[str, Mock],
) -> list[datetime]:
    """Return actual admitted timestamps for process-create rows only."""

    times: list[datetime] = []
    for format_name, emitter in emitters.items():
        for call in emitter.emit.call_args_list:
            if not call.args or call.args[0].event_type not in {
                "process_create",
                "session_process_create",
                "system_process_create",
            }:
                continue
            times.append(generator._source_timing_planner.admission_time(call.args[0], format_name))
    return times


def _register_windows_service_parents(
    generator: ActivityGenerator,
    state: StateManager,
    system: System,
) -> None:
    state.set_current_time(_START - timedelta(hours=1))
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


def _process_state_snapshot(state: StateManager, hostname: str) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            process.pid,
            process.parent_pid,
            process.image,
            process.command_line,
            process.start_time,
            process.last_activity_time,
        )
        for process in state.get_processes_on_system(hostname)
    )


def test_terminal_request_deadlines_preserve_legacy_positional_source() -> None:
    """Appending deadline fields cannot silently reinterpret positional source callers."""

    user = _user()
    system = _windows_system()
    failed = FailedLogonRequest(user, system, _START, 3, "10.0.10.20", None, None, "legacy")
    machine = MachineAccountLogonRequest(
        "WKS-01",
        "WKS-01$",
        "DC-01",
        "10.0.10.10",
        "10.0.20.5",
        _START,
        "EXAMPLE",
        "legacy",
    )
    sudo = LinuxSudoSessionRequest(
        System(hostname="LNX-01", ip="10.0.20.10", os="Ubuntu 24.04", type="server"),
        _START,
        "alice : TTY=pts/1 ; COMMAND=/usr/bin/id",
        "alice",
        1000,
        timedelta(seconds=1),
        "legacy",
    )
    process = ProcessExecutionRequest(
        user,
        system,
        _START,
        "0xabc",
        r"C:\Windows\System32\cmd.exe",
        "cmd.exe /c whoami",
        4,
        False,
        False,
        False,
        True,
        True,
        "",
        "",
        None,
        (),
        "legacy",
    )

    assert failed.source == machine.source == sudo.source == process.source == "legacy"
    assert failed.exclusive_end is None
    assert machine.exclusive_end is None
    assert sudo.latest_end is None
    assert process.reuse_intent is None


def test_endpoint_clock_positive_headroom_includes_long_horizon_drift() -> None:
    """The admission bound projects drift from the runtime reference, not only offset."""

    reference_time = _START - timedelta(days=3650)
    generator, _state, _emitters = _generator(
        profile="messy_collection",
        reference_time=reference_time,
    )
    elapsed_seconds = (_START - reference_time).total_seconds()

    assert generator._source_timing_planner.endpoint_clock_positive_headroom(
        _START,
        "windows",
    ) == timedelta(
        milliseconds=7800,
        microseconds=elapsed_seconds * 35,
    )


def test_system_process_rejects_before_exact_runtime_source_bound_without_mutation() -> None:
    """A finalized runtime source bound rejects before child state or evidence."""

    generator, state, emitters = _generator()
    system = _windows_system()
    parent_pid = generator.generate_system_process(
        system=system,
        time=_START,
        process_name=r"C:\Windows\System32\services.exe",
        command_line="services.exe",
    )
    parent = state.get_process(system.hostname, parent_pid)
    parent_visible = generator._process_source_frontier_or_bound(
        system=system,
        pid=parent_pid,
    )
    assert parent is not None
    assert parent_visible is not None
    child_time = parent.start_time + timedelta(microseconds=1)
    assert child_time <= parent_visible
    deadline = generator._process_create_source_bound(
        system=system,
        canonical_time=child_time,
        parent_source_time=parent_visible,
    ) - timedelta(microseconds=1)

    frontier_before = state.get_current_time()
    processes_before = tuple(state.get_processes_on_system(system.hostname))
    emitted_before = {name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()}

    child_pid = generator.generate_system_process(
        system=system,
        time=child_time,
        process_name=r"C:\Windows\System32\gpupdate.exe",
        command_line="gpupdate.exe /force",
        parent_pid=parent_pid,
        source_visible_by=deadline,
    )

    assert child_pid == 0
    assert state.get_current_time() == frontier_before
    assert tuple(state.get_processes_on_system(system.hostname)) == processes_before
    assert {
        name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()
    } == emitted_before


def test_system_process_accepts_exact_runtime_source_bound() -> None:
    """The inclusive source deadline admits the conservative finalized runtime bound."""

    generator, state, emitters = _generator()
    system = _windows_system()
    parent_pid = generator.generate_system_process(
        system=system,
        time=_START,
        process_name=r"C:\Windows\System32\services.exe",
        command_line="services.exe",
    )
    parent = state.get_process(system.hostname, parent_pid)
    parent_visible = generator._process_source_frontier_or_bound(
        system=system,
        pid=parent_pid,
    )
    assert parent is not None
    assert parent_visible is not None
    child_time = parent.start_time + timedelta(microseconds=1)
    deadline = generator._process_create_source_bound(
        system=system,
        canonical_time=child_time,
        parent_source_time=parent_visible,
    )

    child_pid = generator.generate_system_process(
        system=system,
        time=child_time,
        process_name=r"C:\Windows\System32\gpupdate.exe",
        command_line="gpupdate.exe /force",
        parent_pid=parent_pid,
        source_visible_by=deadline,
    )

    assert child_pid > 0
    child_visible = generator.process_source_create_time(system.hostname, child_pid)
    assert child_visible is not None
    assert max(_emitted_process_create_source_times(generator, emitters)) <= deadline
    assert child_visible <= deadline


def test_process_source_bound_handles_deep_parent_chain_iteratively() -> None:
    """A process chain deeper than Python recursion remains bounded and resolvable."""

    generator, state, _emitters = _generator()
    system = _linux_system()
    parent_pid = 0
    depth = 1_105
    for ordinal in range(depth):
        started_at = _START + timedelta(microseconds=ordinal)
        state.set_current_time(started_at)
        pid = 20_000 + ordinal
        state.register_process(
            system=system.hostname,
            pid=pid,
            parent_pid=parent_pid,
            image=f"/usr/bin/process-{ordinal}",
            command_line=f"process-{ordinal}",
            username="root",
            integrity_level="System",
            os_category="linux",
            start_time=started_at,
        )
        parent_pid = pid

    bound = generator.process_source_create_bound(system, parent_pid)

    assert bound is not None
    assert bound > _START
    assert len(generator._process_source_create_bounds) == depth


def test_process_source_bound_survives_parent_termination_and_retention() -> None:
    """A finalized child keeps its exact bound after its parent identity expires."""

    generator, state, _emitters = _generator()
    system = _windows_system()
    state.set_current_time(_START)
    parent_pid = 1000
    state.register_process(
        system=system.hostname,
        pid=parent_pid,
        parent_pid=0,
        image=r"C:\Windows\System32\services.exe",
        command_line="services.exe",
        username="SYSTEM",
        integrity_level="System",
        os_category="windows",
        start_time=_START,
    )
    child_pid = generator.generate_system_process(
        system=system,
        time=_START + timedelta(milliseconds=1),
        process_name=r"C:\Windows\System32\taskhostw.exe",
        command_line="taskhostw.exe",
        parent_pid=parent_pid,
    )
    child_identity = state.get_process_identity(system.hostname, child_pid)
    assert child_identity is not None
    child_key = (
        system.hostname,
        child_pid,
        child_identity.started_at,
        child_identity.object_id,
    )
    frozen_bound = generator._process_source_create_bounds[child_key]

    parent_end = _START + timedelta(seconds=1)
    state.set_current_time(parent_end)
    assert state.end_process(system.hostname, parent_pid, parent_end)
    child_end = _START + timedelta(minutes=30)
    state.set_current_time(child_end)
    assert state.end_process(system.hostname, child_pid, child_end)
    retention_cutoff = parent_end + timedelta(hours=48, minutes=1)
    state.set_current_time(retention_cutoff)
    generator.advance_process_state_watermark(retention_cutoff)

    assert state.get_process_identity(system.hostname, parent_pid) is None
    assert state.get_process_identity(system.hostname, child_pid) == child_identity
    assert generator.process_source_create_bound(system, child_pid) == frozen_bound

    final_cutoff = child_end + timedelta(hours=49)
    state.set_current_time(final_cutoff)
    generator.advance_process_state_watermark(final_cutoff)

    assert state.get_process_identity(system.hostname, child_pid) is None
    assert child_key not in generator._process_source_create_bounds


def test_profiled_worker_rejects_before_new_manager_and_accepts_exact_deadline() -> None:
    """A bounded profiled family creates neither member unless both source views fit."""

    generator, state, emitters = _generator(profile="messy_collection")
    system = _mail_system()
    _register_windows_service_parents(generator, state, system)
    worker_image = r"C:\Windows\System32\inetsrv\w3wp.exe"
    worker_command = r'C:\Windows\System32\inetsrv\w3wp.exe -ap "MSExchangeOWAAppPool"'
    worker_source_bound = generator._process_create_source_bound(
        system=system,
        canonical_time=_START,
    )
    processes_before = _process_state_snapshot(state, system.hostname)
    frontier_before = state.get_current_time()

    rejected_pid = generator.generate_system_process(
        system=system,
        time=_START,
        process_name=worker_image,
        command_line=worker_command,
        parent_pid=500,
        username="SYSTEM",
        source_visible_by=worker_source_bound - timedelta(microseconds=1),
    )

    assert rejected_pid == 0
    assert state.get_current_time() == frontier_before
    assert _process_state_snapshot(state, system.hostname) == processes_before
    assert all(not emitter.emit.called for emitter in emitters.values())

    worker_pid = generator.generate_system_process(
        system=system,
        time=_START,
        process_name=worker_image,
        command_line=worker_command,
        parent_pid=500,
        username="SYSTEM",
        source_visible_by=worker_source_bound,
    )

    worker = state.get_process(system.hostname, worker_pid)
    assert worker is not None
    assert worker.parent_pid not in {0, 4, 500}
    manager_visible = generator.process_source_create_time(system.hostname, worker.parent_pid)
    worker_visible = generator.process_source_create_time(system.hostname, worker_pid)
    assert manager_visible is not None
    assert manager_visible <= worker_source_bound - timedelta(milliseconds=1)
    assert worker_visible is not None
    assert worker_visible <= worker_source_bound
    assert max(_emitted_process_create_source_times(generator, emitters)) <= worker_source_bound


def test_profiled_worker_reuse_rejects_late_cached_frontier_without_mutation() -> None:
    """A cached worker after the source deadline cannot be returned or touched."""

    generator, state, emitters = _generator(profile="messy_collection")
    system = _mail_system()
    _register_windows_service_parents(generator, state, system)
    worker_image = r"C:\Windows\System32\inetsrv\w3wp.exe"
    worker_command = r'C:\Windows\System32\inetsrv\w3wp.exe -ap "MSExchangeOWAAppPool"'
    worker_pid = generator.generate_system_process(
        system=system,
        time=_START,
        process_name=worker_image,
        command_line=worker_command,
        parent_pid=500,
        username="SYSTEM",
    )
    worker_visible = generator.process_source_create_time(system.hostname, worker_pid)
    assert worker_visible is not None
    assert worker_visible == max(_emitted_process_create_source_times(generator, emitters))
    deadline = worker_visible - timedelta(microseconds=1)
    assert _START + timedelta(milliseconds=1) <= deadline
    processes_before = _process_state_snapshot(state, system.hostname)
    frontier_before = state.get_current_time()
    emitted_before = {name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()}

    reused_pid = generator.generate_system_process(
        system=system,
        time=_START + timedelta(milliseconds=1),
        process_name=worker_image,
        command_line=worker_command,
        parent_pid=500,
        username="SYSTEM",
        source_visible_by=deadline,
    )

    assert reused_pid == 0
    assert state.get_current_time() == frontier_before
    assert _process_state_snapshot(state, system.hostname) == processes_before
    assert {
        name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()
    } == emitted_before


def test_profiled_worker_singleton_conflict_rejects_before_manager_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A late host-singleton worker cannot leave a newly published profile manager."""

    generator, state, emitters = _generator(profile="messy_collection")
    system = _mail_system()
    _register_windows_service_parents(generator, state, system)
    worker_image = r"C:\Windows\System32\inetsrv\w3wp.exe"
    worker_command = r'C:\Windows\System32\inetsrv\w3wp.exe -ap "MSExchangeOWAAppPool"'
    singleton_pid = generator.generate_system_process(
        system=system,
        time=_START,
        process_name=worker_image,
        command_line=worker_command,
        parent_pid=500,
        username="SYSTEM",
        _profiled_service_bypass=True,
        _skip_singleton_reuse=True,
    )
    singleton_visible = generator.process_source_create_time(system.hostname, singleton_pid)
    assert singleton_visible is not None
    assert singleton_visible == max(_emitted_process_create_source_times(generator, emitters))
    deadline = singleton_visible - timedelta(microseconds=1)
    request_time = _START + timedelta(milliseconds=1)
    assert request_time <= deadline
    monkeypatch.setattr(
        "evidenceforge.generation.activity.system_processes.get_windows_singleton_service_paths",
        lambda: {
            "w3wp.exe": {worker_image.replace("/", "\\").lower()},
        },
    )
    processes_before = _process_state_snapshot(state, system.hostname)
    frontier_before = state.get_current_time()
    retained_before = {hostname: dict(pids) for hostname, pids in generator._system_pids.items()}
    emitted_before = {name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()}

    rejected_pid = generator.generate_system_process(
        system=system,
        time=request_time,
        process_name=worker_image,
        command_line=worker_command,
        parent_pid=500,
        username="SYSTEM",
        source_visible_by=deadline,
    )

    assert rejected_pid == 0
    assert state.get_current_time() == frontier_before
    assert _process_state_snapshot(state, system.hostname) == processes_before
    assert generator._system_pids == retained_before
    assert {
        name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()
    } == emitted_before


def test_system_service_singleton_reuse_rejects_late_frontier_without_mutation() -> None:
    """A late cached spooler cannot bypass a bounded system-process request."""

    generator, state, emitters = _generator(profile="messy_collection")
    system = _windows_system()
    _register_windows_service_parents(generator, state, system)
    image = r"C:\Windows\System32\spoolsv.exe"
    pid = generator.generate_system_process(
        system=system,
        time=_START,
        process_name=image,
        command_line="spoolsv.exe",
        parent_pid=500,
    )
    visible = generator.process_source_create_time(system.hostname, pid)
    assert visible is not None
    assert visible == max(_emitted_process_create_source_times(generator, emitters))
    deadline = visible - timedelta(microseconds=1)
    assert _START + timedelta(milliseconds=1) <= deadline
    processes_before = _process_state_snapshot(state, system.hostname)
    frontier_before = state.get_current_time()
    emitted_before = {name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()}

    reused_pid = generator.generate_system_process(
        system=system,
        time=_START + timedelta(milliseconds=1),
        process_name=image,
        command_line="spoolsv.exe",
        parent_pid=500,
        source_visible_by=deadline,
    )

    assert reused_pid == 0
    assert state.get_current_time() == frontier_before
    assert _process_state_snapshot(state, system.hostname) == processes_before
    assert {
        name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()
    } == emitted_before


def test_uwp_rejects_post_session_actor_shift_before_process_planning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bounded UWP launch admits only its full runtime source frontier."""

    generator, state, emitters = _generator()
    system = _windows_system()
    user = _user()
    state.set_current_time(_START - timedelta(hours=1))
    logon_id = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        session_kind="interactive",
        start_time=_START,
    )
    state.register_process(
        system=system.hostname,
        pid=1000,
        parent_pid=0,
        image=r"C:\Windows\explorer.exe",
        command_line="explorer.exe",
        username=user.username,
        integrity_level="Medium",
        os_category="windows",
        start_time=_START - timedelta(minutes=1),
        logon_id=logon_id,
    )
    session = state.get_session(logon_id)
    assert session is not None
    session.explorer_pid = 1000
    session.process_tree_root = 1000
    image = r"C:\Windows\System32\backgroundTaskHost.exe"
    command = "backgroundTaskHost.exe -ServerName:App.AppX"
    session_user = generator._user_model_for_username(user.username)
    actor = generator._prepare_process_effect_actor(
        ProcessExecutionRequest(
            user=session_user,
            system=system,
            time=_START,
            logon_id=logon_id,
            process_name=image,
            command_line=command,
            parent_pid=1000,
            allow_existing_browser_reuse=False,
            source_visible_by=_START,
        )
    )
    assert actor.started_at > _START
    parent_source_time = generator._process_source_frontier_or_bound(
        system=system,
        pid=1000,
    )
    source_bound = generator._process_create_source_bound(
        system=system,
        canonical_time=actor.started_at,
        parent_source_time=parent_source_time,
    )
    assert source_bound > actor.started_at
    processes_before = _process_state_snapshot(state, system.hostname)
    frontier_before = state.get_current_time()
    emitted_before = {name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()}
    side_effect_planner = Mock(wraps=generator._plan_process_execution_side_effects)
    monkeypatch.setattr(
        generator,
        "_plan_process_execution_side_effects",
        side_effect_planner,
    )

    rejected_pid = generator.generate_system_process(
        system=system,
        time=_START,
        process_name=image,
        command_line=command,
        parent_pid=1000,
        source_visible_by=_START,
    )

    assert rejected_pid == 0
    assert not side_effect_planner.called
    assert state.get_current_time() == frontier_before
    assert _process_state_snapshot(state, system.hostname) == processes_before
    assert {
        name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()
    } == emitted_before

    near_bound_pid = generator.generate_system_process(
        system=system,
        time=_START,
        process_name=image,
        command_line=command,
        parent_pid=1000,
        source_visible_by=source_bound - timedelta(microseconds=1),
    )

    assert near_bound_pid == 0
    assert not side_effect_planner.called
    assert state.get_current_time() == frontier_before
    assert _process_state_snapshot(state, system.hostname) == processes_before
    assert {
        name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()
    } == emitted_before

    accepted_pid = generator.generate_system_process(
        system=system,
        time=_START,
        process_name=image,
        command_line=command,
        parent_pid=1000,
        source_visible_by=source_bound,
    )

    assert accepted_pid > 0
    assert side_effect_planner.called
    accepted = state.get_process(system.hostname, accepted_pid)
    accepted_visible = generator.process_source_create_time(system.hostname, accepted_pid)
    assert accepted is not None
    assert accepted.start_time == actor.started_at
    assert accepted_visible is not None
    assert accepted_visible <= source_bound
    assert max(_emitted_process_create_source_times(generator, emitters)) <= source_bound


def test_uwp_overlay_singleton_reuse_rejects_without_duplicate_or_activity_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An overlay-defined singleton after the deadline rejects the whole UWP request."""

    monkeypatch.setattr(
        "evidenceforge.generation.activity.application_catalog.is_singleton_application_image",
        lambda image, _os_category: image.lower().endswith("backgroundtaskhost.exe"),
    )
    generator, state, emitters = _generator(profile="messy_collection")
    system = _windows_system()
    user = _user()
    state.set_current_time(_START - timedelta(minutes=10))
    logon_id = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        session_kind="interactive",
        start_time=_START - timedelta(minutes=10),
    )
    state.set_current_time(_START - timedelta(minutes=1))
    state.register_process(
        system=system.hostname,
        pid=1000,
        parent_pid=0,
        image=r"C:\Windows\explorer.exe",
        command_line="explorer.exe",
        username=user.username,
        integrity_level="Medium",
        os_category="windows",
        logon_id=logon_id,
    )
    session = state.get_session(logon_id)
    assert session is not None
    session.explorer_pid = 1000
    session.process_tree_root = 1000
    image = r"C:\Windows\System32\backgroundTaskHost.exe"
    command = "backgroundTaskHost.exe -ServerName:App.AppX"
    pid = generator.generate_system_process(
        system=system,
        time=_START,
        process_name=image,
        command_line=command,
        parent_pid=1000,
    )
    visible = generator.process_source_create_time(system.hostname, pid)
    canonical_bound = generator.process_source_create_bound(system, pid)
    assert visible is not None
    assert canonical_bound is not None
    assert canonical_bound >= visible
    assert visible == max(_emitted_process_create_source_times(generator, emitters))
    deadline = canonical_bound - timedelta(microseconds=1)
    assert _START + timedelta(milliseconds=1) <= deadline
    processes_before = _process_state_snapshot(state, system.hostname)
    frontier_before = state.get_current_time()
    emitted_before = {name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()}

    reused_pid = generator.generate_system_process(
        system=system,
        time=_START + timedelta(milliseconds=1),
        process_name=image,
        command_line=command,
        parent_pid=1000,
        source_visible_by=deadline,
    )

    assert reused_pid == 0
    assert state.get_current_time() == frontier_before
    assert _process_state_snapshot(state, system.hostname) == processes_before
    assert {
        name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()
    } == emitted_before

    reused_pid = generator.generate_system_process(
        system=system,
        time=_START + timedelta(milliseconds=1),
        process_name=image,
        command_line=command,
        parent_pid=1000,
        source_visible_by=canonical_bound,
    )

    assert reused_pid == pid
    assert len(state.get_processes_on_system(system.hostname)) == len(processes_before)
    assert {
        name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()
    } == emitted_before
    reused = state.get_process(system.hostname, pid)
    assert reused is not None
    assert reused.last_activity_time is not None
    assert reused.last_activity_time >= _START + timedelta(milliseconds=1)


def test_sudo_missing_shell_rejects_immediate_session_before_mutation() -> None:
    """A just-started shell bootstrap cannot mutate before its readiness ceiling fits."""

    generator, state, emitters = _generator()
    system = System(
        hostname="LNX-01",
        ip="10.0.20.10",
        os="Ubuntu 24.04",
        type="server",
    )
    user = _user("analyst")
    state.set_current_time(_START - timedelta(microseconds=1))
    logon_id = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=_START - timedelta(microseconds=1),
        session_kind="interactive",
    )
    session = state.get_session(logon_id)
    assert session is not None
    assert session.session_shell_pid is None

    frontier_before = state.get_current_time()
    sessions_before = tuple(state.get_sessions_on_system(system.hostname))
    processes_before = tuple(state.get_processes_on_system(system.hostname))
    emitted_before = {name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()}

    sudo_pid, child_pid, _shift, _tty = generator.generate_linux_sudo_processes(
        system=system,
        sudo_time=_START,
        child_time=_START + timedelta(milliseconds=200),
        sudo_user=user.username,
        tty="pts/1",
        command="/usr/bin/id",
        reserve_until=_START + timedelta(seconds=1),
        complete_by=_START + timedelta(seconds=1, milliseconds=50),
        latest_end=_START + timedelta(seconds=9),
        lifecycle_group_id="terminal-sudo-reject",
    )

    assert sudo_pid == 0
    assert child_pid is None
    assert state.get_current_time() == frontier_before
    assert tuple(state.get_sessions_on_system(system.hostname)) == sessions_before
    assert tuple(state.get_processes_on_system(system.hostname)) == processes_before
    assert {
        name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()
    } == emitted_before
    assert generator._linux_sudo_tty_assignments == {}
    assert generator._linux_sudo_tty_owners == {}
    assert generator._linux_sudo_tty_sessions == {}
    assert generator._linux_sudo_tty_available == {}
    assert generator._linux_sudo_tty_keys_by_logon_id == {}


def test_sudo_missing_shell_accepts_when_full_readiness_ceiling_fits() -> None:
    """A missing local shell remains admissible when its complete ceiling fits."""

    generator, state, _emitters = _generator()
    system = System(
        hostname="LNX-01",
        ip="10.0.20.10",
        os="Ubuntu 24.04",
        type="server",
    )
    user = _user("analyst")
    state.set_current_time(_START - timedelta(microseconds=1))
    state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=_START - timedelta(microseconds=1),
        session_kind="interactive",
    )

    sudo_pid, child_pid, _shift, _tty = generator.generate_linux_sudo_processes(
        system=system,
        sudo_time=_START,
        child_time=_START + timedelta(milliseconds=200),
        sudo_user=user.username,
        tty="pts/1",
        command="/usr/bin/id",
        reserve_until=_START + timedelta(seconds=1),
        complete_by=_START + timedelta(seconds=1, milliseconds=50),
        latest_end=_START + timedelta(seconds=11),
        lifecycle_group_id="terminal-sudo-accept",
    )

    assert sudo_pid > 0
    assert child_pid is not None


def test_sudo_missing_ssh_shell_uses_full_bootstrap_and_readiness_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The maximal sshd, bash, and foreground-ready delays are admitted atomically."""

    generator, state, emitters = _generator()
    system = System(
        hostname="LNX-01",
        ip="10.0.20.10",
        os="Ubuntu 24.04",
        type="server",
    )
    user = _user("analyst")
    state.set_current_time(_START - timedelta(minutes=1))
    state.register_process(
        system=system.hostname,
        pid=500,
        parent_pid=0,
        image="/usr/sbin/sshd",
        command_line="/usr/sbin/sshd -D",
        username="root",
        integrity_level="root",
        os_category="linux",
    )
    generator._system_pids = {system.hostname: {"sshd": 500}}
    session_start = _START - timedelta(microseconds=1)
    state.set_current_time(session_start)
    logon_id = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=10,
        source_ip="10.0.20.99",
        source_port=55000,
        session_kind="ssh",
        start_time=session_start,
    )
    session = state.get_session(logon_id)
    assert session is not None

    stable_seed = generator_module._stable_seed

    def maximum_shell_seed(text: str) -> int:
        if text.startswith("linux_ssh_session_shell:"):
            return 12_599
        if text.startswith("foreground_shell_initial_ready:"):
            return 5_199
        return stable_seed(text)

    monkeypatch.setattr(generator_module, "_stable_seed", maximum_shell_seed)
    complete_by = _START + timedelta(seconds=1, milliseconds=50)
    serialization_ceiling = generator._linux_sudo_foreground_admission_ceiling(
        system=system,
        username=user.username,
        requested_time=_START,
        command="/usr/bin/id",
        session=session,
    )
    latest_fitting_end = complete_by + (serialization_ceiling - _START)
    frontier_before = state.get_current_time()
    processes_before = tuple(
        (process.pid, process.start_time, process.last_activity_time)
        for process in state.get_processes_on_system(system.hostname)
    )
    session_before = (
        session.session_shell_pid,
        session.process_tree_root,
        session.last_activity_time,
    )
    emitted_before = {name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()}

    sudo_pid, child_pid, _shift, _tty = generator.generate_linux_sudo_processes(
        system=system,
        sudo_time=_START,
        child_time=_START + timedelta(milliseconds=200),
        sudo_user=user.username,
        tty="pts/1",
        command="/usr/bin/id",
        reserve_until=_START + timedelta(seconds=1),
        complete_by=complete_by,
        latest_end=latest_fitting_end - timedelta(microseconds=1),
        lifecycle_group_id="terminal-ssh-sudo-reject",
    )

    assert sudo_pid == 0
    assert child_pid is None
    assert state.get_current_time() == frontier_before
    assert (
        tuple(
            (process.pid, process.start_time, process.last_activity_time)
            for process in state.get_processes_on_system(system.hostname)
        )
        == processes_before
    )
    assert (
        session.session_shell_pid,
        session.process_tree_root,
        session.last_activity_time,
    ) == session_before
    assert {
        name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()
    } == emitted_before
    assert generator._linux_sudo_tty_assignments == {}
    assert generator._linux_sudo_tty_owners == {}
    assert generator._linux_sudo_tty_sessions == {}
    assert generator._linux_sudo_tty_available == {}
    assert generator._linux_sudo_tty_keys_by_logon_id == {}

    sudo_pid, child_pid, timing_shift, _tty = generator.generate_linux_sudo_processes(
        system=system,
        sudo_time=_START,
        child_time=_START + timedelta(milliseconds=200),
        sudo_user=user.username,
        tty="pts/1",
        command="/usr/bin/id",
        reserve_until=_START + timedelta(seconds=1),
        complete_by=complete_by,
        latest_end=latest_fitting_end,
        lifecycle_group_id="terminal-ssh-sudo-accept",
    )

    assert sudo_pid > 0
    assert child_pid is not None
    assert timing_shift == serialization_ceiling - _START
    assert complete_by + timing_shift == latest_fitting_end


def test_failed_logon_cadence_shift_recomputes_full_family_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cadence normalization uses the shifted attempt for exact rendered admission."""

    generator, state, emitters = _generator(profile="messy_collection")
    system = _windows_system()
    user = _user()
    generator.generate_failed_logon(
        user=user,
        system=system,
        time=_START,
        logon_type=2,
    )
    key = (system.hostname.lower(), user.username, 2, "-")
    retained_before = generator._failed_logon_attempt_times.get(key)
    assert retained_before == (_START,)
    requested_time = _START + timedelta(seconds=1)
    normalized_time = _START + timedelta(seconds=2)
    request = FailedLogonRequest(
        user=user,
        system=system,
        time=requested_time,
        logon_type=2,
        source_ip=None,
    )
    headroom = generator._failed_logon_completion_headroom(
        request=request,
        source_ip="-",
        auth_source_ip="-",
        attempt_time=normalized_time,
    )
    exact_end = normalized_time + headroom
    frontier_before = state.get_current_time()
    emitted_before = {name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()}
    rng = generator_module._get_rng()
    rng_before = rng.getstate()
    get_rng = Mock(return_value=rng)
    monkeypatch.setattr(generator_module, "_get_rng", get_rng)

    generator.generate_failed_logon(
        user=user,
        system=system,
        time=requested_time,
        logon_type=2,
        exclusive_end=exact_end,
    )

    assert state.get_current_time() == frontier_before
    assert generator._failed_logon_attempt_times.get(key) == retained_before
    assert len(generator._failed_logon_attempt_times) == 1
    assert generator._failed_logon_attempt_pending == {}
    assert {
        name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()
    } == emitted_before
    assert rng.getstate() == rng_before
    get_rng.assert_not_called()

    generator.generate_failed_logon(
        user=user,
        system=system,
        time=requested_time,
        logon_type=2,
        exclusive_end=exact_end + timedelta(microseconds=1),
    )

    assert generator._failed_logon_attempt_times.get(key) == (
        _START,
        normalized_time,
    )
    assert generator._failed_logon_attempt_pending == {}
    source_times = _emitted_source_times(generator, emitters)
    assert source_times
    assert max(source_times) < exact_end + timedelta(microseconds=1)


def test_remote_failed_logon_rejects_transport_tail_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A remote-auth close at the exclusive end suppresses the whole failed attempt."""

    generator, state, emitters = _generator()
    system = _windows_system()
    user = _user()
    close_bound = _failed_logon_headroom(
        generator,
        user=user,
        system=system,
        logon_type=3,
        source_ip="10.0.10.20",
    )
    exclusive_end = _START + close_bound
    frontier_before = state.get_current_time()
    rng = generator_module._get_rng()
    rng_before = rng.getstate()
    get_rng = Mock(return_value=rng)
    monkeypatch.setattr(generator_module, "_get_rng", get_rng)
    cadence_metrics_before = generator._failed_logon_attempt_times.metrics()
    cadence_watermark_before = generator._failed_logon_attempt_times.watermark_seconds
    pending_before = dict(generator._failed_logon_attempt_pending)
    recent_tuples_before = tuple(generator._recent_connection_tuples.items())
    kerberos_ports_before = {
        key: tuple(reservations)
        for key, reservations in generator._kerberos_source_port_reservations.items()
    }

    generator.generate_failed_logon(
        user=user,
        system=system,
        time=_START,
        logon_type=3,
        source_ip="10.0.10.20",
        exclusive_end=exclusive_end,
    )

    assert state.get_current_time() == frontier_before
    assert state.list_open_connections() == []
    assert generator._failed_logon_attempt_pending == pending_before
    assert len(generator._failed_logon_attempt_times) == 0
    assert generator._failed_logon_attempt_times.metrics() == cadence_metrics_before
    assert generator._failed_logon_attempt_times.watermark_seconds == cadence_watermark_before
    assert tuple(generator._recent_connection_tuples.items()) == recent_tuples_before
    assert {
        key: tuple(reservations)
        for key, reservations in generator._kerberos_source_port_reservations.items()
    } == kerberos_ports_before
    assert all(not emitter.emit.called for emitter in emitters.values())
    assert rng.getstate() == rng_before
    get_rng.assert_not_called()


def test_remote_failed_logon_accepts_transport_inside_exclusive_end() -> None:
    """One microsecond beyond the owned maximum admits the complete remote family."""

    generator, state, emitters = _generator()
    system = _windows_system()
    user = _user()
    close_bound = _failed_logon_headroom(
        generator,
        user=user,
        system=system,
        logon_type=3,
        source_ip="10.0.10.20",
    )
    exclusive_end = _START + close_bound + timedelta(microseconds=1)

    generator.generate_failed_logon(
        user=user,
        system=system,
        time=_START,
        logon_type=3,
        source_ip="10.0.10.20",
        exclusive_end=exclusive_end,
    )

    connections = state.list_open_connections()
    assert len(connections) == 1
    assert connections[0].close_time is not None
    assert connections[0].close_time < exclusive_end
    assert emitters["windows_event_security"].emit.called
    assert generator._failed_logon_attempt_pending == {}
    assert len(generator._failed_logon_attempt_times) == 1
    source_times = _emitted_source_times(generator, emitters)
    assert source_times
    assert max(source_times) < exclusive_end


def test_linux_remote_failed_logon_rejects_ssh_close_tail_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The maximum failed-SSH close at the exclusive end rejects before RNG or state."""

    generator, state, emitters = _generator()
    system = System(
        hostname="LNX-01",
        ip="10.0.20.10",
        os="Ubuntu 24.04",
        type="server",
    )
    user = _user("attacker")
    close_bound = _failed_logon_headroom(
        generator,
        user=user,
        system=system,
        logon_type=3,
        source_ip="10.0.20.99",
    )
    frontier_before = state.get_current_time()
    rng = generator_module._get_rng()
    rng_before = rng.getstate()
    get_rng = Mock(return_value=rng)
    monkeypatch.setattr(generator_module, "_get_rng", get_rng)
    cadence_metrics_before = generator._failed_logon_attempt_times.metrics()
    cadence_watermark_before = generator._failed_logon_attempt_times.watermark_seconds
    recent_tuples_before = tuple(generator._recent_connection_tuples.items())
    processes_before = tuple(state.get_processes_on_system(system.hostname))

    generator.generate_failed_logon(
        user=user,
        system=system,
        time=_START,
        logon_type=3,
        source_ip="10.0.20.99",
        exclusive_end=_START + close_bound,
    )

    assert state.get_current_time() == frontier_before
    assert state.list_open_connections() == []
    assert tuple(state.get_processes_on_system(system.hostname)) == processes_before
    assert generator._failed_logon_attempt_pending == {}
    assert len(generator._failed_logon_attempt_times) == 0
    assert generator._failed_logon_attempt_times.metrics() == cadence_metrics_before
    assert generator._failed_logon_attempt_times.watermark_seconds == cadence_watermark_before
    assert tuple(generator._recent_connection_tuples.items()) == recent_tuples_before
    assert generator._kerberos_source_port_reservations == {}
    assert all(not emitter.emit.called for emitter in emitters.values())
    assert rng.getstate() == rng_before
    get_rng.assert_not_called()


def test_linux_remote_failed_logon_accepts_ssh_close_inside_exclusive_end() -> None:
    """One microsecond beyond the failed-SSH maximum admits its complete lifecycle."""

    generator, state, emitters = _generator()
    system = System(
        hostname="LNX-01",
        ip="10.0.20.10",
        os="Ubuntu 24.04",
        type="server",
    )
    user = _user("attacker")
    exclusive_end = (
        _START
        + _failed_logon_headroom(
            generator,
            user=user,
            system=system,
            logon_type=3,
            source_ip="10.0.20.99",
        )
        + timedelta(microseconds=1)
    )

    generator.generate_failed_logon(
        user=user,
        system=system,
        time=_START,
        logon_type=3,
        source_ip="10.0.20.99",
        exclusive_end=exclusive_end,
    )

    connections = state.list_open_connections()
    assert len(connections) == 1
    assert connections[0].close_time is not None
    assert connections[0].close_time < exclusive_end
    syslog_events = [
        call.args[0]
        for call in emitters["syslog"].emit.call_args_list
        if call.args[0].syslog is not None
    ]
    assert syslog_events
    assert max(event.timestamp for event in syslog_events) < exclusive_end
    assert generator._failed_logon_attempt_pending == {}
    assert len(generator._failed_logon_attempt_times) == 1
    source_times = _emitted_source_times(generator, emitters)
    assert source_times
    assert max(source_times) < exclusive_end


@pytest.mark.parametrize("os_category", ["windows", "linux"])
def test_failed_logon_messy_profile_bound_covers_every_rendered_family(
    os_category: str,
) -> None:
    """Clock drift, provider latency, sensor projection, and syslog delay fit the bound."""

    reference_time = _START - timedelta(days=3650)
    if os_category == "windows":
        system = _windows_system()
        source_ip = "10.0.10.20"
    else:
        system = System(
            hostname="LNX-01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
        )
        source_ip = "10.0.20.99"
    user = _user("attacker")

    rejected, rejected_state, rejected_emitters = _generator(
        profile="messy_collection",
        reference_time=reference_time,
    )
    rejected_bound = _failed_logon_headroom(
        rejected,
        user=user,
        system=system,
        logon_type=3,
        source_ip=source_ip,
    )
    rejected.generate_failed_logon(
        user=user,
        system=system,
        time=_START,
        logon_type=3,
        source_ip=source_ip,
        exclusive_end=_START + rejected_bound,
    )

    assert rejected_state.list_open_connections() == []
    assert rejected_state.get_processes_on_system(system.hostname) == []
    assert all(not emitter.emit.called for emitter in rejected_emitters.values())

    accepted, _accepted_state, accepted_emitters = _generator(
        profile="messy_collection",
        reference_time=reference_time,
    )
    accepted_bound = _failed_logon_headroom(
        accepted,
        user=user,
        system=system,
        logon_type=3,
        source_ip=source_ip,
    )
    exclusive_end = _START + accepted_bound + timedelta(microseconds=1)
    accepted.generate_failed_logon(
        user=user,
        system=system,
        time=_START,
        logon_type=3,
        source_ip=source_ip,
        exclusive_end=exclusive_end,
    )

    source_times = _emitted_source_times(accepted, accepted_emitters)
    assert source_times
    assert max(source_times) < exclusive_end


def test_failed_logon_rejects_dc_validation_tail_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The maximum DC 4776 delay participates in exclusive terminal admission."""

    generator, state, emitters = _generator()
    system = _windows_system()
    dc_system = System(
        hostname="DC-01",
        ip="10.0.20.5",
        os="Windows Server 2022",
        type="domain_controller",
    )
    user = _user()
    failed_profile = Mock(side_effect=AssertionError("profile selection must not run"))
    validation_path = Mock(side_effect=AssertionError("validation selection must not run"))
    generator._failed_logon_profile = failed_profile
    generator._failed_logon_validation_path = validation_path
    frontier_before = state.get_current_time()
    rng = generator_module._get_rng()
    rng_before = rng.getstate()
    get_rng = Mock(return_value=rng)
    monkeypatch.setattr(generator_module, "_get_rng", get_rng)
    cadence_metrics_before = generator._failed_logon_attempt_times.metrics()
    cadence_watermark_before = generator._failed_logon_attempt_times.watermark_seconds
    pending_before = dict(generator._failed_logon_attempt_pending)
    recent_tuples_before = tuple(generator._recent_connection_tuples.items())
    kerberos_ports_before = {
        key: tuple(reservations)
        for key, reservations in generator._kerberos_source_port_reservations.items()
    }

    generator.generate_failed_logon(
        user=user,
        system=system,
        time=_START,
        logon_type=2,
        dc_system=dc_system,
        exclusive_end=_START
        + _failed_logon_headroom(
            generator,
            user=user,
            system=system,
            logon_type=2,
            source_ip=None,
            dc_system=dc_system,
        ),
    )

    assert state.get_current_time() == frontier_before
    assert state.list_open_connections() == []
    assert generator._failed_logon_attempt_pending == pending_before
    assert len(generator._failed_logon_attempt_times) == 0
    assert generator._failed_logon_attempt_times.metrics() == cadence_metrics_before
    assert generator._failed_logon_attempt_times.watermark_seconds == cadence_watermark_before
    assert tuple(generator._recent_connection_tuples.items()) == recent_tuples_before
    assert {
        key: tuple(reservations)
        for key, reservations in generator._kerberos_source_port_reservations.items()
    } == kerberos_ports_before
    assert all(not emitter.emit.called for emitter in emitters.values())
    assert rng.getstate() == rng_before
    get_rng.assert_not_called()
    failed_profile.assert_not_called()
    validation_path.assert_not_called()


def test_failed_logon_accepts_dc_validation_inside_exclusive_end() -> None:
    """A DC 4776 child is retained when the complete validation tail fits."""

    generator, _state, emitters = _generator()
    system = _windows_system()
    dc_system = System(
        hostname="DC-01",
        ip="10.0.20.5",
        os="Windows Server 2022",
        type="domain_controller",
    )
    user = _user()
    generator._failed_logon_profile = lambda *_args: {
        "auth_package": "NTLM",
        "logon_process": "NtLmSsp",
        "lm_package": "NTLM V2",
        "process_pid": 736,
        "process_name": r"C:\Windows\System32\lsass.exe",
        "workstation_name": "WKS-02",
        "source_port": 50000,
        "network_port": 445,
        "emit_network_probability": 0.0,
    }
    generator._failed_logon_validation_path = lambda *_args: {
        "emit_4776": True,
        "emit_4771": False,
    }

    generator.generate_failed_logon(
        user=user,
        system=system,
        time=_START,
        logon_type=2,
        dc_system=dc_system,
        exclusive_end=_START
        + _failed_logon_headroom(
            generator,
            user=user,
            system=system,
            logon_type=2,
            source_ip=None,
            dc_system=dc_system,
        )
        + timedelta(microseconds=1),
    )

    event_types = [
        call.args[0].event_type for call in emitters["windows_event_security"].emit.call_args_list
    ]
    assert event_types == ["failed_logon", "ntlm_validation"]
    source_times = _emitted_source_times(generator, emitters)
    assert source_times
    assert max(source_times) < (
        _START
        + _failed_logon_headroom(
            generator,
            user=user,
            system=system,
            logon_type=2,
            source_ip=None,
            dc_system=dc_system,
        )
        + timedelta(microseconds=1)
    )


def test_machine_account_rejects_full_close_bound_before_rng_or_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exact full-family boundary rejects before any machine-auth planning."""

    generator, state, emitters = _generator()
    state.set_current_time(_START - timedelta(minutes=1))
    frontier_before = state.get_current_time()
    preview_logon_id = Mock(side_effect=AssertionError("logon ID preview must not run"))
    monkeypatch.setattr(state, "preview_logon_id", preview_logon_id)
    get_rng = Mock(side_effect=AssertionError("RNG must not be acquired"))
    monkeypatch.setattr(generator_module, "_get_rng", get_rng)
    bound = _machine_account_headroom(
        generator,
        source_ip="10.0.10.10",
        dc_ip="10.0.20.5",
    )

    generator.generate_machine_account_logon(
        hostname="WKS-01",
        machine_username="WKS-01$",
        dc_hostname="DC-01",
        source_ip="10.0.10.10",
        dc_ip="10.0.20.5",
        time=_START,
        domain="EXAMPLE",
        exclusive_end=_START + bound,
    )

    assert state.get_current_time() == frontier_before
    assert state.list_open_connections() == []
    assert state.get_sessions_on_system("DC-01") == []
    assert all(not emitter.emit.called for emitter in emitters.values())
    preview_logon_id.assert_not_called()
    get_rng.assert_not_called()


def test_machine_account_accepts_full_family_inside_exclusive_end() -> None:
    """One microsecond beyond the full owner bound admits machine auth and close."""

    generator, state, emitters = _generator()
    for system in (
        _windows_system(),
        System(
            hostname="DC-01",
            ip="10.0.20.5",
            os="Windows Server 2022",
            type="domain_controller",
        ),
    ):
        generator._ip_to_system[system.ip] = system
    bound = _machine_account_headroom(
        generator,
        source_ip="10.0.10.10",
        dc_ip="10.0.20.5",
    )
    exclusive_end = _START + bound + timedelta(microseconds=1)

    generator.generate_machine_account_logon(
        hostname="WKS-01",
        machine_username="WKS-01$",
        dc_hostname="DC-01",
        source_ip="10.0.10.10",
        dc_ip="10.0.20.5",
        time=_START,
        domain="EXAMPLE",
        exclusive_end=exclusive_end,
    )

    event_types = [
        call.args[0].event_type for call in emitters["windows_event_security"].emit.call_args_list
    ]
    assert "machine_logon" in event_types
    assert "logoff" in event_types
    assert state.get_sessions_on_system("DC-01") == []
    assert all(
        connection.close_time is None or connection.close_time < exclusive_end
        for connection in state.list_open_connections()
    )
    source_times = _emitted_source_times(generator, emitters)
    assert source_times
    assert max(source_times) < exclusive_end

    asa_rows: list[dict[str, object]] = []
    asa = object.__new__(CiscoAsaEmitter)
    asa._sensor_hostnames = ["fw01"]
    asa._segment_config = [
        {"name": "workstations", "cidr": "10.0.10.0/24"},
        {"name": "servers", "cidr": "10.0.20.0/24"},
    ]
    asa._sensor_interfaces = {
        "fw01": {
            "workstations": "inside",
            "servers": "dmz",
            "_default": "outside",
        }
    }
    asa._sensor_security_levels = {}
    asa._vip_to_real_ip = {}
    asa._dispatch = asa_rows.append
    for call in emitters["cisco_asa"].emit.call_args_list:
        asa.emit(call.args[0])

    teardown_times = [
        row["timestamp"] for row in asa_rows if row["msg_id"] in {302014, 302016, 302021}
    ]
    assert teardown_times
    assert all(type(timestamp) is datetime for timestamp in teardown_times)
    assert max(teardown_times) < exclusive_end


def _register_interactive_parent(
    state: StateManager,
    system: System,
    user: User,
) -> str:
    """Register one old interactive session and Explorer parent."""

    state.set_current_time(_START - timedelta(minutes=10))
    logon_id = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=_START - timedelta(minutes=10),
        session_kind="interactive",
    )
    state.register_process(
        system=system.hostname,
        pid=1000,
        parent_pid=4,
        image=r"C:\Windows\explorer.exe",
        command_line="explorer.exe",
        username=user.username,
        integrity_level="Medium",
        os_category="windows",
        start_time=_START - timedelta(minutes=1),
        logon_id=logon_id,
    )
    session = state.get_session(logon_id)
    assert session is not None
    session.explorer_pid = 1000
    session.process_tree_root = 1000
    return logon_id


def test_direct_process_runtime_bound_rejects_before_planning_and_accepts_exactly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Direct process generation admits the complete rendered create frontier."""

    generator, state, emitters = _generator(profile="messy_collection")
    system = _windows_system()
    user = _user()
    logon_id = _register_interactive_parent(state, system, user)
    session = state.get_session(logon_id)
    assert session is not None
    request = ProcessExecutionRequest(
        user=user,
        system=system,
        time=_START,
        logon_id=logon_id,
        process_name=r"C:\Windows\System32\notepad.exe",
        command_line="notepad.exe",
        parent_pid=1000,
        suppress_command_file_effect=True,
        source_visible_by=_START,
    )
    actor = generator._prepare_process_effect_actor(request)
    source_bound = generator._process_create_source_bound(
        system=system,
        canonical_time=actor.started_at,
        parent_source_time=generator._process_source_frontier_or_bound(
            system=system,
            pid=1000,
        ),
        session_source_time=generator_module._session_source_ready_time(session),
    )
    planner = Mock(wraps=generator._plan_process_execution_side_effects)
    monkeypatch.setattr(generator, "_plan_process_execution_side_effects", planner)
    processes_before = _process_state_snapshot(state, system.hostname)
    emitted_before = {name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()}

    rejected_pid = generator.generate_process(
        user=user,
        system=system,
        time=_START,
        logon_id=logon_id,
        process_name=request.process_name,
        command_line=request.command_line,
        parent_pid=1000,
        suppress_command_file_effect=True,
        source_visible_by=source_bound - timedelta(microseconds=1),
    )

    assert rejected_pid == 0
    assert not planner.called
    assert _process_state_snapshot(state, system.hostname) == processes_before
    assert {
        name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()
    } == emitted_before

    pid = generator.generate_process(
        user=user,
        system=system,
        time=_START,
        logon_id=logon_id,
        process_name=request.process_name,
        command_line=request.command_line,
        parent_pid=1000,
        suppress_command_file_effect=True,
        source_visible_by=source_bound,
    )

    assert pid > 0
    actual = _emitted_process_create_source_times(generator, emitters)
    assert actual and max(actual) <= source_bound
    assert generator.process_source_create_time(system.hostname, pid) == max(actual)


def test_direct_process_exact_reuse_and_token_drift_are_fail_closed() -> None:
    """Exact reuse bypasses fresh headroom while an altered identity is rejected."""

    generator, state, emitters = _generator(profile="messy_collection")
    system = _windows_system()
    user = _user()
    logon_id = _register_interactive_parent(state, system, user)
    image = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
    pid = generator.generate_process(
        user=user,
        system=system,
        time=_START,
        logon_id=logon_id,
        process_name=image,
        command_line="OUTLOOK.EXE",
        parent_pid=1000,
        suppress_command_file_effect=True,
    )
    frontier = generator.process_source_create_time(system.hostname, pid)
    canonical_bound = generator.process_source_create_bound(system, pid)
    running = state.get_process(system.hostname, pid)
    assert frontier is not None and canonical_bound is not None and running is not None
    assert canonical_bound >= frontier
    activity_before = running.last_activity_time
    emitted_before = {name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()}

    late_pid = generator.generate_process(
        user=user,
        system=system,
        time=_START + timedelta(milliseconds=1),
        logon_id=logon_id,
        process_name=image,
        command_line="OUTLOOK.EXE",
        parent_pid=1000,
        suppress_command_file_effect=True,
        source_visible_by=canonical_bound - timedelta(microseconds=1),
    )
    assert late_pid == 0
    assert running.last_activity_time == activity_before
    assert (
        generator.generate_process(
            user=user,
            system=system,
            time=_START + timedelta(milliseconds=1),
            logon_id=logon_id,
            process_name=image,
            command_line="OUTLOOK.EXE",
            parent_pid=1000,
            suppress_command_file_effect=True,
            source_visible_by=canonical_bound,
        )
        == pid
    )
    assert {
        name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()
    } == emitted_before

    prepared = generator._preflight_bounded_process_source_deadline(
        ProcessExecutionRequest(
            user=user,
            system=system,
            time=_START + timedelta(milliseconds=2),
            logon_id=logon_id,
            process_name=image,
            command_line="OUTLOOK.EXE",
            parent_pid=1000,
            suppress_command_file_effect=True,
            source_visible_by=canonical_bound,
        )
    )
    assert prepared is not None and prepared.reuse_intent is not None
    running.command_line = "OUTLOOK.EXE /drift"
    drift_activity = running.last_activity_time
    assert ProcessExecutionActionBundle(generator, prepared).execute() == 0
    assert running.last_activity_time == drift_activity


def test_bounded_linux_profiled_worker_does_not_create_missing_parent_anchor() -> None:
    """A bounded profiled Linux worker rejects before fallback systemd creation."""

    generator, state, emitters = _generator(profile="messy_collection")
    system = System(
        hostname="MAIL-LNX",
        ip="10.0.20.30",
        os="Ubuntu 24.04",
        type="server",
        services=["postfix", "smtp"],
    )
    frontier_before = state.get_current_time()
    pid = generator.generate_system_process(
        system=system,
        time=_START,
        process_name="/usr/lib/postfix/sbin/smtpd",
        command_line="smtpd -n smtp -t inet -u",
        parent_pid=0,
        username="postfix",
        source_visible_by=_START,
    )

    assert pid == 0
    assert state.get_current_time() == frontier_before
    assert _process_state_snapshot(state, system.hostname) == ()
    assert not any(emitter.emit.called for emitter in emitters.values())


def test_bounded_linux_visible_shell_rejects_full_chain_without_mutation() -> None:
    """A tight local-shell deadline leaves systemd-user, terminal, and bash absent."""

    generator, state, emitters = _generator(profile="messy_collection")
    system = _linux_system()
    user = _user()
    state.set_current_time(_START - timedelta(hours=1))
    state.register_process(
        system=system.hostname,
        pid=100,
        parent_pid=0,
        image="/usr/lib/systemd/systemd",
        command_line="/usr/lib/systemd/systemd --system",
        username="root",
        integrity_level="root",
        os_category="linux",
        start_time=_START - timedelta(hours=1),
    )
    generator._system_pids = {system.hostname: {"systemd": 100}}
    session_start = _START - timedelta(minutes=10)
    state.set_current_time(session_start)
    logon_id = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=session_start,
        session_kind="interactive",
    )
    session = state.get_session(logon_id)
    assert session is not None
    processes_before = _process_state_snapshot(state, system.hostname)
    frontier_before = state.get_current_time()

    shell_pid = generator.ensure_linux_visible_shell_parent(
        user,
        system,
        _START,
        logon_id,
        session_start,
        source_visible_by=session_start,
    )

    assert shell_pid is None
    assert state.get_current_time() == frontier_before
    assert _process_state_snapshot(state, system.hostname) == processes_before
    assert session.session_shell_pid is None
    assert session.session_user_manager_pid is None
    assert not any(emitter.emit.called for emitter in emitters.values())


def test_bounded_windows_cli_parent_rejects_before_explorer_bootstrap() -> None:
    """A tight CLI deadline leaves the Windows desktop chain untouched."""

    generator, state, emitters = _generator()
    system = _windows_system()
    user = _user()
    _register_windows_service_parents(generator, state, system)
    session_start = _START - timedelta(minutes=10)
    state.set_current_time(session_start)
    logon_id = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=session_start,
        session_kind="interactive",
    )
    session = state.get_session(logon_id)
    assert session is not None
    processes_before = _process_state_snapshot(state, system.hostname)
    history_before = dict(generator._user_process_history)
    frontier_before = state.get_current_time()

    shell_pid = generator._ensure_windows_user_cli_parent(
        system=system,
        user=user,
        session=session,
        child_time=_START,
        candidate_pid=500,
        child_command_line="ssh.exe bob@host",
        source_visible_by=session_start,
    )

    assert shell_pid == 0
    assert state.get_current_time() == frontier_before
    assert _process_state_snapshot(state, system.hostname) == processes_before
    assert generator._user_process_history == history_before
    assert session.explorer_pid is None
    assert session.session_winlogon_pid is None
    assert not session.windows_shell_bootstrapped
    assert not any(emitter.emit.called for emitter in emitters.values())


def test_bounded_windows_ssh_owner_preflights_full_desktop_process_chain() -> None:
    """The Explorer, CLI-shell, and SSH-client chain admits or rejects as one unit."""

    generator, state, emitters = _generator(profile="messy_collection")
    system = _windows_system()
    user = _user()
    _register_windows_service_parents(generator, state, system)
    session_start = _START - timedelta(minutes=10)
    logon_id = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=session_start,
        session_kind="interactive",
    )
    session = state.get_session(logon_id)
    assert session is not None
    processes_before = _process_state_snapshot(state, system.hostname)
    history_before = dict(generator._user_process_history)
    frontier_before = state.get_current_time()

    rejected = generator._ensure_user_connection_owner_process(
        source_system=system,
        time=_START,
        service="ssh",
        dst_port=22,
        os_category="windows",
        hostname="lnx-target.example.test",
        ssh_attempted_username=user.username,
        source_visible_by=_START,
        session_info=(user, session),
    )

    assert rejected == (-1, None)
    assert state.get_current_time() == frontier_before
    assert _process_state_snapshot(state, system.hostname) == processes_before
    assert generator._user_process_history == history_before
    assert session.explorer_pid is None
    assert session.session_winlogon_pid is None
    assert not session.windows_shell_bootstrapped
    assert not any(emitter.emit.called for emitter in emitters.values())

    accepted_generator, accepted_state, accepted_emitters = _generator()
    accepted_system = _windows_system()
    _register_windows_service_parents(accepted_generator, accepted_state, accepted_system)
    accepted_logon_id = accepted_state.create_session(
        username=user.username,
        system=accepted_system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=session_start,
        session_kind="interactive",
    )
    accepted_session = accepted_state.get_session(accepted_logon_id)
    assert accepted_session is not None
    inside_deadline = _START
    accepted_pid, accepted_image = accepted_generator._ensure_user_connection_owner_process(
        source_system=accepted_system,
        time=_START,
        service="ssh",
        dst_port=22,
        os_category="windows",
        hostname="lnx-target.example.test",
        ssh_attempted_username=user.username,
        source_visible_by=inside_deadline,
        session_info=(user, accepted_session),
    )

    assert accepted_pid > 0
    assert accepted_image is not None
    source_frontier = accepted_generator.process_source_create_time(
        accepted_system.hostname,
        accepted_pid,
    )
    assert source_frontier is not None and source_frontier <= inside_deadline
    assert (
        max(_emitted_process_create_source_times(accepted_generator, accepted_emitters))
        <= inside_deadline
    )


def test_connection_owner_omits_windows_ssh_actor_before_future_process_mutation() -> None:
    """A flow cannot bootstrap an SSH actor whose source create follows the flow."""

    generator, state, emitters = _generator(profile="messy_collection")
    system = _windows_system()
    user = _user()
    _register_windows_service_parents(generator, state, system)
    session_start = _START - timedelta(minutes=10)
    state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=session_start,
        session_kind="interactive",
    )
    generator._users_by_username = {user.username: user}
    processes_before = _process_state_snapshot(state, system.hostname)
    history_before = dict(generator._user_process_history)
    frontier_before = state.get_current_time()

    owner = generator._ensure_high_confidence_connection_owner(
        source_system=system,
        time=_START,
        service="ssh",
        dst_port=22,
        proto="tcp",
        hostname="lnx-target.example.test",
        http=None,
        ssh_attempted_username=user.username,
    )

    assert owner == (-1, None)
    assert state.get_current_time() == frontier_before
    assert _process_state_snapshot(state, system.hostname) == processes_before
    assert generator._user_process_history == history_before
    assert not any(emitter.emit.called for emitter in emitters.values())


def test_bounded_foreground_owner_rejects_late_shell_without_sibling_mutation() -> None:
    """A late Linux shell cannot trigger a bounded sibling-shell fallback."""

    generator, state, emitters = _generator(profile="messy_collection")
    system = _linux_system()
    user = _user()
    state.set_current_time(_START - timedelta(minutes=10))
    state.register_process(
        system=system.hostname,
        pid=100,
        parent_pid=0,
        image="/usr/lib/systemd/systemd",
        command_line="/usr/lib/systemd/systemd --system",
        username="root",
        integrity_level="root",
        os_category="linux",
        start_time=_START - timedelta(minutes=10),
    )
    generator._system_pids = {system.hostname: {"systemd": 100}}
    logon_id = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=_START - timedelta(minutes=10),
        session_kind="interactive",
    )
    shell_pid = generator.generate_process(
        user=user,
        system=system,
        time=_START - timedelta(minutes=1),
        logon_id=logon_id,
        process_name="/bin/bash",
        command_line="-bash",
        parent_pid=100,
        suppress_command_file_effect=True,
    )
    session = state.get_session(logon_id)
    frontier = generator.process_source_create_time(system.hostname, shell_pid)
    assert session is not None and frontier is not None
    session.session_shell_pid = shell_pid
    session.process_tree_root = 100
    processes_before = _process_state_snapshot(state, system.hostname)
    emitted_before = {name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()}
    state_frontier = state.get_current_time()

    prepared = generator._prepare_linux_foreground_connection_owner(
        system=system,
        user=user,
        session=session,
        process_time=_START,
        activity_time=_START,
        process_name="/usr/bin/curl",
        command_line="curl https://example.test/",
        source_visible_by=frontier - timedelta(microseconds=1),
    )

    assert prepared is None
    assert state.get_current_time() == state_frontier
    assert _process_state_snapshot(state, system.hostname) == processes_before
    assert {
        name: len(emitter.emit.call_args_list) for name, emitter in emitters.items()
    } == emitted_before


def test_bounded_foreground_owner_preflights_fresh_sibling_and_client() -> None:
    """A fresh sibling shell is published only when its child can also fit."""

    generator, state, emitters = _generator(profile="messy_collection")
    system = _linux_system()
    user = _user()
    state.set_current_time(_START - timedelta(minutes=10))
    state.register_process(
        system=system.hostname,
        pid=100,
        parent_pid=0,
        image="/usr/lib/systemd/systemd",
        command_line="/usr/lib/systemd/systemd --system",
        username="root",
        integrity_level="root",
        os_category="linux",
        start_time=_START - timedelta(minutes=10),
    )
    generator._system_pids = {system.hostname: {"systemd": 100}}
    logon_id = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=_START - timedelta(minutes=10),
        session_kind="interactive",
    )
    session = state.get_session(logon_id)
    assert session is not None
    session.process_tree_root = 100
    processes_before = _process_state_snapshot(state, system.hostname)
    frontier_before = state.get_current_time()

    rejected = generator._prepare_linux_foreground_connection_owner(
        system=system,
        user=user,
        session=session,
        process_time=_START,
        activity_time=_START,
        process_name="/usr/bin/curl",
        command_line="curl https://example.test/",
        source_visible_by=_START - timedelta(seconds=1),
    )

    assert rejected is None
    assert state.get_current_time() == frontier_before
    assert _process_state_snapshot(state, system.hostname) == processes_before
    assert session.session_shell_pid is None
    assert not any(emitter.emit.called for emitter in emitters.values())

    inside_deadline = _START + timedelta(seconds=30)
    accepted = generator._prepare_linux_foreground_connection_owner(
        system=system,
        user=user,
        session=session,
        process_time=_START,
        activity_time=_START,
        process_name="/usr/bin/curl",
        command_line="curl https://example.test/",
        source_visible_by=inside_deadline,
    )
    assert accepted is not None
    shell_pid, child_time = accepted
    child_pid = generator.generate_process(
        user=user,
        system=system,
        time=child_time,
        logon_id=logon_id,
        process_name="/usr/bin/curl",
        command_line="curl https://example.test/",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
        source_visible_by=inside_deadline,
    )

    assert child_pid > 0
    source_frontier = generator.process_source_create_time(system.hostname, child_pid)
    assert source_frontier is not None and source_frontier <= inside_deadline
    assert max(_emitted_process_create_source_times(generator, emitters)) <= inside_deadline


def test_linux_local_login_never_publishes_zero_pam_owner() -> None:
    """A rejected bounded /bin/login uses a real transient PAM PID, never PID zero."""

    generator, state, emitters = _generator(profile="messy_collection")
    system = System(
        hostname="LNX-SRV",
        ip="10.0.20.20",
        os="Ubuntu 24.04",
        type="server",
    )
    user = _user()
    state.set_current_time(_START - timedelta(hours=1))
    state.register_process(
        system=system.hostname,
        pid=100,
        parent_pid=0,
        image="/usr/lib/systemd/systemd",
        command_line="/usr/lib/systemd/systemd --system",
        username="root",
        integrity_level="root",
        os_category="linux",
        start_time=_START - timedelta(hours=1),
    )
    generator._system_pids = {system.hostname: {"systemd": 100, "init": 100}}

    logon_id = generator.generate_logon(user, system, _START, logon_type=2)

    session = state.get_session(logon_id)
    assert session is not None and session.process_tree_root != 0
    login_events = [
        call.args[0]
        for call in emitters["syslog"].emit.call_args_list
        if call.args and call.args[0].syslog is not None and call.args[0].syslog.app_name == "login"
    ]
    assert login_events
    assert all(event.syslog.pid > 0 for event in login_events)


def test_linux_ssh_client_impossible_root_bound_rejects_before_session_bootstrap() -> None:
    """A messy-clock SSH client rejects before creating its fallback local session."""

    generator, state, emitters = _generator(profile="messy_collection")
    source = _linux_system("LNX-1", "10.0.20.245")
    target = _linux_system("LNX-TARGET", "10.0.20.246")
    user = _user()
    state.set_current_time(_START - timedelta(hours=1))
    state.register_process(
        system=source.hostname,
        pid=100,
        parent_pid=0,
        image="/usr/lib/systemd/systemd",
        command_line="/usr/lib/systemd/systemd --system",
        username="root",
        integrity_level="root",
        os_category="linux",
        start_time=_START - timedelta(hours=1),
    )
    generator._system_pids = {source.hostname: {"systemd": 100, "init": 100}}
    processes_before = _process_state_snapshot(state, source.hostname)
    sessions_before = tuple(state.get_sessions_on_system(source.hostname))
    frontier_before = state.get_current_time()

    result = generator.ensure_linux_ssh_client_process(
        user=user,
        source_system=source,
        target_system=target,
        time=_START,
        process_image="/usr/bin/ssh",
        source_port=40046,
    )

    assert result is None
    assert state.get_current_time() == frontier_before
    assert tuple(state.get_sessions_on_system(source.hostname)) == sessions_before
    assert _process_state_snapshot(state, source.hostname) == processes_before
    assert not any(emitter.emit.called for emitter in emitters.values())


def test_linux_ssh_client_requires_pre_admitted_fallback_session() -> None:
    """A bounded SSH client never commits a fallback local-logon prefix."""

    generator, state, emitters = _generator(profile="messy_collection")
    source = _linux_system("LNX-1", "10.0.20.245")
    target = _linux_system("LNX-TARGET", "10.0.20.246")
    user = _user()
    generator._scenario_start_time = _START
    state.set_current_time(_START - timedelta(hours=1))
    state.register_process(
        system=source.hostname,
        pid=100,
        parent_pid=0,
        image="/usr/lib/systemd/systemd",
        command_line="/usr/lib/systemd/systemd --system",
        username="root",
        integrity_level="root",
        os_category="linux",
        start_time=_START - timedelta(hours=1),
    )
    generator._system_pids = {source.hostname: {"systemd": 100, "init": 100}}
    processes_before = _process_state_snapshot(state, source.hostname)
    sessions_before = tuple(state.get_sessions_on_system(source.hostname))
    frontier_before = state.get_current_time()

    rejected = generator.ensure_linux_ssh_client_process(
        user=user,
        source_system=source,
        target_system=target,
        time=_START + timedelta(seconds=10),
        process_image="/usr/bin/ssh",
        source_port=40046,
    )

    assert rejected is None
    assert state.get_current_time() == frontier_before
    assert tuple(state.get_sessions_on_system(source.hostname)) == sessions_before
    assert _process_state_snapshot(state, source.hostname) == processes_before
    assert not any(emitter.emit.called for emitter in emitters.values())

    logon_id = state.create_session(
        username=user.username,
        system=source.hostname,
        logon_type=2,
        source_ip="-",
        start_time=_START,
        session_kind="interactive",
    )
    session = state.get_session(logon_id)
    assert session is not None
    session.process_tree_root = 100
    requested_time = _START + timedelta(seconds=30)
    accepted = generator.ensure_linux_ssh_client_process(
        user=user,
        source_system=source,
        target_system=target,
        time=requested_time,
        process_image="/usr/bin/ssh",
        source_port=40047,
    )

    assert accepted is not None
    source_frontier = generator.process_source_create_time(source.hostname, accepted[0])
    assert source_frontier is not None and source_frontier <= requested_time
    assert max(_emitted_process_create_source_times(generator, emitters)) <= requested_time
