# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for process lifetime realism helpers."""

import random
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.generator import (
    _linux_foreground_lifetime,
    _linux_shell_process_reserves_foreground,
    _session_active_for_activity,
    _windows_foreground_lifetime,
)
from evidenceforge.generation.engine.baseline import (
    _eligible_for_hourly_module_load,
    _session_active_at,
    _windows_background_process_lifetime_seconds,
    _windows_stale_process_target_lifetime,
)
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System, User
from evidenceforge.models.state import RunningProcess


def _process(image: str, command_line: str, start_time: datetime) -> RunningProcess:
    return RunningProcess(
        pid=4321,
        parent_pid=1000,
        image=image,
        command_line=command_line,
        username="analyst",
        system="WS-01",
        start_time=start_time,
        integrity_level="Medium",
    )


def _linux_interactive_shell(
    *,
    session_kind: str,
    emitter_name: str = "ecar",
) -> tuple[ActivityGenerator, StateManager, System, User, str, int, list[object]]:
    start = datetime(2024, 3, 18, 13, 0, 0, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(start - timedelta(minutes=5))
    events: list[object] = []
    emitter = Mock()
    emitter.can_handle.return_value = True
    emitter.emit.side_effect = lambda event: events.append(event)
    emitters = {emitter_name: emitter}
    dispatcher = EventDispatcher(state_manager=state, emitters=emitters)
    generator = ActivityGenerator(state, emitters, dispatcher=dispatcher)
    user = User(username="analyst", full_name="Alicia Analyst", email="analyst@example.local")
    system = System(
        hostname="LNX-01",
        ip="10.10.2.30",
        os="Ubuntu 22.04",
        type="server" if session_kind == "ssh" else "workstation",
        assigned_user=None if session_kind == "ssh" else user.username,
    )
    root_image = "/usr/sbin/sshd" if session_kind == "ssh" else "/usr/libexec/gnome-terminal-server"
    root_pid = state.create_process(
        system.hostname,
        0,
        root_image,
        root_image,
        "root" if session_kind == "ssh" else user.username,
        "System" if session_kind == "ssh" else "Medium",
    )
    logon_id = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=10 if session_kind == "ssh" else 2,
        source_ip="10.10.1.20" if session_kind == "ssh" else "-",
        start_time=start - timedelta(minutes=4),
        session_kind=session_kind,
    )
    state.set_current_time(start - timedelta(minutes=3))
    shell_pid = state.create_process(
        system.hostname,
        root_pid,
        "/bin/bash",
        "-bash",
        user.username,
        "Medium",
        logon_id=logon_id,
    )
    session = state.get_session(logon_id)
    assert session is not None
    session.session_shell_pid = shell_pid
    return generator, state, system, user, logon_id, shell_pid, events


def _windows_process_family() -> tuple[
    ActivityGenerator,
    StateManager,
    System,
    User,
    str,
    int,
    int,
    Mock,
]:
    """Build one exact interactive parent/child family with observable dispatch."""

    start = datetime(2024, 3, 18, 13, 0, 0, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(start)
    emitter = Mock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(state_manager=state, emitters={"ecar": emitter})
    generator = ActivityGenerator(state, {"ecar": emitter}, dispatcher=dispatcher)
    user = User(username="analyst", full_name="Alicia Analyst", email="analyst@example.local")
    system = System(
        hostname="WIN-01",
        ip="10.10.1.30",
        os="Windows 11",
        type="workstation",
        assigned_user=user.username,
    )
    session_plan = state.plan_session_materialization(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=start,
        session_kind="interactive",
        lifecycle_group_id="test:process-family",
        session_id=2,
    )
    session, _session_receipt = generator._lifecycle_authority.materialize_session(session_plan)
    parent_plan = state.plan_process_materialization(
        system=system.hostname,
        parent_pid=0,
        image=r"C:\Tools\Parent.exe",
        command_line="Parent.exe",
        username=user.username,
        integrity_level="Medium",
        os_category="windows",
        logon_id=session.logon_id,
        lifecycle_group_id=session.lifecycle_group_id,
        start_time=start + timedelta(seconds=1),
        require_session=True,
        auth_session_id=session.session_id,
        auth_logon_type=session.logon_type,
    )
    parent, _parent_receipt = generator._lifecycle_authority.materialize_process(parent_plan)
    child_plan = state.plan_process_materialization(
        system=system.hostname,
        parent_pid=parent.pid,
        image=r"C:\Tools\Child.exe",
        command_line="Child.exe --once",
        username=user.username,
        integrity_level="Medium",
        os_category="windows",
        logon_id=session.logon_id,
        lifecycle_group_id="test:process-child",
        start_time=start + timedelta(seconds=2),
        require_session=True,
        auth_session_id=session.session_id,
        auth_logon_type=session.logon_type,
    )
    child, _child_receipt = generator._lifecycle_authority.materialize_process(child_plan)
    session.process_tree_root = parent.pid
    return (
        generator,
        state,
        system,
        user,
        session.logon_id,
        parent.pid,
        child.pid,
        emitter,
    )


def _materialize_detached_process(
    generator: ActivityGenerator,
    state: StateManager,
    system: System,
    user: User,
    *,
    start_time: datetime,
    image: str,
    command_line: str,
    parent_pid: int = 0,
) -> RunningProcess:
    """Materialize one exact non-session process for finalizer tests."""

    state.set_current_time(start_time)
    plan = state.plan_process_materialization(
        system=system.hostname,
        parent_pid=parent_pid,
        image=image,
        command_line=command_line,
        username=user.username,
        integrity_level="Medium",
        os_category="windows" if "windows" in system.os.casefold() else "linux",
        start_time=start_time,
        lifecycle_group_id=f"test:detached:{image}:{start_time.isoformat()}",
    )
    process, _receipt = generator._lifecycle_authority.materialize_process(plan)
    return process


def test_explicit_foreground_connection_pid_remains_owned_by_caller() -> None:
    """A connection cannot consume a caller-owned foreground process lifecycle."""

    start = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)
    state = StateManager()
    events: list[object] = []
    emitter = Mock()
    emitter.can_handle.return_value = True
    emitter.emit.side_effect = lambda event: events.append(event)
    dispatcher = EventDispatcher(state_manager=state, emitters={"ecar": emitter})
    generator = ActivityGenerator(state, {"ecar": emitter}, dispatcher=dispatcher)
    user = User(username="analyst", full_name="Alicia Analyst", email="analyst@example.local")
    system = System(
        hostname="LNX-OWNER-01",
        ip="10.10.2.31",
        os="Ubuntu 22.04",
        type="workstation",
        assigned_user=user.username,
    )
    process = _materialize_detached_process(
        generator,
        state,
        system,
        user,
        start_time=start,
        image="/usr/bin/curl",
        command_line="curl -s https://example.test/status",
    )
    generator._ip_to_system = {system.ip: system}

    generator.generate_connection(
        src_ip=system.ip,
        dst_ip="93.184.216.34",
        time=start + timedelta(milliseconds=500),
        dst_port=443,
        proto="tcp",
        service="ssl",
        duration=2.0,
        orig_bytes=500,
        resp_bytes=2_500,
        pid=process.pid,
        source_system=system,
        conn_state="SF",
        process_image=process.image,
        suppress_application_side_effects=True,
        suppress_prereq_dns=True,
    )

    assert state.get_process(system.hostname, process.pid) is process
    lifecycle = generator._lifecycle_authority.registry.get_process(process.ecar_object_id)
    assert lifecycle is not None
    assert lifecycle.closed_at is None
    assert not [event for event in events if event.event_type == "process_terminate"]

    generator._generate_bounded_foreground_process_termination(
        user=user,
        system=system,
        start_time=process.start_time,
        pid=process.pid,
        process_name=process.image,
        logon_id=process.logon_id,
        lifetime=(4.0, 4.0),
        rng=random.Random(1),
    )

    assert state.get_process(system.hostname, process.pid) is None
    lifecycle = generator._lifecycle_authority.registry.get_process(process.ecar_object_id)
    assert lifecycle is not None
    assert lifecycle.closed_at is not None
    terminate_events = [event for event in events if event.event_type == "process_terminate"]
    assert len(terminate_events) == 1
    assert terminate_events[0].process is not None
    assert terminate_events[0].process.pid == process.pid


def test_replaced_explicit_connection_pid_uses_replacement_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A synthesized replacement does not inherit ownership of the rejected caller PID."""

    start = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)
    state = StateManager()
    events: list[object] = []
    emitter = Mock()
    emitter.can_handle.return_value = True
    emitter.emit.side_effect = lambda event: events.append(event)
    dispatcher = EventDispatcher(state_manager=state, emitters={"ecar": emitter})
    generator = ActivityGenerator(state, {"ecar": emitter}, dispatcher=dispatcher)
    user = User(username="analyst", full_name="Alicia Analyst", email="analyst@example.local")
    system = System(
        hostname="LNX-OWNER-02",
        ip="10.10.2.32",
        os="Ubuntu 22.04",
        type="workstation",
        assigned_user=user.username,
    )
    caller_process = _materialize_detached_process(
        generator,
        state,
        system,
        user,
        start_time=start - timedelta(seconds=2),
        image="/usr/bin/python3",
        command_line="python3 analyst_job.py",
    )
    replacement_process = _materialize_detached_process(
        generator,
        state,
        system,
        user,
        start_time=start - timedelta(seconds=1),
        image="/usr/bin/curl",
        command_line="curl -s https://resolver.example.test/status",
    )
    generator._ip_to_system = {system.ip: system}
    monkeypatch.setattr(
        generator,
        "_infer_connection_pid",
        lambda _system, _service, _port, _proto: replacement_process.pid,
    )

    generator.generate_connection(
        src_ip=system.ip,
        dst_ip="10.10.1.53",
        time=start,
        dst_port=53,
        proto="udp",
        service="dns",
        duration=0.02,
        orig_bytes=68,
        resp_bytes=156,
        pid=caller_process.pid,
        source_system=system,
        suppress_application_side_effects=True,
        suppress_prereq_dns=True,
    )

    assert state.get_process(system.hostname, caller_process.pid) is caller_process
    assert state.get_process(system.hostname, replacement_process.pid) is None
    terminate_events = [event for event in events if event.event_type == "process_terminate"]
    assert len(terminate_events) == 1
    assert terminate_events[0].process is not None
    assert terminate_events[0].process.pid == replacement_process.pid


def test_compatibility_close_resolver_registers_late_direct_state_child() -> None:
    """Fixture compatibility cannot hide a late direct-State child from admission."""

    start = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(start)
    generator = ActivityGenerator(state, {})
    system = System(
        hostname="LNX-COMPAT-01",
        ip="10.10.2.31",
        os="Ubuntu 22.04",
        type="server",
    )
    parent_pid = state.create_process(
        system.hostname,
        0,
        "/usr/bin/bash",
        "bash -lc worker",
        "analyst",
        "Medium",
    )
    parent = state.get_process(system.hostname, parent_pid)
    assert parent is not None
    generator._lifecycle_authority.ensure_process(system.hostname, parent.pid)
    state.set_current_time(start + timedelta(seconds=1))
    child_pid = state.create_process(
        system.hostname,
        parent.pid,
        "/usr/bin/worker",
        "worker --once",
        "analyst",
        "Medium",
    )
    child = state.get_process(system.hostname, child_pid)
    assert child is not None
    assert generator._lifecycle_authority.registry.get_process(child.ecar_object_id) is None
    state_before = state.list_running_processes()
    current_time_before = state.state.current_time

    resolved = generator.resolve_process_lifecycle_close_candidate(
        system.hostname,
        parent.pid,
        start + timedelta(seconds=5),
    )

    assert resolved is None
    assert state.list_running_processes() == state_before
    assert state.state.current_time == current_time_before
    child_lifecycle = generator._lifecycle_authority.registry.get_process(child.ecar_object_id)
    assert child_lifecycle is not None
    assert child_lifecycle.closed_at is None
    assert child_lifecycle.identity.object_id == child.ecar_object_id
    assert child_lifecycle.identity.hostname == child.system
    assert child_lifecycle.identity.pid == child.pid
    assert child_lifecycle.identity.started_at == child.start_time
    assert child_lifecycle.identity.image == child.image


def test_strict_close_resolver_rejects_state_only_process_without_mutation() -> None:
    """Production lifecycle admission never backfills a State-only process."""

    start = datetime(2024, 3, 18, 12, 30, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(start)
    registry = LifecycleRegistry()
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow)
    dispatcher = EventDispatcher(state_manager=state, emitters={}, lifecycle_shadow=shadow)
    generator = ActivityGenerator(
        state,
        {},
        dispatcher=dispatcher,
        lifecycle_shadow=shadow,
        lifecycle_authority=authority,
    )
    pid = state.create_process(
        "LNX-STRICT-01",
        0,
        "/usr/bin/bash",
        "bash -lc worker",
        "analyst",
        "Medium",
    )
    process = state.get_process("LNX-STRICT-01", pid)
    assert process is not None
    state_before = state.list_running_processes()
    current_time_before = state.state.current_time
    registry_before = registry.stats()

    with pytest.raises(StateError, match="no matching live lifecycle identity"):
        generator.resolve_process_lifecycle_close_candidate(
            "LNX-STRICT-01",
            pid,
            start + timedelta(seconds=5),
        )

    assert state.list_running_processes() == state_before
    assert state.state.current_time == current_time_before
    assert registry.stats() == registry_before
    assert registry.get_process(process.ecar_object_id) is None


def test_sqlcmd_select_query_has_bounded_foreground_lifetime() -> None:
    lifetime = _windows_foreground_lifetime(
        r"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe",
        'sqlcmd.exe -S localhost -d webapp_prod -Q "SELECT TOP 50 * FROM dbo.AuditLog"',
    )

    assert lifetime is not None
    assert lifetime[1] <= 25.0


@pytest.mark.parametrize(
    ("image", "command_line", "maximum"),
    [
        (
            r"C:\Windows\System32\cleanmgr.exe",
            "cleanmgr.exe /autoclean /d C:",
            3600.0,
        ),
        (
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\MpCmdRun.exe",
            "MpCmdRun.exe -SignatureUpdate",
            420.0,
        ),
        (
            r"C:\Windows\System32\dllhost.exe",
            "dllhost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}",
            3600.0,
        ),
        (
            r"C:\Windows\System32\conhost.exe",
            "conhost.exe 0x4",
            900.0,
        ),
        (
            r"C:\Windows\System32\taskhostw.exe",
            "taskhostw.exe /Run",
            900.0,
        ),
    ],
)
def test_windows_background_process_lifetimes_are_bounded(
    image: str,
    command_line: str,
    maximum: float,
) -> None:
    """Maintenance/background process helpers should not fall into stale hourly cleanup."""
    lifetime = _windows_background_process_lifetime_seconds(
        image,
        command_line,
        random.Random(42),
    )

    assert lifetime is not None
    assert 0 < lifetime <= maximum


def test_windows_stale_gui_lifetime_has_broad_tail() -> None:
    """GUI cleanup targets should vary beyond the old one-to-four-hour band."""
    samples = [
        _windows_stale_process_target_lifetime(
            r"C:\Program Files (x86)\Dropbox\Client\Dropbox.exe",
            '"C:\\Program Files (x86)\\Dropbox\\Client\\Dropbox.exe" /home',
            random.Random(seed),
        )
        for seed in range(40)
    ]

    assert min(samples) < 2 * 3600
    assert max(samples) > 5 * 3600


@pytest.mark.parametrize(
    ("image", "command_line"),
    [
        (
            r"C:\Windows\System32\dsquery.exe",
            'dsquery.exe group -name "Domain Admins"',
        ),
        (
            r"C:\Windows\System32\gpresult.exe",
            "gpresult.exe /r",
        ),
        (
            r"C:\Windows\System32\gpupdate.exe",
            "gpupdate.exe /target:computer /force",
        ),
    ],
)
def test_windows_one_shot_admin_utilities_have_short_lifetimes(
    image: str, command_line: str
) -> None:
    lifetime = _windows_foreground_lifetime(image, command_line)

    assert lifetime is not None
    assert lifetime[1] <= 6.0


@pytest.mark.parametrize(
    ("image", "command_line"),
    [
        (
            r"C:\Windows\System32\curl.exe",
            "curl.exe --proxy http://PROXY-01:8080 http://www.bing.com/",
        ),
        (
            r"C:\Windows\System32\cmd.exe",
            "cmd.exe /c whoami /all",
        ),
        (
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -NoProfile -Command Invoke-WebRequest https://example.test",
        ),
    ],
)
def test_windows_one_shot_shell_and_http_commands_have_bounded_lifetimes(
    image: str, command_line: str
) -> None:
    lifetime = _windows_foreground_lifetime(image, command_line)

    assert lifetime is not None
    assert lifetime[1] <= 25.0


def test_cmd_c_wrapper_terminates_after_final_foreground_child() -> None:
    """A noninteractive cmd wrapper closes just after its invoked child exits."""
    start = datetime(2024, 3, 18, 17, 1, 30, tzinfo=UTC)
    state = StateManager()
    emitter = Mock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(state_manager=state, emitters={"ecar": emitter})
    generator = ActivityGenerator(state, {"ecar": emitter}, dispatcher=dispatcher)
    user = User(username="SYSTEM", full_name="SYSTEM", email="system@example.local")
    system = System(
        hostname="FILE-SRV-01",
        ip="10.10.2.20",
        os="Windows Server 2022",
        type="server",
    )
    logon_id = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=5,
        source_ip="-",
        start_time=start - timedelta(minutes=5),
    )
    state.set_current_time(start)
    parent_pid = state.create_process(
        system.hostname,
        4,
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\cmd.exe /c net view \\FILE-SRV-01",
        user.username,
        "System",
        logon_id=logon_id,
    )
    state.set_current_time(start + timedelta(milliseconds=600))
    child_pid = state.create_process(
        system.hostname,
        parent_pid,
        r"C:\Windows\System32\net.exe",
        r"net view \\FILE-SRV-01",
        user.username,
        "System",
        logon_id=logon_id,
    )

    generator.generate_process_termination(
        user=user,
        system=system,
        time=start + timedelta(seconds=2),
        pid=child_pid,
        process_name=r"C:\Windows\System32\net.exe",
        logon_id=logon_id,
    )

    terminations = {
        call.args[0].process.pid: call.args[0].timestamp
        for call in emitter.emit.call_args_list
        if call.args
        for event in (call.args[0],)
        if event.event_type == "process_terminate" and event.process is not None
    }
    assert child_pid in terminations
    assert parent_pid in terminations
    assert terminations[child_pid] < terminations[parent_pid]
    assert terminations[parent_pid] - terminations[child_pid] <= timedelta(seconds=1)
    assert state.get_process(system.hostname, parent_pid) is None


@pytest.mark.parametrize(
    ("image", "command_line"),
    [
        ("/usr/bin/curl", "curl -sS https://grafana.example/api/health"),
        ("/usr/bin/wget", "wget -qO- https://api.example/status"),
    ],
)
def test_linux_http_cli_commands_have_short_lifetimes(image: str, command_line: str) -> None:
    lifetime = _linux_foreground_lifetime(image, command_line)

    assert lifetime is not None
    assert lifetime[1] <= 12.0


@pytest.mark.parametrize(
    ("image", "command_line", "maximum"),
    [
        ("/usr/bin/smbclient", "smbclient //FILE-SRV/Shared -c 'ls'", 20.0),
        ("/usr/bin/git", "git pull origin release/v2.4", 90.0),
        ("/usr/bin/npm", "npm run build", 180.0),
        ("/usr/bin/python3", "python3 --version", 2.0),
    ],
)
def test_linux_bounded_foreground_commands_use_executable_aware_lifetimes(
    image: str,
    command_line: str,
    maximum: float,
) -> None:
    lifetime = _linux_foreground_lifetime(image, command_line)

    assert lifetime is not None
    assert lifetime[1] <= maximum


def test_interactive_smbclient_is_not_forced_to_one_shot_lifetime() -> None:
    assert _linux_foreground_lifetime("/usr/bin/smbclient", "smbclient //FILE-SRV/Shared") is None


@pytest.mark.parametrize(
    ("image", "command_line"),
    [
        ("/usr/bin/vim", "vim /opt/company/webapp/main.py"),
        ("/usr/bin/nano", "nano /etc/nginx/nginx.conf"),
        ("/usr/bin/emacs", "emacs -nw /opt/company/webapp/index.js"),
    ],
)
def test_linux_terminal_editors_have_interactive_lifetimes(image: str, command_line: str) -> None:
    lifetime = _linux_foreground_lifetime(image, command_line)

    assert lifetime is not None
    assert lifetime[0] >= 20.0


@pytest.mark.parametrize(
    ("image", "command_line", "minimum"),
    [
        ("/usr/bin/mysql", "mysql -u root -p -e 'SHOW PROCESSLIST'", 8.0),
        ("/usr/bin/psql", "psql -c 'SELECT count(*) FROM pg_stat_activity'", 1.5),
        ("/usr/bin/systemctl", "systemctl status mysql --no-pager", 0.8),
        ("/usr/bin/journalctl", "journalctl -u systemd-resolved -n 20", 0.8),
        ("/usr/bin/du", "du -sh /var/lib/mysql/*", 0.8),
    ],
)
def test_linux_io_commands_have_source_visible_lifetimes(
    image: str, command_line: str, minimum: float
) -> None:
    lifetime = _linux_foreground_lifetime(image, command_line)

    assert lifetime is not None
    assert lifetime[0] >= minimum


@pytest.mark.parametrize("session_kind", ["ssh", "interactive"])
def test_linux_shell_serializes_unrelated_foreground_children(session_kind: str) -> None:
    """SSH and local/GDM shells reject overlapping unrelated foreground jobs."""
    generator, _state, system, user, logon_id, shell_pid, events = _linux_interactive_shell(
        session_kind=session_kind
    )
    start = datetime(2024, 3, 18, 13, 0, 0, tzinfo=UTC)
    first_pid = generator.generate_process(
        user=user,
        system=system,
        time=start,
        logon_id=logon_id,
        process_name="/usr/bin/git",
        command_line="git status",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
        concurrency_group_id="foreground:first",
    )
    generator.generate_process_termination(
        user=user,
        system=system,
        time=start + timedelta(seconds=20),
        pid=first_pid,
        process_name="/usr/bin/git",
        logon_id=logon_id,
    )
    generator.generate_process(
        user=user,
        system=system,
        time=start + timedelta(seconds=1),
        logon_id=logon_id,
        process_name="/usr/bin/kubectl",
        command_line="kubectl get nodes -o wide",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
        concurrency_group_id="foreground:second",
    )

    creates = {
        event.process.command_line: event.timestamp
        for event in events
        if getattr(event, "event_type", "") == "process_create"
        and getattr(event, "process", None) is not None
    }
    first_termination = next(
        event.timestamp
        for event in events
        if getattr(event, "event_type", "") == "process_terminate"
        and event.process is not None
        and event.process.pid == first_pid
    )
    assert creates["kubectl get nodes -o wide"] > first_termination


def test_linux_foreground_release_is_independent_of_endpoint_renderer() -> None:
    """A process termination must release its shell identically without eCAR."""

    def next_start(emitter_name: str) -> datetime:
        generator, _state, system, user, logon_id, shell_pid, _events = _linux_interactive_shell(
            session_kind="interactive",
            emitter_name=emitter_name,
        )
        start = datetime(2024, 3, 18, 13, 0, 0, tzinfo=UTC)
        first_pid = generator.generate_process(
            user=user,
            system=system,
            time=start,
            logon_id=logon_id,
            process_name="/usr/bin/journalctl",
            command_line="journalctl -u smb-server --since '30 min ago'",
            parent_pid=shell_pid,
            suppress_command_file_effect=True,
            concurrency_group_id="foreground:first",
        )
        generator.generate_process_termination(
            user=user,
            system=system,
            time=start + timedelta(seconds=8),
            pid=first_pid,
            process_name="/usr/bin/journalctl",
            logon_id=logon_id,
        )
        return generator.reserve_linux_foreground_process_start(
            system=system,
            username=user.username,
            logon_id=logon_id,
            parent_pid=shell_pid,
            requested_time=start + timedelta(seconds=1),
            process_name="/usr/bin/apt-cache",
            command_line="apt-cache policy openssl",
        )

    assert next_start("ecar") == next_start("syslog")


def test_linux_shell_allows_pipeline_and_background_concurrency() -> None:
    """True pipeline peers and explicit background jobs do not serialize as unrelated work."""
    generator, _state, system, user, logon_id, shell_pid, events = _linux_interactive_shell(
        session_kind="interactive"
    )
    start = datetime(2024, 3, 18, 13, 0, 0, tzinfo=UTC)
    pipeline_group = "bash-history:pipeline"
    grep_pid = generator.generate_process(
        user=user,
        system=system,
        time=start,
        logon_id=logon_id,
        process_name="/usr/bin/grep",
        command_line="grep ERROR /var/log/syslog",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
        concurrency_group_id=pipeline_group,
    )
    generator.generate_process_termination(
        user=user,
        system=system,
        time=start + timedelta(seconds=8),
        pid=grep_pid,
        process_name="/usr/bin/grep",
        logon_id=logon_id,
    )
    generator.generate_process(
        user=user,
        system=system,
        time=start + timedelta(milliseconds=35),
        logon_id=logon_id,
        process_name="/usr/bin/head",
        command_line="head -20",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
        concurrency_group_id=pipeline_group,
    )
    generator.generate_process(
        user=user,
        system=system,
        time=start + timedelta(seconds=10),
        logon_id=logon_id,
        process_name="/usr/bin/tail",
        command_line="tail -f /var/log/syslog &",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
        concurrency_group_id="background:tail",
    )

    creates = {
        event.process.command_line: event.timestamp
        for event in events
        if getattr(event, "event_type", "") == "process_create"
        and getattr(event, "process", None) is not None
    }
    assert creates["head -20"] < start + timedelta(seconds=1)
    assert creates["tail -f /var/log/syslog &"] == start + timedelta(seconds=10)
    assert _linux_shell_process_reserves_foreground("/usr/bin/grep", "grep ERROR")
    assert not _linux_shell_process_reserves_foreground(
        "/usr/bin/tail", "tail -f /var/log/syslog &"
    )
    assert not _linux_shell_process_reserves_foreground(
        "/usr/bin/code", "code --no-sandbox /srv/app"
    )


def test_linux_unbounded_foreground_child_reserves_until_session_boundary() -> None:
    """A hung or interactive foreground child blocks siblings through session teardown."""
    generator, state, system, user, logon_id, shell_pid, _events = _linux_interactive_shell(
        session_kind="ssh"
    )
    start = datetime(2024, 3, 18, 13, 0, 0, tzinfo=UTC)
    session_end = start + timedelta(minutes=12)
    state.update_session_metadata(logon_id, network_close_time=session_end)
    generator.generate_process(
        user=user,
        system=system,
        time=start,
        logon_id=logon_id,
        process_name="/usr/bin/smbclient",
        command_line="smbclient //FILE-SRV/Shared",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
        concurrency_group_id="foreground:interactive-smbclient",
    )

    reserved = generator.reserve_linux_foreground_process_start(
        system=system,
        username=user.username,
        logon_id=logon_id,
        parent_pid=shell_pid,
        requested_time=start + timedelta(seconds=30),
        process_name="/usr/bin/hostname",
        command_line="hostname -f",
    )

    assert reserved > session_end


def test_anchored_linux_client_uses_sibling_shell_when_foreground_is_busy() -> None:
    """A transport-anchored client cannot bypass or rewind a busy GDM shell."""
    generator, state, system, user, logon_id, shell_pid, _events = _linux_interactive_shell(
        session_kind="interactive"
    )
    start = datetime(2024, 3, 18, 13, 0, 0, tzinfo=UTC)
    first_pid = generator.generate_process(
        user=user,
        system=system,
        time=start,
        logon_id=logon_id,
        process_name="/usr/bin/npm",
        command_line="npm run test",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
    )
    generator._remember_process_connection_hold(
        system=system,
        pid=first_pid,
        close_time=start + timedelta(minutes=30),
    )
    target = System(
        hostname="APP-01",
        ip="10.10.2.40",
        os="Ubuntu 22.04",
        type="server",
    )

    result = generator.ensure_linux_ssh_client_process(
        user=user,
        source_system=system,
        target_system=target,
        time=start + timedelta(minutes=5),
        process_image="/usr/bin/ssh",
        source_port=50222,
    )

    assert result is not None
    second = state.get_process(system.hostname, result[0])
    assert second is not None
    assert second.parent_pid != shell_pid
    sibling_shell = state.get_process(system.hostname, second.parent_pid)
    assert sibling_shell is not None
    assert sibling_shell.image == "/bin/bash"
    assert sibling_shell.logon_id == logon_id


def test_linux_process_termination_retains_observation_concurrency_group() -> None:
    """eCAR missingness must keep one process create/terminate lifecycle together."""
    generator, _state, system, user, logon_id, shell_pid, events = _linux_interactive_shell(
        session_kind="ssh"
    )
    start = datetime(2024, 3, 18, 13, 0, 0, tzinfo=UTC)
    pid = generator.generate_process(
        user=user,
        system=system,
        time=start,
        logon_id=logon_id,
        process_name="/usr/bin/ss",
        command_line="ss -s",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
        concurrency_group_id="bash-history:ss-summary",
    )
    generator.generate_process_termination(
        user=user,
        system=system,
        time=start + timedelta(seconds=2),
        pid=pid,
        process_name="/usr/bin/ss",
        logon_id=logon_id,
    )

    termination = next(
        event
        for event in events
        if getattr(event, "event_type", "") == "process_terminate"
        and event.process is not None
        and event.process.pid == pid
    )
    assert termination.process.concurrency_group_id == "bash-history:ss-summary"


def test_direct_linux_process_creation_claims_provisional_foreground_lifetime() -> None:
    """Loose GDM process paths reserve and close their slot without caller bookkeeping."""
    generator, state, system, user, logon_id, shell_pid, events = _linux_interactive_shell(
        session_kind="interactive"
    )
    start = datetime(2024, 3, 18, 13, 0, 0, tzinfo=UTC)
    first_pid = generator.generate_process(
        user=user,
        system=system,
        time=start,
        logon_id=logon_id,
        process_name="/usr/bin/docker",
        command_line="docker images",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
    )
    provisional_end = generator.foreground_process_termination_time(system.hostname, first_pid)
    assert provisional_end is not None

    second_pid = generator.generate_process(
        user=user,
        system=system,
        time=start + timedelta(milliseconds=75),
        logon_id=logon_id,
        process_name="/usr/bin/git",
        command_line="git diff --stat",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
    )
    second = state.get_process(system.hostname, second_pid)
    assert second is not None
    assert second.start_time > provisional_end

    generator.finalize_foreground_process_lifetimes(start + timedelta(minutes=5))
    first_termination = next(
        event.timestamp
        for event in events
        if getattr(event, "event_type", "") == "process_terminate"
        and event.process is not None
        and event.process.pid == first_pid
    )
    assert first_termination < second.start_time


def test_linux_sudo_companions_share_shell_foreground_slot_across_ttys() -> None:
    """Loose sudo/admin companions cannot bypass serialization by selecting another TTY."""
    generator, _state, system, user, logon_id, shell_pid, events = _linux_interactive_shell(
        session_kind="interactive"
    )
    start = datetime(2024, 3, 18, 13, 0, 0, tzinfo=UTC)
    first_sudo, first_child, _, _ = generator.generate_linux_sudo_processes(
        system=system,
        sudo_time=start,
        child_time=start + timedelta(milliseconds=200),
        sudo_user=user.username,
        tty="pts/1",
        command="/usr/bin/journalctl -u sshd -n 40",
        reserve_until=start + timedelta(seconds=10),
        lifecycle_group_id="sudo:first",
    )
    assert first_child is not None
    generator.terminate_linux_sudo_process(
        system=system,
        time=start + timedelta(seconds=9),
        pid=first_child,
    )
    generator.terminate_linux_sudo_process(
        system=system,
        time=start + timedelta(seconds=10),
        pid=first_sudo,
    )
    second_sudo, _second_child, _, _ = generator.generate_linux_sudo_processes(
        system=system,
        sudo_time=start + timedelta(milliseconds=100),
        child_time=start + timedelta(milliseconds=300),
        sudo_user=user.username,
        tty="pts/2",
        command="/usr/sbin/iptables -L -n -v",
        reserve_until=start + timedelta(seconds=6),
        lifecycle_group_id="sudo:second",
    )

    creates = {
        event.process.pid: event.timestamp
        for event in events
        if getattr(event, "event_type", "") == "process_create"
        and getattr(event, "process", None) is not None
    }
    first_termination = next(
        event.timestamp
        for event in events
        if getattr(event, "event_type", "") == "process_terminate"
        and event.process is not None
        and event.process.pid == first_sudo
    )
    assert creates[first_sudo] < first_termination < creates[second_sudo]
    assert creates[first_sudo] >= start
    assert creates[second_sudo] > start + timedelta(seconds=10)
    assert shell_pid > 0 and logon_id


def test_linux_sudo_rejects_foreground_shift_past_ssh_transport_close() -> None:
    """A busy SSH shell cannot acquire a sudo dependent after its transport closes."""
    generator, state, system, user, logon_id, shell_pid, events = _linux_interactive_shell(
        session_kind="ssh"
    )
    start = datetime(2024, 3, 18, 13, 0, 0, tzinfo=UTC)
    close = start + timedelta(minutes=1)
    state.update_session_metadata(logon_id, network_close_time=close)
    busy_pid = generator.generate_process(
        user=user,
        system=system,
        time=start,
        logon_id=logon_id,
        process_name="/usr/bin/git",
        command_line="git status --short",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
    )
    generator._remember_process_connection_hold(
        system=system,
        pid=busy_pid,
        close_time=close + timedelta(seconds=30),
    )

    sudo_pid, child_pid, _shift, _tty = generator.generate_linux_sudo_processes(
        system=system,
        sudo_time=close - timedelta(seconds=30),
        child_time=close - timedelta(seconds=29, milliseconds=800),
        sudo_user=user.username,
        tty="pts/1",
        command="/usr/bin/id",
        reserve_until=close - timedelta(seconds=25),
        lifecycle_group_id="sudo:after-ssh-close",
    )

    assert sudo_pid == 0
    assert child_pid is None
    assert not any(
        event.event_type == "process_create"
        and event.process is not None
        and event.process.image == "/usr/bin/sudo"
        for event in events
    )


def test_ssh_session_activity_stops_before_transport_close() -> None:
    start = datetime(2024, 3, 18, 20, 20, 0, tzinfo=UTC)
    close = start + timedelta(minutes=7)
    session = SimpleNamespace(start_time=start, network_close_time=close)

    assert _session_active_for_activity(session, close - timedelta(seconds=2), margin_seconds=1.5)
    assert not _session_active_for_activity(
        session,
        close - timedelta(milliseconds=500),
        margin_seconds=1.5,
    )
    assert not _session_active_for_activity(session, close + timedelta(milliseconds=1))


def test_baseline_session_activity_stops_at_network_close() -> None:
    start = datetime(2024, 3, 18, 20, 20, 0, tzinfo=UTC)
    close = start + timedelta(minutes=7)
    session = SimpleNamespace(
        start_time=start,
        network_close_time=close,
        system="SRV-LIN-01",
        logon_id="0x1234",
    )

    assert _session_active_at(session, close - timedelta(milliseconds=1), start, None)
    assert not _session_active_at(session, close, start, None)
    assert not _session_active_at(session, close + timedelta(seconds=1), start, None)


def test_baseline_session_activity_stops_at_authoritative_end_plan() -> None:
    """Storyline session deadlines must bound baseline dependents before dispatch."""
    start = datetime(2024, 3, 18, 20, 20, 0, tzinfo=UTC)
    close = start + timedelta(minutes=7)
    session = SimpleNamespace(
        start_time=start,
        network_close_time=None,
        system="WS-01",
        logon_id="0x1234",
        end_plan=SessionEndPlan(
            canonical_end=close,
            authority="explicit_storyline",
            storyline_event_id="evt-logoff",
        ),
    )

    assert _session_active_at(session, close - timedelta(milliseconds=1), start, None)
    assert not _session_active_at(session, close, start, None)
    assert not _session_active_at(session, close + timedelta(seconds=1), start, None)


def test_process_owned_ssh_transport_holds_client_process_until_close() -> None:
    """A source SSH client should not terminate before its correlated transport closes."""
    start = datetime(2024, 3, 18, 15, 59, 55, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(start - timedelta(minutes=5))
    events: list[object] = []
    emitter = Mock()
    emitter.can_handle.return_value = True
    emitter.emit.side_effect = lambda event: events.append(event)
    dispatcher = EventDispatcher(state_manager=state, emitters={"ecar": emitter})
    generator = ActivityGenerator(state, {"ecar": emitter}, dispatcher=dispatcher)
    user = User(
        username="aisha.johnson",
        full_name="Aisha Johnson",
        email="aisha.johnson@example.local",
    )
    source = System(
        hostname="WS-AJOHNSON-01",
        ip="10.10.1.35",
        os="Windows 11",
        type="workstation",
        assigned_user=user.username,
    )
    target = System(
        hostname="DB-PROD-01",
        ip="10.10.4.10",
        os="Ubuntu 22.04",
        type="server",
        roles=["database"],
        services=["ssh"],
    )
    generator._ip_to_system = {source.ip: source, target.ip: target}
    logon_id = state.create_session(
        username=user.username,
        system=source.hostname,
        logon_type=2,
        source_ip="-",
        session_kind="interactive",
        start_time=start - timedelta(minutes=5),
    )
    state.set_current_time(start - timedelta(seconds=5))
    pid = state.create_process(
        source.hostname,
        0,
        r"C:\Windows\System32\OpenSSH\ssh.exe",
        "ssh.exe aisha.johnson@DB-PROD-01.meridianhcs.local",
        user.username,
        "Medium",
        logon_id=logon_id,
    )
    state.set_current_time(start)

    generator.generate_connection(
        src_ip=source.ip,
        dst_ip=target.ip,
        time=start,
        dst_port=22,
        proto="tcp",
        service="ssh",
        duration=1800.0,
        orig_bytes=38_000,
        resp_bytes=58_000,
        src_port=60175,
        pid=pid,
        source_system=source,
        conn_state="SF",
        process_image=r"C:\Windows\System32\OpenSSH\ssh.exe",
        suppress_application_side_effects=True,
        suppress_prereq_dns=True,
    )
    connection_event = next(
        event
        for event in events
        if event.event_type == "connection"
        and event.network is not None
        and event.network.dst_port == 22
    )
    close_time = connection_event.timestamp + timedelta(seconds=connection_event.network.duration)

    state.end_session(logon_id, start + timedelta(seconds=30))
    generator.generate_process_termination(
        user=user,
        system=source,
        time=start + timedelta(seconds=45),
        pid=pid,
        process_name=r"C:\Windows\System32\OpenSSH\ssh.exe",
        logon_id=logon_id,
    )

    terminate_event = next(event for event in events if event.event_type == "process_terminate")
    assert terminate_event.timestamp > close_time
    assert state.get_process(source.hostname, pid) is None


def test_finalize_foreground_process_lifetimes_closes_tracked_one_shot() -> None:
    start = datetime(2024, 3, 18, 17, 56, 39, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(start)
    dispatcher = EventDispatcher(state_manager=state, emitters={})
    generator = ActivityGenerator(state, {}, dispatcher=dispatcher)
    system = System(
        hostname="APP-INT-01",
        ip="10.10.2.30",
        os="Ubuntu 22.04",
        type="server",
    )
    user = User(
        username="marcus.chen",
        full_name="Marcus Chen",
        email="marcus.chen@example.local",
    )
    pid = state.create_process(
        system=system.hostname,
        parent_pid=0,
        image="/usr/bin/curl",
        command_line="curl -sI https://localhost",
        username=user.username,
        integrity_level="Medium",
        logon_id="0x1234",
    )

    generator._remember_foreground_process_finalizer(
        system=system,
        user=user,
        pid=pid,
        process_name="/usr/bin/curl",
        logon_id="0x1234",
        termination_time=start + timedelta(seconds=5),
    )

    generator.finalize_foreground_process_lifetimes(start + timedelta(minutes=1))

    assert state.get_process(system.hostname, pid) is None
    assert generator._process_termination_recorded(
        system.hostname,
        pid,
        start,
    )


def test_bounded_foreground_parent_defers_to_children_first_session_teardown() -> None:
    """An advisory parent close must not precede a live exact child lifecycle."""

    (
        generator,
        state,
        system,
        user,
        logon_id,
        parent_pid,
        child_pid,
        emitter,
    ) = _windows_process_family()
    parent = state.get_process(system.hostname, parent_pid)
    child = state.get_process(system.hostname, child_pid)
    assert parent is not None
    assert child is not None
    parent_lifecycle_before = generator._lifecycle_authority.registry.get_process(
        parent.ecar_object_id
    )
    calls_before = len(emitter.emit.call_args_list)

    candidate = generator._generate_bounded_foreground_process_termination(
        user=user,
        system=system,
        start_time=parent.start_time,
        pid=parent.pid,
        process_name=parent.image,
        logon_id=logon_id,
        lifetime=(10.0, 10.0),
        rng=random.Random(1),
    )

    assert candidate == parent.start_time + timedelta(seconds=10)
    assert state.get_process(system.hostname, parent.pid) is parent
    assert len(emitter.emit.call_args_list) == calls_before
    assert (
        generator._lifecycle_authority.registry.get_process(parent.ecar_object_id)
        == parent_lifecycle_before
    )

    generator.generate_logoff(
        user,
        system,
        child.start_time + timedelta(minutes=10),
        logon_id,
        from_storyline=True,
    )

    parent_lifecycle = generator._lifecycle_authority.registry.get_process(parent.ecar_object_id)
    child_lifecycle = generator._lifecycle_authority.registry.get_process(child.ecar_object_id)
    assert parent_lifecycle is not None
    assert child_lifecycle is not None
    assert child_lifecycle.closed_at is not None
    assert parent_lifecycle.closed_at is not None
    assert child_lifecycle.closed_at < parent_lifecycle.closed_at
    assert generator.dispatcher.lifecycle_shadow.violation_summary["total"] == 0


def test_detached_finalizer_retries_live_parent_and_resolves_retained_child_frontier() -> None:
    """A detached parent remains queued until its exact child graph drains."""

    start = datetime(2024, 3, 18, 18, 0, tzinfo=UTC)
    state = StateManager()
    emitter = Mock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(state_manager=state, emitters={"ecar": emitter})
    generator = ActivityGenerator(state, {"ecar": emitter}, dispatcher=dispatcher)
    system = System(
        hostname="APP-INT-01",
        ip="10.10.2.30",
        os="Ubuntu 22.04",
        type="server",
    )
    user = User(
        username="marcus.chen",
        full_name="Marcus Chen",
        email="marcus.chen@example.local",
    )
    parent = _materialize_detached_process(
        generator,
        state,
        system,
        user,
        start_time=start,
        image="/usr/bin/bash",
        command_line="bash -lc worker",
    )
    child = _materialize_detached_process(
        generator,
        state,
        system,
        user,
        start_time=start + timedelta(seconds=1),
        image="/usr/bin/worker",
        command_line="worker --once",
        parent_pid=parent.pid,
    )
    candidate = start + timedelta(seconds=5)
    first_cutoff = start + timedelta(seconds=10)
    generator._remember_foreground_process_finalizer(
        system=system,
        user=user,
        pid=parent.pid,
        process_name=parent.image,
        logon_id="",
        termination_time=candidate,
    )
    parent_lifecycle_before = generator._lifecycle_authority.registry.get_process(
        parent.ecar_object_id
    )

    generator.finalize_foreground_process_lifetimes(first_cutoff)

    assert state.get_process(system.hostname, parent.pid) is parent
    assert (
        generator._lifecycle_authority.registry.get_process(parent.ecar_object_id)
        == parent_lifecycle_before
    )
    assert generator.foreground_process_termination_time(
        system.hostname, parent.pid
    ) == first_cutoff + timedelta(microseconds=1)
    assert not emitter.emit.call_args_list

    child_close = start + timedelta(seconds=20)
    generator.generate_process_termination(
        user=user,
        system=system,
        time=child_close,
        pid=child.pid,
        process_name=child.image,
        logon_id="",
    )
    generator.finalize_foreground_process_lifetimes(start + timedelta(seconds=30))

    parent_lifecycle = generator._lifecycle_authority.registry.get_process(parent.ecar_object_id)
    assert parent_lifecycle is not None
    assert parent_lifecycle.closed_at == child_close + timedelta(microseconds=1)
    assert state.get_process(system.hostname, parent.pid) is None
    assert generator.dispatcher.lifecycle_shadow.violation_summary["total"] == 0


def test_detached_due_finalizers_close_children_first_in_one_pass() -> None:
    """A due parent and child drain in depth order during one finalizer pass."""

    start = datetime(2024, 3, 18, 18, 30, tzinfo=UTC)
    state = StateManager()
    emitter = Mock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(state_manager=state, emitters={"ecar": emitter})
    generator = ActivityGenerator(state, {"ecar": emitter}, dispatcher=dispatcher)
    system = System(
        hostname="APP-INT-01",
        ip="10.10.2.30",
        os="Ubuntu 22.04",
        type="server",
    )
    user = User(
        username="marcus.chen",
        full_name="Marcus Chen",
        email="marcus.chen@example.local",
    )
    parent = _materialize_detached_process(
        generator,
        state,
        system,
        user,
        start_time=start,
        image="/usr/bin/bash",
        command_line="bash -lc worker",
    )
    child = _materialize_detached_process(
        generator,
        state,
        system,
        user,
        start_time=start + timedelta(seconds=1),
        image="/usr/bin/worker",
        command_line="worker --once",
        parent_pid=parent.pid,
    )
    parent_candidate = start + timedelta(seconds=5)
    child_candidate = start + timedelta(seconds=10)
    generator._remember_foreground_process_finalizer(
        system=system,
        user=user,
        pid=parent.pid,
        process_name=parent.image,
        logon_id="",
        termination_time=parent_candidate,
    )
    generator._remember_foreground_process_finalizer(
        system=system,
        user=user,
        pid=child.pid,
        process_name=child.image,
        logon_id="",
        termination_time=child_candidate,
    )

    generator.finalize_foreground_process_lifetimes(start + timedelta(seconds=20))

    parent_lifecycle = generator._lifecycle_authority.registry.get_process(parent.ecar_object_id)
    child_lifecycle = generator._lifecycle_authority.registry.get_process(child.ecar_object_id)
    assert parent_lifecycle is not None
    assert child_lifecycle is not None
    assert child_lifecycle.closed_at == child_candidate
    assert parent_lifecycle.closed_at == child_candidate + timedelta(microseconds=1)
    assert state.get_process(system.hostname, child.pid) is None
    assert state.get_process(system.hostname, parent.pid) is None
    assert generator.dispatcher.lifecycle_shadow.violation_summary["total"] == 0


def test_finalize_foreground_process_lifetimes_preserves_commands_beyond_window() -> None:
    start = datetime(2024, 3, 18, 17, 59, 58, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(start)
    dispatcher = EventDispatcher(state_manager=state, emitters={})
    generator = ActivityGenerator(state, {}, dispatcher=dispatcher)
    system = System(
        hostname="APP-INT-01",
        ip="10.10.2.30",
        os="Ubuntu 22.04",
        type="server",
    )
    user = User(
        username="marcus.chen",
        full_name="Marcus Chen",
        email="marcus.chen@example.local",
    )
    pid = state.create_process(
        system=system.hostname,
        parent_pid=0,
        image="/usr/bin/curl",
        command_line="curl -sI https://localhost",
        username=user.username,
        integrity_level="Medium",
        logon_id="0x1234",
    )

    generator._remember_foreground_process_finalizer(
        system=system,
        user=user,
        pid=pid,
        process_name="/usr/bin/curl",
        logon_id="0x1234",
        termination_time=start + timedelta(seconds=5),
    )

    generator.finalize_foreground_process_lifetimes(start + timedelta(seconds=2))

    assert state.get_process(system.hostname, pid) is not None
    assert not generator._process_termination_recorded(
        system.hostname,
        pid,
        start,
    )


def test_dependent_hold_extends_registered_foreground_finalizer() -> None:
    """Action-bundle effects retain their foreground actor through the final dependent."""
    start = datetime(2024, 3, 18, 17, 59, 58, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(start)
    dispatcher = EventDispatcher(state_manager=state, emitters={})
    generator = ActivityGenerator(state, {}, dispatcher=dispatcher)
    system = System(
        hostname="LNX-CLIENT-01",
        ip="10.10.2.30",
        os="Ubuntu 22.04",
        type="workstation",
    )
    user = User(
        username="marcus.chen",
        full_name="Marcus Chen",
        email="marcus.chen@example.local",
    )
    pid = state.create_process(
        system=system.hostname,
        parent_pid=0,
        image="/usr/bin/cp",
        command_line='cp -- "/mnt/shared/report.xlsx" "/var/tmp/report.xlsx"',
        username=user.username,
        integrity_level="Medium",
        logon_id="0x1234",
    )
    initial_termination = start + timedelta(seconds=1)
    required_until = start + timedelta(seconds=10)
    generator._remember_foreground_process_finalizer(
        system=system,
        user=user,
        pid=pid,
        process_name="/usr/bin/cp",
        logon_id="0x1234",
        termination_time=initial_termination,
    )

    generator._remember_process_dependent_hold(
        system=system,
        pid=pid,
        required_until=required_until,
    )

    assert generator.foreground_process_termination_time(system.hostname, pid) > required_until
    generator.finalize_foreground_process_lifetimes(required_until)
    assert state.get_process(system.hostname, pid) is not None
    generator.finalize_foreground_process_lifetimes(start + timedelta(minutes=1))
    assert state.get_process(system.hostname, pid) is None


def test_process_watermark_drops_pid_scoped_state_before_reuse() -> None:
    """A reused PID must not inherit timing, holds, or modules from its old instance."""
    start = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(start)
    generator = ActivityGenerator(state, {})
    pid = state.create_process(
        "WS-01",
        0,
        r"C:\old.exe",
        "old.exe",
        "analyst",
        "Medium",
    )
    old_key = generator._process_instance_key("WS-01", pid)
    generator._process_source_create_times[old_key] = start
    generator._process_source_terminate_times[old_key] = start + timedelta(seconds=1)
    generator._process_connection_hold_until[old_key] = start + timedelta(seconds=2)
    generator._loaded_modules_by_process.add(("WS-01", pid, start.isoformat(), r"c:\old.dll"))
    generator._terminated_process_keys.add(old_key)
    generator._terminated_process_times[old_key] = start + timedelta(seconds=3)
    assert state.end_process("WS-01", pid, start + timedelta(seconds=3))

    cutoff = start + timedelta(hours=1)
    state.advance_pid_allocation_watermark(cutoff)
    generator.advance_process_state_watermark(cutoff)
    state._pid_counters["WS-01"] = pid
    state.set_current_time(cutoff)
    reused_pid = state.create_process(
        "WS-01",
        0,
        r"C:\new.exe",
        "new.exe",
        "analyst",
        "Medium",
    )

    assert reused_pid == pid
    assert generator._process_instance_key("WS-01", pid) != old_key
    assert generator.process_source_create_time("WS-01", pid) is None
    assert generator.process_source_terminate_time("WS-01", pid) is None
    assert not generator._loaded_modules_by_process
    assert not generator._terminated_process_keys


def test_expired_linux_curl_is_not_valid_for_later_network_attribution() -> None:
    start = datetime(2024, 3, 18, 13, 28, 11, tzinfo=UTC)
    proc = _process("/usr/bin/curl", "curl -sS https://grafana.example/api/health", start)
    system = System(
        hostname="APP-INT-01",
        ip="10.10.2.30",
        os="Ubuntu 22.04",
        type="server",
    )
    generator = ActivityGenerator(StateManager(), {})

    assert not generator._foreground_process_expired_for_attribution(
        system,
        proc,
        start + timedelta(seconds=10),
    )
    assert generator._foreground_process_expired_for_attribution(
        system,
        proc,
        start + timedelta(minutes=5),
    )


def test_future_process_is_not_valid_for_network_attribution() -> None:
    start = datetime(2024, 3, 18, 13, 28, 11, tzinfo=UTC)
    proc = _process(
        r"C:\Program Files\Mozilla Firefox\firefox.exe",
        r'"C:\Program Files\Mozilla Firefox\firefox.exe" -osint -url https://example.test',
        start + timedelta(seconds=30),
    )
    system = System(
        hostname="WS-01",
        ip="10.10.1.20",
        os="Windows 11",
        type="workstation",
    )
    generator = ActivityGenerator(StateManager(), {})

    assert generator._foreground_process_expired_for_attribution(system, proc, start)


def test_reserved_kerberos_port_skips_active_connection_tuple() -> None:
    start = datetime(2024, 3, 18, 13, 28, 11, tzinfo=UTC)
    generator = ActivityGenerator(StateManager(), {})
    source_ip = "10.10.1.31"
    dc_ip = "10.10.2.10"
    dc_hostname = "DC-01"
    source_port = 54613

    generator._reserve_kerberos_source_port(source_ip, dc_hostname, start, source_port)
    generator._remember_connection_tuple(
        source_ip,
        source_port,
        dc_ip,
        88,
        "tcp",
        start,
        duration=7.0,
    )

    assert (
        generator._find_reserved_kerberos_source_port(
            source_ip,
            dc_hostname,
            start + timedelta(seconds=1),
            dst_ip=dc_ip,
        )
        is None
    )
    assert (
        generator._find_reserved_kerberos_source_port(
            source_ip,
            dc_hostname,
            start + timedelta(seconds=10),
            dst_ip=dc_ip,
            window_seconds=10.0,
        )
        == source_port
    )


def test_interactive_windows_shells_are_not_forced_to_short_lifetimes() -> None:
    assert _windows_foreground_lifetime(r"C:\Windows\System32\cmd.exe", "cmd.exe /k") is None
    assert (
        _windows_foreground_lifetime(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe",
        )
        is None
    )


def test_hourly_module_noise_skips_stale_one_shot_processes() -> None:
    start = datetime(2024, 3, 18, 13, 28, 11, tzinfo=UTC)
    proc = _process(
        r"C:\Windows\System32\dsquery.exe",
        'dsquery.exe group -name "Domain Admins"',
        start,
    )

    assert _eligible_for_hourly_module_load(proc, start + timedelta(seconds=8))
    assert not _eligible_for_hourly_module_load(proc, start + timedelta(minutes=10))


def test_hourly_module_noise_keeps_long_running_windows_processes() -> None:
    start = datetime(2024, 3, 18, 13, 28, 11, tzinfo=UTC)
    proc = _process(
        r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
        r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
        start,
    )

    assert _eligible_for_hourly_module_load(proc, start + timedelta(hours=2))


def test_image_load_after_exact_process_termination_is_suppressed() -> None:
    start = datetime(2024, 3, 18, 13, 28, 11, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(start)
    dispatcher = EventDispatcher(state_manager=state, emitters={})
    dispatcher.dispatch_builder = Mock()
    generator = ActivityGenerator(state, {}, dispatcher=dispatcher)
    system = System(
        hostname="WS-01",
        ip="10.10.1.44",
        os="Windows 11",
        type="workstation",
    )
    user = User(username="analyst", full_name="Alicia Analyst", email="analyst@example.local")
    pid = state.create_process(
        system=system.hostname,
        parent_pid=4,
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami",
        username=user.username,
        integrity_level="Medium",
        logon_id="0x1234",
    )
    state.end_process(system.hostname, pid, end_time=start + timedelta(seconds=2))

    generator.generate_image_load(
        user=user,
        system=system,
        time=start + timedelta(minutes=3),
        pid=pid,
        image=r"C:\Windows\System32\cmd.exe",
        dll_path=r"C:\Windows\System32\user32.dll",
    )

    dispatcher.dispatch_builder.assert_not_called()


def test_process_termination_dedup_allows_reused_windows_pid() -> None:
    start = datetime(2024, 3, 18, 17, 56, 39, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(start)
    dispatcher = EventDispatcher(state_manager=state, emitters={})
    generator = ActivityGenerator(state, {}, dispatcher=dispatcher)
    system = System(
        hostname="WS-01",
        ip="10.10.1.44",
        os="Windows 11",
        type="workstation",
    )
    user = User(
        username="analyst",
        full_name="Alicia Analyst",
        email="analyst@example.local",
    )

    first_pid = state.create_process(
        system=system.hostname,
        parent_pid=0,
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami",
        username=user.username,
        integrity_level="Medium",
        logon_id="0x1234",
    )
    first_proc = state.get_process(system.hostname, first_pid)
    assert first_proc is not None
    first_start_time = first_proc.start_time
    generator.generate_process_termination(
        user=user,
        system=system,
        time=start + timedelta(seconds=5),
        pid=first_pid,
        process_name=r"C:\Windows\System32\cmd.exe",
        logon_id="0x1234",
    )

    assert state.get_process(system.hostname, first_pid) is None
    assert generator._process_termination_recorded(system.hostname, first_pid, first_start_time)

    state.set_current_time(start + timedelta(minutes=10))
    state._pid_counters[system.hostname] = first_pid
    state._pid_os[system.hostname] = "windows"
    reused_pid = state.create_process(
        system=system.hostname,
        parent_pid=0,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -NoProfile -Command Get-Date",
        username=user.username,
        integrity_level="Medium",
        logon_id="0x1234",
    )
    reused_proc = state.get_process(system.hostname, reused_pid)
    assert reused_proc is not None
    reused_start_time = reused_proc.start_time

    assert reused_pid == first_pid
    assert reused_start_time != first_start_time

    generator.generate_process_termination(
        user=user,
        system=system,
        time=start + timedelta(minutes=10, seconds=5),
        pid=reused_pid,
        process_name=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        logon_id="0x1234",
    )

    assert state.get_process(system.hostname, reused_pid) is None
    assert generator._process_termination_recorded(system.hostname, reused_pid, reused_start_time)
