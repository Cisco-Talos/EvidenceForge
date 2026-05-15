# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for process lifetime realism helpers."""

from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.generator import (
    _linux_foreground_lifetime,
    _windows_foreground_lifetime,
)
from evidenceforge.generation.engine.baseline import _eligible_for_hourly_module_load
from evidenceforge.generation.state_manager import StateManager
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


def test_sqlcmd_select_query_has_bounded_foreground_lifetime() -> None:
    lifetime = _windows_foreground_lifetime(
        r"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe",
        'sqlcmd.exe -S localhost -d webapp_prod -Q "SELECT TOP 50 * FROM dbo.AuditLog"',
    )

    assert lifetime is not None
    assert lifetime[1] <= 25.0


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
    assert (system.hostname, pid) in generator._terminated_process_keys


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
    assert (system.hostname, pid) not in generator._terminated_process_keys


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
