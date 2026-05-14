# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for process lifetime realism helpers."""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

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


def test_windows_docker_ps_has_bounded_foreground_lifetime() -> None:
    lifetime = _windows_foreground_lifetime(
        r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
        "docker.exe ps",
    )

    assert lifetime is not None
    assert lifetime[1] <= 8.0


def test_linux_curl_status_check_has_bounded_foreground_lifetime() -> None:
    lifetime = _linux_foreground_lifetime(
        "/usr/bin/curl",
        "curl -sS -o /dev/null -w '%{http_code}' https://grafana.corp.local/",
    )

    assert lifetime is not None
    assert lifetime[1] <= 18.0


def test_linux_expired_foreground_pid_is_not_reused_for_later_connection() -> None:
    state_manager = StateManager()
    start = datetime(2024, 3, 18, 13, 28, 11, tzinfo=UTC)
    state_manager.set_current_time(start)
    pid = state_manager.create_process(
        system="APP-01",
        parent_pid=0,
        image="/usr/bin/curl",
        command_line="curl -s https://api.example.com/status",
        username="analyst",
        integrity_level="Medium",
        logon_id="0x123",
    )
    process = state_manager.get_process("APP-01", pid)
    assert process is not None
    assert process.last_activity_time is None

    ecar = Mock()
    generator = ActivityGenerator(state_manager, {"ecar": ecar})
    system = System(hostname="APP-01", ip="10.10.3.20", os="Ubuntu 22.04", type="server")
    generator._ip_to_system = {system.ip: system}

    generator.generate_connection(
        src_ip=system.ip,
        dst_ip="198.51.100.10",
        time=start + timedelta(minutes=25),
        dst_port=443,
        proto="tcp",
        service="ssl",
        duration=0.8,
        orig_bytes=300,
        resp_bytes=1200,
        pid=pid,
        source_system=system,
        conn_state="SF",
    )

    event = ecar.emit.call_args[0][0]
    assert event.process is None
    assert event.network.initiating_pid == -1
    assert process.last_activity_time is None


def test_non_story_foreground_termination_is_capped_to_command_lifetime() -> None:
    state_manager = StateManager()
    start = datetime(2024, 3, 18, 13, 28, 11, tzinfo=UTC)
    state_manager.set_current_time(start)
    pid = state_manager.create_process(
        system="APP-01",
        parent_pid=0,
        image="/usr/bin/curl",
        command_line="curl -s https://api.example.com/status",
        username="analyst",
        integrity_level="Medium",
        logon_id="0x123",
    )
    process = state_manager.get_process("APP-01", pid)
    assert process is not None
    process.last_activity_time = start + timedelta(hours=1)

    ecar = Mock()
    generator = ActivityGenerator(state_manager, {"ecar": ecar})
    system = System(hostname="APP-01", ip="10.10.3.20", os="Ubuntu 22.04", type="server")
    user = User(username="analyst", full_name="Analyst", email="analyst@example.com")

    generator.generate_process_termination(
        user=user,
        system=system,
        time=start + timedelta(hours=2),
        pid=pid,
        process_name="/usr/bin/curl",
        logon_id="0x123",
    )

    event = ecar.emit.call_args[0][0]
    assert start < event.timestamp <= start + timedelta(seconds=20)


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
