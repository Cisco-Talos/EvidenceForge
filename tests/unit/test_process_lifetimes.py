# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for process lifetime realism helpers."""

from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.generation.activity.generator import _windows_foreground_lifetime
from evidenceforge.generation.engine.baseline import _eligible_for_hourly_module_load
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
