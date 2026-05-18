# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Tests for Windows Snare-over-syslog sidecar output."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from evidenceforge.formats.loader import load_format
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
from evidenceforge.generation.emitters.windows import WindowsEventEmitter
from evidenceforge.generation.emitters.windows_snare import (
    render_windows_security_snare_syslog,
)


def test_windows_security_snare_renderer_uses_payload_marker_without_syslog_app_tag() -> None:
    event = _security_event(datetime(2026, 6, 15, 14, 23, 5, tzinfo=UTC))

    rendered = render_windows_security_snare_syslog(event)

    assert rendered.startswith(
        "<86>Jun 15 14:23:05 WIN-01.example.test "
        "WIN-01.example.test\tMSWinEventLog\t0\tSecurity\t101\t"
    )
    assert "\t4624\tMicrosoft-Windows-Security-Auditing\talice\t" in rendered
    assert "An account was successfully logged on.:  " in rendered
    assert "Security ID: S-1-5-18" in rendered
    assert "Account Name: alice" in rendered


def test_windows_security_emitter_writes_xml_and_year_partitioned_snare_sidecar(
    tmp_path: Path,
) -> None:
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path,
        buffer_size=10,
    )
    emitter.emit_event(_security_event(datetime(2025, 12, 31, 23, 59, 58, tzinfo=UTC)))
    emitter.emit_event(_security_event(datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC)))
    emitter.close()

    xml_path = tmp_path / "WIN-01.example.test" / "windows_event_security.xml"
    snare_2025 = tmp_path / "WIN-01.example.test" / "2025" / "windows_event_security_snare.log"
    snare_2026 = tmp_path / "WIN-01.example.test" / "2026" / "windows_event_security_snare.log"

    assert xml_path.exists()
    assert snare_2025.exists()
    assert snare_2026.exists()
    assert "\tSecurity\t" in snare_2026.read_text(encoding="utf-8")
    assert "\tMicrosoft-Windows-Security-Auditing\t" in snare_2026.read_text(encoding="utf-8")


def test_sysmon_emitter_writes_xml_and_year_partitioned_snare_sidecar(tmp_path: Path) -> None:
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path,
        buffer_size=10,
    )
    emitter.emit_event(_sysmon_process_create_event(datetime(2026, 6, 15, 14, 23, 5, tzinfo=UTC)))
    emitter.close()

    xml_path = tmp_path / "WIN-01.example.test" / "windows_event_sysmon.xml"
    snare_path = tmp_path / "WIN-01.example.test" / "2026" / "windows_event_sysmon_snare.log"
    snare = snare_path.read_text(encoding="utf-8")

    assert xml_path.exists()
    assert snare.startswith(
        "<14>Jun 15 14:23:05 WIN-01.example.test "
        "WIN-01.example.test\tMSWinEventLog\t0\t"
        "Microsoft-Windows-Sysmon/Operational\t"
    )
    assert "\t1\tMicrosoft-Windows-Sysmon\tCORP\\alice\t" in snare
    assert "ProcessId: 4321" in snare
    assert "Image: C:\\Windows\\System32\\cmd.exe" in snare
    assert "UtcTime: 2026-06-15 14:23:05." in snare


def _security_event(timestamp: datetime) -> dict[str, object]:
    return {
        "EventID": 4624,
        "TimeCreated": timestamp,
        "Computer": "WIN-01.example.test",
        "Channel": "Security",
        "Level": 0,
        "EventRecordID": 101,
        "ExecutionProcessID": 704,
        "ExecutionThreadID": 812,
        "SubjectUserSid": "S-1-5-18",
        "SubjectUserName": "SYSTEM",
        "SubjectDomainName": "NT AUTHORITY",
        "SubjectLogonId": "0x3e7",
        "TargetUserSid": "S-1-5-21-1000-1001",
        "TargetUserName": "alice",
        "TargetDomainName": "CORP",
        "TargetLogonId": "0x46a3f",
        "LogonType": 3,
        "WorkstationName": "WS-01",
        "ProcessId": "0x3e4",
        "ProcessName": "C:\\Windows\\System32\\lsass.exe",
        "IpAddress": "10.0.10.25",
        "IpPort": 54321,
    }


def _sysmon_process_create_event(timestamp: datetime) -> dict[str, object]:
    return {
        "EventID": 1,
        "TimeCreated": timestamp,
        "Computer": "WIN-01.example.test",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Level": 4,
        "EventRecordID": 100001,
        "ExecutionProcessID": 4020,
        "ExecutionThreadID": 4024,
        "RuleName": "-",
        "UtcTime": "2026-06-15 14:23:05.000",
        "ProcessGuid": "{11111111-1111-1111-1111-111111111111}",
        "ProcessId": 4321,
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "User": "CORP\\alice",
        "LogonGuid": "{22222222-2222-2222-2222-222222222222}",
        "LogonId": "0x46a3f",
        "IntegrityLevel": "Medium",
        "Hashes": "MD5=0123456789abcdef0123456789abcdef",
        "ParentProcessGuid": "{33333333-3333-3333-3333-333333333333}",
        "ParentProcessId": 4000,
        "ParentImage": "C:\\Windows\\explorer.exe",
        "ParentCommandLine": "C:\\Windows\\explorer.exe",
    }
