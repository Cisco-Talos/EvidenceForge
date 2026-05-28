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

"""External parser tests for SOF-ELK Snare Windows Event ingestion."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from evidenceforge.external_parsers.sof_elk import run_sof_elk_parser
from evidenceforge.external_parsers.sof_elk_zeek import SofElkHarnessError, find_container_runtime
from evidenceforge.external_parsers.tag_policy import (
    SOF_ELK_WINDOWS_SECURITY_SNARE_VALIDATOR,
    SOF_ELK_WINDOWS_SYSMON_SNARE_VALIDATOR,
)
from evidenceforge.generation.emitters.windows_snare import (
    render_windows_security_snare_syslog,
    render_windows_sysmon_snare_syslog,
)

pytestmark = pytest.mark.external_parser


def test_sof_elk_parses_windows_security_and_sysmon_snare_sidecars(tmp_path: Path) -> None:
    runtime = _runtime_or_skip()
    data_dir = tmp_path / "data"
    host_dir = data_dir / "WIN-01.example.test" / "2026"
    host_dir.mkdir(parents=True)
    (host_dir / "windows_event_security_snare.log").write_text(
        render_windows_security_snare_syslog(_security_event()) + "\n",
        encoding="utf-8",
    )
    (host_dir / "windows_event_sysmon_snare.log").write_text(
        render_windows_sysmon_snare_syslog(_sysmon_event()) + "\n",
        encoding="utf-8",
    )

    result = run_sof_elk_parser(
        data_dir,
        tmp_path / "work",
        validators=(
            SOF_ELK_WINDOWS_SECURITY_SNARE_VALIDATOR,
            SOF_ELK_WINDOWS_SYSMON_SNARE_VALIDATOR,
        ),
        runtime=runtime,
    )

    assert result.logstash_config_tested
    assert result.manifest.expected_counts == {
        "windows_event_security_snare": 1,
        "windows_event_sysmon_snare": 1,
    }
    assert len(result.events_by_type["windows_event_security_snare"]) == 1
    assert len(result.events_by_type["windows_event_sysmon_snare"]) == 1


def _runtime_or_skip() -> str:
    try:
        return find_container_runtime()
    except SofElkHarnessError as exc:
        pytest.skip(str(exc))


def _security_event() -> dict[str, object]:
    return {
        "EventID": 4624,
        "TimeCreated": datetime(2026, 6, 15, 14, 23, 5, tzinfo=UTC),
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
        "ProcessId": "0x3e4",
        "ProcessName": "C:\\Windows\\System32\\lsass.exe",
        "IpAddress": "10.0.10.25",
        "IpPort": 54321,
    }


def _sysmon_event() -> dict[str, object]:
    return {
        "EventID": 1,
        "TimeCreated": datetime(2026, 6, 15, 14, 23, 6, tzinfo=UTC),
        "Computer": "WIN-01.example.test",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Level": 4,
        "EventRecordID": 100001,
        "ExecutionProcessID": 4020,
        "ExecutionThreadID": 4024,
        "RuleName": "-",
        "UtcTime": "2026-06-15 14:23:06.000",
        "ProcessGuid": "{11111111-1111-1111-1111-111111111111}",
        "ProcessId": 4321,
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "User": "CORP\\alice",
        "Hashes": "MD5=0123456789abcdef0123456789abcdef",
        "ParentProcessGuid": "{33333333-3333-3333-3333-333333333333}",
        "ParentProcessId": 4000,
        "ParentImage": "C:\\Windows\\explorer.exe",
        "ParentCommandLine": "C:\\Windows\\explorer.exe",
    }
