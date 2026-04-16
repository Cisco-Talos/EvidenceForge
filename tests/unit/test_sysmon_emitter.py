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

"""Unit tests for Sysmon event emitter."""

from datetime import UTC, datetime

import pytest

from evidenceforge.formats import load_format
from evidenceforge.generation.emitters import SysmonEventEmitter


class TestSysmonEventEmitter:
    """Tests for Sysmon Event Log emitter."""

    @pytest.fixture
    def format_def(self):
        """Load Sysmon Event format definition."""
        return load_format("windows_event_sysmon")

    @pytest.fixture
    def temp_output(self, tmp_path):
        """Create temporary output file path."""
        return tmp_path / "sysmon_events.xml"

    def test_emit_sysmon_process_create(self, format_def, temp_output):
        """Test emitting Sysmon Event 1 (ProcessCreate)."""
        emitter = SysmonEventEmitter(format_def, temp_output, buffer_size=1)

        event_data = {
            "EventID": 1,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "WKS-01.corp.local",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": 2756,
            "ExecutionThreadID": 3632,
            "UtcTime": "2024-01-15 10:30:00.000",
            "ProcessGuid": "{12345678-abcd-ef01-2345-678901234567}",
            "ProcessId": 8052,
            "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": r"cmd.exe /c whoami",
            "User": r"CORP\jsmith",
            "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
            "LogonId": "0x3e7abc",
            "IntegrityLevel": "Medium",
            "Hashes": "SHA1=ABC123,MD5=DEF456,SHA256=GHI789,IMPHASH=JKL012",
            "ParentProcessGuid": "{87654321-dcba-10fe-5432-109876543210}",
            "ParentProcessId": 4200,
            "ParentImage": r"C:\Windows\explorer.exe",
            "ParentCommandLine": r"C:\Windows\explorer.exe",
        }

        emitter.emit_event(event_data)
        emitter.close()

        content = temp_output.read_text()
        assert "<EventID>1</EventID>" in content
        assert "<Version>5</Version>" in content
        assert "<Level>4</Level>" in content
        assert "<Task>1</Task>" in content
        assert "<Keywords>0x8000000000000000</Keywords>" in content
        assert "Microsoft-Windows-Sysmon" in content
        assert "Microsoft-Windows-Sysmon/Operational" in content
        assert '<Data Name="ProcessGuid">{12345678-abcd-ef01-2345-678901234567}</Data>' in content
        assert '<Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>' in content
        assert '<Data Name="Hashes">SHA1=ABC123' in content
        assert '<Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>' in content

    def test_emit_sysmon_create_remote_thread(self, format_def, temp_output):
        """Test emitting Sysmon Event 8 (CreateRemoteThread)."""
        emitter = SysmonEventEmitter(format_def, temp_output, buffer_size=1)

        event_data = {
            "EventID": 8,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "WKS-01.corp.local",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": 1876,
            "ExecutionThreadID": 1444,
            "UtcTime": "2024-01-15 10:30:00.000",
            "SourceProcessGuid": "{11111111-2222-3333-4444-555555555555}",
            "SourceProcessId": 3772,
            "SourceImage": r"C:\Temp\inject.exe",
            "TargetProcessGuid": "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
            "TargetProcessId": 2812,
            "TargetImage": r"C:\Windows\explorer.exe",
            "NewThreadId": 840,
            "StartAddress": "0x02060000",
        }

        emitter.emit_event(event_data)
        emitter.close()

        content = temp_output.read_text()
        assert "<EventID>8</EventID>" in content
        assert "<Version>2</Version>" in content
        assert "<Task>8</Task>" in content
        assert '<Data Name="SourceProcessId">3772</Data>' in content
        assert '<Data Name="TargetProcessId">2812</Data>' in content
        assert '<Data Name="SourceImage">C:\\Temp\\inject.exe</Data>' in content
        assert '<Data Name="TargetImage">C:\\Windows\\explorer.exe</Data>' in content
        assert '<Data Name="StartAddress">0x02060000</Data>' in content

    def test_emit_sysmon_process_terminate(self, format_def, temp_output):
        """Test emitting Sysmon Event 5 (ProcessTerminate)."""
        emitter = SysmonEventEmitter(format_def, temp_output, buffer_size=1)

        event_data = {
            "EventID": 5,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "WKS-01.corp.local",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": 2756,
            "ExecutionThreadID": 3632,
            "UtcTime": "2024-01-15 10:30:00.000",
            "ProcessGuid": "{12345678-abcd-ef01-2345-678901234567}",
            "ProcessId": 8052,
            "Image": r"C:\Windows\System32\cmd.exe",
            "User": r"CORP\jsmith",
        }

        emitter.emit_event(event_data)
        emitter.close()

        content = temp_output.read_text()
        assert "<EventID>5</EventID>" in content
        assert "<Version>3</Version>" in content
        assert "<Task>5</Task>" in content
        assert '<Data Name="ProcessGuid">{12345678-abcd-ef01-2345-678901234567}</Data>' in content
        assert '<Data Name="ProcessId">8052</Data>' in content
        assert '<Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>' in content
        assert '<Data Name="User">CORP\\jsmith</Data>' in content

    def test_emit_sysmon_process_terminate_via_event(self, format_def, tmp_path):
        """Test Sysmon Event 5 via SecurityEvent dispatch."""
        from evidenceforge.events.base import SecurityEvent
        from evidenceforge.events.contexts import AuthContext, HostContext, ProcessContext

        output_dir = tmp_path / "output"
        output_dir.mkdir()
        emitter = SysmonEventEmitter(format_def, output_dir, buffer_size=1)

        host = HostContext(
            hostname="WKS-01",
            ip="10.0.0.50",
            os="Windows 10",
            os_category="windows",
            system_type="workstation",
            domain="corp.local",
            fqdn="WKS-01.corp.local",
            netbios_domain="CORP",
        )
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="process_terminate",
            src_host=host,
            process=ProcessContext(
                pid=8052,
                parent_pid=4200,
                image=r"C:\Windows\System32\cmd.exe",
                command_line="cmd.exe /c whoami",
                username="jsmith",
            ),
            auth=AuthContext(username="jsmith"),
        )

        assert emitter.can_handle(event) is True
        emitter.emit(event)
        emitter.close()

        output_file = output_dir / "WKS-01.corp.local" / "windows_event_sysmon.xml"
        assert output_file.exists()
        content = output_file.read_text()
        assert "<EventID>5</EventID>" in content
        assert '<Data Name="ProcessId">8052</Data>' in content

    def test_process_guid_deterministic(self, format_def, temp_output):
        """Test that ProcessGuid generation is deterministic."""
        emitter = SysmonEventEmitter(format_def, temp_output)
        ts = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)
        guid1 = emitter._generate_process_guid("WKS-01", 1234, ts)
        guid2 = emitter._generate_process_guid("WKS-01", 1234, ts)
        guid3 = emitter._generate_process_guid("WKS-01", 5678, ts)

        assert guid1 == guid2  # Same inputs → same GUID
        assert guid1 != guid3  # Different PID → different GUID
        assert guid1.startswith("{") and guid1.endswith("}")
        assert len(guid1) == 38  # {8-4-4-4-12} = 38 chars
