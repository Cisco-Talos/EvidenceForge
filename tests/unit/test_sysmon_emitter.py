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

import re
from datetime import UTC, datetime, timedelta

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
        assert '<Data Name="ProcessGuid">{' in content
        assert '<Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>' in content
        assert '<Data Name="Hashes">SHA1=ABC123' in content
        assert '<Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>' in content

    def test_sysmon_thread_ids_reuse_pool_without_round_robin_balance(
        self, format_def, temp_output
    ):
        """Sysmon provider threads should be reused in bursts, not perfectly round-robin."""
        emitter = SysmonEventEmitter(format_def, temp_output, buffer_size=1)

        thread_ids = [emitter._get_sysmon_thread_id("WS-01") for _ in range(120)]
        counts = {thread_id: thread_ids.count(thread_id) for thread_id in set(thread_ids)}

        assert 3 <= len(counts) <= 5
        assert max(counts.values()) - min(counts.values()) >= 10

    def test_emit_sysmon_aligns_provider_execution_ids(self, format_def, temp_output):
        """Sysmon XML provider PID/TID values should be 4-byte aligned."""
        emitter = SysmonEventEmitter(format_def, temp_output, buffer_size=1)

        event_data = {
            "EventID": 1,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "WKS-01.corp.local",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": 2753,
            "ExecutionThreadID": 1543,
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
        assert '<Execution ProcessID="2756" ThreadID="1544"/>' in content

    def test_emit_sysmon_preserves_oversized_decimal_execution_id(self, format_def, temp_output):
        """Oversized raw decimal PID/TID strings should not abort Sysmon XML rendering."""
        emitter = SysmonEventEmitter(format_def, temp_output, buffer_size=1)
        oversized_pid = "9" * 5000

        event_data = {
            "EventID": 1,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "WKS-01.corp.local",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": oversized_pid,
            "ExecutionThreadID": "1543",
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
        assert f'<Execution ProcessID="{oversized_pid}" ThreadID="1544"/>' in content

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
            "StartModule": r"C:\Windows\System32\kernel32.dll",
            "StartFunction": "BaseThreadInitThunk",
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
        assert '<Data Name="StartModule">C:\\Windows\\System32\\kernel32.dll</Data>' in content
        assert '<Data Name="StartFunction">BaseThreadInitThunk</Data>' in content

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
        assert 'SystemTime="2024-01-15T10:30:00.0000000Z"' not in content
        assert '<Data Name="UtcTime">2024-01-15 10:30:00.000</Data>' not in content

    def test_logon_guid_is_stable_per_host_logon_session(self, format_def, temp_output):
        """Sysmon LogonGuid should identify the logon session, not each process."""
        emitter = SysmonEventEmitter(format_def, temp_output, buffer_size=10)

        guid_a = emitter._generate_logon_guid("WKS-01", "0xabc123")
        guid_b = emitter._generate_logon_guid("WKS-01", "0xabc123")
        guid_other_session = emitter._generate_logon_guid("WKS-01", "0xdef456")
        guid_other_host = emitter._generate_logon_guid("WKS-02", "0xabc123")

        assert guid_a == guid_b
        assert guid_a != guid_other_session
        assert guid_a != guid_other_host
        assert re.fullmatch(
            r"\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}",
            guid_a,
        )

    def test_process_create_uses_state_session_logon_guid(self, format_def, tmp_path):
        """Sysmon Event 1 should share the canonical session LogonGuid with Security 4624."""
        from evidenceforge.events.base import SecurityEvent
        from evidenceforge.events.contexts import AuthContext, HostContext, ProcessContext
        from evidenceforge.generation.state_manager import StateManager

        output_dir = tmp_path / "output"
        output_dir.mkdir()
        emitter = SysmonEventEmitter(format_def, output_dir, buffer_size=1)
        state_manager = StateManager()
        state_manager.set_current_time(datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC))
        logon_id = state_manager.create_session("jsmith", "WKS-01", 3, "10.0.0.20")
        logon_guid = state_manager.get_or_create_session_logon_guid(logon_id, "WKS-01")
        emitter._state_manager = state_manager

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
            timestamp=datetime(2024, 1, 15, 10, 30, 5, tzinfo=UTC),
            event_type="process_create",
            src_host=host,
            auth=AuthContext(username="jsmith", logon_id=logon_id),
            process=ProcessContext(
                pid=8052,
                parent_pid=4200,
                image=r"C:\Windows\System32\cmd.exe",
                command_line="cmd.exe /c whoami",
                username="jsmith",
                logon_id=logon_id,
            ),
        )

        emitter.emit(event)
        emitter.close()

        output_file = output_dir / "WKS-01.corp.local" / "windows_event_sysmon.xml"
        content = output_file.read_text()
        assert f'<Data Name="LogonGuid">{logon_guid}</Data>' in content
        assert f'<Data Name="LogonId">{logon_id}</Data>' in content

    def test_create_remote_thread_uses_canonical_context_values(self, format_def, tmp_path):
        """Sysmon Event 8 should not derive fields independently from eCAR."""
        from evidenceforge.events.base import SecurityEvent
        from evidenceforge.events.contexts import (
            AuthContext,
            HostContext,
            ProcessContext,
            RemoteThreadContext,
        )

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
            event_type="create_remote_thread",
            src_host=host,
            auth=AuthContext(username="jsmith", target_server=r"C:\Windows\System32\lsass.exe"),
            process=ProcessContext(
                pid=3772,
                parent_pid=4200,
                image=r"C:\Temp\inject.exe",
                command_line=r"C:\Temp\inject.exe",
                username="jsmith",
            ),
            remote_thread=RemoteThreadContext(
                target_pid=688,
                target_image=r"C:\Windows\System32\lsass.exe",
                new_thread_id=840,
                start_address=0x02060000,
                start_module=r"C:\Windows\System32\ntdll.dll",
                start_function="NtCreateThreadEx",
            ),
        )

        emitter.emit(event)
        emitter.close()

        output_file = output_dir / "WKS-01.corp.local" / "windows_event_sysmon.xml"
        content = output_file.read_text()
        assert '<Data Name="TargetProcessId">688</Data>' in content
        assert '<Data Name="NewThreadId">840</Data>' in content
        assert '<Data Name="StartAddress">0x02060000</Data>' in content
        assert '<Data Name="StartModule">C:\\Windows\\System32\\ntdll.dll</Data>' in content
        assert '<Data Name="StartFunction">NtCreateThreadEx</Data>' in content

    def test_process_terminate_guid_uses_process_create_render_time(self, format_def, tmp_path):
        """Event 5 ProcessGuid should match Event 1 even after process state is removed."""
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
        start_time = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)
        terminate_time = datetime(2024, 1, 15, 10, 35, 0, tzinfo=UTC)
        event = SecurityEvent(
            timestamp=terminate_time,
            event_type="process_terminate",
            src_host=host,
            process=ProcessContext(
                pid=8052,
                parent_pid=4200,
                image=r"C:\Windows\System32\cmd.exe",
                command_line="",
                username="jsmith",
                start_time=start_time,
            ),
            auth=AuthContext(username="jsmith"),
        )

        expected_guid = emitter._get_stable_process_guid("WKS-01", 8052, start_time)
        terminate_time_guid = emitter._get_stable_process_guid("WKS-01", 8052, terminate_time)

        emitter.emit(event)
        emitter.close()

        output_file = output_dir / "WKS-01.corp.local" / "windows_event_sysmon.xml"
        content = output_file.read_text()
        assert f'<Data Name="ProcessGuid">{expected_guid}</Data>' in content
        assert terminate_time_guid not in content

    def test_process_terminate_payload_time_updates_after_followon_shift(
        self, format_def, temp_output
    ):
        """Event 5 UtcTime should follow final source-native TimeCreated normalization."""
        emitter = SysmonEventEmitter(format_def, temp_output, buffer_size=100)
        guid = "{12345678-abcd-ef01-2345-678901234567}"
        base = {
            "Computer": "WKS-01.corp.local",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": 2756,
            "ExecutionThreadID": 3632,
            "ProcessGuid": guid,
            "ProcessId": 8052,
            "Image": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "User": r"CORP\jsmith",
        }
        emitter.emit_event(
            {
                **base,
                "EventID": 7,
                "TimeCreated": datetime(2024, 1, 15, 16, 32, 44, 527000, tzinfo=UTC),
                "UtcTime": "2024-01-15 16:32:44.527",
                "ImageLoaded": r"C:\Program Files\Microsoft Office\root\Office16\mso.dll",
                "Hashes": "SHA1=ABC,MD5=DEF,SHA256=GHI,IMPHASH=JKL",
                "Signed": "true",
                "Signature": "Microsoft Corporation",
                "SignatureStatus": "Valid",
            }
        )
        emitter.emit_event(
            {
                **base,
                "EventID": 5,
                "TimeCreated": datetime(2024, 1, 15, 15, 44, 49, 138000, tzinfo=UTC),
                "UtcTime": "2024-01-15 15:44:49.138",
            }
        )

        emitter.close()

        content = temp_output.read_text()
        event5 = content.split("<EventID>5</EventID>", 1)[1]
        assert "2024-01-15 15:44:49.138" not in event5
        assert '<Data Name="UtcTime">2024-01-15 16:32:44.' in event5

    def test_interactive_process_create_uses_nonzero_terminal_session(self, format_def, tmp_path):
        """Interactive user process creates should not all render TerminalSessionId 0."""
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
            event_type="process_create",
            src_host=host,
            process=ProcessContext(
                pid=8052,
                parent_pid=4200,
                image=r"C:\Windows\explorer.exe",
                command_line=r"C:\Windows\explorer.exe",
                username="jsmith",
                logon_id="0xabc123",
            ),
            auth=AuthContext(username="jsmith", logon_id="0xabc123", logon_type=2),
        )

        emitter.emit(event)
        emitter.close()

        content = (output_dir / "WKS-01.corp.local" / "windows_event_sysmon.xml").read_text()
        match = re.search(r'<Data Name="TerminalSessionId">(\d+)</Data>', content)
        assert match is not None
        assert int(match.group(1)) > 0

    def test_process_create_prefers_canonical_auth_session_id(self, format_def, tmp_path):
        """Sysmon TerminalSessionId should reuse the StateManager-owned session ID."""
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
            event_type="process_create",
            src_host=host,
            process=ProcessContext(
                pid=8052,
                parent_pid=4200,
                image=r"C:\Windows\explorer.exe",
                command_line=r"C:\Windows\explorer.exe",
                username="jsmith",
                logon_id="0xabc123",
            ),
            auth=AuthContext(
                username="jsmith",
                logon_id="0xabc123",
                session_id=7,
                logon_type=2,
            ),
        )

        emitter.emit(event)
        emitter.close()

        content = (output_dir / "WKS-01.corp.local" / "windows_event_sysmon.xml").read_text()
        assert '<Data Name="TerminalSessionId">7</Data>' in content

    def test_process_create_keeps_terminal_session_stable_per_logon_id(self, format_def, tmp_path):
        """Sysmon TerminalSessionId should not drift for children in the same logon."""
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
        logon_id = "0xabc123"
        parent = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="process_create",
            src_host=host,
            process=ProcessContext(
                pid=8052,
                parent_pid=4200,
                image=r"C:\Windows\System32\cmd.exe",
                command_line=r"C:\Windows\System32\cmd.exe /k",
                username="jsmith",
                logon_id=logon_id,
            ),
            auth=AuthContext(username="jsmith", logon_id=logon_id, session_id=2, logon_type=2),
        )
        child = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 1, tzinfo=UTC),
            event_type="process_create",
            src_host=host,
            process=ProcessContext(
                pid=8056,
                parent_pid=8052,
                image=r"C:\Windows\System32\whoami.exe",
                command_line="whoami /all",
                username="jsmith",
                logon_id=logon_id,
            ),
            auth=AuthContext(username="jsmith", logon_id=logon_id, session_id=4, logon_type=2),
        )

        emitter.emit(parent)
        emitter.emit(child)
        emitter.close()

        content = (output_dir / "WKS-01.corp.local" / "windows_event_sysmon.xml").read_text()
        session_ids = re.findall(r'<Data Name="TerminalSessionId">(\d+)</Data>', content)
        assert session_ids == ["2", "2"]

    def test_process_create_renders_current_directory_from_context(self, format_def, tmp_path):
        """Sysmon Event 1 should preserve the process working directory."""
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
            event_type="process_create",
            src_host=host,
            process=ProcessContext(
                pid=8052,
                parent_pid=4200,
                image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                command_line='WINWORD.EXE /n "Vendor Proposal.docx"',
                username="jsmith",
                logon_id="0xabc123",
                current_directory="C:\\Users\\jsmith\\Documents\\",
            ),
            auth=AuthContext(username="jsmith", logon_id="0xabc123", logon_type=2),
        )

        emitter.emit(event)
        emitter.close()

        content = (output_dir / "WKS-01.corp.local" / "windows_event_sysmon.xml").read_text()
        assert '<Data Name="CurrentDirectory">C:\\Users\\jsmith\\Documents\\</Data>' in content

    def test_process_create_parent_guid_uses_context_parent_start_time(self, format_def, tmp_path):
        """ParentProcessGuid should not be recomputed from a later reused parent PID."""
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
        parent_start = datetime(2024, 1, 15, 9, 59, 0, tzinfo=UTC)
        child_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        later_reused_parent_start = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)
        event = SecurityEvent(
            timestamp=child_start,
            event_type="process_create",
            src_host=host,
            process=ProcessContext(
                pid=8052,
                parent_pid=4200,
                image=r"C:\Windows\System32\cmd.exe",
                command_line="cmd.exe /c whoami",
                username="jsmith",
                parent_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                parent_command_line="powershell.exe",
                parent_start_time=parent_start,
                start_time=child_start,
            ),
            auth=AuthContext(username="jsmith", logon_id="0xabc123"),
        )

        expected_parent_guid = emitter._get_stable_process_guid("WKS-01", 4200, parent_start)
        later_parent_guid = emitter._get_stable_process_guid(
            "WKS-01", 4200, later_reused_parent_start
        )

        emitter.emit(event)
        emitter.close()

        output_file = output_dir / "WKS-01.corp.local" / "windows_event_sysmon.xml"
        content = output_file.read_text()
        assert f'<Data Name="ParentProcessGuid">{expected_parent_guid}</Data>' in content
        assert later_parent_guid not in content

    def test_close_preserves_chronological_order_for_same_second_events(
        self, format_def, temp_output
    ):
        """Rendered microsecond jitter should not reorder same-second Sysmon events."""
        emitter = SysmonEventEmitter(format_def, temp_output, buffer_size=10)

        for idx in range(5):
            emitter.emit_event(
                {
                    "EventID": 5,
                    "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
                    "Computer": "WKS-01.corp.local",
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "Level": 4,
                    "ExecutionProcessID": 2756,
                    "ExecutionThreadID": 3632 + idx,
                    "UtcTime": "2024-01-15 10:30:00.000",
                    "ProcessGuid": f"{{12345678-abcd-ef01-2345-67890123456{idx}}}",
                    "ProcessId": 8052 + idx,
                    "Image": r"C:\Windows\System32\cmd.exe",
                    "User": r"CORP\jsmith",
                }
            )

        emitter.close()

        content = temp_output.read_text()
        timestamps = re.findall(r'SystemTime="([^"]+)"', content)
        assert timestamps == sorted(timestamps)
        assert len(set(timestamps)) == len(timestamps)
        assert all(re.search(r"\.\d{7}Z$", ts) for ts in timestamps)

    def test_follow_on_shifted_after_process_create(self, format_def, temp_output):
        """Follow-on telemetry with a ProcessGuid should not precede Event 1."""
        emitter = SysmonEventEmitter(format_def, temp_output, buffer_size=10)
        create_time = datetime(2024, 1, 15, 10, 0, 10, tzinfo=UTC)
        follow_on_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        process_guid = "{12345678-abcd-ef01-2345-678901234567}"

        emitter._event_dicts = [
            {
                "EventID": 7,
                "TimeCreated": follow_on_time,
                "Computer": "WKS-01.corp.local",
                "ProcessGuid": process_guid,
            },
            {
                "EventID": 1,
                "TimeCreated": create_time,
                "Computer": "WKS-01.corp.local",
                "ProcessGuid": process_guid,
            },
        ]

        emitter._shift_followons_after_process_create()

        assert emitter._event_dicts[0]["TimeCreated"] == create_time + timedelta(milliseconds=1)

    def test_process_create_shifted_after_visible_parent_create_transitively(
        self, format_def, temp_output
    ):
        """Multi-level child Event 1 records should render after shifted visible parent Event 1 records."""
        emitter = SysmonEventEmitter(format_def, temp_output, buffer_size=10)
        root_guid = "{11111111-abcd-ef01-2345-678901234567}"
        parent_guid = "{22222222-abcd-ef01-2345-678901234567}"
        child_guid = "{33333333-abcd-ef01-2345-678901234567}"
        root_time = datetime(2024, 1, 15, 10, 0, 10, tzinfo=UTC)
        parent_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        child_time = datetime(2024, 1, 15, 10, 0, 0, 500000, tzinfo=UTC)

        emitter._event_dicts = [
            {
                "EventID": 1,
                "TimeCreated": parent_time,
                "Computer": "WKS-01.corp.local",
                "ProcessGuid": parent_guid,
                "ParentProcessGuid": root_guid,
            },
            {
                "EventID": 1,
                "TimeCreated": child_time,
                "Computer": "WKS-01.corp.local",
                "ProcessGuid": child_guid,
                "ParentProcessGuid": parent_guid,
            },
            {
                "EventID": 1,
                "TimeCreated": root_time,
                "Computer": "WKS-01.corp.local",
                "ProcessGuid": root_guid,
            },
        ]

        emitter._shift_process_creates_after_visible_parent()

        shifted_parent_time = emitter._event_dicts[0]["TimeCreated"]
        shifted_child_time = emitter._event_dicts[1]["TimeCreated"]
        assert shifted_parent_time > root_time
        assert shifted_child_time > shifted_parent_time

    def test_process_create_shifted_after_visible_parent_create(self, format_def, temp_output):
        """Child Event 1 should not render before a visible parent Event 1."""
        emitter = SysmonEventEmitter(format_def, temp_output, buffer_size=10)
        parent_time = datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC)
        child_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        parent_guid = "{12345678-abcd-ef01-2345-678901234567}"

        emitter._event_dicts = [
            {
                "EventID": 1,
                "TimeCreated": child_time,
                "Computer": "WKS-01.corp.local",
                "ProcessGuid": "{22222222-abcd-ef01-2345-678901234567}",
                "ParentProcessGuid": parent_guid,
            },
            {
                "EventID": 1,
                "TimeCreated": parent_time,
                "Computer": "WKS-01.corp.local",
                "ProcessGuid": parent_guid,
            },
        ]

        emitter._shift_process_creates_after_visible_parent()

        assert emitter._event_dicts[0]["TimeCreated"] == parent_time + timedelta(milliseconds=1)

    def test_process_create_self_parent_is_not_shifted_forever(self, format_def, temp_output):
        """Self-parent raw Sysmon Event 1 records should be treated as unshiftable."""
        emitter = SysmonEventEmitter(format_def, temp_output, buffer_size=10)
        event_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        process_guid = "{12345678-abcd-ef01-2345-678901234567}"

        emitter._event_dicts = [
            {
                "EventID": 1,
                "TimeCreated": event_time,
                "Computer": "WKS-01.corp.local",
                "ProcessGuid": process_guid,
                "ParentProcessGuid": process_guid,
            },
        ]

        emitter._shift_process_creates_after_visible_parent()

        assert emitter._event_dicts[0]["TimeCreated"] == event_time

    def test_process_create_parent_cycle_is_not_shifted_forever(self, format_def, temp_output):
        """Cyclic raw Sysmon parent relationships should be treated as unshiftable."""
        emitter = SysmonEventEmitter(format_def, temp_output, buffer_size=10)
        first_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        second_time = datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC)
        first_guid = "{11111111-abcd-ef01-2345-678901234567}"
        second_guid = "{22222222-abcd-ef01-2345-678901234567}"

        emitter._event_dicts = [
            {
                "EventID": 1,
                "TimeCreated": first_time,
                "Computer": "WKS-01.corp.local",
                "ProcessGuid": first_guid,
                "ParentProcessGuid": second_guid,
            },
            {
                "EventID": 1,
                "TimeCreated": second_time,
                "Computer": "WKS-01.corp.local",
                "ProcessGuid": second_guid,
                "ParentProcessGuid": first_guid,
            },
        ]

        emitter._shift_process_creates_after_visible_parent()

        assert emitter._event_dicts[0]["TimeCreated"] == first_time
        assert emitter._event_dicts[1]["TimeCreated"] == second_time

    def test_termination_shifted_after_follow_on(self, format_def, temp_output):
        """Event 5 should not precede later visible telemetry for the same ProcessGuid."""
        emitter = SysmonEventEmitter(format_def, temp_output, buffer_size=10)
        terminate_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        network_time = datetime(2024, 1, 15, 10, 0, 10, tzinfo=UTC)
        process_guid = "{12345678-abcd-ef01-2345-678901234567}"

        emitter._event_dicts = [
            {
                "EventID": 5,
                "TimeCreated": terminate_time,
                "Computer": "WKS-01.corp.local",
                "ProcessGuid": process_guid,
            },
            {
                "EventID": 3,
                "TimeCreated": network_time,
                "Computer": "WKS-01.corp.local",
                "ProcessGuid": process_guid,
            },
        ]

        emitter._shift_terminations_after_followons()

        assert emitter._event_dicts[0]["TimeCreated"] == network_time + timedelta(milliseconds=1)

    def test_parent_termination_shifted_after_child_create(self, format_def, temp_output):
        """A visible child Event 1 should keep the parent ProcessGuid alive."""
        emitter = SysmonEventEmitter(format_def, temp_output, buffer_size=10)
        terminate_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        child_time = datetime(2024, 1, 15, 10, 0, 10, tzinfo=UTC)
        parent_guid = "{12345678-abcd-ef01-2345-678901234567}"

        emitter._event_dicts = [
            {
                "EventID": 5,
                "TimeCreated": terminate_time,
                "Computer": "WKS-01.corp.local",
                "ProcessGuid": parent_guid,
            },
            {
                "EventID": 1,
                "TimeCreated": child_time,
                "Computer": "WKS-01.corp.local",
                "ProcessGuid": "{22222222-abcd-ef01-2345-678901234567}",
                "ParentProcessGuid": parent_guid,
            },
        ]

        emitter._shift_terminations_after_followons()

        assert emitter._event_dicts[0]["TimeCreated"] == child_time + timedelta(milliseconds=1)

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
        assert guid1.strip("{}").split("-")[3] != f"{1234:04x}"
        assert not guid1.strip("{}").split("-")[4].startswith("000000")

    def test_event1_time_shift_rewrites_process_guid_references(self, format_def, temp_output):
        """Final Event 1 timestamp shifts should not leave stale ProcessGuid references."""
        emitter = SysmonEventEmitter(format_def, temp_output)
        original = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)
        shifted = original + timedelta(seconds=2)
        old_guid = emitter._generate_process_guid("WKS-01", 1234, original)
        new_guid = emitter._generate_process_guid("WKS-01", 1234, shifted)
        emitter._event_dicts = [
            {
                "EventID": 1,
                "Computer": "WKS-01.corp.local",
                "TimeCreated": shifted,
                "ProcessGuid": old_guid,
                "ProcessId": 1234,
            },
            {
                "EventID": 5,
                "Computer": "WKS-01.corp.local",
                "TimeCreated": shifted + timedelta(seconds=1),
                "ProcessGuid": old_guid,
                "ProcessId": 1234,
            },
        ]

        emitter._sync_process_guids_to_event1_times()

        assert emitter._event_dicts[0]["ProcessGuid"] == new_guid
        assert emitter._event_dicts[1]["ProcessGuid"] == new_guid

    def test_event1_time_shift_persists_process_guid_for_later_batches(
        self, format_def, temp_output
    ):
        """Event 1 GUID rewrites should persist for follow-on events in later flushes."""
        emitter = SysmonEventEmitter(format_def, temp_output)
        original = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)
        shifted = original + timedelta(microseconds=453)
        old_guid = emitter._generate_process_guid("WKS-01", 1234, original)
        new_guid = emitter._generate_process_guid("WKS-01", 1234, shifted)
        emitter._event_dicts = [
            {
                "EventID": 1,
                "Computer": "WKS-01.corp.local",
                "TimeCreated": shifted,
                "ProcessGuid": old_guid,
                "ProcessId": 1234,
            }
        ]

        emitter._sync_process_guids_to_event1_times()

        assert emitter._event_dicts[0]["ProcessGuid"] == new_guid
        assert emitter._get_stable_process_guid("WKS-01", 1234, original) == new_guid
