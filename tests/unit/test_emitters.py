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

"""Unit tests for log emitters."""

import json
import re
from datetime import UTC, datetime

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import AuthContext, HostContext, NetworkContext
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters import WindowsEventEmitter, ZeekEmitter
from evidenceforge.generation.emitters.host_base import sanitize_host_routing_key
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.utils import generate_zeek_uid


class TestWindowsEventEmitter:
    """Tests for Windows Event Log emitter."""

    @pytest.fixture
    def format_def(self):
        """Load Windows Event format definition."""
        return load_format("windows_event_security")

    @pytest.fixture
    def temp_output(self, tmp_path):
        """Create temporary output file path."""
        return tmp_path / "windows_events.xml"

    def test_emit_logon_event(self, format_def, temp_output):
        """Test emitting a single logon event (4624)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        event_data = {
            "EventID": 4624,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 45, 123456, tzinfo=UTC),
            "Computer": "WIN-TEST-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "EventRecordID": 12345,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 100,
            # Logon variant fields
            "TargetUserName": "jsmith",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x3e7abc",
            "LogonType": 2,
            "WorkstationName": "WIN-TEST-01",
            "IpAddress": "192.168.1.100",
            "LogonProcessName": "User32",
            "AuthenticationPackageName": "Negotiate",
        }

        emitter.emit_event(event_data)
        emitter.close()

        # Verify file was created
        assert temp_output.exists()

        # Read and verify content
        content = temp_output.read_text()
        assert "<EventID>4624</EventID>" in content
        assert "<TimeCreated" in content
        assert re.search(r"2024-01-15T10:30:45\.123456\dZ", content)
        assert "<Computer>WIN-TEST-01.corp.local</Computer>" in content
        assert '<Data Name="TargetUserName">jsmith</Data>' in content

    def test_network_logon_workstation_name_uses_source_host(self, format_def, temp_output):
        """Network 4624 events should name the source workstation, not the destination."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 45, tzinfo=UTC),
            event_type="logon",
            src_host=HostContext(
                hostname="WS-01",
                ip="10.0.1.10",
                fqdn="WS-01.example.com",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
            ),
            dst_host=HostContext(
                hostname="FS-01",
                ip="10.0.2.20",
                fqdn="FS-01.example.com",
                os="Windows Server 2022",
                os_category="windows",
                system_type="server",
            ),
            auth=AuthContext(
                username="jsmith",
                user_sid="S-1-5-21-1-2-3-1001",
                logon_id="0x12345",
                logon_type=3,
                source_ip="10.0.1.10",
                auth_package="NTLM",
                logon_process="NtLmSsp",
                lm_package="NTLM V2",
                subject_sid="S-1-5-18",
                subject_username="SYSTEM",
                subject_domain="NT AUTHORITY",
                subject_logon_id="0x3e7",
                reporting_pid=744,
            ),
        )

        emitter.emit(event)
        emitter.close()

        content = temp_output.read_text()
        assert '<Data Name="WorkstationName">WS-01</Data>' in content
        assert "<Computer>FS-01.example.com</Computer>" in content

    def test_emit_logoff_event(self, format_def, temp_output):
        """Test emitting a logoff event (4634)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        event_data = {
            "EventID": 4634,
            "TimeCreated": datetime(2024, 1, 15, 18, 15, 30, 0, tzinfo=UTC),
            "Computer": "WIN-TEST-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "EventRecordID": 12346,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 100,
            # Logoff variant fields
            "TargetUserName": "jsmith",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x3e7abc",
            "LogonType": 2,
        }

        emitter.emit_event(event_data)
        emitter.close()

        # Verify file was created
        assert temp_output.exists()

        # Read and verify content
        content = temp_output.read_text()
        assert "<EventID>4634</EventID>" in content
        assert "2024-01-15T18:15:30." in content  # Microseconds are jittered
        assert '<Data Name="TargetUserName">jsmith</Data>' in content

        print(f"\n{'=' * 80}")
        print("WINDOWS EVENT LOG SAMPLE (4634 - Logoff):")
        print(f"{'=' * 80}")
        print(content)
        print(f"{'=' * 80}\n")

    def test_emit_process_creation_event(self, format_def, temp_output):
        """Test emitting a process creation event (4688)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        event_data = {
            "EventID": 4688,
            "TimeCreated": datetime(2024, 1, 15, 10, 31, 0, 0, tzinfo=UTC),
            "Computer": "WIN-TEST-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "EventRecordID": 12347,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 100,
            # Process variant fields
            "SubjectUserName": "jsmith",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7abc",
            "NewProcessId": "0x1234",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "TokenElevationType": "%%1936",
            "ProcessId": "0x5678",
            "CommandLine": "cmd.exe /c dir",
            "TargetUserName": "jsmith",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x3e7abc",
        }

        emitter.emit_event(event_data)
        emitter.close()

        # Verify file was created
        assert temp_output.exists()

        # Read and verify content
        content = temp_output.read_text()
        assert "<EventID>4688</EventID>" in content
        assert '<Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>' in content
        assert '<Data Name="CommandLine">cmd.exe /c dir</Data>' in content

        print(f"\n{'=' * 80}")
        print("WINDOWS EVENT LOG SAMPLE (4688 - Process Creation):")
        print(f"{'=' * 80}")
        print(content)
        print(f"{'=' * 80}\n")

    def test_buffering(self, format_def, temp_output):
        """Test that events are buffered before flushing."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=3)

        # Emit 2 events (below buffer size)
        for i in range(2):
            event_data = {
                "EventID": 4624,
                "TimeCreated": datetime(2024, 1, 15, 10, 30, i, 0, tzinfo=UTC),
                "Computer": "WIN-TEST-01",
                "Channel": "Security",
                "Level": 0,
                "EventRecordID": 10000 + i,
                "ExecutionProcessID": 4,
                "ExecutionThreadID": 100,
                "TargetUserName": f"user{i}",
                "TargetDomainName": "CORP",
                "TargetLogonId": f"0x{i:06x}",
                "LogonType": 2,
                "WorkstationName": "WIN-TEST-01",
                "IpAddress": "192.168.1.100",
                "LogonProcessName": "User32",
                "AuthenticationPackageName": "Negotiate",
            }
            emitter.emit_event(event_data)

        # File shouldn't exist yet (still in buffer)
        assert not temp_output.exists()

        # Emit 3rd event (reaches buffer size)
        event_data = {
            "EventID": 4624,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 2, 0, tzinfo=UTC),
            "Computer": "WIN-TEST-01",
            "Channel": "Security",
            "Level": 0,
            "EventRecordID": 10002,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 100,
            "TargetUserName": "user2",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x000002",
            "LogonType": 2,
            "WorkstationName": "WIN-TEST-01",
            "IpAddress": "192.168.1.100",
            "LogonProcessName": "User32",
            "AuthenticationPackageName": "Negotiate",
        }
        emitter.emit_event(event_data)

        # File should now exist (buffer flushed)
        assert temp_output.exists()

        # Verify all 3 events are in the file
        content = temp_output.read_text()
        assert content.count("<EventID>4624</EventID>") == 3
        assert "user0" in content
        assert "user1" in content
        assert "user2" in content

    def test_close_preserves_chronological_order_for_same_second_events(
        self, format_def, temp_output
    ):
        """Rendered microsecond jitter should not reorder same-second Windows events."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)

        for idx in range(5):
            emitter.emit_event(
                {
                    "EventID": 4624,
                    "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
                    "Computer": "WIN-TEST-01",
                    "Channel": "Security",
                    "Level": 0,
                    "ExecutionProcessID": 4,
                    "ExecutionThreadID": 100 + idx,
                    "TargetUserName": f"user{idx}",
                    "TargetDomainName": "CORP",
                    "TargetLogonId": f"0x{idx:06x}",
                    "LogonType": 2,
                    "WorkstationName": "WIN-TEST-01",
                    "IpAddress": "192.168.1.100",
                    "LogonProcessName": "User32",
                    "AuthenticationPackageName": "Negotiate",
                }
            )

        emitter.close()

        content = temp_output.read_text()
        timestamps = re.findall(r'SystemTime="([^"]+)"', content)
        assert timestamps == sorted(timestamps)
        assert len(set(timestamps)) == len(timestamps)

    def test_failed_logon_keywords_and_task(self, format_def, temp_output):
        """Test that 4625 uses Audit Failure keywords and correct task ID."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        event_data = {
            "EventID": 4625,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "WIN-TEST-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "Keywords": "0x8010000000000000",
            "ExecutionProcessID": 600,
            "ExecutionThreadID": 100,
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "SYSTEM",
            "SubjectDomainName": "NT AUTHORITY",
            "SubjectLogonId": "0x3e7",
            "TargetUserSid": "S-1-0-0",
            "TargetUserName": "baduser",
            "TargetDomainName": "CORP",
            "Status": "0xc000006d",
            "FailureReason": "%%2313",
            "SubStatus": "0xc000006a",
            "LogonType": 3,
            "IpAddress": "10.0.0.50",
        }

        emitter.emit_event(event_data)
        emitter.close()

        content = temp_output.read_text()
        assert "<Keywords>0x8010000000000000</Keywords>" in content  # Audit Failure
        assert "<Task>12544</Task>" in content  # Logon category, not Account Lockout
        assert "<Version>0</Version>" in content  # 4625 is always Version 0

    def test_ntlm_field_names(self, format_def, temp_output):
        """Test that 4776 uses correct field names (TargetUserName, Workstation)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        event_data = {
            "EventID": 4776,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "DC-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 600,
            "ExecutionThreadID": 100,
            "PackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
            "TargetUserName": "jsmith",
            "Workstation": "WKS-01",
            "Status": "0x00000000",
        }

        emitter.emit_event(event_data)
        emitter.close()

        content = temp_output.read_text()
        assert '<Data Name="TargetUserName">jsmith</Data>' in content
        assert '<Data Name="Workstation">WKS-01</Data>' in content
        assert "LogonAccount" not in content
        assert "SourceWorkstation" not in content

    def test_privilege_order(self, format_def, temp_output):
        """Test that 4672 privilege list matches standard Windows order."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        expected_privs = (
            "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\t"
            "SeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege"
        )
        event_data = {
            "EventID": 4672,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "WIN-TEST-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 600,
            "ExecutionThreadID": 100,
            "SubjectUserSid": "S-1-5-21-123-456-789-500",
            "SubjectUserName": "Administrator",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7abc",
            "PrivilegeList": expected_privs,
        }

        emitter.emit_event(event_data)
        emitter.close()

        content = temp_output.read_text()
        # Verify Security comes before Backup (standard Windows order)
        sec_pos = content.index("SeSecurityPrivilege")
        backup_pos = content.index("SeBackupPrivilege")
        assert sec_pos < backup_pos

    def test_emit_explicit_credentials_event(self, format_def, temp_output):
        """Test emitting 4648 (explicit credentials)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        event_data = {
            "EventID": 4648,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "WKS-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 600,
            "ExecutionThreadID": 100,
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "WKS-01$",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
            "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
            "TargetUserName": "admin01",
            "TargetDomainName": "CORP",
            "TargetLogonGuid": "{00000000-0000-0000-0000-000000000000}",
            "TargetServerName": "fileserver01",
            "TargetInfo": "fileserver01",
            "ProcessId": "0x704",
            "ProcessName": r"C:\Windows\System32\winlogon.exe",
            "IpAddress": "10.0.0.50",
            "IpPort": 0,
        }

        emitter.emit_event(event_data)
        emitter.close()

        content = temp_output.read_text()
        assert "<EventID>4648</EventID>" in content
        assert "<Version>0</Version>" in content
        assert "<Task>12544</Task>" in content
        assert '<Data Name="TargetServerName">fileserver01</Data>' in content
        assert '<Data Name="TargetInfo">fileserver01</Data>' in content
        assert '<Data Name="TargetUserName">admin01</Data>' in content

    def test_emit_wfp_outbound_connection(self, format_def, temp_output):
        """Test emitting 5156 (WFP outbound connection)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        event_data = {
            "EventID": 5156,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "WKS-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 56,
            "ProcessID": 520,
            "Application": r"\device\harddiskvolume1\windows\system32\lsass.exe",
            "Direction": "%%14593",
            "SourceAddress": "10.0.0.50",
            "SourcePort": 49263,
            "DestAddress": "10.0.0.10",
            "DestPort": 88,
            "Protocol": 6,
            "FilterRTID": 0,
            "LayerName": "%%14611",
            "LayerRTID": 48,
            "RemoteUserID": "S-1-0-0",
            "RemoteMachineID": "S-1-0-0",
        }

        emitter.emit_event(event_data)
        emitter.close()

        content = temp_output.read_text()
        assert "<EventID>5156</EventID>" in content
        assert "<Version>1</Version>" in content
        assert "<Task>12810</Task>" in content
        assert '<Data Name="Direction">%%14593</Data>' in content  # Outbound
        assert (
            '<Data Name="Application">\\device\\harddiskvolume1\\windows\\system32\\lsass.exe</Data>'
            in content
        )
        assert '<Data Name="Protocol">6</Data>' in content

    def test_wfp_connection_resolves_application_from_state_manager(self, format_def, temp_output):
        """WFP 5156 uses canonical process state when the event lacks ProcessContext."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        state_manager = StateManager()
        state_manager.set_current_time(datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC))
        pid = state_manager.create_process(
            system="WKS-01",
            parent_pid=4,
            image=r"C:\Program Files\Mozilla Firefox\firefox.exe",
            command_line="firefox.exe",
            username="CORP\\jsmith",
            integrity_level="Medium",
            logon_id="0x12345",
        )
        emitter._state_manager = state_manager

        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 31, 0, tzinfo=UTC),
            event_type="wfp_connection",
            src_host=HostContext(
                hostname="WKS-01",
                ip="10.0.0.50",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
                fqdn="WKS-01.corp.local",
            ),
            network=NetworkContext(
                src_ip="10.0.0.50",
                src_port=49263,
                dst_ip="93.184.216.34",
                dst_port=443,
                protocol="tcp",
                initiating_pid=pid,
            ),
        )

        emitter.emit(event)
        emitter.close()

        content = temp_output.read_text()
        assert f'<Data Name="ProcessID">{pid}</Data>' in content
        assert (
            '<Data Name="Application">\\device\\harddiskvolume1\\program files\\mozilla '
            "firefox\\firefox.exe</Data>"
        ) in content

    def test_wfp_connection_pid4_renders_system_application(self, format_def, temp_output):
        """WFP 5156 for PID 4 should render System, not a synthetic svchost path."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 31, 0, tzinfo=UTC),
            event_type="wfp_connection",
            src_host=HostContext(
                hostname="WKS-01",
                ip="10.0.0.50",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
                fqdn="WKS-01.corp.local",
            ),
            network=NetworkContext(
                src_ip="10.0.0.50",
                src_port=49263,
                dst_ip="93.184.216.34",
                dst_port=443,
                protocol="tcp",
                initiating_pid=4,
            ),
        )

        emitter.emit(event)
        emitter.close()

        content = temp_output.read_text()
        assert '<Data Name="ProcessID">4</Data>' in content
        assert '<Data Name="Application">System</Data>' in content
        assert "svchost.exe" not in content

    def test_wfp_connection_skips_unresolved_non_system_pid(self, format_def, temp_output):
        """WFP 5156 should not invent an Application value for unknown non-system PIDs."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 31, 0, tzinfo=UTC),
            event_type="wfp_connection",
            src_host=HostContext(
                hostname="WKS-01",
                ip="10.0.0.50",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
                fqdn="WKS-01.corp.local",
            ),
            network=NetworkContext(
                src_ip="10.0.0.50",
                src_port=49263,
                dst_ip="93.184.216.34",
                dst_port=443,
                protocol="tcp",
                initiating_pid=5156,
            ),
        )

        emitter.emit(event)
        emitter.close()

        assert not temp_output.exists() or temp_output.read_text() == ""

    def test_device_path_conversion(self):
        """Test _to_device_path helper converts Windows paths correctly."""
        assert (
            WindowsEventEmitter._to_device_path(r"C:\Windows\System32\svchost.exe")
            == r"\device\harddiskvolume1\windows\system32\svchost.exe"
        )

        assert (
            WindowsEventEmitter._to_device_path(r"D:\Program Files\app.exe")
            == r"\device\harddiskvolume1\program files\app.exe"
        )

        # Already a device path — lowercase only
        assert (
            WindowsEventEmitter._to_device_path(r"\device\harddiskvolume1\test.exe")
            == r"\device\harddiskvolume1\test.exe"
        )

    def test_timestamp_100ns_precision(self, format_def, temp_output):
        """Test that timestamps have EVTX-like 100ns precision."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        event_data = {
            "EventID": 4634,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 45, 123456, tzinfo=UTC),
            "Computer": "WIN-TEST-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 600,
            "ExecutionThreadID": 100,
            "TargetUserSid": "S-1-5-21-123-456-789-1001",
            "TargetUserName": "jsmith",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x3e7abc",
            "LogonType": 2,
        }

        emitter.emit_event(event_data)
        emitter.close()

        content = temp_output.read_text()
        assert re.search(r"2024-01-15T10:30:45\.123456\dZ", content)

    def test_timestamp_100ns_digit_varies(self, format_def, temp_output):
        """The synthetic 100ns digit should not always be zero."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=50)
        for idx in range(20):
            event_data = {
                "EventID": 4624,
                "TimeCreated": datetime(2024, 1, 15, 10, 30, idx, 123456, tzinfo=UTC),
                "Computer": "WIN-TEST-01.corp.local",
                "Channel": "Security",
                "Level": 0,
                "ExecutionProcessID": 600,
                "ExecutionThreadID": 100 + idx,
                "TargetUserSid": "S-1-5-21-123-456-789-1001",
                "TargetUserName": f"user{idx}",
                "TargetDomainName": "CORP",
                "TargetLogonId": f"0x{idx:06x}",
                "LogonType": 2,
                "WorkstationName": "WIN-TEST-01",
                "IpAddress": "-",
                "LogonProcessName": "User32",
                "AuthenticationPackageName": "Negotiate",
            }
            emitter.emit_event(event_data)
        emitter.close()

        content = temp_output.read_text()
        timestamps = re.findall(r'SystemTime="[^"]+\.(\d{7})Z"', content)
        assert len(timestamps) == 20
        assert len({fraction[-1] for fraction in timestamps}) > 1

    def test_emit_kerberos_preauth_failed(self, format_def, temp_output):
        """Test emitting 4771 (Kerberos pre-auth failed)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        event_data = {
            "EventID": 4771,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "DC-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "Keywords": "0x8010000000000000",
            "ExecutionProcessID": 624,
            "ExecutionThreadID": 100,
            "TargetUserName": "jsmith",
            "TargetSid": "S-1-5-21-123-456-789-1001",
            "ServiceName": "krbtgt",
            "TicketOptions": "0x40810010",
            "Status": "0x18",
            "PreAuthType": 0,
            "IpAddress": "::ffff:10.0.0.50",
            "IpPort": 55961,
        }
        emitter.emit_event(event_data)
        emitter.close()
        content = temp_output.read_text()
        assert "<EventID>4771</EventID>" in content
        assert "<Keywords>0x8010000000000000</Keywords>" in content
        assert "<Task>14339</Task>" in content
        assert '<Data Name="Status">0x18</Data>' in content

    def test_emit_log_cleared(self, format_def, temp_output):
        """Test emitting 1102 (security log cleared) with UserData structure."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        event_data = {
            "EventID": 1102,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "WKS-01.corp.local",
            "Channel": "Security",
            "Level": 4,
            "Keywords": "0x4020000000000000",
            "ExecutionProcessID": 820,
            "ExecutionThreadID": 608,
            "SubjectUserSid": "S-1-5-21-123-456-789-1001",
            "SubjectUserName": "admin01",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
        }
        emitter.emit_event(event_data)
        emitter.close()
        content = temp_output.read_text()
        assert "<EventID>1102</EventID>" in content
        assert "<Keywords>0x4020000000000000</Keywords>" in content
        assert "<Level>4</Level>" in content
        assert "Microsoft-Windows-Eventlog" in content
        assert "LogFileCleared" in content
        assert "UserData" in content
        assert "<SubjectUserName>admin01</SubjectUserName>" in content
        assert "<SubjectDomainName>CORP</SubjectDomainName>" in content
        assert "EventData" not in content or content.count("EventData") == 0

    def test_event_record_id_restarts_after_log_cleared(self, format_def, temp_output):
        """Security EventRecordID should restart after source-native 1102 log clear."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        base = {
            "Computer": "WIN-TEST-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 600,
            "ExecutionThreadID": 100,
        }
        emitter.emit_event(
            {
                **base,
                "EventID": 4624,
                "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
                "TargetUserName": "jsmith",
                "TargetDomainName": "CORP",
                "TargetLogonId": "0x1",
                "LogonType": 2,
                "WorkstationName": "WIN-TEST-01",
                "IpAddress": "-",
                "LogonProcessName": "User32",
                "AuthenticationPackageName": "Negotiate",
            }
        )
        emitter.emit_event(
            {
                **base,
                "EventID": 1102,
                "TimeCreated": datetime(2024, 1, 15, 10, 31, 0, tzinfo=UTC),
                "SubjectUserSid": "S-1-5-21-123-456-789-1001",
                "SubjectUserName": "admin01",
                "SubjectDomainName": "CORP",
                "SubjectLogonId": "0x2",
            }
        )
        emitter.emit_event(
            {
                **base,
                "EventID": 4624,
                "TimeCreated": datetime(2024, 1, 15, 10, 32, 0, tzinfo=UTC),
                "TargetUserName": "jsmith",
                "TargetDomainName": "CORP",
                "TargetLogonId": "0x3",
                "LogonType": 2,
                "WorkstationName": "WIN-TEST-01",
                "IpAddress": "-",
                "LogonProcessName": "User32",
                "AuthenticationPackageName": "Negotiate",
            }
        )
        emitter.close()

        content = temp_output.read_text()
        record_ids = [
            int(value) for value in re.findall(r"<EventRecordID>(\d+)</EventRecordID>", content)
        ]
        assert len(record_ids) == 3
        assert record_ids[0] < record_ids[1]
        assert record_ids[2] < record_ids[1]
        assert record_ids[2] <= 20

    def test_emit_workstation_lock_contains_event_data(self, format_def, temp_output):
        """Test emitting 4800 (workstation locked) with populated EventData fields."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        event_data = {
            "EventID": 4800,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "WKS-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 540,
            "ExecutionThreadID": 112,
            "TargetUserSid": "S-1-5-21-123-456-789-1001",
            "TargetUserName": "jsmith",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x4f2a1b",
            "SessionId": 2,
        }
        emitter.emit_event(event_data)
        emitter.close()
        content = temp_output.read_text()
        assert "<EventID>4800</EventID>" in content
        assert '<Data Name="TargetUserName">jsmith</Data>' in content
        assert '<Data Name="TargetLogonId">0x4f2a1b</Data>' in content
        assert '<Data Name="SessionId">2</Data>' in content

    def test_emit_workstation_unlock_contains_event_data(self, format_def, temp_output):
        """Test emitting 4801 (workstation unlocked) with populated EventData fields."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        event_data = {
            "EventID": 4801,
            "TimeCreated": datetime(2024, 1, 15, 10, 35, 0, 0, tzinfo=UTC),
            "Computer": "WKS-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 541,
            "ExecutionThreadID": 113,
            "TargetUserSid": "S-1-5-21-123-456-789-1001",
            "TargetUserName": "jsmith",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x4f2a1b",
            "SessionId": 2,
        }
        emitter.emit_event(event_data)
        emitter.close()
        content = temp_output.read_text()
        assert "<EventID>4801</EventID>" in content
        assert '<Data Name="TargetUserName">jsmith</Data>' in content
        assert '<Data Name="TargetLogonId">0x4f2a1b</Data>' in content
        assert '<Data Name="SessionId">2</Data>' in content

    def test_lock_unlock_share_stable_session_id(self, format_def, temp_output):
        """4800 and 4801 for the same LogonID should share the same SessionId."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        host = HostContext(
            hostname="WKS-01",
            fqdn="WKS-01.corp.local",
            ip="10.0.0.50",
            os="Windows 11",
            os_category="windows",
            system_type="workstation",
            netbios_domain="CORP",
        )
        auth = AuthContext(
            username="jsmith",
            user_sid="S-1-5-21-123-456-789-1001",
            logon_id="0x4f2a1b",
        )
        emitter.emit(
            SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
                event_type="workstation_locked",
                dst_host=host,
                auth=auth,
            )
        )
        emitter.emit(
            SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 35, 0, 0, tzinfo=UTC),
                event_type="workstation_unlocked",
                dst_host=host,
                auth=auth,
            )
        )
        emitter.close()
        content = temp_output.read_text()
        session_lines = [line for line in content.splitlines() if 'Data Name="SessionId"' in line]
        assert len(session_lines) == 2
        assert session_lines[0] == session_lines[1]

    def test_emit_service_installed(self, format_def, temp_output):
        """Test emitting 4697 (service installed)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        event_data = {
            "EventID": 4697,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "WKS-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 600,
            "ExecutionThreadID": 100,
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "SYSTEM",
            "SubjectDomainName": "NT AUTHORITY",
            "SubjectLogonId": "0x3e7",
            "ServiceName": "EvilSvc",
            "ServiceFileName": r"C:\Windows\Temp\evil.exe -d",
            "ServiceType": "0x10",
            "ServiceStartType": "2",
            "ServiceAccount": "LocalSystem",
        }
        emitter.emit_event(event_data)
        emitter.close()
        content = temp_output.read_text()
        assert "<EventID>4697</EventID>" in content
        assert "<Task>12289</Task>" in content
        assert '<Data Name="ServiceName">EvilSvc</Data>' in content
        assert '<Data Name="ServiceFileName">' in content

    def test_emit_scheduled_task_created(self, format_def, temp_output):
        """Test emitting 4698 (scheduled task created)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        event_data = {
            "EventID": 4698,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "WKS-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 600,
            "ExecutionThreadID": 100,
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "admin01",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
            "TaskName": r"\MaliciousTask",
            "TaskContent": "&lt;Task&gt;content&lt;/Task&gt;",
        }
        emitter.emit_event(event_data)
        emitter.close()
        content = temp_output.read_text()
        assert "<EventID>4698</EventID>" in content
        assert "<Task>12804</Task>" in content
        assert '<Data Name="TaskName">\\MaliciousTask</Data>' in content
        assert '<Data Name="TaskContent">' in content

    def test_emit_scheduled_task_deleted(self, format_def, temp_output):
        """Test emitting 4699 (scheduled task deleted)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        event_data = {
            "EventID": 4699,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "WKS-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 600,
            "ExecutionThreadID": 100,
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "admin01",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
            "TaskName": r"\MaliciousTask",
            "TaskContent": "",
        }
        emitter.emit_event(event_data)
        emitter.close()
        content = temp_output.read_text()
        assert "<EventID>4699</EventID>" in content

    def test_emit_group_member_added_global(self, format_def, temp_output):
        """Test emitting 4728 (member added to global group)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        event_data = {
            "EventID": 4728,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "DC-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 624,
            "ExecutionThreadID": 100,
            "MemberName": "-",
            "MemberSid": "S-1-5-21-123-456-789-1001",
            "TargetUserName": "Domain Admins",
            "TargetDomainName": "CORP",
            "TargetSid": "S-1-5-21-123-456-789-512",
            "SubjectUserSid": "S-1-5-21-123-456-789-500",
            "SubjectUserName": "Administrator",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
            "PrivilegeList": "-",
        }
        emitter.emit_event(event_data)
        emitter.close()
        content = temp_output.read_text()
        assert "<EventID>4728</EventID>" in content
        assert "<Task>13826</Task>" in content
        assert '<Data Name="MemberSid">S-1-5-21-123-456-789-1001</Data>' in content
        assert '<Data Name="TargetUserName">Domain Admins</Data>' in content

    def test_emit_group_member_removed_local(self, format_def, temp_output):
        """Test emitting 4733 (member removed from local group)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        event_data = {
            "EventID": 4733,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "WKS-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 624,
            "ExecutionThreadID": 100,
            "MemberName": "-",
            "MemberSid": "S-1-5-21-123-456-789-1001",
            "TargetUserName": "Administrators",
            "TargetDomainName": "Builtin",
            "TargetSid": "S-1-5-32-544",
            "SubjectUserSid": "S-1-5-21-123-456-789-500",
            "SubjectUserName": "Administrator",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
            "PrivilegeList": "-",
        }
        emitter.emit_event(event_data)
        emitter.close()
        content = temp_output.read_text()
        assert "<EventID>4733</EventID>" in content

    def test_emit_group_member_added_universal(self, format_def, temp_output):
        """Test emitting 4756 (member added to universal group)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        event_data = {
            "EventID": 4756,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "DC-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 624,
            "ExecutionThreadID": 100,
            "MemberName": "-",
            "MemberSid": "S-1-5-21-123-456-789-1001",
            "TargetUserName": "Enterprise Admins",
            "TargetDomainName": "CORP",
            "TargetSid": "S-1-5-21-123-456-789-519",
            "SubjectUserSid": "S-1-5-21-123-456-789-500",
            "SubjectUserName": "Administrator",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
            "PrivilegeList": "-",
        }
        emitter.emit_event(event_data)
        emitter.close()
        content = temp_output.read_text()
        assert "<EventID>4756</EventID>" in content

    def test_emit_account_created(self, format_def, temp_output):
        """Test emitting 4720 (user account created) with full fields."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        event_data = {
            "EventID": 4720,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "DC-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 624,
            "ExecutionThreadID": 100,
            "TargetUserName": "backdoor01",
            "TargetDomainName": "CORP",
            "TargetSid": "S-1-5-21-123-456-789-9999",
            "SubjectUserSid": "S-1-5-21-123-456-789-500",
            "SubjectUserName": "Administrator",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
            "SamAccountName": "backdoor01",
            "OldUacValue": "0x0",
            "NewUacValue": "0x15",
            "PasswordLastSet": "%%1794",
            "PrimaryGroupId": "513",
        }
        emitter.emit_event(event_data)
        emitter.close()
        content = temp_output.read_text()
        assert "<EventID>4720</EventID>" in content
        assert "<Task>13824</Task>" in content
        assert '<Data Name="TargetUserName">backdoor01</Data>' in content
        assert '<Data Name="SamAccountName">backdoor01</Data>' in content
        assert '<Data Name="NewUacValue">0x15</Data>' in content

    def test_emit_password_reset(self, format_def, temp_output):
        """Test emitting 4724 (password reset)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        event_data = {
            "EventID": 4724,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "DC-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 624,
            "ExecutionThreadID": 100,
            "TargetUserName": "jsmith",
            "TargetDomainName": "CORP",
            "TargetSid": "S-1-5-21-123-456-789-1001",
            "SubjectUserSid": "S-1-5-21-123-456-789-500",
            "SubjectUserName": "Administrator",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
        }
        emitter.emit_event(event_data)
        emitter.close()
        content = temp_output.read_text()
        assert "<EventID>4724</EventID>" in content
        assert "PrivilegeList" not in content  # 4724 has no PrivilegeList

    def test_emit_account_deleted(self, format_def, temp_output):
        """Test emitting 4726 (user account deleted)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        event_data = {
            "EventID": 4726,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "DC-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 624,
            "ExecutionThreadID": 100,
            "TargetUserName": "backdoor01",
            "TargetDomainName": "CORP",
            "TargetSid": "S-1-5-21-123-456-789-9999",
            "SubjectUserSid": "S-1-5-21-123-456-789-500",
            "SubjectUserName": "Administrator",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
            "PrivilegeList": "-",
        }
        emitter.emit_event(event_data)
        emitter.close()
        content = temp_output.read_text()
        assert "<EventID>4726</EventID>" in content
        assert '<Data Name="PrivilegeList">-</Data>' in content

    def test_emit_account_changed(self, format_def, temp_output):
        """Test emitting 4738 (user account changed) with Dummy field."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        event_data = {
            "EventID": 4738,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            "Computer": "DC-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 624,
            "ExecutionThreadID": 100,
            "TargetUserName": "jsmith",
            "TargetDomainName": "CORP",
            "TargetSid": "S-1-5-21-123-456-789-1001",
            "SubjectUserSid": "S-1-5-21-123-456-789-500",
            "SubjectUserName": "Administrator",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
            "SamAccountName": "jsmith",
            "OldUacValue": "0x10",
            "NewUacValue": "0x10",
            "PasswordLastSet": "-",
            "PrimaryGroupId": "513",
        }
        emitter.emit_event(event_data)
        emitter.close()
        content = temp_output.read_text()
        assert "<EventID>4738</EventID>" in content
        assert '<Data Name="Dummy">-</Data>' in content  # 4738 unique Dummy field

    def test_emit_event_with_unsafe_computer_routes_to_flat_output(self, format_def, tmp_path):
        """Unsafe Computer values must not create traversing per-host paths."""
        output_dir = tmp_path / "output"
        emitter = WindowsEventEmitter(format_def, output_dir, buffer_size=1)
        event_data = {
            "EventID": 4624,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 45, 0, tzinfo=UTC),
            "Computer": "../../escape",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 100,
            "TargetUserName": "jsmith",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x3e7abc",
            "LogonType": 2,
            "WorkstationName": "WIN-TEST-01",
            "IpAddress": "192.168.1.100",
            "LogonProcessName": "User32",
            "AuthenticationPackageName": "Negotiate",
        }
        emitter.emit_event(event_data)
        emitter.close()

        assert (output_dir / "windows_event_security.xml").exists()
        assert not (tmp_path / "escape" / "windows_event_security.xml").exists()


def test_sanitize_host_routing_key_rejects_path_traversal() -> None:
    """Path traversal and separators must be rejected for host routing keys."""
    assert sanitize_host_routing_key("../../pwned") == ""
    assert sanitize_host_routing_key("..\\..\\pwned") == ""
    assert sanitize_host_routing_key("host/child") == ""
    assert sanitize_host_routing_key("safe-host.corp.local") == "safe-host.corp.local"


class TestZeekEmitter:
    """Tests for Zeek conn.log emitter."""

    @pytest.fixture
    def format_def(self):
        """Load Zeek format definition."""
        return load_format("zeek_conn")

    @pytest.fixture
    def temp_output(self, tmp_path):
        """Create temporary output file path."""
        return tmp_path / "conn.json"

    def test_emit_tcp_connection(self, format_def, temp_output):
        """Test emitting a TCP connection."""
        emitter = ZeekEmitter(format_def, temp_output, buffer_size=1)

        uid = generate_zeek_uid()
        event_data = {
            "ts": datetime(2024, 1, 15, 10, 0, 0, 123456, tzinfo=UTC),
            "uid": uid,
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 49152,
            "id.resp_h": "93.184.216.34",
            "id.resp_p": 80,
            "proto": "tcp",
            "service": "http",
            "duration": 1.234,
            "orig_bytes": 512,
            "resp_bytes": 4096,
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": False,
            "missed_bytes": 0,
            "history": "ShADadfF",
            "orig_pkts": 10,
            "orig_ip_bytes": 1024,
            "resp_pkts": 8,
            "resp_ip_bytes": 8192,
            "ip_proto": 6,
        }

        emitter.emit_event(event_data)
        emitter.close()

        # Verify file was created
        assert temp_output.exists()

        # Read and verify content
        content = temp_output.read_text().strip()

        # Parse as JSON
        conn = json.loads(content)

        assert conn["uid"] == uid
        assert conn["id.orig_h"] == "192.168.1.100"
        assert conn["id.orig_p"] == 49152
        assert conn["id.resp_h"] == "93.184.216.34"
        assert conn["id.resp_p"] == 80
        assert conn["proto"] == "tcp"
        assert conn["service"] == "http"
        assert conn["conn_state"] == "SF"
        assert conn["local_orig"] is True
        assert conn["local_resp"] is False

        print(f"\n{'=' * 80}")
        print("ZEEK CONN.LOG SAMPLE (TCP Connection):")
        print(f"{'=' * 80}")
        print("Raw file content (JSONL/NDJSON format - single line):")
        print(content)
        print(f"{'=' * 80}\n")

    def test_emit_udp_connection(self, format_def, temp_output):
        """Test emitting a UDP connection (DNS query)."""
        emitter = ZeekEmitter(format_def, temp_output, buffer_size=1)

        uid = generate_zeek_uid()
        event_data = {
            "ts": datetime(2024, 1, 15, 10, 0, 5, 654321, tzinfo=UTC),
            "uid": uid,
            "id.orig_h": "10.0.0.50",
            "id.orig_p": 53123,
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "proto": "udp",
            "service": "dns",
            "duration": 0.012,
            "orig_bytes": 64,
            "resp_bytes": 128,
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": False,
            "orig_pkts": 1,
            "orig_ip_bytes": 92,
            "resp_pkts": 1,
            "resp_ip_bytes": 156,
            "ip_proto": 17,
        }

        emitter.emit_event(event_data)
        emitter.close()

        # Verify file was created
        assert temp_output.exists()

        # Read and parse
        content = temp_output.read_text().strip()
        conn = json.loads(content)

        assert conn["proto"] == "udp"
        assert conn["service"] == "dns"
        assert conn["id.resp_p"] == 53
        assert conn["orig_bytes"] == 64
        assert conn["resp_bytes"] == 128

        print(f"\n{'=' * 80}")
        print("ZEEK CONN.LOG SAMPLE (UDP/DNS Query):")
        print(f"{'=' * 80}")
        print("Raw file content (JSONL/NDJSON format - single line):")
        print(content)
        print(f"{'=' * 80}\n")

    def test_emit_incomplete_connection(self, format_def, temp_output):
        """Test emitting an incomplete connection (no established state)."""
        emitter = ZeekEmitter(format_def, temp_output, buffer_size=1)

        uid = generate_zeek_uid()
        event_data = {
            "ts": datetime(2024, 1, 15, 10, 0, 10, 543210, tzinfo=UTC),
            "uid": uid,
            "id.orig_h": "192.168.1.200",
            "id.orig_p": 12345,
            "id.resp_h": "203.0.113.50",
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "S0",  # SYN sent, no response
        }

        emitter.emit_event(event_data)
        emitter.close()

        # Verify file was created
        assert temp_output.exists()

        # Read and parse
        content = temp_output.read_text().strip()
        conn = json.loads(content)

        assert conn["conn_state"] == "S0"
        assert "service" not in conn  # No service for incomplete connection
        assert "duration" not in conn  # No duration

        print(f"\n{'=' * 80}")
        print("ZEEK CONN.LOG SAMPLE (Incomplete Connection - S0):")
        print(f"{'=' * 80}")
        print("Raw file content (JSONL/NDJSON format - single line):")
        print(content)
        print(f"{'=' * 80}\n")

    def test_multiple_connections(self, format_def, temp_output):
        """Test emitting multiple connections (one per line JSON)."""
        emitter = ZeekEmitter(format_def, temp_output, buffer_size=10)

        # Emit 3 connections
        uids = [generate_zeek_uid() for _ in range(3)]
        # Use realistic microsecond values (not sequential patterns)
        microseconds = [876543, 291047, 638219]
        for i in range(3):
            event_data = {
                "ts": datetime(2024, 1, 15, 10, 0, i, microseconds[i], tzinfo=UTC),
                "uid": uids[i],
                "id.orig_h": f"192.168.1.{100 + i}",
                "id.orig_p": 49152 + i,
                "id.resp_h": "93.184.216.34",
                "id.resp_p": 80,
                "proto": "tcp",
                "service": "http",
                "duration": float(i + 1),
                "orig_bytes": (i + 1) * 100,
                "resp_bytes": (i + 1) * 1000,
                "conn_state": "SF",
                "ip_proto": 6,
            }
            emitter.emit_event(event_data)

        emitter.close()

        # Verify file was created
        assert temp_output.exists()

        # Read and verify - should be 3 lines of JSON
        lines = temp_output.read_text().strip().split("\n")
        assert len(lines) == 3

        # Parse each line and verify data
        for i, line in enumerate(lines):
            conn = json.loads(line)
            assert conn["uid"] == uids[i]
            assert conn["id.orig_h"] == f"192.168.1.{100 + i}"
            assert conn["orig_bytes"] == (i + 1) * 100

        print(f"\n{'=' * 80}")
        print("ZEEK CONN.LOG SAMPLE (Multiple Connections):")
        print(f"{'=' * 80}")
        print("Raw file content (JSONL/NDJSON format - one JSON object per line):")
        for line in lines:
            print(line)
        print(f"{'=' * 80}\n")
