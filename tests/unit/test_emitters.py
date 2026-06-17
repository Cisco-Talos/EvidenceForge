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
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    AuthContext,
    DhcpContext,
    HostContext,
    KerberosContext,
    NetworkContext,
    ProcessContext,
)
from evidenceforge.formats import load_format
from evidenceforge.generation.activity.timing_profiles import sample_timing_delta
from evidenceforge.generation.emitters import WindowsEventEmitter, ZeekEmitter
from evidenceforge.generation.emitters.host_base import sanitize_host_routing_key
from evidenceforge.generation.emitters.windows import (
    _auth_subject_domain,
    _normalize_windows_time_created,
    _special_privilege_fallback,
    _windows_pid_hex,
)
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

    def test_spool_database_uses_local_runtime_directory(self, format_def, tmp_path, monkeypatch):
        """Windows Security spool state should stay out of the final output directory."""
        output_dir = tmp_path / "onedrive-like-output"
        spool_dir = tmp_path / "local-spool"
        monkeypatch.setenv("EFORGE_SPOOL_DIR", str(spool_dir))
        emitter = WindowsEventEmitter(format_def, output_dir, buffer_size=1)

        emitter.emit_event(
            {
                "EventID": 4624,
                "TimeCreated": datetime(2024, 1, 15, 10, 30, 45, tzinfo=UTC),
                "Computer": "WIN-TEST-01.corp.local",
                "Channel": "Security",
                "Level": 0,
                "EventRecordID": 12345,
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
        )

        assert emitter._spool_path is not None
        assert emitter._spool_path.parent == spool_dir.resolve()
        assert not list(output_dir.glob(".windows_event_spool_*.sqlite3"))

        emitter.close()

        assert not list(spool_dir.glob(".windows_event_spool_*.sqlite3"))

    def test_windows_pid_hex_rejects_oversized_decimal_pid(self) -> None:
        """Oversized decimal PID text should not raise and should remain unchanged."""
        oversized_pid = "9" * 5000
        assert _windows_pid_hex(oversized_pid) == oversized_pid

    @pytest.mark.parametrize(
        ("logon_type", "expected_role", "expected_process"),
        [
            (2, "winlogon", r"C:\Windows\System32\winlogon.exe"),
            (5, "services", r"C:\Windows\System32\services.exe"),
            (10, "winlogon", r"C:\Windows\System32\winlogon.exe"),
            (3, "lsass", r"C:\Windows\System32\lsass.exe"),
        ],
    )
    def test_render_logon_uses_source_native_caller_process(
        self,
        format_def,
        temp_output,
        logon_type,
        expected_role,
        expected_process,
    ):
        """4624 ProcessName should reflect the logon type's caller, not always lsass."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        emitter.emit_event = Mock()
        emitter._system_pids = {
            "WIN-TEST-01": {
                "winlogon": 612,
                "services": 704,
                "lsass": 736,
            }
        }
        host = HostContext(
            hostname="WIN-TEST-01",
            ip="10.0.0.10",
            os="Windows 10",
            os_category="windows",
            system_type="workstation",
            domain="corp.local",
            fqdn="WIN-TEST-01.corp.local",
            netbios_domain="CORP",
        )
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 45, tzinfo=UTC),
            event_type="logon",
            dst_host=host,
            auth=AuthContext(
                username="jsmith",
                user_sid="S-1-5-21-1-2-3-1001",
                logon_id="0x12345",
                logon_type=logon_type,
                auth_package="Negotiate",
                source_ip="-" if logon_type in {2, 5} else "10.0.0.50",
                source_port=0 if logon_type in {2, 5} else 50123,
                logon_process="User32" if logon_type in {2, 10} else "Kerberos",
                subject_sid="S-1-5-18",
                subject_username="SYSTEM",
                subject_domain="NT AUTHORITY",
                subject_logon_id="0x3e7",
                reporting_pid=736,
            ),
        )

        emitter._render_logon(event)

        rendered = emitter.emit_event.call_args.args[0]
        assert rendered["ProcessName"] == expected_process
        assert rendered["ProcessId"] == f"0x{emitter._system_pids['WIN-TEST-01'][expected_role]:x}"

    def test_emit_event_aligns_provider_execution_ids(self, format_def, temp_output):
        """Security XML provider PID/TID values should look Windows-native."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        event_data = {
            "EventID": 4624,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 45, tzinfo=UTC),
            "Computer": "WIN-TEST-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 541,
            "ExecutionThreadID": 113,
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

        content = temp_output.read_text()
        assert '<Execution ProcessID="544" ThreadID="116"/>' in content

    def test_emit_event_preserves_malformed_raw_event_id(self, format_def, temp_output):
        """Malformed raw EventID should not abort Security XML rendering."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        event_data = {
            "EventID": "not-an-int",
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 45, tzinfo=UTC),
            "Computer": "WIN-TEST-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 100,
        }

        emitter.emit_event(event_data)
        emitter.close()

        content = temp_output.read_text()
        assert "<EventID>not-an-int</EventID>" in content

    def test_emit_event_preserves_oversized_decimal_execution_id(self, format_def, temp_output):
        """Oversized raw decimal PID/TID strings should not abort Security XML rendering."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        oversized_pid = "9" * 5000

        event_data = {
            "EventID": 4624,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 45, tzinfo=UTC),
            "Computer": "WIN-TEST-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": oversized_pid,
            "ExecutionThreadID": "113",
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

        content = temp_output.read_text()
        assert f'<Execution ProcessID="{oversized_pid}" ThreadID="116"/>' in content

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
        assert '<Data Name="ElevatedToken">%%1843</Data>' in content

    def test_kerberos_network_logon_can_render_blank_workstation_name(
        self, format_def, temp_output
    ):
        """Native Kerberos type-3 4624 often leaves WorkstationName unset."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 45, tzinfo=UTC),
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
                logon_id="0xkerb1",
                logon_type=3,
                source_ip="10.0.1.10",
                auth_package="Kerberos",
                logon_process="Kerberos",
                lm_package="-",
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
        assert '<Data Name="WorkstationName">-</Data>' in content

    def test_logon_elevated_token_reflects_auth_context(self, format_def, temp_output):
        """4624 ElevatedToken should vary with canonical auth.elevated."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        host = HostContext(
            hostname="WS-01",
            ip="10.0.1.10",
            fqdn="WS-01.example.com",
            os="Windows 11",
            os_category="windows",
            system_type="workstation",
            netbios_domain="CORP",
        )

        for username, elevated, logon_id in [
            ("jsmith", False, "0x111"),
            ("admin", True, "0x222"),
        ]:
            emitter.emit(
                SecurityEvent(
                    timestamp=datetime(2024, 1, 15, 10, 30, 45, tzinfo=UTC),
                    event_type="logon",
                    dst_host=host,
                    auth=AuthContext(
                        username=username,
                        user_sid="S-1-5-21-1-2-3-1001",
                        logon_id=logon_id,
                        logon_type=2,
                        elevated=elevated,
                        subject_sid="S-1-5-18",
                        subject_username="SYSTEM",
                        subject_domain="NT AUTHORITY",
                        subject_logon_id="0x3e7",
                    ),
                )
            )
        emitter.close()

        content = temp_output.read_text()
        assert '<Data Name="ElevatedToken">%%1843</Data>' in content
        assert '<Data Name="ElevatedToken">%%1842</Data>' in content

    def test_anonymous_logon_uses_nt_authority_domain_and_source_workstation(
        self, format_def, temp_output
    ):
        """ANONYMOUS LOGON should not inherit the AD domain or local workstation."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        host = HostContext(
            hostname="FS-01",
            ip="10.0.2.20",
            fqdn="FS-01.example.com",
            os="Windows Server 2022",
            os_category="windows",
            system_type="server",
            netbios_domain="CORP",
        )
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 45, tzinfo=UTC),
            event_type="logon",
            dst_host=host,
            auth=AuthContext(
                username="ANONYMOUS LOGON",
                user_sid="S-1-5-7",
                logon_id="0x12345",
                logon_type=3,
                source_ip="10.0.1.10",
                source_port=52222,
                workstation_name="WS-01",
                auth_package="NTLM",
                logon_process="NtLmSsp",
                lm_package="NTLM V2",
                subject_sid="S-1-0-0",
                subject_username="-",
                subject_domain="-",
                subject_logon_id="0x0",
            ),
        )

        emitter.emit(event)
        emitter.close()

        content = temp_output.read_text()
        assert '<Data Name="TargetDomainName">NT AUTHORITY</Data>' in content
        assert '<Data Name="WorkstationName">WS-01</Data>' in content
        assert '<Data Name="IpAddress">::ffff:10.0.1.10</Data>' in content
        assert '<Data Name="ElevatedToken">%%1843</Data>' in content

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

    def test_logoff_shifted_after_same_session_dependents(self, format_def, temp_output):
        """A visible 4634 should not precede later rendered evidence for the same session."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        logoff_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        process_time = logoff_time + timedelta(seconds=10)

        emitter._event_dicts = [
            {
                "EventID": 4634,
                "TimeCreated": logoff_time,
                "Computer": "WIN-TEST-01.corp.local",
                "TargetLogonId": "0xabc123",
            },
            {
                "EventID": 4689,
                "TimeCreated": process_time,
                "Computer": "WIN-TEST-01.corp.local",
                "SubjectLogonId": "0xabc123",
            },
        ]

        emitter._shift_logoffs_after_dependents()

        expected_delta = sample_timing_delta(
            "windows.logoff_after_rendered_dependents",
            seed_parts=("WIN-TEST-01.corp.local", "0xabc123", process_time),
        )
        assert emitter._event_dicts[0]["TimeCreated"] == process_time + expected_delta

    def test_storyline_logoff_shifted_after_same_session_dependents(self, format_def, temp_output):
        """Storyline logoffs still need source-native ordering against rendered dependents."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        logoff_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        process_time = logoff_time + timedelta(seconds=10)

        emitter._event_dicts = [
            {
                "EventID": 4634,
                "TimeCreated": logoff_time,
                "Computer": "WIN-TEST-01.corp.local",
                "TargetLogonId": "0xabc123",
                "_storyline_origin": True,
            },
            {
                "EventID": 4688,
                "TimeCreated": process_time,
                "Computer": "WIN-TEST-01.corp.local",
                "SubjectLogonId": "0xabc123",
                "NewProcessName": "C:\\Windows\\System32\\dsquery.exe",
            },
        ]

        emitter._shift_logoffs_after_dependents()

        expected_delta = sample_timing_delta(
            "windows.logoff_after_rendered_dependents",
            seed_parts=("WIN-TEST-01.corp.local", "0xabc123", process_time),
        )
        assert emitter._event_dicts[0]["TimeCreated"] == process_time + expected_delta

    def test_process_termination_shifted_after_visible_child_create(self, format_def, temp_output):
        """Security 4689 should not visibly terminate a parent before later child 4688."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        terminate_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        child_time = terminate_time + timedelta(seconds=15)

        emitter._event_dicts = [
            {
                "EventID": 4689,
                "TimeCreated": terminate_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessId": "0x116c",
            },
            {
                "EventID": 4688,
                "TimeCreated": child_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessId": "0x116c",
                "NewProcessId": "0x2200",
            },
        ]

        emitter._shift_process_terminations_after_dependents()

        expected_delta = sample_timing_delta(
            "windows.process_exit_after_visible_child",
            seed_parts=("WIN-TEST-01.corp.local", "0x116c", child_time),
        )
        assert emitter._event_dicts[0]["TimeCreated"] == child_time + expected_delta

    def test_browser_process_termination_is_not_rendered_as_security_4689(
        self, format_def, temp_output
    ):
        """Long-lived browser exits should not create brittle Security/Sysmon death conflicts."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        host = HostContext(
            hostname="WS-01",
            ip="10.0.1.10",
            fqdn="WS-01.example.com",
            os="Windows 11",
            os_category="windows",
            system_type="workstation",
            netbios_domain="CORP",
        )
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            event_type="process_terminate",
            src_host=host,
            auth=AuthContext(username="jsmith", user_sid="S-1-5-21-1-2-3-1001"),
            process=ProcessContext(
                pid=6712,
                parent_pid=4556,
                image=r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                command_line="msedge.exe --type=renderer",
                username="jsmith",
                logon_id="0xabc123",
            ),
        )

        emitter.emit(event)
        emitter.close()

        assert not temp_output.exists() or "<EventID>4689</EventID>" not in temp_output.read_text()

    def test_non_browser_process_termination_still_renders_security_4689(
        self, format_def, temp_output
    ):
        """Short-lived command tools should still render process-exit audit evidence."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        host = HostContext(
            hostname="WS-01",
            ip="10.0.1.10",
            fqdn="WS-01.example.com",
            os="Windows 11",
            os_category="windows",
            system_type="workstation",
            netbios_domain="CORP",
        )
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            event_type="process_terminate",
            src_host=host,
            auth=AuthContext(username="jsmith", user_sid="S-1-5-21-1-2-3-1001"),
            process=ProcessContext(
                pid=7420,
                parent_pid=4556,
                image=r"C:\Windows\System32\cmd.exe",
                command_line="cmd.exe /c whoami",
                username="jsmith",
                logon_id="0xabc123",
            ),
        )

        emitter.emit(event)
        emitter.close()

        content = temp_output.read_text()
        assert "<EventID>4689</EventID>" in content
        assert '<Data Name="ProcessName">C:\\Windows\\System32\\cmd.exe</Data>' in content

    def test_spooled_logoff_shifted_after_same_session_dependents(self, format_def, temp_output):
        """Spooled 4634 fixups should run without materializing all events."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        logoff_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        process_time = logoff_time + timedelta(seconds=10)
        emitter._event_dicts = [
            {
                "EventID": 4634,
                "TimeCreated": logoff_time,
                "Computer": "WIN-TEST-01.corp.local",
                "TargetLogonId": "0xabc123",
            },
            {
                "EventID": 4689,
                "TimeCreated": process_time,
                "Computer": "WIN-TEST-01.corp.local",
                "SubjectLogonId": "0xabc123",
            },
        ]

        emitter._spool_event_dicts_unlocked()
        emitter._shift_spooled_logoffs_after_dependents_unlocked()
        events = list(emitter._iter_spooled_events_unlocked())

        expected_delta = sample_timing_delta(
            "windows.logoff_after_rendered_dependents",
            seed_parts=("WIN-TEST-01.corp.local", "0xabc123", process_time),
        )
        assert events[1]["EventID"] == 4634
        assert events[1]["TimeCreated"] == process_time + expected_delta
        emitter._cleanup_spool_unlocked()

    def test_spooled_process_termination_shifted_after_visible_child_create(
        self, format_def, temp_output
    ):
        """Spooled Security 4689 fixups should preserve lifecycle ordering."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        terminate_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        child_time = terminate_time + timedelta(seconds=15)
        emitter._event_dicts = [
            {
                "EventID": 4689,
                "TimeCreated": terminate_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessId": "0x116c",
            },
            {
                "EventID": 4688,
                "TimeCreated": child_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessId": "0x116c",
                "NewProcessId": "0x2200",
            },
        ]

        emitter._spool_event_dicts_unlocked()
        emitter._shift_spooled_process_terminations_after_dependents_unlocked()
        events = list(emitter._iter_spooled_events_unlocked())

        expected_delta = sample_timing_delta(
            "windows.process_exit_after_visible_child",
            seed_parts=("WIN-TEST-01.corp.local", "0x116c", child_time),
        )
        termination = next(event for event in events if event["EventID"] == 4689)
        assert termination["TimeCreated"] == child_time + expected_delta
        emitter._cleanup_spool_unlocked()

    def test_process_termination_shifted_after_same_process_wfp(self, format_def, temp_output):
        """Security 4689 should not visibly terminate before later same-process 5156."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        terminate_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        wfp_time = terminate_time + timedelta(hours=1)
        emitter._event_dicts = [
            {
                "EventID": 4689,
                "TimeCreated": terminate_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessId": "0xe78",
                "ProcessName": r"C:\Python311\python.exe",
            },
            {
                "EventID": 5156,
                "TimeCreated": wfp_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessID": 3704,
                "Application": r"\device\harddiskvolume1\python311\python.exe",
            },
        ]

        emitter._shift_process_terminations_after_dependents()

        expected_delta = sample_timing_delta(
            "windows.process_exit_after_visible_dependent",
            seed_parts=(
                "WIN-TEST-01.corp.local",
                "0xe78",
                "python.exe",
                wfp_time,
            ),
        )
        assert emitter._event_dicts[0]["TimeCreated"] == wfp_time + expected_delta

    def test_spooled_process_termination_shifted_after_same_process_wfp(
        self, format_def, temp_output
    ):
        """Spooled Security 4689 fixups should account for later same-process 5156."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        terminate_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        wfp_time = terminate_time + timedelta(hours=1)
        emitter._event_dicts = [
            {
                "EventID": 4689,
                "TimeCreated": terminate_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessId": "0xe78",
                "ProcessName": r"C:\Python311\python.exe",
            },
            {
                "EventID": 5156,
                "TimeCreated": wfp_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessID": 3704,
                "Application": r"\device\harddiskvolume1\python311\python.exe",
            },
        ]

        emitter._spool_event_dicts_unlocked()
        emitter._shift_spooled_process_terminations_after_dependents_unlocked()
        events = list(emitter._iter_spooled_events_unlocked())

        expected_delta = sample_timing_delta(
            "windows.process_exit_after_visible_dependent",
            seed_parts=(
                "WIN-TEST-01.corp.local",
                "0xe78",
                "python.exe",
                wfp_time,
            ),
        )
        termination = next(event for event in events if event["EventID"] == 4689)
        assert termination["TimeCreated"] == wfp_time + expected_delta
        emitter._cleanup_spool_unlocked()

    def test_process_termination_shifted_after_same_pid_create(self, format_def, temp_output):
        """Security 4689 should not visibly precede same-process Security 4688."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        terminate_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        create_time = terminate_time + timedelta(milliseconds=44)
        emitter._event_dicts = [
            {
                "EventID": 4689,
                "TimeCreated": terminate_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessId": "0x1e1c",
                "ProcessName": r"C:\Windows\System32\gpupdate.exe",
            },
            {
                "EventID": 4688,
                "TimeCreated": create_time,
                "Computer": "WIN-TEST-01.corp.local",
                "NewProcessId": "0x1e1c",
                "NewProcessName": r"C:\Windows\System32\gpupdate.exe",
            },
        ]

        emitter._shift_process_dependents_after_create()

        expected_delta = sample_timing_delta(
            "windows.process_exit_after_visible_create",
            seed_parts=(
                "WIN-TEST-01.corp.local",
                "0x1e1c",
                "gpupdate.exe",
                create_time,
            ),
        )
        assert emitter._event_dicts[0]["TimeCreated"] == create_time + expected_delta

    def test_wfp_connection_shifted_after_same_pid_create(self, format_def, temp_output):
        """Security 5156 should not visibly precede same-process Security 4688."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        wfp_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        create_time = wfp_time + timedelta(milliseconds=245)
        emitter._event_dicts = [
            {
                "EventID": 5156,
                "TimeCreated": wfp_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessID": 7416,
                "Application": r"\device\harddiskvolume1\windows\system32\mstsc.exe",
            },
            {
                "EventID": 4688,
                "TimeCreated": create_time,
                "Computer": "WIN-TEST-01.corp.local",
                "NewProcessId": "0x1cf8",
                "NewProcessName": r"C:\Windows\System32\mstsc.exe",
            },
        ]

        emitter._shift_process_dependents_after_create()

        expected_delta = sample_timing_delta(
            "source.windows_wfp_connection",
            seed_parts=(
                "WIN-TEST-01.corp.local",
                "0x1cf8",
                "mstsc.exe",
                create_time,
            ),
        )
        assert emitter._event_dicts[0]["TimeCreated"] == create_time + expected_delta

    def test_spooled_wfp_connection_shifted_after_same_pid_create(self, format_def, temp_output):
        """Spooled Security 5156 fixups should preserve process-before-network order."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        wfp_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        create_time = wfp_time + timedelta(milliseconds=136)
        emitter._event_dicts = [
            {
                "EventID": 5156,
                "TimeCreated": wfp_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessID": 6136,
                "Application": r"\device\harddiskvolume1\program files\palo alto\pangpa.exe",
            },
            {
                "EventID": 4688,
                "TimeCreated": create_time,
                "Computer": "WIN-TEST-01.corp.local",
                "NewProcessId": "0x17f8",
                "NewProcessName": r"C:\Program Files\Palo Alto\pangpa.exe",
            },
        ]

        emitter._spool_event_dicts_unlocked()
        emitter._shift_spooled_process_dependents_after_create_unlocked()
        events = list(emitter._iter_spooled_events_unlocked())

        expected_delta = sample_timing_delta(
            "source.windows_wfp_connection",
            seed_parts=(
                "WIN-TEST-01.corp.local",
                "0x17f8",
                "pangpa.exe",
                create_time,
            ),
        )
        wfp = next(event for event in events if event["EventID"] == 5156)
        assert wfp["TimeCreated"] == create_time + expected_delta
        emitter._cleanup_spool_unlocked()

    def test_process_create_shifted_after_visible_parent_create(self, format_def, temp_output):
        """Security 4688 should not visibly create a child before its parent 4688."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        child_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        parent_time = child_time + timedelta(seconds=1)

        emitter._event_dicts = [
            {
                "EventID": 4688,
                "TimeCreated": child_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessId": "0x1070",
                "NewProcessId": "0x1084",
            },
            {
                "EventID": 4688,
                "TimeCreated": parent_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessId": "0x4",
                "NewProcessId": "0x1070",
            },
        ]

        emitter._shift_process_creates_after_visible_parent()

        assert emitter._event_dicts[0]["TimeCreated"] == parent_time + timedelta(milliseconds=1)

    def test_process_create_self_parent_is_not_shifted_forever(self, format_def, temp_output):
        """Self-parent raw Security 4688 records should be treated as unshiftable."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        event_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        emitter._event_dicts = [
            {
                "EventID": 4688,
                "TimeCreated": event_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessId": "0x1234",
                "NewProcessId": "0x1234",
            },
        ]

        emitter._shift_process_creates_after_visible_parent()

        assert emitter._event_dicts[0]["TimeCreated"] == event_time

    def test_process_create_parent_cycle_is_not_shifted_forever(self, format_def, temp_output):
        """Cyclic raw Security 4688 parent PIDs should be treated as unshiftable."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        first_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        second_time = datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC)

        emitter._event_dicts = [
            {
                "EventID": 4688,
                "TimeCreated": first_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessId": "0x2222",
                "NewProcessId": "0x1111",
            },
            {
                "EventID": 4688,
                "TimeCreated": second_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessId": "0x1111",
                "NewProcessId": "0x2222",
            },
        ]

        emitter._shift_process_creates_after_visible_parent()

        assert emitter._event_dicts[0]["TimeCreated"] == first_time
        assert emitter._event_dicts[1]["TimeCreated"] == second_time

    def test_process_create_shifted_after_visible_logon(self, format_def, temp_output):
        """Security 4688 should not visibly precede its same-session 4624 row."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        process_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_time = process_time + timedelta(milliseconds=1)

        emitter._event_dicts = [
            {
                "EventID": 4688,
                "TimeCreated": process_time,
                "Computer": "WIN-TEST-01.corp.local",
                "SubjectLogonId": "0xabc123",
                "NewProcessId": "0x1084",
            },
            {
                "EventID": 4624,
                "TimeCreated": logon_time,
                "Computer": "WIN-TEST-01.corp.local",
                "TargetLogonId": "0xabc123",
                "LogonType": 11,
            },
        ]

        emitter._shift_process_creates_after_logons()

        assert emitter._event_dicts[0]["TimeCreated"] == logon_time + timedelta(milliseconds=1)

    def test_process_create_not_shifted_after_type7_unlock(self, format_def, temp_output):
        """Type 7 unlock 4624 rows are not original session creation events."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        process_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        unlock_time = process_time + timedelta(minutes=5)

        emitter._event_dicts = [
            {
                "EventID": 4688,
                "TimeCreated": process_time,
                "Computer": "WIN-TEST-01.corp.local",
                "SubjectLogonId": "0xabc123",
                "NewProcessId": "0x1084",
            },
            {
                "EventID": 4624,
                "TimeCreated": unlock_time,
                "Computer": "WIN-TEST-01.corp.local",
                "TargetLogonId": "0xabc123",
                "LogonType": 7,
            },
        ]

        emitter._shift_process_creates_after_logons()

        assert emitter._event_dicts[0]["TimeCreated"] == process_time

    def test_spooled_process_create_shifted_after_visible_parent_create(
        self, format_def, temp_output
    ):
        """Spooled Security 4688 fixups should preserve parent-before-child ordering."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        child_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        parent_time = child_time + timedelta(seconds=1)
        emitter._event_dicts = [
            {
                "EventID": 4688,
                "TimeCreated": child_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessId": "0x1070",
                "NewProcessId": "0x1084",
            },
            {
                "EventID": 4688,
                "TimeCreated": parent_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessId": "0x4",
                "NewProcessId": "0x1070",
            },
        ]

        emitter._spool_event_dicts_unlocked()
        emitter._shift_spooled_process_creates_after_visible_parent_unlocked()
        events = list(emitter._iter_spooled_events_unlocked())

        child = next(event for event in events if event["NewProcessId"] == "0x1084")
        assert child["TimeCreated"] == parent_time + timedelta(milliseconds=1)
        emitter._cleanup_spool_unlocked()

    def test_spooled_process_create_parent_cycle_is_not_shifted_forever(
        self, format_def, temp_output
    ):
        """Spooled cyclic raw Security 4688 parent PIDs should be treated as unshiftable."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        first_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        second_time = datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC)
        emitter._event_dicts = [
            {
                "EventID": 4688,
                "TimeCreated": first_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessId": "0x2222",
                "NewProcessId": "0x1111",
            },
            {
                "EventID": 4688,
                "TimeCreated": second_time,
                "Computer": "WIN-TEST-01.corp.local",
                "ProcessId": "0x1111",
                "NewProcessId": "0x2222",
            },
        ]

        emitter._spool_event_dicts_unlocked()
        emitter._shift_spooled_process_creates_after_visible_parent_unlocked()
        events = list(emitter._iter_spooled_events_unlocked())

        first = next(event for event in events if event["NewProcessId"] == "0x1111")
        second = next(event for event in events if event["NewProcessId"] == "0x2222")
        assert first["TimeCreated"] == first_time
        assert second["TimeCreated"] == second_time
        emitter._cleanup_spool_unlocked()

    def test_spooled_process_create_shifted_after_visible_logon(self, format_def, temp_output):
        """Spooled Security 4688 fixups should preserve logon-before-process ordering."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        process_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_time = process_time + timedelta(milliseconds=1)
        emitter._event_dicts = [
            {
                "EventID": 4688,
                "TimeCreated": process_time,
                "Computer": "WIN-TEST-01.corp.local",
                "SubjectLogonId": "0xabc123",
                "NewProcessId": "0x1084",
            },
            {
                "EventID": 4624,
                "TimeCreated": logon_time,
                "Computer": "WIN-TEST-01.corp.local",
                "TargetLogonId": "0xabc123",
                "LogonType": 11,
            },
        ]

        emitter._spool_event_dicts_unlocked()
        emitter._shift_spooled_process_creates_after_logons_unlocked()
        events = list(emitter._iter_spooled_events_unlocked())

        process = next(event for event in events if event["EventID"] == 4688)
        assert process["TimeCreated"] == logon_time + timedelta(milliseconds=1)
        emitter._cleanup_spool_unlocked()

    def test_windows_time_created_spreads_large_same_timestamp_clusters(self):
        """Dense same-host Windows/Sysmon timestamp ties should not compress into microseconds."""
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        last_by_computer: dict[str, datetime] = {}
        collision_count_by_computer: dict[str, int] = {}
        rendered_times: list[datetime] = []

        for sequence in range(30):
            event = {
                "EventID": 4688,
                "TimeCreated": base_time,
                "Computer": "WIN-TEST-01.corp.local",
            }
            _normalize_windows_time_created(
                event,
                last_by_computer,
                collision_count_by_computer,
                sequence,
                "test_windows_time_created",
            )
            rendered_times.append(event["TimeCreated"])

        gaps = [rendered_times[i] - rendered_times[i - 1] for i in range(1, len(rendered_times))]
        assert max(gaps[:24]) < timedelta(milliseconds=1)
        assert min(gaps[25:]) >= timedelta(seconds=1)

    def test_kerberos_tgt_shifted_before_visible_service_ticket(self, format_def, temp_output):
        """Rendered DC Security 4768 rows should visibly precede dependent 4769 rows."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        tgs_time = datetime(2024, 1, 15, 10, 0, 0, 500_000, tzinfo=UTC)
        tgt_time = tgs_time + timedelta(milliseconds=50)
        tgs = {
            "EventID": 4769,
            "TimeCreated": tgs_time,
            "Computer": "DC-01.corp.local",
            "TargetUserName": "alice@CORP.LOCAL",
            "IpAddress": "::ffff:10.0.0.25",
            "IpPort": "51234",
        }
        tgt = {
            "EventID": 4768,
            "TimeCreated": tgt_time,
            "Computer": "DC-01.corp.local",
            "TargetUserName": "alice",
            "IpAddress": "::ffff:10.0.0.25",
            "IpPort": "51234",
        }
        emitter._event_dicts = [tgs, tgt]

        emitter._shift_kerberos_tgts_before_service_tickets()

        assert tgt["TimeCreated"] < tgs["TimeCreated"]
        assert tgt["TimeCreated"].microsecond % 1000 != tgs["TimeCreated"].microsecond % 1000

    def test_kerberos_tgt_shift_uses_source_port_specific_key(self, format_def, temp_output):
        """An older TGT on a different client port should not satisfy a later TGS."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        tgs_time = datetime(2024, 1, 15, 10, 0, 0, 500_000, tzinfo=UTC)
        previous_tgt = {
            "EventID": 4768,
            "TimeCreated": tgs_time - timedelta(seconds=30),
            "Computer": "DC-01.corp.local",
            "TargetUserName": "alice",
            "IpAddress": "::ffff:10.0.0.25",
            "IpPort": "49152",
        }
        tgs = {
            "EventID": 4769,
            "TimeCreated": tgs_time,
            "Computer": "DC-01.corp.local",
            "TargetUserName": "alice@CORP.LOCAL",
            "IpAddress": "::ffff:10.0.0.25",
            "IpPort": "51234",
        }
        matching_tgt = {
            "EventID": 4768,
            "TimeCreated": tgs_time + timedelta(milliseconds=50),
            "Computer": "DC-01.corp.local",
            "TargetUserName": "alice",
            "IpAddress": "::ffff:10.0.0.25",
            "IpPort": "51234",
        }
        emitter._event_dicts = [previous_tgt, tgs, matching_tgt]

        emitter._shift_kerberos_tgts_before_service_tickets()

        assert matching_tgt["TimeCreated"] < tgs["TimeCreated"]
        assert previous_tgt["TimeCreated"] < matching_tgt["TimeCreated"]

    def test_spooled_kerberos_tgt_shifted_before_visible_service_ticket(
        self,
        format_def,
        temp_output,
    ):
        """Spooled Windows rows should keep visible TGT before TGS after final sort."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        tgs_time = datetime(2024, 1, 15, 10, 0, 0, 500_000, tzinfo=UTC)
        emitter._event_dicts = [
            {
                "EventID": 4769,
                "TimeCreated": tgs_time,
                "Computer": "DC-01.corp.local",
                "TargetUserName": "alice@CORP.LOCAL",
                "IpAddress": "::ffff:10.0.0.25",
                "IpPort": "51234",
            },
            {
                "EventID": 4768,
                "TimeCreated": tgs_time + timedelta(milliseconds=50),
                "Computer": "DC-01.corp.local",
                "TargetUserName": "alice",
                "IpAddress": "::ffff:10.0.0.25",
                "IpPort": "51234",
            },
        ]
        emitter._spool_event_dicts_unlocked()

        emitter._shift_spooled_kerberos_tgts_before_service_tickets_unlocked()
        events = list(emitter._iter_spooled_events_unlocked())

        assert [event["EventID"] for event in events] == [4768, 4769]
        assert events[0]["TimeCreated"] < events[1]["TimeCreated"]

    def test_windows_events_defer_rendering_until_close(self, format_def, temp_output):
        """Windows events should render in one final chronological RecordID pass."""
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

        # Intermediate flushes should not materialize partial Windows logs.
        emitter.flush()
        assert not temp_output.exists()

        emitter.close()

        # Verify all 3 events are in the file
        content = temp_output.read_text()
        assert content.count("<EventID>4624</EventID>") == 3
        assert "user0" in content
        assert "user1" in content
        assert "user2" in content

    def test_windows_emitter_spools_buffer_to_bound_memory(self, format_def, temp_output):
        """Windows event dict buffering should remain bounded before final rendering."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=3)

        for idx in range(10):
            emitter.emit_event(
                {
                    "EventID": 4624,
                    "TimeCreated": datetime(2024, 1, 15, 10, 30, idx, tzinfo=UTC),
                    "Computer": "WIN-TEST-01",
                    "Channel": "Security",
                    "Level": 0,
                    "ExecutionProcessID": 4,
                    "ExecutionThreadID": 100,
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

            assert len(emitter._event_dicts) < emitter.buffer_size

        assert emitter._spooled_count == 9
        assert not temp_output.exists()

        emitter.close()

        content = temp_output.read_text()
        assert content.count("<EventID>4624</EventID>") == 10
        assert emitter._spooled_count == 0
        assert len(emitter._event_dicts) == 0

    def test_windows_spool_preserves_sentinel_prefixed_raw_strings(self, format_def, temp_output):
        """Spool decoding should not parse attacker-controlled strings as datetimes."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        emitter.emit_event(
            {
                "EventID": 4624,
                "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
                "Computer": "WIN-TEST-01",
                "Channel": "Security",
                "Level": 0,
                "ExecutionProcessID": 4,
                "ExecutionThreadID": 100,
                "TargetUserName": "__dt__:not-a-date",
                "TargetDomainName": "CORP",
                "TargetLogonId": "0x000001",
                "LogonType": 2,
                "WorkstationName": "WIN-TEST-01",
                "IpAddress": "192.168.1.100",
                "LogonProcessName": "User32",
                "AuthenticationPackageName": "Negotiate",
            }
        )

        emitter.close()

        content = temp_output.read_text()
        assert "__dt__:not-a-date" in content
        assert content.count("<EventID>4624</EventID>") == 1

    def test_windows_spooled_flush_uses_streaming_fixups(self, format_def, temp_output):
        """Final spooled rendering should not fall back to list-based event fixups."""

        class GuardedWindowsEventEmitter(WindowsEventEmitter):
            def _shift_process_creates_after_visible_parent(self) -> None:
                raise AssertionError("spooled flush must not materialize list-based create fixups")

            def _shift_process_terminations_after_dependents(self) -> None:
                raise AssertionError("spooled flush must not materialize list-based process fixups")

            def _shift_logoffs_after_dependents(self) -> None:
                raise AssertionError("spooled flush must not materialize list-based logoff fixups")

            def _suppress_duplicate_lock_unlock_transitions(self) -> None:
                raise AssertionError("spooled flush must not materialize list-based lock fixups")

        emitter = GuardedWindowsEventEmitter(format_def, temp_output, buffer_size=1)
        for idx in range(3):
            emitter.emit_event(
                {
                    "EventID": 4624,
                    "TimeCreated": datetime(2024, 1, 15, 10, 30, idx, tzinfo=UTC),
                    "Computer": "WIN-TEST-01",
                    "Channel": "Security",
                    "Level": 0,
                    "ExecutionProcessID": 4,
                    "ExecutionThreadID": 100,
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
        assert content.count("<EventID>4624</EventID>") == 3

    def test_threaded_windows_barrier_spools_buffer_to_bound_memory(self, format_def, temp_output):
        """Threaded Windows barrier flush should release in-memory event dicts."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=100, threaded=True)

        for idx in range(10):
            emitter.emit_event(
                {
                    "EventID": 4624,
                    "TimeCreated": datetime(2024, 1, 15, 10, 30, idx, tzinfo=UTC),
                    "Computer": "WIN-TEST-01",
                    "Channel": "Security",
                    "Level": 0,
                    "ExecutionProcessID": 4,
                    "ExecutionThreadID": 100,
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

        emitter.barrier_flush()

        assert len(emitter._event_dicts) == 0
        assert emitter._spooled_count == 10
        assert not temp_output.exists()

        emitter.close()

        content = temp_output.read_text()
        assert content.count("<EventID>4624</EventID>") == 10

    def test_windows_record_ids_follow_global_chronology_across_flushes(
        self, format_def, temp_output
    ):
        """A late-discovered earlier event should not get a higher RecordID."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        base = {
            "Computer": "WIN-TEST-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 100,
            "TargetUserName": "jsmith",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x123",
            "LogonType": 2,
            "WorkstationName": "WIN-TEST-01",
            "IpAddress": "10.0.0.10",
            "LogonProcessName": "User32",
            "AuthenticationPackageName": "Negotiate",
        }
        later = {
            **base,
            "EventID": 4624,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
        }
        earlier = {
            **base,
            "EventID": 4624,
            "TimeCreated": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            "TargetUserName": "adoe",
        }

        emitter.emit_event(later)
        emitter.flush()
        emitter.emit_event(earlier)
        emitter.close()

        content = temp_output.read_text()
        records = [
            int(match.group(1))
            for match in re.finditer(r"<EventRecordID>(\d+)</EventRecordID>", content)
        ]
        users = re.findall(r'<Data Name="TargetUserName">([^<]+)</Data>', content)
        assert users == ["adoe", "jsmith"]
        assert records == sorted(records)

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

    def test_event_record_ids_preserve_rendered_time_order_for_storyline_events(
        self, format_def, temp_output
    ):
        """RecordID order should not move backward in rendered SystemTime."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        base = {
            "Computer": "WIN-TEST-01",
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 100,
            "TargetUserName": "jsmith",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x123",
            "LogonType": 2,
            "WorkstationName": "WIN-TEST-01",
            "IpAddress": "10.0.0.10",
            "LogonProcessName": "User32",
            "AuthenticationPackageName": "Negotiate",
        }

        for idx in range(3):
            emitter.emit_event(
                {
                    **base,
                    "EventID": 4624,
                    "TimeCreated": datetime(2024, 1, 15, 10, 30, 17, 361258, tzinfo=UTC),
                    "ExecutionThreadID": 100 + idx,
                    "TargetUserName": f"user{idx}",
                    "_storyline_origin": True,
                }
            )

        emitter.close()

        content = temp_output.read_text()
        rows = list(
            zip(
                re.findall(r"<EventRecordID>(\d+)</EventRecordID>", content),
                re.findall(r'SystemTime="([^"]+)"', content),
                strict=True,
            )
        )

        assert [int(record_id) for record_id, _ in rows] == sorted(
            int(record_id) for record_id, _ in rows
        )
        assert [timestamp for _, timestamp in rows] == sorted(timestamp for _, timestamp in rows)
        assert len({timestamp for _, timestamp in rows}) == len(rows)

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

    def test_failed_logon_without_source_ip_does_not_keep_source_port(
        self, format_def, temp_output
    ):
        """4625 source port should not survive when the source address is unavailable."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        host = HostContext(
            hostname="DC-01",
            ip="10.0.0.10",
            fqdn="DC-01.corp.local",
            os="Windows Server 2022",
            os_category="windows",
            system_type="server",
            netbios_domain="CORP",
        )
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="failed_logon",
            dst_host=host,
            auth=AuthContext(
                username="baduser",
                user_sid="S-1-0-0",
                logon_type=3,
                source_ip="-",
                source_port=58680,
                subject_sid="S-1-5-18",
                subject_username="SYSTEM",
                subject_domain="NT AUTHORITY",
                subject_logon_id="0x3e7",
                failure_status="0xc000006d",
                failure_substatus="0xc000006a",
                failure_reason="%%2313",
                logon_process="NtLmSsp",
                auth_package="NTLM",
                lm_package="NTLM V2",
            ),
        )

        emitter.emit(event)
        emitter.close()

        content = temp_output.read_text()
        assert '<Data Name="IpAddress">-</Data>' in content
        assert '<Data Name="IpPort">-</Data>' in content
        assert "58680" not in content

    def test_local_logon_blank_source_renders_dash_port(self, format_def, temp_output):
        """4624 local/service logons should render unavailable IP and port as dashes."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        host = HostContext(
            hostname="DC-01",
            ip="10.0.0.10",
            fqdn="DC-01.corp.local",
            os="Windows Server 2022",
            os_category="windows",
            system_type="server",
            netbios_domain="CORP",
        )
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="logon",
            dst_host=host,
            auth=AuthContext(
                username="SYSTEM",
                user_sid="S-1-5-18",
                logon_type=5,
                source_ip="-",
                source_port=0,
                subject_sid="S-1-5-18",
                subject_username="SYSTEM",
                subject_domain="NT AUTHORITY",
                subject_logon_id="0x3e7",
                logon_process="Advapi",
                auth_package="Negotiate",
            ),
        )

        emitter.emit(event)
        emitter.close()

        content = temp_output.read_text()
        assert '<Data Name="IpAddress">-</Data>' in content
        assert '<Data Name="IpPort">-</Data>' in content

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

    def test_network_service_privilege_fallback_is_not_single_low_privilege(self):
        """4672 fallback for NETWORK SERVICE includes real special privileges."""
        privs = _special_privilege_fallback("NETWORK SERVICE")

        assert "SeImpersonatePrivilege" in privs
        assert "SeAssignPrimaryTokenPrivilege" in privs
        assert privs != "SeChangeNotifyPrivilege"

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
            "NetworkAddress": "10.0.0.50",
            "NetworkPort": 50123,
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
        assert '<Data Name="NetworkAddress">10.0.0.50</Data>' in content
        assert '<Data Name="NetworkPort">50123</Data>' in content

    def test_explicit_credentials_blank_endpoint_renders_dash_port(self, format_def, temp_output):
        """4648 should render unavailable NetworkAddress and NetworkPort consistently."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
            event_type="explicit_credentials",
            dst_host=HostContext(
                hostname="WKS-01",
                ip="10.0.0.25",
                fqdn="WKS-01.corp.local",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
                netbios_domain="CORP",
            ),
            auth=AuthContext(
                username="admin01",
                subject_username="SYSTEM",
                subject_sid="S-1-5-18",
                subject_domain="NT AUTHORITY",
                subject_logon_id="0x3e7",
                source_ip="-",
                source_port=0,
                target_server="WKS-01",
                process_name=r"C:\Windows\System32\runas.exe",
                process_pid=4242,
            ),
        )

        emitter.emit(event)
        emitter.close()

        content = temp_output.read_text()
        assert '<Data Name="NetworkAddress">-</Data>' in content
        assert '<Data Name="NetworkPort">-</Data>' in content

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

    def test_wfp_connection_uses_source_native_timestamp_offset(self, format_def, temp_output):
        """WFP 5156 should render with a host-audit offset from the canonical connection."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        event_time = datetime(2024, 1, 15, 10, 31, 0, tzinfo=UTC)
        event = SecurityEvent(
            timestamp=event_time,
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

        expected_delta = sample_timing_delta(
            "source.windows_wfp_connection",
            seed_parts=("WKS-01", 4, "10.0.0.50", 49263, "93.184.216.34", 443, event_time),
        )
        assert emitter._event_dicts[0]["TimeCreated"] == event_time + expected_delta

    def test_wfp_connection_reuses_filter_rtid_per_policy_bucket(self, format_def, temp_output):
        """WFP 5156 should reuse runtime filter IDs for the same host policy bucket."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        event_time = datetime(2024, 1, 15, 10, 31, 0, tzinfo=UTC)

        def make_event(src_port: int, dst_ip: str, dst_port: int, protocol: str = "tcp"):
            return SecurityEvent(
                timestamp=event_time,
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
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=protocol,
                    ip_proto=17 if protocol == "udp" else 6,
                    initiating_pid=4,
                ),
            )

        emitter.emit(make_event(49263, "93.184.216.34", 443))
        emitter.emit(make_event(49264, "151.101.0.223", 443))
        emitter.emit(make_event(49265, "10.0.0.10", 53, "udp"))

        filter_ids = [event["FilterRTID"] for event in emitter._event_dicts]
        assert filter_ids[0] == filter_ids[1]
        assert filter_ids[2] != filter_ids[0]
        assert len(set(filter_ids)) == 2

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

    def test_wfp_connection_renders_inbound_direction(self, format_def, temp_output):
        """Target-side WFP rows should render inbound direction and local service PID."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 31, 0, tzinfo=UTC),
            event_type="wfp_connection",
            src_host=HostContext(
                hostname="DC-01",
                ip="10.0.0.10",
                os="Windows Server 2022",
                os_category="windows",
                system_type="domain_controller",
                fqdn="DC-01.corp.local",
            ),
            process=ProcessContext(
                pid=684,
                parent_pid=500,
                image=r"C:\Windows\System32\lsass.exe",
                command_line="lsass.exe",
                username="SYSTEM",
                start_time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            ),
            network=NetworkContext(
                src_ip="10.0.0.50",
                src_port=49263,
                dst_ip="10.0.0.10",
                dst_port=88,
                protocol="tcp",
                initiating_pid=684,
            ),
        )

        emitter.emit(event)
        emitter.close()

        content = temp_output.read_text()
        assert '<Data Name="Direction">%%14592</Data>' in content
        assert '<Data Name="ProcessID">684</Data>' in content
        assert '<Data Name="DestAddress">10.0.0.10</Data>' in content

    def test_wfp_dns_connection_uses_dns_client_svchost_pid(self, format_def, temp_output):
        """DNS-client WFP rows should align with Sysmon Event 22's svchost identity."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        emitter._system_pids = {"WKS-01": {"svchost_local_svc": 1184}}

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
                dst_ip="10.0.0.10",
                dst_port=53,
                protocol="udp",
                initiating_pid=4321,
            ),
        )

        emitter.emit(event)
        emitter.close()

        content = temp_output.read_text()
        assert '<Data Name="ProcessID">1184</Data>' in content
        assert (
            '<Data Name="Application">\\device\\harddiskvolume1\\windows\\system32\\'
            "svchost.exe</Data>"
        ) in content

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

    def test_system_subject_domain_normalizes_to_nt_authority(self):
        """S-1-5-18/SYSTEM subjects should not inherit the AD domain."""
        auth = AuthContext(
            username="svc_sqlreader",
            subject_sid="S-1-5-18",
            subject_username="SYSTEM",
            subject_domain="MERIDIANHCS",
        )

        assert _auth_subject_domain(auth, "MERIDIANHCS") == "NT AUTHORITY"

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

    def test_kerberos_preauth_without_source_ip_does_not_keep_source_port(
        self, format_def, temp_output
    ):
        """4771 source port should not survive when the source address is unavailable."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)
        host = HostContext(
            hostname="DC-01",
            ip="10.0.0.10",
            fqdn="DC-01.corp.local",
            os="Windows Server 2022",
            os_category="windows",
            system_type="domain_controller",
            netbios_domain="CORP",
        )
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="kerberos_preauth_failed",
            dst_host=host,
            kerberos=KerberosContext(
                target_username="aisha.johnson",
                target_domain="CORP.LOCAL",
                target_sid="S-1-5-21-123-456-789-1104",
                service_name="krbtgt",
                ticket_options="0x40810010",
                ticket_status="0x18",
                pre_auth_type=2,
                source_ip="-",
                source_port=49888,
                reporting_pid=732,
            ),
        )

        emitter.emit(event)
        emitter.close()

        content = temp_output.read_text()
        assert '<Data Name="IpAddress">-</Data>' in content
        assert '<Data Name="IpPort">-</Data>' in content
        assert "49888" not in content

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
        assert '<Security UserID="S-1-5-21-123-456-789-1001"/>' in content
        assert "<SubjectUserName>admin01</SubjectUserName>" in content
        assert "<SubjectDomainName>CORP</SubjectDomainName>" in content
        assert "EventData" not in content or content.count("EventData") == 0

    def test_event_record_id_remains_monotonic_after_log_cleared(self, format_def, temp_output):
        """Security EventRecordID should remain monotonic in a rendered output stream."""
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
        assert record_ids == sorted(record_ids)
        assert record_ids[1] > record_ids[0]
        assert record_ids[2] > record_ids[1]

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

    def test_lock_unlock_render_canonical_session_id_from_auth_context(
        self, format_def, temp_output
    ):
        """4800/4801 SessionId should come from session state, not LogonID hashing."""
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
        base_auth = {
            "username": "jsmith",
            "user_sid": "S-1-5-21-123-456-789-1001",
        }
        emitter.emit(
            SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 30, 0, 0, tzinfo=UTC),
                event_type="workstation_locked",
                dst_host=host,
                auth=AuthContext(**base_auth, logon_id="0x2664c4e", session_id=5),
            )
        )
        emitter.emit(
            SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 35, 0, 0, tzinfo=UTC),
                event_type="workstation_unlocked",
                dst_host=host,
                auth=AuthContext(**base_auth, logon_id="0x2802b88", session_id=6),
            )
        )
        emitter.close()
        content = temp_output.read_text()
        assert '<Data Name="TargetLogonId">0x2664c4e</Data>' in content
        assert '<Data Name="SessionId">5</Data>' in content
        assert '<Data Name="TargetLogonId">0x2802b88</Data>' in content
        assert '<Data Name="SessionId">6</Data>' in content

    def test_duplicate_unlock_suppression_handles_many_paired_type7_logons(
        self, format_def, temp_output
    ):
        """Duplicate unlock suppression should drop paired type 7 logons at scale."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        host = "WKS-01.corp.local"
        logon_id = "0x4f2a1b"
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        event_count = 400
        events = [
            {
                "EventID": 4801,
                "TimeCreated": base,
                "Computer": host,
                "TargetLogonId": logon_id,
                "SessionId": 2,
            },
        ]
        for offset in range(1, event_count):
            unlock_time = base + timedelta(seconds=offset * 3)
            events.extend(
                [
                    {
                        "EventID": 4801,
                        "TimeCreated": unlock_time,
                        "Computer": host,
                        "TargetLogonId": logon_id,
                        "SessionId": 2,
                    },
                    {
                        "EventID": 4624,
                        "TimeCreated": unlock_time + timedelta(milliseconds=50),
                        "Computer": host,
                        "TargetLogonId": logon_id,
                        "LogonType": 7,
                    },
                ]
            )
        emitter._event_dicts = events

        emitter._suppress_duplicate_lock_unlock_transitions()

        assert emitter._event_dicts == [events[0]]

    def test_duplicate_lock_unlock_state_transitions_are_suppressed(self, format_def, temp_output):
        """Security 4800/4801 should alternate chronologically for a session."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        host = "WKS-01.corp.local"
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        emitter._event_dicts = [
            {
                "EventID": 4801,
                "TimeCreated": base + timedelta(minutes=30),
                "Computer": host,
                "TargetLogonId": "0x4f2a1b",
                "SessionId": 2,
            },
            {
                "EventID": 4800,
                "TimeCreated": base,
                "Computer": host,
                "TargetLogonId": "0x4f2a1b",
                "SessionId": 2,
            },
            {
                "EventID": 4800,
                "TimeCreated": base + timedelta(minutes=10),
                "Computer": host,
                "TargetLogonId": "0x4f2a1b",
                "SessionId": 2,
            },
            {
                "EventID": 4801,
                "TimeCreated": base + timedelta(minutes=20),
                "Computer": host,
                "TargetLogonId": "0x4f2a1b",
                "SessionId": 2,
            },
            {
                "EventID": 4624,
                "TimeCreated": base + timedelta(minutes=30, milliseconds=50),
                "Computer": host,
                "TargetLogonId": "0x4f2a1b",
                "LogonType": 7,
            },
        ]

        emitter._suppress_duplicate_lock_unlock_transitions()

        remaining = [(event["EventID"], event["TimeCreated"]) for event in emitter._event_dicts]
        assert remaining == [
            (4800, base),
            (4801, base + timedelta(minutes=20)),
        ]

    def test_spooled_duplicate_lock_unlock_state_transitions_are_suppressed(
        self, format_def, temp_output
    ):
        """Spooled 4800/4801 fixups should preserve the session state machine."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=10)
        host = "WKS-01.corp.local"
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        emitter._event_dicts = [
            {
                "EventID": 4801,
                "TimeCreated": base + timedelta(minutes=30),
                "Computer": host,
                "TargetLogonId": "0x4f2a1b",
                "SessionId": 2,
            },
            {
                "EventID": 4800,
                "TimeCreated": base,
                "Computer": host,
                "TargetLogonId": "0x4f2a1b",
                "SessionId": 2,
            },
            {
                "EventID": 4800,
                "TimeCreated": base + timedelta(minutes=10),
                "Computer": host,
                "TargetLogonId": "0x4f2a1b",
                "SessionId": 2,
            },
            {
                "EventID": 4801,
                "TimeCreated": base + timedelta(minutes=20),
                "Computer": host,
                "TargetLogonId": "0x4f2a1b",
                "SessionId": 2,
            },
            {
                "EventID": 4624,
                "TimeCreated": base + timedelta(minutes=30, milliseconds=50),
                "Computer": host,
                "TargetLogonId": "0x4f2a1b",
                "LogonType": 7,
            },
        ]

        emitter._spool_event_dicts_unlocked()
        emitter._suppress_spooled_duplicate_lock_unlock_transitions_unlocked()
        events = list(emitter._iter_spooled_events_unlocked())

        remaining = [(event["EventID"], event["TimeCreated"]) for event in events]
        assert remaining == [
            (4800, base),
            (4801, base + timedelta(minutes=20)),
        ]
        emitter._cleanup_spool_unlocked()

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
        """Test emitting 4738 (user account changed) with native account fields."""
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
        assert '<Data Name="Dummy">' not in content
        assert '<Data Name="TargetUserName">jsmith</Data>' in content

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

    def test_can_handle_ssh_transport_only_as_connection(self, format_def, temp_output):
        """SSH transport rows must come from canonical connection events."""
        emitter = ZeekEmitter(format_def, temp_output, buffer_size=1)
        network = NetworkContext(
            src_ip="10.0.1.10",
            src_port=51111,
            dst_ip="10.0.2.20",
            dst_port=22,
            protocol="tcp",
            service="ssh",
            zeek_uid=generate_zeek_uid(),
            conn_state="SF",
        )

        connection_event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            event_type="connection",
            network=network,
        )
        ssh_session_event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            event_type="ssh_session",
            network=network,
        )

        assert emitter.can_handle(connection_event) is True
        assert emitter.can_handle(ssh_session_event) is False

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

    @pytest.mark.parametrize(
        ("canonical", "expected"),
        [
            ("kerberos", "krb"),
            ("sql", "tds"),
            ("mssql", "tds"),
            ("rpc", "dce_rpc"),
        ],
    )
    def test_emit_connection_uses_zeek_native_service_names(
        self, format_def, temp_output, canonical, expected
    ):
        """conn.service should use Zeek analyzer vocabulary."""
        emitter = ZeekEmitter(format_def, temp_output, buffer_size=1)
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.0.50",
                src_port=49152,
                dst_ip="10.0.0.10",
                dst_port=88,
                protocol="tcp",
                service=canonical,
                zeek_uid="CNativeSvc12345",
                duration=0.1,
                orig_bytes=100,
                resp_bytes=200,
                conn_state="SF",
                history="ShADadfF",
                orig_pkts=3,
                orig_ip_bytes=220,
                resp_pkts=3,
                resp_ip_bytes=320,
                ip_proto=6,
            ),
        )

        emitter.emit(event)
        emitter.close()

        conn = json.loads(temp_output.read_text().strip())
        assert conn["service"] == expected

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

    def test_emit_icmp_uses_zeek_type_code_ports(self, format_def, temp_output):
        """ICMP conn rows should render type/code semantics, not all-zero ports."""
        emitter = ZeekEmitter(format_def, temp_output, buffer_size=1)
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 5, 654321, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.0.50",
                src_port=0,
                dst_ip="8.8.8.8",
                dst_port=0,
                protocol="icmp",
                zeek_uid="CTestIcmp123456",
                duration=0.04,
                orig_bytes=64,
                resp_bytes=64,
                conn_state="OTH",
                history="-",
                orig_pkts=1,
                orig_ip_bytes=92,
                resp_pkts=1,
                resp_ip_bytes=92,
                ip_proto=1,
            ),
        )

        emitter.emit(event)
        emitter.close()

        conn = json.loads(temp_output.read_text().strip())
        assert conn["proto"] == "icmp"
        assert conn["id.orig_p"] == 8
        assert conn["id.resp_p"] == 0
        assert conn["conn_state"] == "SF"
        assert conn["history"] == "Dd"

    def test_dhcp_discover_renders_unassigned_client_tuple(self, format_def, temp_output):
        """Initial DHCP acquisition should not render the assigned lease as originator."""
        emitter = ZeekEmitter(format_def, temp_output, buffer_size=1)
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="dhcp_lease",
            network=NetworkContext(
                src_ip="10.0.10.2",
                src_port=68,
                dst_ip="10.0.10.1",
                dst_port=67,
                protocol="udp",
                service="dhcp",
                zeek_uid="CTestDhcpDiscover",
                conn_state="SF",
                history="DdDd",
                link_local=True,
            ),
            dhcp=DhcpContext(
                client_addr="0.0.0.0",
                server_addr="10.0.10.1",
                assigned_addr="10.0.10.2",
                mac="00:50:56:ab:cd:ef",
                host_name="LNX-01",
                msg_types=["DISCOVER", "OFFER", "REQUEST", "ACK"],
            ),
        )

        emitter.emit(event)
        emitter.close()

        conn = json.loads(temp_output.read_text().strip())
        assert conn["id.orig_h"] == "0.0.0.0"
        assert conn["id.resp_h"] == "255.255.255.255"
        assert conn["uid"] == "CTestDhcpDiscover"

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

    def test_rstr_history_uses_responder_reset_direction(self):
        """Zeek RSTR histories should end with responder-side lowercase r."""
        assert ZeekEmitter._normalize_history_for_state("RSTR", "ShADadR") == "ShADadr"
        assert ZeekEmitter._normalize_history_for_state("RSTO", "ShADadr") == "ShADadR"

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
