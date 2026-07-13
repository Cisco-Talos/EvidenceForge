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

"""Tests for eCAR format spec compliance.

Verifies that the EcarEmitter produces records matching the eCAR spec:
- pid and tid are present only when source-native IDs are known
- ppid only on PROCESS events
- All properties values are strings
- parent_image_path in PROCESS/CREATE properties
"""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    AuthContext,
    EdrContext,
    FileContext,
    HostContext,
    NetworkContext,
    ProcessContext,
    RegistryContext,
    RemoteThreadContext,
)
from evidenceforge.formats.loader import load_format
from evidenceforge.formats.validator import validate_event
from evidenceforge.generation.activity.endpoint_noise import ecar_flow_identity_config
from evidenceforge.generation.activity.timing_profiles import sample_timing_delta
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.state_manager import StateManager


@pytest.fixture
def emitter(tmp_path):
    """Create an EcarEmitter with a mock format_def."""
    format_def = Mock()
    format_def.output.template = "{}"
    format_def.output.header_template = None
    format_def.output.footer_template = None
    format_def.output.encoding = "utf-8"
    e = EcarEmitter(format_def, tmp_path, threaded=False)
    return e


@pytest.fixture
def ts():
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


class TestPidEmission:
    def test_pid_present_on_process_create(self, emitter, ts):
        """PROCESS/CREATE should have pid."""
        rendered = emitter._render_event(
            {"timestamp": ts, "object": "PROCESS", "action": "CREATE", "pid": 1234, "ppid": 4}
        )
        record = json.loads(rendered)
        assert record["pid"] == 1234

    def test_pid_zero_not_dropped(self, emitter, ts):
        """pid=0 (kernel process) must not be silently dropped."""
        rendered = emitter._render_event(
            {"timestamp": ts, "object": "PROCESS", "action": "CREATE", "pid": 0, "ppid": 0}
        )
        record = json.loads(rendered)
        assert record["pid"] == 0

    def test_pid_omitted_when_unavailable(self, emitter, ts):
        """When pid is unavailable, session rows should not carry sentinel IDs."""
        rendered = emitter._render_event(
            {"timestamp": ts, "object": "USER_SESSION", "action": "LOGIN"}
        )
        record = json.loads(rendered)
        assert "pid" not in record

    def test_unlock_reauth_renders_login_with_logon_type(self, emitter, ts):
        """Type 7 unlock reauth should use session lifecycle action vocabulary."""
        event = SecurityEvent(
            timestamp=ts,
            event_type="logon",
            dst_host=HostContext(
                hostname="WS-01",
                ip="10.0.0.10",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
            ),
            auth=AuthContext(username="alice", logon_id="0x123", logon_type=7),
            edr=EdrContext(object_id="session-1"),
        )

        emitter.emit_event = Mock()
        emitter.emit(event)

        row = emitter.emit_event.call_args[0][0]
        assert row["object"] == "USER_SESSION"
        assert row["action"] == "LOGIN"
        assert row["logon_type"] == 7
        assert row["objectID"] == "session-1"

        record = json.loads(emitter._render_event(row))
        assert record["properties"]["logon_type"] == "7"

    def test_linux_ssh_login_renders_session_type_not_windows_logon_type(self, emitter, ts):
        """Linux eCAR sessions should use OS-native session semantics."""
        event = SecurityEvent(
            timestamp=ts,
            event_type="ssh_session",
            dst_host=HostContext(
                hostname="LINUX-01",
                ip="10.0.0.20",
                os="Ubuntu 22.04",
                os_category="linux",
                system_type="server",
            ),
            auth=AuthContext(
                username="alice",
                logon_id="0x123",
                logon_type=10,
                source_ip="10.0.0.10",
                source_port=55222,
            ),
            edr=EdrContext(object_id="session-1"),
        )

        emitter.emit_event = Mock()
        emitter.emit(event)

        row = emitter.emit_event.call_args[0][0]
        assert row["object"] == "USER_SESSION"
        assert row["action"] == "LOGIN"
        assert "logon_type" not in row
        assert row["session_type"] == "ssh"
        assert row["src_ip"] == "10.0.0.10"
        assert row["src_port"] == 55222

        record = json.loads(emitter._render_event(row))
        assert "logon_type" not in record["properties"]
        assert record["properties"]["logon_id"] == "0x123"
        assert record["properties"]["session_type"] == "ssh"
        assert record["properties"]["src_port"] == "55222"

    def test_windows_logout_preserves_session_properties(self, emitter, ts):
        """Logout rows should retain source-native session correlation fields."""
        event = SecurityEvent(
            timestamp=ts,
            event_type="logoff",
            dst_host=HostContext(
                hostname="WS-01",
                ip="10.0.0.10",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
            ),
            auth=AuthContext(
                username="alice",
                logon_id="0x123",
                session_id=2,
                logon_type=3,
                logon_guid="{11111111-2222-3333-4444-555555555555}",
                source_ip="10.0.0.20",
                source_port=54433,
            ),
            edr=EdrContext(object_id="session-1"),
        )

        emitter.emit_event = Mock()
        emitter.emit(event)

        row = emitter.emit_event.call_args[0][0]
        assert row["object"] == "USER_SESSION"
        assert row["action"] == "LOGOUT"
        assert row["logon_id"] == "0x123"
        assert row["logon_type"] == 3
        assert row["session_id"] == 2
        assert row["logon_guid"] == "{11111111-2222-3333-4444-555555555555}"
        assert row["src_ip"] == "10.0.0.20"
        assert row["src_port"] == 54433

        record = json.loads(emitter._render_event(row))
        assert record["properties"]["logon_id"] == "0x123"
        assert record["properties"]["logon_type"] == "3"
        assert record["properties"]["session_id"] == "2"
        assert record["properties"]["logon_guid"] == "{11111111-2222-3333-4444-555555555555}"

    def test_machine_logout_preserves_logon_id_without_remote_source(self, emitter, ts):
        """Machine-account logouts should not render empty eCAR properties."""
        event = SecurityEvent(
            timestamp=ts,
            event_type="logoff",
            dst_host=HostContext(
                hostname="DC-01",
                ip="10.0.0.10",
                os="Windows Server 2022",
                os_category="windows",
                system_type="domain_controller",
            ),
            auth=AuthContext(username="WS-01$", logon_id="0x456", logon_type=3),
            edr=EdrContext(object_id="session-2"),
        )

        emitter.emit_event = Mock()
        emitter.emit(event)

        row = emitter.emit_event.call_args[0][0]
        assert "src_ip" not in row
        record = json.loads(emitter._render_event(row))
        assert record["properties"]["logon_id"] == "0x456"
        assert record["properties"]["logon_type"] == "3"

    def test_linux_logout_without_logon_id_preserves_logind_session_id(self, emitter, ts):
        """Unmanaged SSH logouts should still carry a source-native session identifier."""
        event = SecurityEvent(
            timestamp=ts,
            event_type="logoff",
            dst_host=HostContext(
                hostname="LINUX-01",
                ip="10.0.0.20",
                os="Ubuntu 22.04",
                os_category="linux",
                system_type="server",
            ),
            auth=AuthContext(
                username="alice",
                session_id=742,
                logon_type=10,
                source_ip="10.0.0.10",
                source_port=55222,
            ),
            edr=EdrContext(object_id="session-3"),
        )

        emitter.emit_event = Mock()
        emitter.emit(event)

        row = emitter.emit_event.call_args[0][0]
        record = json.loads(emitter._render_event(row))
        assert "logon_id" not in record["properties"]
        assert record["properties"]["session_id"] == "742"
        assert record["properties"]["session_type"] == "ssh"

    def test_user_session_logon_type_is_declared_ecar_property(self, emitter, ts, caplog):
        """Rendered eCAR login logon_type should be accepted by format validation."""
        record = json.loads(
            emitter._render_event(
                {
                    "timestamp": ts,
                    "hostname": "WS-01",
                    "object": "USER_SESSION",
                    "action": "LOGIN",
                    "objectID": "session-1",
                    "principal": "alice",
                    "logon_type": 7,
                }
            )
        )
        flattened = {key: value for key, value in record.items() if key != "properties"}
        flattened.update(record["properties"])

        result = validate_event(
            load_format("ecar"),
            flattened,
            event_context="USER_SESSION/LOGIN",
        )

        assert result.valid, result.errors
        assert not [
            log_record
            for log_record in caplog.records
            if "Unknown field in ecar (USER_SESSION/LOGIN): logon_type" in log_record.getMessage()
        ]

    def test_pid_none_is_omitted(self, emitter, ts):
        """Explicit pid=None should be omitted."""
        rendered = emitter._render_event(
            {"timestamp": ts, "object": "FILE", "action": "CREATE", "pid": None}
        )
        record = json.loads(rendered)
        assert "pid" not in record


class TestFileEventActions:
    def test_file_read_and_modify_render_read_write_actions(self, emitter, ts):
        """Canonical file_read/file_modify events should render as eCAR READ/WRITE."""
        host = HostContext(
            hostname="FS-01",
            ip="10.0.0.20",
            os="Windows Server 2022",
            os_category="windows",
            system_type="server",
            fqdn="fs-01.example.com",
        )
        emitter.emit_event = Mock()

        for event_type in ("file_read", "file_modify"):
            emitter._render_file_event(
                SecurityEvent(
                    timestamp=ts,
                    event_type=event_type,
                    src_host=host,
                    auth=AuthContext(username="jdoe"),
                    file=FileContext(
                        path=r"\\FS-01\Shared\budget.xlsx",
                        action=event_type.removeprefix("file_"),
                        pid=4,
                    ),
                )
            )

        actions = [call.args[0]["action"] for call in emitter.emit_event.call_args_list]
        assert actions == ["READ", "WRITE"]

    def test_file_event_renders_after_process_create_offset(self, emitter, ts):
        """Dependent eCAR records should not render before PROCESS/CREATE."""
        host = HostContext(
            hostname="FS-01",
            ip="10.0.0.20",
            os="Windows Server 2022",
            os_category="windows",
            system_type="server",
            fqdn="fs-01.example.com",
        )
        proc = ProcessContext(
            pid=4321,
            parent_pid=4,
            image=r"C:\Temp\tool.exe",
            command_line=r"C:\Temp\tool.exe",
            username="jdoe",
            start_time=ts,
        )
        emitter.emit_event = Mock()

        emitter._render_process_create(
            SecurityEvent(
                timestamp=ts,
                event_type="process_create",
                src_host=host,
                auth=AuthContext(username="jdoe"),
                process=proc,
            )
        )
        emitter._render_file_event(
            SecurityEvent(
                timestamp=ts,
                event_type="file_create",
                src_host=host,
                auth=AuthContext(username="jdoe"),
                process=proc,
                file=FileContext(path=r"C:\Temp\tool.exe", action="create", pid=4321),
            )
        )

        process_create, file_create = [call.args[0] for call in emitter.emit_event.call_args_list]
        assert file_create["timestamp"] > process_create["timestamp"]

    def test_file_event_carries_known_process_provenance(self, emitter, ts):
        """eCAR FILE rows should preserve known source process image and command line."""
        host = HostContext(
            hostname="WS-01",
            ip="10.0.0.10",
            os="Windows 11",
            os_category="windows",
            system_type="workstation",
            fqdn="ws-01.example.com",
        )
        proc = ProcessContext(
            pid=4321,
            parent_pid=4,
            image=r"C:\Windows\System32\cmd.exe",
            command_line=r"cmd.exe /c type C:\Temp\note.txt",
            username="jdoe",
            start_time=ts,
        )
        emitter.emit_event = Mock()

        emitter._render_file_event(
            SecurityEvent(
                timestamp=ts,
                event_type="file_read",
                src_host=host,
                auth=AuthContext(username="jdoe"),
                process=proc,
                file=FileContext(path=r"C:\Temp\note.txt", action="read", pid=4321),
            )
        )

        row = emitter.emit_event.call_args.args[0]
        record = json.loads(emitter._render_event(row))
        assert record["properties"]["image_path"] == proc.image
        assert record["properties"]["command_line"] == proc.command_line

    def test_registry_event_carries_known_process_provenance(self, emitter, ts):
        """eCAR REGISTRY rows should preserve known source process provenance."""
        host = HostContext(
            hostname="WS-01",
            ip="10.0.0.10",
            os="Windows 11",
            os_category="windows",
            system_type="workstation",
            fqdn="ws-01.example.com",
        )
        proc = ProcessContext(
            pid=4321,
            parent_pid=4,
            image=r"C:\Windows\System32\reg.exe",
            command_line=r"reg.exe add HKCU\Software\Example /v Enabled /d 1",
            username="jdoe",
            start_time=ts,
        )
        emitter.emit_event = Mock()

        emitter._render_registry_event(
            SecurityEvent(
                timestamp=ts,
                event_type="registry_modify",
                src_host=host,
                auth=AuthContext(username="jdoe"),
                process=proc,
                registry=RegistryContext(
                    key=r"HKCU\Software\Example",
                    value="Enabled=1",
                    action="modify",
                    pid=4321,
                ),
            )
        )

        row = emitter.emit_event.call_args.args[0]
        record = json.loads(emitter._render_event(row))
        assert record["properties"]["image_path"] == proc.image
        assert record["properties"]["command_line"] == proc.command_line


class TestRemoteThreadRendering:
    def test_remote_thread_uses_canonical_context_values(self, emitter, ts):
        """THREAD/REMOTE_CREATE should render the same values Sysmon receives."""
        host = HostContext(
            hostname="WS-01",
            ip="10.0.0.10",
            os="Windows 11",
            os_category="windows",
            system_type="workstation",
            fqdn="ws-01.example.com",
        )
        emitter.emit_event = Mock()
        event = SecurityEvent(
            timestamp=ts,
            event_type="create_remote_thread",
            src_host=host,
            process=ProcessContext(
                pid=4321,
                parent_pid=1234,
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
                source_thread_id=2222,
                target_thread_id=840,
                target_process_object_id="target-process-id",
                thread_object_id="thread-object-id",
                stack_base=0xFFFFF80000100000,
                stack_limit=0xFFFFF800000FA000,
                user_stack_base=0x000000C0001000,
                user_stack_limit=0x000000BFF01000,
            ),
            edr=EdrContext(object_id="thread-object-id", actor_id="source-process-id"),
        )

        emitter._render_create_remote_thread(event)

        rendered = emitter.emit_event.call_args[0][0]
        expected_delta = sample_timing_delta(
            "source.ecar_remote_thread",
            seed_parts=("WS-01", 4321, 688, 840, ts),
        )
        assert rendered["timestamp"] == ts + expected_delta
        assert rendered["target_pid"] == "688"
        assert rendered["tgt_tid"] == "840"
        assert rendered["target_process_uuid"] == "target-process-id"
        assert rendered["start_address"] == "0000000002060000"


class TestSessionOutcomeRendering:
    def test_session_source_latency_spreads_same_timestamp_logins(self, emitter, ts):
        """Independent eCAR session rows should not inherit the exact same millisecond."""
        host = HostContext(
            hostname="WS-01",
            ip="10.0.0.10",
            os="Windows 11",
            os_category="windows",
            system_type="workstation",
            fqdn="ws-01.example.com",
        )
        emitter.emit_event = Mock()
        events = [
            SecurityEvent(
                timestamp=ts,
                event_type="logon",
                dst_host=host,
                auth=AuthContext(username="alice", source_ip="10.0.0.21", logon_id="0x1001"),
                edr=EdrContext(object_id="session-alice"),
            ),
            SecurityEvent(
                timestamp=ts,
                event_type="logon",
                dst_host=host,
                auth=AuthContext(username="bob", source_ip="10.0.0.22", logon_id="0x1002"),
                edr=EdrContext(object_id="session-bob"),
            ),
        ]

        rendered_rows = []
        for event in events:
            emitter._render_logon(event)
            rendered_rows.append(emitter.emit_event.call_args.args[0])

        timestamp_ms = [
            json.loads(emitter._render_event(row))["timestamp_ms"] for row in rendered_rows
        ]
        assert all(row["timestamp"] > ts for row in rendered_rows)
        assert len(set(timestamp_ms)) == len(timestamp_ms)

    def test_session_source_latency_stays_before_same_time_process_create(self, emitter, ts):
        """eCAR session latency should not move a login after its first process."""
        host = HostContext(
            hostname="WS-01",
            ip="10.0.0.10",
            os="Windows 11",
            os_category="windows",
            system_type="workstation",
            fqdn="ws-01.example.com",
        )
        emitter.emit_event = Mock()
        emitter._render_logon(
            SecurityEvent(
                timestamp=ts,
                event_type="logon",
                dst_host=host,
                auth=AuthContext(username="alice", logon_id="0x1001"),
                edr=EdrContext(object_id="session-alice"),
            )
        )
        logon_row = emitter.emit_event.call_args.args[0]
        emitter._render_process_create(
            SecurityEvent(
                timestamp=ts,
                event_type="process_create",
                src_host=host,
                process=ProcessContext(
                    pid=4321,
                    parent_pid=4,
                    image=r"C:\Windows\System32\cmd.exe",
                    command_line="cmd.exe",
                    username="alice",
                    start_time=ts,
                ),
            )
        )
        process_row = emitter.emit_event.call_args.args[0]

        assert logon_row["timestamp"] < process_row["timestamp"]

    def test_ssh_session_login_renders_after_matching_inbound_flow(self, emitter, ts):
        """eCAR SSH LOGIN should not appear before the same tuple's FLOW."""
        host = HostContext(
            hostname="LINUX-01",
            ip="10.0.0.20",
            os="Ubuntu 22.04",
            os_category="linux",
            system_type="server",
            fqdn="linux-01.example.com",
        )
        emitter.emit_event = Mock()
        flow_event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            dst_host=host,
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=55222,
                dst_ip="10.0.0.20",
                dst_port=22,
                protocol="tcp",
                service="ssh",
                duration=120.0,
                conn_state="SF",
                history="ShADadFf",
            ),
            edr=EdrContext(object_id="flow-1"),
        )
        session_event = SecurityEvent(
            timestamp=ts,
            event_type="ssh_session",
            dst_host=host,
            auth=AuthContext(
                username="alice",
                source_ip="10.0.0.10",
                source_port=55222,
                logon_id="0x123",
                logon_type=10,
            ),
            edr=EdrContext(object_id="session-1"),
        )

        emitter._render_connection(flow_event)
        flow_row = emitter.emit_event.call_args.args[0]
        emitter._render_logon(session_event)
        login_row = emitter.emit_event.call_args.args[0]

        assert login_row["timestamp"] > flow_row["timestamp"]

    def test_rdp_session_login_renders_after_matching_inbound_flow(self, emitter, ts):
        """eCAR RDP LOGIN should not appear before the same tuple's FLOW."""
        host = HostContext(
            hostname="WIN-01",
            ip="10.0.0.20",
            os="Windows Server 2022",
            os_category="windows",
            system_type="server",
            fqdn="win-01.example.com",
        )
        emitter.emit_event = Mock()
        flow_event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            dst_host=host,
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=55222,
                dst_ip="10.0.0.20",
                dst_port=3389,
                protocol="tcp",
                service="rdp",
                duration=120.0,
                conn_state="SF",
                history="ShADadFf",
            ),
            edr=EdrContext(object_id="flow-1"),
        )
        session_event = SecurityEvent(
            timestamp=ts,
            event_type="logon",
            dst_host=host,
            auth=AuthContext(
                username="alice",
                source_ip="10.0.0.10",
                source_port=55222,
                logon_id="0x123",
                logon_type=10,
            ),
            edr=EdrContext(object_id="session-1"),
        )

        emitter._render_connection(flow_event)
        flow_row = emitter.emit_event.call_args.args[0]
        emitter._render_logon(session_event)
        login_row = emitter.emit_event.call_args.args[0]

        assert login_row["timestamp"] > flow_row["timestamp"]

    def test_failed_logon_includes_outcome_and_status(self, emitter, ts):
        """Failed eCAR logons should be explicit attempts, not ambiguous sessions."""
        host = HostContext(
            hostname="WS-01",
            ip="10.0.0.10",
            os="Windows 11",
            os_category="windows",
            system_type="workstation",
            fqdn="ws-01.example.com",
        )
        emitter.emit_event = Mock()
        event = SecurityEvent(
            timestamp=ts,
            event_type="failed_logon",
            dst_host=host,
            auth=AuthContext(
                username="jdoe",
                source_ip="10.0.0.20",
                failure_status="0xC000006D",
                failure_substatus="0xC000006A",
            ),
        )

        emitter._render_failed_logon(event)

        rendered = emitter.emit_event.call_args[0][0]
        assert rendered["outcome"] == "failure"
        assert rendered["session_lifecycle"] == "attempt_failed"
        assert rendered["failure_reason"] == "bad_password"
        assert rendered["status_code"] == "0xC000006D"
        assert rendered["sub_status"] == "0xC000006A"

    @pytest.mark.parametrize(
        ("substatus", "expected_reason"),
        [
            ("0xC0000064", "unknown_user"),
            ("0xC0000072", "account_disabled"),
            ("0xC0000234", "account_locked"),
        ],
    )
    def test_failed_logon_maps_windows_substatus_to_reason(
        self, emitter, ts, substatus, expected_reason
    ):
        """eCAR should preserve native failed-auth meaning instead of flattening."""
        host = HostContext(
            hostname="WS-01",
            ip="10.0.0.10",
            os="Windows 11",
            os_category="windows",
            system_type="workstation",
            fqdn="ws-01.example.com",
        )
        emitter.emit_event = Mock()
        event = SecurityEvent(
            timestamp=ts,
            event_type="failed_logon",
            dst_host=host,
            auth=AuthContext(
                username="jdoe",
                source_ip="10.0.0.20",
                failure_status="0xC000006D",
                failure_substatus=substatus,
            ),
        )

        emitter._render_failed_logon(event)

        rendered = emitter.emit_event.call_args[0][0]
        assert rendered["failure_reason"] == expected_reason

    def test_linux_failed_logon_omits_windows_ntstatus_fields(self, emitter, ts):
        """Linux eCAR login failures should not carry Windows-only NTSTATUS details."""
        host = HostContext(
            hostname="LNX-01",
            ip="10.0.0.30",
            os="Ubuntu 22.04",
            os_category="linux",
            system_type="server",
            fqdn="lnx-01.example.com",
        )
        emitter.emit_event = Mock()
        event = SecurityEvent(
            timestamp=ts,
            event_type="failed_logon",
            dst_host=host,
            auth=AuthContext(
                username="jdoe",
                source_ip="10.0.0.20",
                failure_status="0xC000006D",
                failure_substatus="0xC000006A",
            ),
        )

        emitter._render_failed_logon(event)

        rendered = emitter.emit_event.call_args[0][0]
        assert rendered["outcome"] == "failure"
        assert rendered["failure_reason"] == "bad_password"
        assert rendered["session_type"] == "remote"
        assert "status_code" not in rendered
        assert "sub_status" not in rendered


class TestChronologicalOutput:
    def test_close_sorts_per_host_ecar_by_timestamp(self, tmp_path, ts):
        """Per-host eCAR files should be written chronologically on close."""
        fmt = Mock()
        fmt.output.template = "{}"
        fmt.output.header_template = None
        fmt.output.footer_template = None
        fmt.output.encoding = "utf-8"
        emitter = EcarEmitter(fmt, tmp_path, threaded=False)

        for offset in (5, 1, 3):
            emitter.emit_event(
                {
                    "timestamp": ts.replace(second=offset),
                    "hostname": "ws01",
                    "object": "FLOW",
                    "action": "CONNECT",
                    "pid": 100,
                    "_host_fqdn": "ws01.example.org",
                }
            )

        emitter.close()

        rows = [
            json.loads(line)
            for line in (tmp_path / "ws01.example.org" / "ecar.json").read_text().splitlines()
        ]
        assert [row["timestamp_ms"] for row in rows] == sorted(row["timestamp_ms"] for row in rows)

    def test_close_removes_semantic_duplicate_events(self, tmp_path, ts):
        """UUID-only duplicate eCAR facts should collapse during final flush."""
        fmt = Mock()
        fmt.output.template = "{}"
        fmt.output.header_template = None
        fmt.output.footer_template = None
        fmt.output.encoding = "utf-8"
        emitter = EcarEmitter(fmt, tmp_path, threaded=False)
        base = {
            "timestamp": ts,
            "hostname": "ws01",
            "object": "MODULE",
            "action": "LOAD",
            "pid": 1234,
            "principal": "alice",
            "file_path": r"C:\Windows\System32\msvcrt.dll",
            "_host_fqdn": "ws01.example.org",
        }

        emitter.emit_event({**base, "id": "event-one", "objectID": "object-one"})
        emitter.emit_event({**base, "id": "event-two", "objectID": "object-two"})
        emitter.close()

        rows = [
            json.loads(line)
            for line in (tmp_path / "ws01.example.org" / "ecar.json").read_text().splitlines()
        ]
        assert len(rows) == 1

    def test_close_drops_rows_shifted_after_output_window(self, tmp_path, ts):
        """Final eCAR source ordering should not leak records after scenario end."""
        fmt = Mock()
        fmt.output.template = "{}"
        fmt.output.header_template = None
        fmt.output.footer_template = None
        fmt.output.encoding = "utf-8"
        emitter = EcarEmitter(fmt, tmp_path, threaded=False)
        emitter._output_end_time = ts + timedelta(seconds=10)

        for offset in (5, 10, 11):
            emitter.emit_event(
                {
                    "timestamp": ts + timedelta(seconds=offset),
                    "hostname": "ws01",
                    "object": "FLOW",
                    "action": "CONNECT",
                    "pid": 100 + offset,
                    "_host_fqdn": "ws01.example.org",
                }
            )

        emitter.close()

        rows = [
            json.loads(line)
            for line in (tmp_path / "ws01.example.org" / "ecar.json").read_text().splitlines()
        ]
        assert len(rows) == 1
        assert rows[0]["pid"] == 105

    def test_close_moves_process_terminate_after_later_references(self, tmp_path, ts):
        """eCAR output should not terminate a process before later same-process telemetry."""
        fmt = Mock()
        fmt.output.template = "{}"
        fmt.output.header_template = None
        fmt.output.footer_template = None
        fmt.output.encoding = "utf-8"
        emitter = EcarEmitter(fmt, tmp_path, threaded=False)
        process_id = "proc-123"

        emitter.emit_event(
            {
                "timestamp": ts.replace(second=1),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": process_id,
                "pid": 100,
                "_host_fqdn": "ws01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts.replace(second=2),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "TERMINATE",
                "objectID": process_id,
                "pid": 100,
                "_host_fqdn": "ws01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts.replace(second=5),
                "hostname": "ws01",
                "object": "MODULE",
                "action": "LOAD",
                "actorID": process_id,
                "pid": 100,
                "_host_fqdn": "ws01.example.org",
            }
        )

        emitter.close()

        rows = [
            json.loads(line)
            for line in (tmp_path / "ws01.example.org" / "ecar.json").read_text().splitlines()
        ]
        module_ts = next(row["timestamp_ms"] for row in rows if row["object"] == "MODULE")
        terminate_ts = next(
            row["timestamp_ms"]
            for row in rows
            if row["object"] == "PROCESS" and row["action"] == "TERMINATE"
        )
        assert terminate_ts > module_ts

    def test_close_drops_stale_module_after_process_terminate(self, tmp_path, ts):
        """Long-stale process-owned module rows should not drag termination forward."""
        fmt = Mock()
        fmt.output.template = "{}"
        fmt.output.header_template = None
        fmt.output.footer_template = None
        fmt.output.encoding = "utf-8"
        emitter = EcarEmitter(fmt, tmp_path, threaded=False)
        process_id = "proc-123"

        emitter.emit_event(
            {
                "timestamp": ts.replace(second=1),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": process_id,
                "pid": 100,
                "_host_fqdn": "ws01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts.replace(second=2),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "TERMINATE",
                "objectID": process_id,
                "pid": 100,
                "_host_fqdn": "ws01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts + timedelta(hours=1),
                "hostname": "ws01",
                "object": "MODULE",
                "action": "LOAD",
                "actorID": process_id,
                "pid": 100,
                "_host_fqdn": "ws01.example.org",
            }
        )

        emitter.close()

        rows = [
            json.loads(line)
            for line in (tmp_path / "ws01.example.org" / "ecar.json").read_text().splitlines()
        ]
        assert {row["object"] for row in rows} == {"PROCESS"}
        terminate_ts = next(
            row["timestamp_ms"]
            for row in rows
            if row["object"] == "PROCESS" and row["action"] == "TERMINATE"
        )
        assert terminate_ts < int((ts + timedelta(minutes=5)).timestamp() * 1000)

    def test_close_drops_minute_scale_module_after_process_terminate(self, tmp_path, ts):
        """Minute-scale module rows should not keep a terminated process alive."""
        fmt = Mock()
        fmt.output.template = "{}"
        fmt.output.header_template = None
        fmt.output.footer_template = None
        fmt.output.encoding = "utf-8"
        emitter = EcarEmitter(fmt, tmp_path, threaded=False)
        process_id = "proc-123"

        emitter.emit_event(
            {
                "timestamp": ts.replace(second=1),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": process_id,
                "pid": 100,
                "_host_fqdn": "ws01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts.replace(second=2),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "TERMINATE",
                "objectID": process_id,
                "pid": 100,
                "_host_fqdn": "ws01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts + timedelta(seconds=45),
                "hostname": "ws01",
                "object": "MODULE",
                "action": "LOAD",
                "actorID": process_id,
                "pid": 100,
                "_host_fqdn": "ws01.example.org",
            }
        )

        emitter.close()

        rows = [
            json.loads(line)
            for line in (tmp_path / "ws01.example.org" / "ecar.json").read_text().splitlines()
        ]
        assert {row["object"] for row in rows} == {"PROCESS"}
        terminate_ts = next(
            row["timestamp_ms"]
            for row in rows
            if row["object"] == "PROCESS" and row["action"] == "TERMINATE"
        )
        assert terminate_ts < int((ts + timedelta(seconds=30)).timestamp() * 1000)

    def test_close_scrubs_stale_flow_process_identity_after_process_terminate(self, tmp_path, ts):
        """Late FLOW rows should keep transport evidence without stale PID attribution."""
        fmt = Mock()
        fmt.output.template = "{}"
        fmt.output.header_template = None
        fmt.output.footer_template = None
        fmt.output.encoding = "utf-8"
        emitter = EcarEmitter(fmt, tmp_path, threaded=False)
        process_id = "proc-123"

        emitter.emit_event(
            {
                "timestamp": ts.replace(second=1),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": process_id,
                "pid": 100,
                "_host_fqdn": "ws01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts.replace(second=2),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "TERMINATE",
                "objectID": process_id,
                "pid": 100,
                "_host_fqdn": "ws01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts + timedelta(hours=1),
                "hostname": "ws01",
                "object": "FLOW",
                "action": "CONNECT",
                "actorID": process_id,
                "pid": 100,
                "principal": "alice",
                "image_path": r"C:\Program Files\App\app.exe",
                "_host_fqdn": "ws01.example.org",
            }
        )

        emitter.close()

        rows = [
            json.loads(line)
            for line in (tmp_path / "ws01.example.org" / "ecar.json").read_text().splitlines()
        ]
        flow = next(row for row in rows if row["object"] == "FLOW")
        assert "actorID" not in flow
        assert "pid" not in flow
        assert "principal" not in flow
        assert "image_path" not in flow["properties"]

    def test_close_scrubs_flow_actor_without_visible_process_create(self, tmp_path, ts):
        """FLOW rows should not claim actors absent from the same host stream."""
        fmt = Mock()
        fmt.output.template = "{}"
        fmt.output.header_template = None
        fmt.output.footer_template = None
        fmt.output.encoding = "utf-8"
        emitter = EcarEmitter(fmt, tmp_path, threaded=False)

        emitter.emit_event(
            {
                "timestamp": ts.replace(second=5),
                "hostname": "ws01",
                "object": "FLOW",
                "action": "CONNECT",
                "objectID": "flow-123",
                "actorID": "missing-process",
                "pid": 1234,
                "principal": "alice",
                "image_path": r"C:\Program Files\App\app.exe",
                "command_line": r'"C:\Program Files\App\app.exe" --sync',
                "src_ip": "10.0.0.10",
                "src_port": 49152,
                "dst_ip": "10.0.0.20",
                "dst_port": 443,
                "protocol": "tcp",
                "_host_fqdn": "ws01.example.org",
            }
        )

        emitter.close()

        rows = [
            json.loads(line)
            for line in (tmp_path / "ws01.example.org" / "ecar.json").read_text().splitlines()
        ]
        flow = next(row for row in rows if row["object"] == "FLOW")
        assert flow["objectID"] == "flow-123"
        assert "actorID" not in flow
        assert "pid" not in flow
        assert "principal" not in flow
        assert "image_path" not in flow["properties"]
        assert "command_line" not in flow["properties"]
        assert flow["properties"]["dst_port"] == "443"

    def test_close_preserves_flow_actor_with_visible_process_create(self, tmp_path, ts):
        """FLOW actor attribution is valid when the same host has the process create."""
        fmt = Mock()
        fmt.output.template = "{}"
        fmt.output.header_template = None
        fmt.output.footer_template = None
        fmt.output.encoding = "utf-8"
        emitter = EcarEmitter(fmt, tmp_path, threaded=False)
        process_id = "process-123"

        emitter.emit_event(
            {
                "timestamp": ts.replace(second=1),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": process_id,
                "pid": 1234,
                "ppid": 4,
                "image_path": r"C:\Program Files\App\app.exe",
                "_host_fqdn": "ws01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts.replace(second=5),
                "hostname": "ws01",
                "object": "FLOW",
                "action": "CONNECT",
                "objectID": "flow-123",
                "actorID": process_id,
                "pid": 1234,
                "principal": "alice",
                "image_path": r"C:\Program Files\App\app.exe",
                "command_line": r'"C:\Program Files\App\app.exe" --sync',
                "src_ip": "10.0.0.10",
                "src_port": 49152,
                "dst_ip": "10.0.0.20",
                "dst_port": 443,
                "protocol": "tcp",
                "_host_fqdn": "ws01.example.org",
            }
        )

        emitter.close()

        rows = [
            json.loads(line)
            for line in (tmp_path / "ws01.example.org" / "ecar.json").read_text().splitlines()
        ]
        flow = next(row for row in rows if row["object"] == "FLOW")
        assert flow["actorID"] == process_id
        assert flow["pid"] == 1234
        assert flow["principal"] == "alice"
        assert flow["properties"]["image_path"] == r"C:\Program Files\App\app.exe"

    def test_close_rewrites_linux_pids_by_source_timestamp_not_canonical_order(self, tmp_path, ts):
        """Linux PID morphology should follow rendered source time, not canonical time."""
        fmt = Mock()
        fmt.output.template = "{}"
        fmt.output.header_template = None
        fmt.output.footer_template = None
        fmt.output.encoding = "utf-8"
        emitter = EcarEmitter(fmt, tmp_path, threaded=False)

        emitter.emit_event(
            {
                "timestamp": ts.replace(second=2),
                "hostname": "linux01",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": "proc-a",
                "pid": 5000,
                "image_path": "/usr/bin/parent",
                "_canonical_ms": int(ts.replace(second=1).timestamp() * 1000),
                "_host_fqdn": "linux01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts.replace(second=1),
                "hostname": "linux01",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": "proc-b",
                "pid": 1000,
                "image_path": "/usr/bin/child",
                "_canonical_ms": int(ts.replace(second=3).timestamp() * 1000),
                "_host_fqdn": "linux01.example.org",
            }
        )

        emitter.close()

        rows = [
            json.loads(line)
            for line in (tmp_path / "linux01.example.org" / "ecar.json").read_text().splitlines()
        ]
        creates = sorted(
            (row for row in rows if row["object"] == "PROCESS" and row["action"] == "CREATE"),
            key=lambda row: row["timestamp_ms"],
        )
        assert [row["pid"] for row in creates] == sorted(row["pid"] for row in creates)
        assert creates[0]["pid"] == 1000
        assert creates[1]["pid"] == 5000
        assert "_canonical_ms" not in creates[0]
        assert "_canonical_ms" not in creates[1]

    def test_flow_uses_source_native_timestamp_offset(self, emitter, monkeypatch, ts):
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=HostContext(
                hostname="ws01",
                ip="10.0.0.10",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
                fqdn="ws01.example.org",
            ),
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=49152,
                dst_ip="93.184.216.34",
                dst_port=443,
                protocol="tcp",
                initiating_pid=1234,
            ),
        )

        emitter._render_connection(event)

        expected_delta = sample_timing_delta(
            "source.ecar_flow",
            seed_parts=(
                "outbound",
                "ws01",
                1234,
                "10.0.0.10",
                49152,
                "93.184.216.34",
                443,
                ts,
            ),
        )
        assert emitted[0]["timestamp"] == ts + expected_delta

    def test_short_flow_stays_inside_canonical_connection_interval(
        self,
        emitter,
        monkeypatch,
        ts,
    ):
        """Very short FLOW rows retain texture without moving past transport close."""
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        process = ProcessContext(
            pid=1234,
            parent_pid=4,
            image=r"C:\Windows\System32\curl.exe",
            command_line="curl.exe https://example.org",
            username="alice",
            start_time=ts,
        )
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=HostContext(
                hostname="ws01",
                ip="10.0.0.10",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
                fqdn="ws01.example.org",
            ),
            process=process,
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=49152,
                dst_ip="93.184.216.34",
                dst_port=443,
                protocol="tcp",
                duration=0.05,
                initiating_pid=1234,
            ),
            edr=EdrContext(object_id="flow-1", actor_id="process-1"),
        )

        emitter._render_connection(event)

        assert ts + timedelta(milliseconds=18) <= emitted[0]["timestamp"]
        assert emitted[0]["timestamp"] < ts + timedelta(milliseconds=50)
        assert emitted[0]["pid"] == -1
        assert "actorID" not in emitted[0]

    def test_delayed_flow_uses_finalized_canonical_interval(
        self,
        emitter,
        monkeypatch,
        ts,
    ):
        """Collection delay must not shift an endpoint FLOW beyond canonical close."""
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        event = SecurityEvent(
            timestamp=ts + timedelta(milliseconds=700),
            event_type="connection",
            src_host=HostContext(
                hostname="ws01",
                ip="10.0.0.10",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
            ),
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=49152,
                dst_ip="10.0.0.53",
                dst_port=53,
                protocol="udp",
                conn_state="SF",
                duration=0.04,
                initiating_pid=-1,
                source_visible_start_time=ts,
                source_visible_close_time=ts + timedelta(milliseconds=40),
            ),
        )

        emitter._render_connection(event)

        assert ts <= emitted[0]["timestamp"] <= ts + timedelta(milliseconds=40)

    def test_incomplete_flow_without_duration_uses_attempt_result_latency(
        self,
        emitter,
        monkeypatch,
        ts,
    ):
        """Failed no-duration FLOW rows should not share Zeek's exact packet timestamp."""
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=HostContext(
                hostname="ws01",
                ip="10.0.0.10",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
                fqdn="ws01.example.org",
            ),
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=49152,
                dst_ip="10.0.0.20",
                dst_port=135,
                protocol="tcp",
                conn_state="S0",
                initiating_pid=-1,
            ),
        )

        emitter._render_connection(event)

        assert ts < emitted[0]["timestamp"] <= ts + timedelta(milliseconds=664)

    def test_paired_endpoint_flows_do_not_share_exact_millisecond(
        self,
        emitter,
        monkeypatch,
        ts,
    ):
        """Paired endpoint FLOW rows should carry host-local observation texture."""
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=HostContext(
                hostname="ws01",
                ip="10.0.0.10",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
                fqdn="ws01.example.org",
            ),
            dst_host=HostContext(
                hostname="srv01",
                ip="10.0.0.20",
                os="Windows Server 2022",
                os_category="windows",
                system_type="server",
                fqdn="srv01.example.org",
            ),
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=49152,
                dst_ip="10.0.0.20",
                dst_port=445,
                protocol="tcp",
                conn_state="S0",
                initiating_pid=-1,
            ),
        )

        emitter._render_connection(event)

        rendered_ms = [json.loads(emitter._render_event(row))["timestamp_ms"] for row in emitted]
        assert len(rendered_ms) == 2
        assert len(set(rendered_ms)) == 2
        assert all(
            ts - timedelta(milliseconds=540) <= row["timestamp"] <= ts + timedelta(milliseconds=664)
            for row in emitted
        )

    def test_paired_endpoint_success_flows_without_close_bound_get_texture(
        self,
        emitter,
        monkeypatch,
        ts,
    ):
        """Unbounded successful paired FLOW rows should not cluster on one millisecond."""
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=HostContext(
                hostname="ws01",
                ip="10.0.0.10",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
                fqdn="ws01.example.org",
            ),
            dst_host=HostContext(
                hostname="dc01",
                ip="10.0.0.20",
                os="Windows Server 2022",
                os_category="windows",
                system_type="server",
                fqdn="dc01.example.org",
            ),
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=57124,
                dst_ip="10.0.0.20",
                dst_port=53,
                protocol="udp",
                conn_state="SF",
                initiating_pid=-1,
            ),
        )

        emitter._render_connection(event)

        rendered_ms = [json.loads(emitter._render_event(row))["timestamp_ms"] for row in emitted]
        assert len(rendered_ms) == 2
        assert abs(rendered_ms[0] - rendered_ms[1]) > 5
        assert all(ts <= row["timestamp"] <= ts + timedelta(milliseconds=1800) for row in emitted)

    def test_actor_linked_flow_renders_after_process_create(self, emitter, monkeypatch, ts):
        """FLOW rows should not reference an actor before its visible PROCESS/CREATE row."""
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        process = ProcessContext(
            pid=1234,
            parent_pid=4,
            image=r"C:\Windows\System32\dsquery.exe",
            command_line='dsquery.exe group -name "Domain Admins"',
            username="alice",
            start_time=ts,
        )
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=HostContext(
                hostname="ws01",
                ip="10.0.0.10",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
                fqdn="ws01.example.org",
            ),
            process=process,
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=49152,
                dst_ip="10.0.0.20",
                dst_port=389,
                protocol="tcp",
                initiating_pid=1234,
            ),
            edr=EdrContext(object_id="flow-1", actor_id="process-1"),
        )

        emitter._render_connection(event)

        assert emitted[0]["timestamp"] > emitter._process_create_timestamp(event, process)

    def test_inbound_flow_drops_late_listener_identity_instead_of_delaying_flow(
        self,
        emitter,
        monkeypatch,
        ts,
    ):
        """Inbound FLOW observations should not wait for late listener PROCESS visibility."""
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        state_manager = StateManager()
        state_manager.set_current_time(ts + timedelta(seconds=2))
        listener_pid = state_manager.create_process(
            "linux01",
            parent_pid=0,
            image="/usr/sbin/sshd",
            command_line="sshd: admin [priv]",
            username="root",
            integrity_level="System",
        )
        emitter._state_manager = state_manager
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=HostContext(
                hostname="ws01",
                ip="10.0.0.10",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
                fqdn="ws01.example.org",
            ),
            dst_host=HostContext(
                hostname="linux01",
                ip="10.0.0.20",
                os="Ubuntu 24.04",
                os_category="linux",
                system_type="server",
                fqdn="linux01.example.org",
            ),
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=49152,
                dst_ip="10.0.0.20",
                dst_port=22,
                protocol="tcp",
                duration=None,
                conn_state="SF",
                history="ShADadfF",
                initiating_pid=-1,
                responding_pid=listener_pid,
            ),
        )

        emitter._render_connection(event)

        inbound = next(row for row in emitted if row["direction"] == "INBOUND")
        assert inbound["timestamp"] <= EcarEmitter._flow_identity_deadline(event)
        assert inbound["pid"] == -1
        assert "principal" not in inbound

    def test_inbound_ssh_flow_prefers_stable_listener_over_session_child(
        self,
        emitter,
        monkeypatch,
        ts,
    ):
        """SSH transport FLOW ownership should use the daemon listener, not auth child pids."""
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        state_manager = StateManager()
        state_manager.set_current_time(ts - timedelta(hours=1))
        listener_pid = state_manager.create_process(
            "linux01",
            parent_pid=0,
            image="/usr/sbin/sshd",
            command_line="/usr/sbin/sshd -D",
            username="root",
            integrity_level="System",
        )
        state_manager.set_current_time(ts + timedelta(milliseconds=450))
        child_pid = state_manager.create_process(
            "linux01",
            parent_pid=listener_pid,
            image="/usr/sbin/sshd",
            command_line="sshd: admin [priv]",
            username="root",
            integrity_level="System",
        )
        emitter._state_manager = state_manager
        emitter._system_pids = {"linux01": {"sshd": listener_pid}}
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=HostContext(
                hostname="ws01",
                ip="10.0.0.10",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
                fqdn="ws01.example.org",
            ),
            dst_host=HostContext(
                hostname="linux01",
                ip="10.0.0.20",
                os="Ubuntu 24.04",
                os_category="linux",
                system_type="server",
                fqdn="linux01.example.org",
            ),
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=49152,
                dst_ip="10.0.0.20",
                dst_port=22,
                protocol="tcp",
                duration=0.35,
                conn_state="SF",
                history="ShADadfF",
                initiating_pid=-1,
                responding_pid=child_pid,
            ),
        )

        emitter._render_connection(event)

        inbound = next(row for row in emitted if row["direction"] == "INBOUND")
        assert inbound["pid"] == listener_pid
        assert inbound["pid"] != child_pid

    def test_rdp_inbound_flow_drops_late_listener_identity_instead_of_delaying_flow(
        self,
        emitter,
        monkeypatch,
        ts,
    ):
        """RDP FLOW observations should not wait for late TermService PROCESS visibility."""
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        state_manager = StateManager()
        state_manager.set_current_time(ts + timedelta(seconds=2))
        listener_pid = state_manager.create_process(
            "win01",
            parent_pid=4,
            image=r"C:\Windows\System32\svchost.exe",
            command_line=r"C:\Windows\System32\svchost.exe -k termsvcs",
            username="NETWORK SERVICE",
            integrity_level="System",
        )
        emitter._state_manager = state_manager
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=HostContext(
                hostname="ws01",
                ip="10.0.0.10",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
                fqdn="ws01.example.org",
            ),
            dst_host=HostContext(
                hostname="win01",
                ip="10.0.0.20",
                os="Windows Server 2022",
                os_category="windows",
                system_type="server",
                fqdn="win01.example.org",
            ),
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=49152,
                dst_ip="10.0.0.20",
                dst_port=3389,
                protocol="tcp",
                duration=60.0,
                conn_state="SF",
                history="ShADadfF",
                initiating_pid=-1,
                responding_pid=listener_pid,
            ),
        )

        emitter._render_connection(event)

        inbound = next(row for row in emitted if row["direction"] == "INBOUND")
        assert inbound["timestamp"] <= EcarEmitter._flow_identity_deadline(event)
        assert inbound["pid"] == -1
        assert "principal" not in inbound

    def test_outbound_remote_session_flow_drops_late_process_identity(
        self,
        emitter,
        monkeypatch,
        ts,
    ):
        """Remote-session FLOW observations should not wait for late client PROCESS visibility."""
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        process = ProcessContext(
            pid=4321,
            parent_pid=1000,
            image="/usr/bin/ssh",
            command_line="ssh admin@linux01",
            username="alice",
            start_time=ts + timedelta(seconds=2),
        )
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=HostContext(
                hostname="linux02",
                ip="10.0.0.10",
                os="Ubuntu 24.04",
                os_category="linux",
                system_type="server",
                fqdn="linux02.example.org",
            ),
            dst_host=HostContext(
                hostname="linux01",
                ip="10.0.0.20",
                os="Ubuntu 24.04",
                os_category="linux",
                system_type="server",
                fqdn="linux01.example.org",
            ),
            process=process,
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=49152,
                dst_ip="10.0.0.20",
                dst_port=22,
                protocol="tcp",
                duration=60.0,
                conn_state="SF",
                history="ShADadfF",
                initiating_pid=process.pid,
            ),
        )

        emitter._render_connection(event)

        outbound = next(row for row in emitted if row["direction"] == "OUTBOUND")
        assert outbound["timestamp"] <= EcarEmitter._flow_identity_deadline(event)
        assert outbound["pid"] == -1
        assert "principal" not in outbound

    def test_outbound_flow_can_render_user_principal(self, emitter, monkeypatch, ts):
        """User-owned FLOW records should be able to carry mixed principal attribution."""
        monkeypatch.setattr(
            "evidenceforge.generation.emitters.ecar.ecar_flow_identity_config",
            lambda: {
                "user_process_probability": 1.0,
                "service_process_probability": 0.0,
                "root_process_probability": 0.0,
                "inbound_listener_probability": 0.0,
            },
        )
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=HostContext(
                hostname="ws01",
                ip="10.0.0.10",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
                fqdn="ws01.example.org",
            ),
            process=ProcessContext(
                pid=1234,
                parent_pid=777,
                image=r"C:\Program Files\Mozilla Firefox\firefox.exe",
                command_line="firefox.exe",
                username="alice",
                start_time=ts,
            ),
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=49152,
                dst_ip="93.184.216.34",
                dst_port=443,
                protocol="tcp",
                initiating_pid=1234,
            ),
        )

        emitter._render_connection(event)

        assert emitted[0]["object"] == "FLOW"
        assert emitted[0]["direction"] == "OUTBOUND"
        assert emitted[0]["principal"] == "alice"
        record = json.loads(emitter._render_event(emitted[0]))
        assert record["properties"]["image_path"] == event.process.image
        assert record["properties"]["command_line"] == event.process.command_line

    def test_service_flow_can_omit_principal(self, emitter, monkeypatch, ts):
        """Service-owned FLOW records should still model vendor attribution gaps."""
        monkeypatch.setattr(
            "evidenceforge.generation.emitters.ecar.ecar_flow_identity_config",
            lambda: {
                "user_process_probability": 1.0,
                "service_process_probability": 0.0,
                "root_process_probability": 0.0,
                "inbound_listener_probability": 0.0,
            },
        )
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=HostContext(
                hostname="dc01",
                ip="10.0.0.10",
                os="Windows Server 2022",
                os_category="windows",
                system_type="domain_controller",
                fqdn="dc01.example.org",
            ),
            process=ProcessContext(
                pid=444,
                parent_pid=4,
                image=r"C:\Windows\System32\svchost.exe",
                command_line="svchost.exe -k netsvcs",
                username="SYSTEM",
                start_time=ts,
            ),
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=49153,
                dst_ip="10.0.0.20",
                dst_port=88,
                protocol="tcp",
                initiating_pid=444,
            ),
        )

        emitter._render_connection(event)

        assert "principal" not in emitted[0]

    def test_service_flow_default_policy_keeps_known_principal_visible(self, emitter, ts):
        """Default service FLOW policy should not create high-volume principal flips."""
        cfg = ecar_flow_identity_config()
        assert cfg["service_process_probability"] >= 0.98
        assert cfg["root_process_probability"] >= 0.96
        assert cfg["inbound_listener_probability"] >= 0.92

        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=HostContext(
                hostname="dc01",
                ip="10.0.0.10",
                os="Windows Server 2022",
                os_category="windows",
                system_type="domain_controller",
                fqdn="dc01.example.org",
            ),
            process=ProcessContext(
                pid=444,
                parent_pid=4,
                image=r"C:\Windows\System32\svchost.exe",
                command_line="svchost.exe -k netsvcs",
                username="SYSTEM",
                start_time=ts,
            ),
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=49153,
                dst_ip="10.0.0.20",
                dst_port=88,
                protocol="tcp",
                initiating_pid=444,
            ),
        )

        assert (
            emitter._flow_principal_for_process(
                event,
                event.src_host,
                event.process,
                "OUTBOUND",
            )
            == "SYSTEM"
        )

    def test_actor_linked_user_flow_preserves_principal(self, emitter, monkeypatch, ts):
        """Actor-linked user FLOW rows should not drop a known user principal."""
        monkeypatch.setattr(
            "evidenceforge.generation.emitters.ecar.ecar_flow_identity_config",
            lambda: {
                "user_process_probability": 0.0,
                "service_process_probability": 0.0,
                "root_process_probability": 0.0,
                "inbound_listener_probability": 0.0,
            },
        )
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=HostContext(
                hostname="WS-MCHEN-01",
                ip="10.10.1.24",
                os="Windows 11",
                os_category="windows",
                system_type="workstation",
                fqdn="ws-mchen-01.example.org",
            ),
            process=ProcessContext(
                pid=6124,
                parent_pid=3340,
                image=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                command_line="chrome.exe --type=utility",
                username="marcus.chen",
                start_time=ts,
            ),
            network=NetworkContext(
                src_ip="10.10.1.24",
                src_port=50124,
                dst_ip="142.250.72.14",
                dst_port=443,
                protocol="tcp",
                initiating_pid=6124,
            ),
            edr=EdrContext(
                object_id="11111111-2222-3333-4444-555555555555",
                actor_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            ),
        )

        emitter._render_connection(event)

        assert emitted[0]["direction"] == "OUTBOUND"
        assert emitted[0]["actorID"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        assert emitted[0]["principal"] == "marcus.chen"

    def test_inbound_flow_uses_destination_listener_pid(self, emitter, monkeypatch, ts):
        """Inbound host observations should use the local listener PID when known."""
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        emitter._system_pids = {"WEB-EXT-01": {"apache2": 24118}}
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            dst_host=HostContext(
                hostname="WEB-EXT-01",
                ip="10.0.0.20",
                os="Ubuntu 22.04",
                os_category="linux",
                system_type="server",
                fqdn="web-ext-01.example.org",
            ),
            network=NetworkContext(
                src_ip="198.51.100.7",
                src_port=49152,
                dst_ip="10.0.0.20",
                dst_port=443,
                protocol="tcp",
                initiating_pid=-1,
            ),
            edr=EdrContext(object_id="flow-1", actor_id=""),
        )

        emitter._render_connection(event)

        assert emitted[0]["direction"] == "INBOUND"
        assert emitted[0]["pid"] == 24118

    @pytest.mark.parametrize(
        ("dst_port", "proto", "system_pids", "expected_pid"),
        [
            (53, "udp", {"dns": 5300, "lsass": 700}, 5300),
            (88, "udp", {"dns": 5300, "lsass": 700}, 700),
            (389, "tcp", {"dns": 5300, "lsass": 700}, 700),
            (445, "tcp", {"system": 4, "lsass": 700}, 4),
            (8080, "tcp", {"squid": 3128, "apache2": 24118}, 3128),
            (1433, "tcp", {"sqlservr": 14330}, 14330),
            (3306, "tcp", {"mysqld": 33060}, 33060),
            (5432, "tcp", {"postgres": 54320}, 54320),
        ],
    )
    def test_inbound_infrastructure_flow_uses_destination_service_pid(
        self,
        emitter,
        monkeypatch,
        ts,
        dst_port,
        proto,
        system_pids,
        expected_pid,
    ):
        """Infrastructure listener FLOW rows should use destination-local owners."""
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        emitter._system_pids = {"DC-01": system_pids}
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            dst_host=HostContext(
                hostname="DC-01",
                ip="10.0.3.10",
                os="Windows Server 2022",
                os_category="windows",
                system_type="domain_controller",
                fqdn="dc-01.example.org",
            ),
            network=NetworkContext(
                src_ip="10.0.1.7",
                src_port=49152,
                dst_ip="10.0.3.10",
                dst_port=dst_port,
                protocol=proto,
                conn_state="SF",
                history="ShADadF" if proto == "tcp" else "Dd",
                initiating_pid=-1,
            ),
            edr=EdrContext(object_id="flow-1", actor_id=""),
        )

        emitter._render_connection(event)

        assert emitted[0]["direction"] == "INBOUND"
        assert emitted[0]["pid"] == expected_pid

    def test_short_inbound_service_flow_keeps_preexisting_listener_pid(
        self, emitter, monkeypatch, ts
    ):
        """Long-running service PIDs should survive tiny source-native flow windows."""
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        state = StateManager()
        state.set_current_time(ts - timedelta(minutes=10))
        dns_pid = state.create_process(
            "DC-01",
            0,
            r"C:\Windows\System32\dns.exe",
            "dns.exe",
            "SYSTEM",
            "System",
        )
        emitter._state_manager = state
        emitter._system_pids = {"DC-01": {"dns": dns_pid}}
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            dst_host=HostContext(
                hostname="DC-01",
                ip="10.0.3.10",
                os="Windows Server 2022",
                os_category="windows",
                system_type="domain_controller",
                fqdn="dc-01.example.org",
            ),
            network=NetworkContext(
                src_ip="10.0.1.7",
                src_port=49152,
                dst_ip="10.0.3.10",
                dst_port=53,
                protocol="udp",
                duration=0.0002,
                conn_state="SF",
                history="Dd",
                initiating_pid=-1,
            ),
            edr=EdrContext(object_id="flow-1", actor_id=""),
        )

        emitter._render_connection(event)

        assert emitted[0]["direction"] == "INBOUND"
        assert emitted[0]["pid"] == dns_pid

    def test_inbound_flow_prefers_canonical_destination_pid_for_non_remote_session(
        self, emitter, monkeypatch, ts
    ):
        """Non-remote-session inbound flows should prefer a canonical listener PID."""
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        state = StateManager()
        state.set_current_time(ts - timedelta(seconds=2))
        listener_pid = state.create_process(
            "APP-INT-01",
            0,
            "/usr/sbin/apache2",
            "/usr/sbin/apache2 -DFOREGROUND",
            "www-data",
            "System",
        )
        emitter._state_manager = state
        emitter._system_pids = {"APP-INT-01": {"apache2": 36148}}
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            dst_host=HostContext(
                hostname="APP-INT-01",
                ip="10.10.2.30",
                os="Ubuntu 22.04",
                os_category="linux",
                system_type="server",
                fqdn="app-int-01.example.org",
            ),
            network=NetworkContext(
                src_ip="10.10.1.31",
                src_port=50049,
                dst_ip="10.10.2.30",
                dst_port=443,
                protocol="tcp",
                responding_pid=listener_pid,
            ),
            edr=EdrContext(object_id="flow-1", actor_id=""),
        )

        emitter._render_connection(event)

        assert emitted[0]["direction"] == "INBOUND"
        assert emitted[0]["pid"] == listener_pid
        assert emitted[0]["pid"] != 36148

    def test_inbound_listener_flow_can_render_principal(self, emitter, monkeypatch, ts):
        """Observed listener-side FLOW rows can carry local service principal context."""
        monkeypatch.setattr(
            "evidenceforge.generation.emitters.ecar.ecar_flow_identity_config",
            lambda: {
                "user_process_probability": 0.0,
                "service_process_probability": 0.0,
                "root_process_probability": 0.0,
                "inbound_listener_probability": 1.0,
            },
        )
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        state = StateManager()
        state.set_current_time(ts)
        pid = state.create_process(
            "WEB-EXT-01",
            0,
            "/usr/sbin/apache2",
            "/usr/sbin/apache2 -DFOREGROUND",
            "www-data",
            "System",
        )
        emitter._state_manager = state
        emitter._system_pids = {"WEB-EXT-01": {"apache2": pid}}
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            dst_host=HostContext(
                hostname="WEB-EXT-01",
                ip="10.0.0.20",
                os="Ubuntu 22.04",
                os_category="linux",
                system_type="server",
                fqdn="web-ext-01.example.org",
            ),
            network=NetworkContext(
                src_ip="198.51.100.7",
                src_port=49152,
                dst_ip="10.0.0.20",
                dst_port=443,
                protocol="tcp",
                initiating_pid=-1,
            ),
        )

        emitter._render_connection(event)

        assert emitted[0]["direction"] == "INBOUND"
        assert emitted[0]["pid"] == pid
        assert emitted[0]["principal"] == "www-data"
        assert emitted[0]["actorID"] == state.get_process_object_id("WEB-EXT-01", pid)

    def test_rejected_inbound_flow_does_not_claim_listener_pid(self, emitter, monkeypatch, ts):
        """Rejected inbound attempts should not be attributed to a server process."""
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        emitter._system_pids = {"WEB-EXT-01": {"apache2": 24118}}
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            dst_host=HostContext(
                hostname="WEB-EXT-01",
                ip="10.0.0.20",
                os="Ubuntu 22.04",
                os_category="linux",
                system_type="server",
                fqdn="web-ext-01.example.org",
            ),
            network=NetworkContext(
                src_ip="198.51.100.7",
                src_port=49152,
                dst_ip="10.0.0.20",
                dst_port=443,
                protocol="tcp",
                conn_state="REJ",
                history="Sr",
                initiating_pid=-1,
            ),
        )

        emitter._render_connection(event)

        assert emitted[0]["direction"] == "INBOUND"
        assert emitted[0]["pid"] == -1
        assert emitted[0]["outcome"] == "failure"
        assert emitted[0]["connection_state"] == "REJ"
        rendered = json.loads(emitter._render_event(emitted[0]))
        assert "pid" not in rendered
        assert "tid" not in rendered

    def test_failed_outbound_flow_includes_failure_outcome(self, emitter, monkeypatch, ts):
        """Outbound endpoint FLOW rows should expose failed transport outcomes."""
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=HostContext(
                hostname="DC-01",
                ip="10.0.0.10",
                os="Windows Server 2022",
                os_category="windows",
                system_type="domain_controller",
                fqdn="dc-01.example.org",
            ),
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=62552,
                dst_ip="10.0.0.22",
                dst_port=445,
                protocol="tcp",
                conn_state="S0",
                history="S",
                orig_bytes=0,
                resp_bytes=0,
                initiating_pid=4,
            ),
        )

        emitter._render_connection(event)

        assert emitted[0]["direction"] == "OUTBOUND"
        assert emitted[0]["outcome"] == "failure"
        assert emitted[0]["connection_state"] == "S0"

    def test_outbound_flow_with_pid_only_renders_after_process_create(
        self, emitter, monkeypatch, ts
    ):
        """FLOW actor references should not appear before the visible PROCESS/CREATE row."""
        emitted: list[dict] = []
        monkeypatch.setattr(emitter, "emit_event", emitted.append)
        state = StateManager()
        state.set_current_time(ts)
        pid = state.create_process(
            "WS-01",
            4,
            r"C:\Windows\System32\dsquery.exe",
            r'dsquery.exe computer -name "*-01" -limit 200',
            "alice",
            "Medium",
        )
        emitter._state_manager = state
        host = HostContext(
            hostname="WS-01",
            ip="10.0.0.10",
            os="Windows 11",
            os_category="windows",
            system_type="workstation",
            fqdn="ws-01.example.org",
        )
        process_event = SecurityEvent(
            timestamp=ts,
            event_type="process_create",
            src_host=host,
            process=ProcessContext(
                pid=pid,
                parent_pid=4,
                image=r"C:\Windows\System32\dsquery.exe",
                command_line=r'dsquery.exe computer -name "*-01" -limit 200',
                username="alice",
                start_time=ts,
            ),
        )
        flow_event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=host,
            network=NetworkContext(
                src_ip="10.0.0.10",
                src_port=49152,
                dst_ip="10.0.0.20",
                dst_port=389,
                protocol="tcp",
                conn_state="SF",
                initiating_pid=pid,
            ),
            edr=EdrContext(actor_id=state.get_process_object_id("WS-01", pid)),
        )

        emitter._render_process_create(process_event)
        emitter._render_connection(flow_event)

        process_create, flow = emitted
        assert flow["object"] == "FLOW"
        assert flow["timestamp"] > process_create["timestamp"]

    def test_close_sorts_process_create_before_same_ms_children(self, tmp_path, ts):
        """Same-millisecond child telemetry should not sort before PROCESS/CREATE."""
        fmt = Mock()
        fmt.output.template = "{}"
        fmt.output.header_template = None
        fmt.output.footer_template = None
        fmt.output.encoding = "utf-8"
        emitter = EcarEmitter(fmt, tmp_path, threaded=False)

        for object_name, action in (("REGISTRY", "MODIFY"), ("PROCESS", "CREATE")):
            emitter.emit_event(
                {
                    "timestamp": ts,
                    "hostname": "ws01",
                    "object": object_name,
                    "action": action,
                    "pid": 5616,
                    "_host_fqdn": "ws01.example.org",
                }
            )

        emitter.close()

        rows = [
            json.loads(line)
            for line in (tmp_path / "ws01.example.org" / "ecar.json").read_text().splitlines()
        ]
        assert [(row["object"], row["action"]) for row in rows] == [
            ("PROCESS", "CREATE"),
            ("REGISTRY", "MODIFY"),
        ]

    def test_close_moves_child_process_create_after_visible_parent(self, tmp_path, ts):
        """Visible eCAR child PROCESS/CREATE rows should not precede parent creates."""
        fmt = Mock()
        fmt.output.template = "{}"
        fmt.output.header_template = None
        fmt.output.footer_template = None
        fmt.output.encoding = "utf-8"
        emitter = EcarEmitter(fmt, tmp_path, threaded=False)

        emitter.emit_event(
            {
                "timestamp": ts.replace(second=5),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": "child-process",
                "actorID": "parent-process",
                "pid": 4904,
                "ppid": 4896,
                "_host_fqdn": "ws01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts.replace(second=7),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": "parent-process",
                "pid": 4896,
                "_host_fqdn": "ws01.example.org",
            }
        )

        emitter.close()

        rows = [
            json.loads(line)
            for line in (tmp_path / "ws01.example.org" / "ecar.json").read_text().splitlines()
        ]
        parent_ms = next(row["timestamp_ms"] for row in rows if row["objectID"] == "parent-process")
        child_ms = next(row["timestamp_ms"] for row in rows if row["objectID"] == "child-process")
        assert child_ms > parent_ms
        assert 18 <= child_ms - parent_ms <= 150

    def test_close_moves_parent_termination_after_visible_child_termination(self, tmp_path, ts):
        """Visible eCAR parents should not terminate before foreground children."""
        fmt = Mock()
        fmt.output.template = "{}"
        fmt.output.header_template = None
        fmt.output.footer_template = None
        fmt.output.encoding = "utf-8"
        emitter = EcarEmitter(fmt, tmp_path, threaded=False)

        emitter.emit_event(
            {
                "timestamp": ts.replace(microsecond=0),
                "hostname": "linux01",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": "shell-process",
                "pid": 837798,
                "ppid": 36175,
                "_host_fqdn": "linux01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts.replace(microsecond=80_000),
                "hostname": "linux01",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": "debian-sa1-process",
                "actorID": "shell-process",
                "pid": 837826,
                "ppid": 837798,
                "_host_fqdn": "linux01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts.replace(microsecond=90_000),
                "hostname": "linux01",
                "object": "PROCESS",
                "action": "TERMINATE",
                "objectID": "shell-process",
                "pid": 837798,
                "_host_fqdn": "linux01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts.replace(microsecond=200_000),
                "hostname": "linux01",
                "object": "PROCESS",
                "action": "TERMINATE",
                "objectID": "debian-sa1-process",
                "pid": 837826,
                "_host_fqdn": "linux01.example.org",
            }
        )

        emitter.close()

        rows = [
            json.loads(line)
            for line in (tmp_path / "linux01.example.org" / "ecar.json").read_text().splitlines()
        ]
        shell_ms = next(
            row["timestamp_ms"]
            for row in rows
            if row["objectID"] == "shell-process" and row["action"] == "TERMINATE"
        )
        child_ms = next(
            row["timestamp_ms"]
            for row in rows
            if row["objectID"] == "debian-sa1-process" and row["action"] == "TERMINATE"
        )
        assert shell_ms > child_ms

    def test_close_does_not_drag_parent_termination_past_long_lived_child(self, tmp_path, ts):
        """A long-lived child should not keep a finished parent alive for hours."""
        fmt = Mock()
        fmt.output.template = "{}"
        fmt.output.header_template = None
        fmt.output.footer_template = None
        fmt.output.encoding = "utf-8"
        emitter = EcarEmitter(fmt, tmp_path, threaded=False)

        emitter.emit_event(
            {
                "timestamp": ts.replace(microsecond=0),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": "parent-process",
                "pid": 7496,
                "_host_fqdn": "ws01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts + timedelta(seconds=2),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": "child-process",
                "actorID": "parent-process",
                "pid": 7508,
                "ppid": 7496,
                "_host_fqdn": "ws01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts + timedelta(minutes=10),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "TERMINATE",
                "objectID": "parent-process",
                "pid": 7496,
                "_host_fqdn": "ws01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts + timedelta(hours=2),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "TERMINATE",
                "objectID": "child-process",
                "pid": 7508,
                "_host_fqdn": "ws01.example.org",
            }
        )

        emitter.close()

        rows = [
            json.loads(line)
            for line in (tmp_path / "ws01.example.org" / "ecar.json").read_text().splitlines()
        ]
        parent_ms = next(
            row["timestamp_ms"]
            for row in rows
            if row["objectID"] == "parent-process" and row["action"] == "TERMINATE"
        )
        child_ms = next(
            row["timestamp_ms"]
            for row in rows
            if row["objectID"] == "child-process" and row["action"] == "TERMINATE"
        )
        assert parent_ms < child_ms
        assert parent_ms < int((ts + timedelta(minutes=15)).timestamp() * 1000)

    def test_close_moves_dependent_telemetry_after_reordered_process_create(self, tmp_path, ts):
        """Dependent eCAR records should follow a process create shifted after its parent."""
        fmt = Mock()
        fmt.output.template = "{}"
        fmt.output.header_template = None
        fmt.output.footer_template = None
        fmt.output.encoding = "utf-8"
        emitter = EcarEmitter(fmt, tmp_path, threaded=False)

        emitter.emit_event(
            {
                "timestamp": ts.replace(second=5),
                "hostname": "ws01",
                "object": "FILE",
                "action": "WRITE",
                "actorID": "child-process",
                "pid": 4904,
                "file_path": r"C:\Users\alice\AppData\Local\Temp\cache.bin",
                "_host_fqdn": "ws01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts.replace(second=6),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": "child-process",
                "actorID": "parent-process",
                "pid": 4904,
                "ppid": 4896,
                "_host_fqdn": "ws01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts.replace(second=7),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": "parent-process",
                "pid": 4896,
                "_host_fqdn": "ws01.example.org",
            }
        )

        emitter.close()

        rows = [
            json.loads(line)
            for line in (tmp_path / "ws01.example.org" / "ecar.json").read_text().splitlines()
        ]
        parent_ms = next(row["timestamp_ms"] for row in rows if row["objectID"] == "parent-process")
        child_ms = next(row["timestamp_ms"] for row in rows if row["objectID"] == "child-process")
        file_ms = next(row["timestamp_ms"] for row in rows if row["object"] == "FILE")
        assert parent_ms < child_ms < file_ms

    def test_close_moves_child_process_create_after_parent_pid_without_actor_id(self, tmp_path, ts):
        """Visible eCAR child creates should also respect ppid when actorID is absent."""
        fmt = Mock()
        fmt.output.template = "{}"
        fmt.output.header_template = None
        fmt.output.footer_template = None
        fmt.output.encoding = "utf-8"
        emitter = EcarEmitter(fmt, tmp_path, threaded=False)

        emitter.emit_event(
            {
                "timestamp": ts.replace(second=5),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": "child-process",
                "pid": 4324,
                "ppid": 4300,
                "_host_fqdn": "ws01.example.org",
            }
        )
        emitter.emit_event(
            {
                "timestamp": ts.replace(second=7),
                "hostname": "ws01",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": "parent-process",
                "pid": 4300,
                "_host_fqdn": "ws01.example.org",
            }
        )

        emitter.close()

        rows = [
            json.loads(line)
            for line in (tmp_path / "ws01.example.org" / "ecar.json").read_text().splitlines()
        ]
        parent_ms = next(row["timestamp_ms"] for row in rows if row["objectID"] == "parent-process")
        child_ms = next(row["timestamp_ms"] for row in rows if row["objectID"] == "child-process")
        assert child_ms > parent_ms
        assert 18 <= child_ms - parent_ms <= 150

    def test_parent_order_skips_self_parented_pid_without_hanging(self):
        """Raw eCAR self-parented PID records should not loop forever."""
        line = json.dumps(
            {
                "timestamp_ms": 1000,
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": "self-parent",
                "pid": 123,
                "ppid": 123,
            },
            separators=(",", ":"),
        )

        normalized = EcarEmitter._normalize_process_parent_order([line])

        row = json.loads(normalized[0])
        assert row["timestamp_ms"] == 1000

    def test_linux_pid_morphology_rewrites_later_lower_process_pids(self):
        """Linux eCAR PID rendering should not move backward over source time."""
        lines = [
            json.dumps(
                {
                    "timestamp_ms": 1000,
                    "object": "PROCESS",
                    "action": "CREATE",
                    "objectID": "parent",
                    "pid": 500,
                    "tid": 500,
                    "properties": {"image_path": "/bin/sh"},
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 2000,
                    "object": "PROCESS",
                    "action": "CREATE",
                    "objectID": "shell",
                    "pid": 450,
                    "tid": 450,
                    "properties": {"image_path": "/usr/bin/journalctl"},
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 2100,
                    "object": "FILE",
                    "action": "READ",
                    "actorID": "shell",
                    "pid": 450,
                    "properties": {"file_path": "/var/log/syslog"},
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 2200,
                    "object": "PROCESS",
                    "action": "CREATE",
                    "objectID": "child",
                    "actorID": "shell",
                    "pid": 440,
                    "tid": 440,
                    "ppid": 450,
                    "properties": {"image_path": "/usr/bin/tail"},
                },
                separators=(",", ":"),
            ),
        ]

        normalized = [
            json.loads(line) for line in EcarEmitter._normalize_linux_pid_morphology(lines)
        ]

        parent = next(row for row in normalized if row.get("objectID") == "parent")
        shell = next(row for row in normalized if row.get("objectID") == "shell")
        file_row = next(row for row in normalized if row.get("object") == "FILE")
        child = next(row for row in normalized if row.get("objectID") == "child")
        assert shell["pid"] > parent["pid"]
        assert file_row["pid"] == shell["pid"]
        assert child["pid"] > shell["pid"]
        assert child["ppid"] == shell["pid"]

    def test_linux_pid_morphology_keeps_process_create_tid_as_main_thread(self):
        """Linux eCAR PROCESS/CREATE PID rewrites should keep TID as the main thread."""
        lines = [
            json.dumps(
                {
                    "timestamp_ms": 1000,
                    "object": "PROCESS",
                    "action": "CREATE",
                    "objectID": "parent",
                    "pid": 500,
                    "tid": 503,
                    "properties": {"image_path": "/bin/sh"},
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 2000,
                    "object": "PROCESS",
                    "action": "CREATE",
                    "objectID": "child",
                    "pid": 450,
                    "tid": 455,
                    "ppid": 500,
                    "properties": {"image_path": "/usr/bin/tail"},
                },
                separators=(",", ":"),
            ),
        ]

        normalized = [
            json.loads(line) for line in EcarEmitter._normalize_linux_pid_morphology(lines)
        ]

        child = next(row for row in normalized if row.get("objectID") == "child")
        assert child["pid"] > 500
        assert child["tid"] == child["pid"]

    def test_linux_pid_morphology_preserves_cron_group_canonical_pids(self):
        """Cron-correlated eCAR rows keep PIDs shared with CRON syslog."""
        lines = [
            json.dumps(
                {
                    "timestamp_ms": 1000,
                    "object": "PROCESS",
                    "action": "CREATE",
                    "objectID": "other",
                    "pid": 500,
                    "tid": 500,
                    "properties": {"image_path": "/usr/bin/bash"},
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 2000,
                    "object": "PROCESS",
                    "action": "CREATE",
                    "objectID": "cron-shell",
                    "actorID": "cron-daemon",
                    "pid": 450,
                    "tid": 450,
                    "ppid": 200,
                    "_concurrency_group_id": "cron:WEB-EXT-01:debian-sa1:1710766860000",
                    "properties": {"image_path": "/bin/sh"},
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 2100,
                    "object": "PROCESS",
                    "action": "CREATE",
                    "objectID": "cron-workload",
                    "actorID": "cron-shell",
                    "pid": 451,
                    "tid": 451,
                    "ppid": 450,
                    "_concurrency_group_id": "cron:WEB-EXT-01:debian-sa1:1710766860000",
                    "properties": {"image_path": "/usr/lib/sysstat/debian-sa1"},
                },
                separators=(",", ":"),
            ),
        ]

        normalized = [
            json.loads(line) for line in EcarEmitter._normalize_linux_pid_morphology(lines)
        ]

        shell = next(row for row in normalized if row.get("objectID") == "cron-shell")
        workload = next(row for row in normalized if row.get("objectID") == "cron-workload")
        assert shell["pid"] == 450
        assert shell["tid"] == 450
        assert workload["pid"] == 451
        assert workload["tid"] == 451
        assert workload["ppid"] == 450

    def test_linux_pid_morphology_preserves_process_open_actor_pid(self):
        """PROCESS/OPEN top-level pid should track actorID (source), not objectID target."""
        lines = [
            json.dumps(
                {
                    "timestamp_ms": 1000,
                    "object": "PROCESS",
                    "action": "CREATE",
                    "objectID": "source",
                    "pid": 500,
                    "tid": 500,
                    "properties": {"image_path": "/usr/bin/bash"},
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 2000,
                    "object": "PROCESS",
                    "action": "CREATE",
                    "objectID": "target",
                    "pid": 400,
                    "tid": 400,
                    "properties": {"image_path": "/usr/bin/ssh"},
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 2100,
                    "object": "PROCESS",
                    "action": "OPEN",
                    "objectID": "target",
                    "actorID": "source",
                    "pid": 500,
                    "tid": 500,
                    "properties": {"target_pid": 400, "target_process_uuid": "target"},
                },
                separators=(",", ":"),
            ),
        ]

        normalized = [
            json.loads(line) for line in EcarEmitter._normalize_linux_pid_morphology(lines)
        ]

        source_create = next(row for row in normalized if row.get("objectID") == "source")
        target_create = next(row for row in normalized if row.get("objectID") == "target")
        process_open = next(
            row
            for row in normalized
            if row.get("object") == "PROCESS" and row.get("action") == "OPEN"
        )

        assert target_create["pid"] > source_create["pid"]
        assert process_open["pid"] == source_create["pid"]
        assert process_open["properties"]["target_pid"] == target_create["pid"]

    def test_linux_process_lifecycle_tid_uses_main_thread(self, ts):
        """Linux PROCESS/CREATE and PROCESS/TERMINATE rows should share main-thread TID."""
        pid = 3200

        create_tid = EcarEmitter._stable_tid("linux-01", pid, ts, "process_create", "linux")
        terminate_tid = EcarEmitter._stable_tid(
            "linux-01",
            pid,
            ts + timedelta(seconds=5),
            "process_terminate",
            "linux",
        )

        assert create_tid == pid
        assert terminate_tid == pid

    def test_linux_dependent_tids_keep_source_thread_texture(self, ts):
        """Linux non-lifecycle eCAR rows may still carry source-native thread texture."""
        tids = {
            EcarEmitter._stable_tid("linux-01", 3200, ts + timedelta(seconds=i), salt, "linux")
            for i, salt in enumerate(["flow_inbound", "flow_outbound", "file", "module"])
        }

        assert all(tid > 3200 for tid in tids)
        assert len(tids) > 1

    def test_flow_principal_visibility_is_stable_for_same_process_and_direction(self, ts):
        """FLOW principal attribution should be a process-level source decision."""
        host = HostContext(
            hostname="PROXY-01",
            ip="10.10.3.20",
            os="Ubuntu 22.04",
            os_category="linux",
            system_type="server",
        )
        process = ProcessContext(
            pid=18750,
            parent_pid=1,
            image="/usr/sbin/nginx",
            command_line="nginx: worker process",
            username="www-data",
            start_time=ts,
        )
        first = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=host,
            process=process,
            network=NetworkContext(
                src_ip="10.10.3.20",
                src_port=40001,
                dst_ip="203.0.113.10",
                dst_port=443,
                protocol="tcp",
            ),
        )
        second = SecurityEvent(
            timestamp=ts + timedelta(seconds=30),
            event_type="connection",
            src_host=host,
            process=process,
            network=NetworkContext(
                src_ip="10.10.3.20",
                src_port=40002,
                dst_ip="203.0.113.11",
                dst_port=443,
                protocol="tcp",
            ),
        )
        emitter = object.__new__(EcarEmitter)

        assert emitter._flow_principal_for_process(first, host, process, "OUTBOUND") == (
            emitter._flow_principal_for_process(second, host, process, "OUTBOUND")
        )

    def test_flow_principal_visibility_is_stable_across_directions(self, ts):
        """FLOW principal attribution should not flip for the same local process."""
        host = HostContext(
            hostname="PROXY-01",
            ip="10.10.3.20",
            os="Ubuntu 22.04",
            os_category="linux",
            system_type="server",
        )
        process = ProcessContext(
            pid=18750,
            parent_pid=1,
            image="/usr/sbin/squid",
            command_line="/usr/sbin/squid --foreground -YC",
            username="proxy",
            start_time=ts,
        )
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=host,
            dst_host=host,
            process=process,
            network=NetworkContext(
                src_ip="10.10.3.20",
                src_port=40001,
                dst_ip="10.10.3.20",
                dst_port=8080,
                protocol="tcp",
            ),
        )
        emitter = object.__new__(EcarEmitter)

        assert emitter._flow_principal_for_process(event, host, process, "OUTBOUND") == (
            emitter._flow_principal_for_process(event, host, process, "INBOUND")
        )

    def test_parent_order_skips_pid_parent_cycles_without_hanging(self):
        """Raw eCAR cyclic ppid records should not loop forever."""
        lines = [
            json.dumps(
                {
                    "timestamp_ms": 1000,
                    "object": "PROCESS",
                    "action": "CREATE",
                    "objectID": "first",
                    "pid": 123,
                    "ppid": 456,
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 1000,
                    "object": "PROCESS",
                    "action": "CREATE",
                    "objectID": "second",
                    "pid": 456,
                    "ppid": 123,
                },
                separators=(",", ":"),
            ),
        ]

        normalized = EcarEmitter._normalize_process_parent_order(lines)

        rows = [json.loads(line) for line in normalized]
        assert [row["timestamp_ms"] for row in rows] == [1000, 1000]

    def test_user_session_logout_shifted_after_login(self):
        """Short network sessions must not render USER_SESSION LOGOUT before LOGIN."""
        lines = [
            json.dumps(
                {
                    "timestamp_ms": 1710768759642,
                    "object": "USER_SESSION",
                    "action": "LOGOUT",
                    "objectID": "session-object",
                    "hostname": "WS-01",
                    "principal": "evelyn.brooks",
                    "properties": {
                        "logon_id": "0xa445274",
                        "logon_type": "3",
                        "src_ip": "10.10.1.34",
                        "src_port": "60409",
                    },
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 1710768760347,
                    "object": "FLOW",
                    "action": "CONNECT",
                    "objectID": "flow-object",
                    "hostname": "WS-01",
                    "properties": {
                        "src_ip": "10.10.1.34",
                        "src_port": "60409",
                        "dst_ip": "10.10.1.33",
                        "dst_port": "445",
                        "direction": "INBOUND",
                    },
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 1710768760419,
                    "object": "USER_SESSION",
                    "action": "LOGIN",
                    "objectID": "session-object",
                    "hostname": "WS-01",
                    "principal": "evelyn.brooks",
                    "properties": {
                        "outcome": "success",
                        "logon_id": "0xa445274",
                        "logon_type": "3",
                        "src_ip": "10.10.1.34",
                        "src_port": "60409",
                    },
                },
                separators=(",", ":"),
            ),
        ]

        normalized = [
            json.loads(line) for line in EcarEmitter._normalize_user_session_lifecycle_order(lines)
        ]
        login = next(
            row
            for row in normalized
            if row["object"] == "USER_SESSION" and row["action"] == "LOGIN"
        )
        logout = next(
            row
            for row in normalized
            if row["object"] == "USER_SESSION" and row["action"] == "LOGOUT"
        )
        flow = next(row for row in normalized if row["object"] == "FLOW")

        assert flow["timestamp_ms"] == 1710768760347
        assert login["timestamp_ms"] == 1710768760419
        assert logout["timestamp_ms"] > login["timestamp_ms"]

    def test_user_session_logout_shifted_after_same_session_dependents(self):
        """USER_SESSION LOGOUT must trail visible same-logon endpoint activity."""
        lines = [
            json.dumps(
                {
                    "timestamp_ms": 2000,
                    "object": "USER_SESSION",
                    "action": "LOGOUT",
                    "objectID": "session-object",
                    "hostname": "WS-01",
                    "properties": {"logon_id": "0xabc", "session_id": "2"},
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 2600,
                    "object": "PROCESS",
                    "action": "TERMINATE",
                    "objectID": "process-object",
                    "hostname": "WS-01",
                    "pid": 4300,
                    "properties": {"logon_id": "0xabc", "session_id": "2"},
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 2800,
                    "object": "FILE",
                    "action": "CREATE",
                    "objectID": "file-object",
                    "hostname": "WS-01",
                    "pid": 4300,
                    "properties": {"logon_id": "0xabc", "file_path": r"C:\Users\alice\a.txt"},
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 3200,
                    "object": "FLOW",
                    "action": "CONNECT",
                    "objectID": "flow-object",
                    "hostname": "WS-01",
                    "properties": {
                        "logon_id": "0xabc",
                        "src_ip": "10.10.1.20",
                        "dst_ip": "10.10.2.20",
                    },
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 5000,
                    "object": "PROCESS",
                    "action": "TERMINATE",
                    "objectID": "system-process-object",
                    "hostname": "WS-01",
                    "pid": 4,
                    "properties": {"logon_id": "0x3e7"},
                },
                separators=(",", ":"),
            ),
        ]

        normalized = [
            json.loads(line)
            for line in EcarEmitter._normalize_user_session_logout_after_dependents(lines)
        ]
        logout = next(row for row in normalized if row["object"] == "USER_SESSION")
        latest_dependent_ms = max(
            row["timestamp_ms"]
            for row in normalized
            if row["object"] in {"PROCESS", "FILE", "FLOW"}
            and row["properties"].get("logon_id") == "0xabc"
        )

        assert logout["timestamp_ms"] > latest_dependent_ms
        assert logout["timestamp_ms"] < 5000

    def test_remote_thread_shifted_after_matching_process_open(self):
        """THREAD/REMOTE_CREATE must not precede its PROCESS/OPEN prerequisite."""
        lines = [
            json.dumps(
                {
                    "timestamp_ms": 2000,
                    "object": "THREAD",
                    "action": "REMOTE_CREATE",
                    "objectID": "thread-object",
                    "actorID": "source-process-object",
                    "hostname": "WS-01",
                    "pid": 4300,
                    "properties": {
                        "target_pid": "500",
                        "target_process_uuid": "target-process-object",
                    },
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 2600,
                    "object": "PROCESS",
                    "action": "OPEN",
                    "objectID": "target-process-object",
                    "actorID": "source-process-object",
                    "hostname": "WS-01",
                    "pid": 4300,
                    "properties": {
                        "target_pid": "500",
                        "target_process_uuid": "target-process-object",
                    },
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 1800,
                    "object": "PROCESS",
                    "action": "OPEN",
                    "objectID": "other-target-process-object",
                    "actorID": "source-process-object",
                    "hostname": "WS-01",
                    "pid": 4300,
                    "properties": {
                        "target_pid": "501",
                        "target_process_uuid": "other-target-process-object",
                    },
                },
                separators=(",", ":"),
            ),
        ]

        normalized = [
            json.loads(line)
            for line in EcarEmitter._normalize_remote_thread_after_process_open(lines)
        ]
        remote_thread = next(row for row in normalized if row["object"] == "THREAD")
        matching_open = next(
            row
            for row in normalized
            if row["object"] == "PROCESS" and row["objectID"] == "target-process-object"
        )
        other_open = next(
            row
            for row in normalized
            if row["object"] == "PROCESS" and row["objectID"] == "other-target-process-object"
        )

        assert remote_thread["timestamp_ms"] > matching_open["timestamp_ms"]
        assert other_open["timestamp_ms"] == 1800

    def test_remote_thread_uses_pid_fallback_for_process_open_order(self):
        """PID-only eCAR rows should still preserve access-before-thread ordering."""
        lines = [
            json.dumps(
                {
                    "timestamp_ms": 4000,
                    "object": "THREAD",
                    "action": "REMOTE_CREATE",
                    "objectID": "thread-object",
                    "hostname": "WS-01",
                    "pid": 4300,
                    "properties": {"target_pid": "500"},
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 4300,
                    "object": "PROCESS",
                    "action": "OPEN",
                    "objectID": "target-process-object",
                    "hostname": "WS-01",
                    "pid": 4300,
                    "properties": {"target_pid": "500"},
                },
                separators=(",", ":"),
            ),
        ]

        normalized = [
            json.loads(line)
            for line in EcarEmitter._normalize_remote_thread_after_process_open(lines)
        ]
        remote_thread = next(row for row in normalized if row["object"] == "THREAD")
        process_open = next(row for row in normalized if row["object"] == "PROCESS")

        assert remote_thread["timestamp_ms"] > process_open["timestamp_ms"]

    def test_remote_thread_preserves_existing_prior_process_open_order(self):
        """A valid prior PROCESS/OPEN should not be shifted by a later matching row."""
        lines = [
            json.dumps(
                {
                    "timestamp_ms": 1900,
                    "object": "PROCESS",
                    "action": "OPEN",
                    "objectID": "target-process-object",
                    "actorID": "source-process-object",
                    "hostname": "WS-01",
                    "pid": 4300,
                    "properties": {
                        "target_pid": "500",
                        "target_process_uuid": "target-process-object",
                    },
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 2000,
                    "object": "THREAD",
                    "action": "REMOTE_CREATE",
                    "objectID": "thread-object",
                    "actorID": "source-process-object",
                    "hostname": "WS-01",
                    "pid": 4300,
                    "properties": {
                        "target_pid": "500",
                        "target_process_uuid": "target-process-object",
                    },
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 2600,
                    "object": "PROCESS",
                    "action": "OPEN",
                    "objectID": "target-process-object",
                    "actorID": "source-process-object",
                    "hostname": "WS-01",
                    "pid": 4300,
                    "properties": {
                        "target_pid": "500",
                        "target_process_uuid": "target-process-object",
                    },
                },
                separators=(",", ":"),
            ),
        ]

        normalized = [
            json.loads(line)
            for line in EcarEmitter._normalize_remote_thread_after_process_open(lines)
        ]
        remote_thread = next(row for row in normalized if row["object"] == "THREAD")

        assert remote_thread["timestamp_ms"] == 2000

    def test_remote_user_session_login_shifted_after_late_inbound_flow(self):
        """Remote eCAR LOGIN rows should not precede same-tuple inbound FLOW rows."""
        lines = [
            json.dumps(
                {
                    "timestamp_ms": 1710764221308,
                    "object": "USER_SESSION",
                    "action": "LOGIN",
                    "objectID": "session-object",
                    "hostname": "MAIL-EDGE-01",
                    "principal": "marcus.chen",
                    "properties": {
                        "outcome": "success",
                        "session_type": "ssh",
                        "src_ip": "10.10.1.34",
                        "src_port": "61712",
                    },
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 1710764222532,
                    "object": "FLOW",
                    "action": "CONNECT",
                    "objectID": "flow-object",
                    "hostname": "MAIL-EDGE-01",
                    "properties": {
                        "src_ip": "10.10.1.34",
                        "src_port": "61712",
                        "dst_ip": "10.10.2.25",
                        "dst_port": "22",
                        "protocol": "tcp",
                        "direction": "INBOUND",
                    },
                },
                separators=(",", ":"),
            ),
        ]

        normalized = [
            json.loads(line)
            for line in EcarEmitter._normalize_remote_session_transport_order(lines)
        ]
        login = next(row for row in normalized if row["object"] == "USER_SESSION")
        flow = next(row for row in normalized if row["object"] == "FLOW")

        assert login["timestamp_ms"] > flow["timestamp_ms"]

    def test_linux_login_shell_create_shifted_after_session_login(self):
        """Interactive Linux shell PROCESS/CREATE rows should not predate session LOGIN."""
        lines = [
            json.dumps(
                {
                    "timestamp_ms": 1710765140391,
                    "object": "PROCESS",
                    "action": "CREATE",
                    "objectID": "shell-object",
                    "hostname": "MAIL-EDGE-01",
                    "principal": "aisha.johnson",
                    "pid": 601049,
                    "tid": 601049,
                    "properties": {
                        "command_line": "-bash",
                        "image_path": "/bin/bash",
                        "parent_image_path": "/usr/lib/systemd/systemd",
                    },
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 1710765142724,
                    "object": "USER_SESSION",
                    "action": "LOGIN",
                    "objectID": "session-object",
                    "hostname": "MAIL-EDGE-01",
                    "principal": "aisha.johnson",
                    "properties": {
                        "outcome": "success",
                        "session_type": "ssh",
                        "src_ip": "10.10.2.20",
                        "src_port": "64417",
                    },
                },
                separators=(",", ":"),
            ),
        ]

        normalized = [
            json.loads(line)
            for line in EcarEmitter._normalize_linux_login_shell_session_order(lines)
        ]
        shell = next(row for row in normalized if row["object"] == "PROCESS")
        login = next(row for row in normalized if row["object"] == "USER_SESSION")

        assert shell["timestamp_ms"] > login["timestamp_ms"]

    def test_failed_user_session_login_does_not_anchor_logout_order(self):
        """Failed USER_SESSION LOGIN attempts should not become session start anchors."""
        lines = [
            json.dumps(
                {
                    "timestamp_ms": 2000,
                    "object": "USER_SESSION",
                    "action": "LOGOUT",
                    "objectID": "session-object",
                    "hostname": "WS-01",
                    "properties": {"logon_id": "0x999"},
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "timestamp_ms": 3000,
                    "object": "USER_SESSION",
                    "action": "LOGIN",
                    "objectID": "session-object",
                    "hostname": "WS-01",
                    "properties": {"logon_id": "0x999", "outcome": "failure"},
                },
                separators=(",", ":"),
            ),
        ]

        normalized = [
            json.loads(line) for line in EcarEmitter._normalize_user_session_lifecycle_order(lines)
        ]

        logout = next(row for row in normalized if row["action"] == "LOGOUT")
        assert logout["timestamp_ms"] == 2000


class TestTidEmission:
    def test_tid_omitted_when_unavailable(self, emitter, ts):
        """Rows without a source-native thread ID should omit tid."""
        rendered = emitter._render_event(
            {"timestamp": ts, "object": "USER_SESSION", "action": "LOGIN"}
        )
        record = json.loads(rendered)
        assert "tid" not in record

    def test_tid_not_invented_on_raw_process_dict(self, emitter, ts):
        """Low-level rendering should not invent a thread ID without event context."""
        rendered = emitter._render_event(
            {"timestamp": ts, "object": "PROCESS", "action": "CREATE", "pid": 100, "ppid": 4}
        )
        record = json.loads(rendered)
        assert "tid" not in record

    def test_tid_explicit_value(self, emitter, ts):
        """Explicit tid value should be preserved."""
        rendered = emitter._render_event(
            {"timestamp": ts, "object": "PROCESS", "action": "CREATE", "pid": 100, "tid": 200}
        )
        record = json.loads(rendered)
        assert record["tid"] == 200

    def test_process_create_derives_tid_when_context_has_pid(self, emitter, ts):
        """Process-owned eCAR rows should avoid placeholder thread IDs when possible."""
        host = HostContext(
            hostname="WS-01",
            ip="10.0.0.10",
            os="Windows 11",
            os_category="windows",
            system_type="workstation",
            fqdn="ws-01.example.com",
        )
        emitter.emit_event = Mock()

        emitter._render_process_create(
            SecurityEvent(
                timestamp=ts,
                event_type="process_create",
                src_host=host,
                process=ProcessContext(
                    pid=4321,
                    parent_pid=4,
                    image=r"C:\Windows\System32\cmd.exe",
                    command_line="cmd.exe",
                    username="alice",
                ),
            )
        )

        row = emitter.emit_event.call_args.args[0]
        assert row["tid"] > 0
        assert row["tid"] % 4 == 0

    def test_linux_process_create_uses_pid_as_main_thread_id(self, emitter, ts):
        """Linux eCAR PROCESS/CREATE should use the PID as the main thread ID."""
        host = HostContext(
            hostname="APP-01",
            ip="10.0.0.20",
            os="Ubuntu 22.04",
            os_category="linux",
            system_type="server",
            fqdn="app-01.example.com",
        )
        emitter.emit_event = Mock()

        emitter._render_process_create(
            SecurityEvent(
                timestamp=ts,
                event_type="process_create",
                src_host=host,
                process=ProcessContext(
                    pid=14233,
                    parent_pid=900,
                    image="/usr/bin/mysql",
                    command_line="mysql -u root",
                    username="root",
                ),
            )
        )

        row = emitter.emit_event.call_args.args[0]
        assert row["tid"] == 14233


class TestPpidOnlyOnProcess:
    def test_ppid_on_process_create(self, emitter, ts):
        """ppid should appear on PROCESS/CREATE."""
        rendered = emitter._render_event(
            {"timestamp": ts, "object": "PROCESS", "action": "CREATE", "pid": 100, "ppid": 4}
        )
        record = json.loads(rendered)
        assert record["ppid"] == 4

    def test_ppid_absent_on_file(self, emitter, ts):
        """ppid should NOT appear on FILE events."""
        rendered = emitter._render_event(
            {"timestamp": ts, "object": "FILE", "action": "CREATE", "pid": 100}
        )
        record = json.loads(rendered)
        assert "ppid" not in record

    def test_ppid_absent_on_flow(self, emitter, ts):
        """ppid should NOT appear on FLOW events."""
        rendered = emitter._render_event(
            {
                "timestamp": ts,
                "object": "FLOW",
                "action": "CONNECT",
                "pid": 100,
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "dst_port": 443,
                "protocol": "tcp",
            }
        )
        record = json.loads(rendered)
        assert "ppid" not in record

    def test_ppid_absent_on_user_session(self, emitter, ts):
        """ppid should NOT appear on USER_SESSION events."""
        rendered = emitter._render_event(
            {"timestamp": ts, "object": "USER_SESSION", "action": "LOGIN"}
        )
        record = json.loads(rendered)
        assert "ppid" not in record


class TestPropertiesAreStrings:
    def test_icmp_flow_omits_transport_ports(self, emitter, ts):
        """ICMP FLOW rows should expose type/code instead of fake port zeroes."""
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            src_host=HostContext(
                hostname="SRC-01",
                ip="10.0.0.1",
                os="Ubuntu 22.04",
                os_category="linux",
                system_type="server",
            ),
            dst_host=HostContext(
                hostname="DST-01",
                ip="10.0.0.2",
                os="Ubuntu 22.04",
                os_category="linux",
                system_type="server",
            ),
            network=NetworkContext(
                src_ip="10.0.0.1",
                src_port=0,
                dst_ip="10.0.0.2",
                dst_port=0,
                protocol="icmp",
                conn_state="SF",
            ),
        )

        emitter.emit_event = Mock()
        emitter.emit(event)

        assert emitter.emit_event.call_count == 2
        for call in emitter.emit_event.call_args_list:
            record = json.loads(emitter._render_event(call.args[0]))
            props = record["properties"]
            assert props["protocol"] == "icmp"
            assert "src_port" not in props
            assert "dst_port" not in props
            assert props["icmp_type"] == "8"
            assert props["icmp_code"] == "0"

    def test_ports_are_strings(self, emitter, ts):
        """src_port and dst_port in properties must be strings."""
        rendered = emitter._render_event(
            {
                "timestamp": ts,
                "object": "FLOW",
                "action": "CONNECT",
                "pid": 100,
                "src_ip": "10.0.0.1",
                "src_port": 54321,
                "dst_ip": "10.0.0.2",
                "dst_port": 443,
                "protocol": "tcp",
            }
        )
        record = json.loads(rendered)
        assert isinstance(record["properties"]["src_port"], str)
        assert record["properties"]["src_port"] == "54321"
        assert isinstance(record["properties"]["dst_port"], str)
        assert record["properties"]["dst_port"] == "443"

    def test_all_property_values_are_strings(self, emitter, ts):
        """Every value in the properties map must be a string."""
        rendered = emitter._render_event(
            {
                "timestamp": ts,
                "object": "PROCESS",
                "action": "CREATE",
                "pid": 100,
                "ppid": 4,
                "command_line": "cmd.exe /c dir",
                "image_path": "C:\\Windows\\System32\\cmd.exe",
            }
        )
        record = json.loads(rendered)
        for key, val in record["properties"].items():
            assert isinstance(val, str), f"properties[{key!r}] = {val!r} is not a string"


class TestParentImagePath:
    def test_parent_image_path_in_properties(self, emitter, ts):
        """parent_image_path should appear in PROCESS/CREATE properties."""
        rendered = emitter._render_event(
            {
                "timestamp": ts,
                "object": "PROCESS",
                "action": "CREATE",
                "pid": 100,
                "ppid": 4,
                "image_path": "C:\\Windows\\System32\\cmd.exe",
                "parent_image_path": "C:\\Windows\\explorer.exe",
                "command_line": "cmd.exe",
            }
        )
        record = json.loads(rendered)
        assert record["properties"]["parent_image_path"] == "C:\\Windows\\explorer.exe"
