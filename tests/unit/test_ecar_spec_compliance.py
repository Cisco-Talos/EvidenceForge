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
from datetime import UTC, datetime
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
    RemoteThreadContext,
)
from evidenceforge.formats.loader import load_format
from evidenceforge.formats.validator import validate_event
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
            auth=AuthContext(username="alice", logon_id="0x123", logon_type=10),
            edr=EdrContext(object_id="session-1"),
        )

        emitter.emit_event = Mock()
        emitter.emit(event)

        row = emitter.emit_event.call_args[0][0]
        assert row["object"] == "USER_SESSION"
        assert row["action"] == "LOGIN"
        assert "logon_type" not in row
        assert row["session_type"] == "ssh"

        record = json.loads(emitter._render_event(row))
        assert "logon_type" not in record["properties"]
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
