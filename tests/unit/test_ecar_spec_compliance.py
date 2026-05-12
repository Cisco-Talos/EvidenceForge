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
- pid and tid always present (with -1 sentinel for unavailable)
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
from evidenceforge.generation.activity.timing_profiles import sample_timing_delta
from evidenceforge.generation.emitters.ecar import EcarEmitter


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


class TestPidAlwaysPresent:
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

    def test_pid_defaults_to_negative_one(self, emitter, ts):
        """When pid not set, it should default to -1."""
        rendered = emitter._render_event(
            {"timestamp": ts, "object": "USER_SESSION", "action": "LOGIN"}
        )
        record = json.loads(rendered)
        assert record["pid"] == -1

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

    def test_pid_none_becomes_negative_one(self, emitter, ts):
        """Explicit pid=None should become -1."""
        rendered = emitter._render_event(
            {"timestamp": ts, "object": "FILE", "action": "CREATE", "pid": None}
        )
        record = json.loads(rendered)
        assert record["pid"] == -1


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
        assert rendered["status_code"] == "0xC000006D"
        assert rendered["sub_status"] == "0xC000006A"

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


class TestTidAlwaysPresent:
    def test_tid_present_default(self, emitter, ts):
        """tid should always be present, defaulting to -1."""
        rendered = emitter._render_event(
            {"timestamp": ts, "object": "USER_SESSION", "action": "LOGIN"}
        )
        record = json.loads(rendered)
        assert "tid" in record
        assert record["tid"] == -1

    def test_tid_present_on_process(self, emitter, ts):
        """tid should be present on PROCESS events."""
        rendered = emitter._render_event(
            {"timestamp": ts, "object": "PROCESS", "action": "CREATE", "pid": 100, "ppid": 4}
        )
        record = json.loads(rendered)
        assert "tid" in record

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
