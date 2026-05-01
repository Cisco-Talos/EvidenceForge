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

"""Tests for eCAR THREAD/REMOTE_CREATE and PROCESS/OPEN events."""

import json
from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    AuthContext,
    HostContext,
    ProcessAccessContext,
    ProcessContext,
)
from evidenceforge.generation.emitters.ecar import EcarEmitter


@pytest.fixture
def emitter(tmp_path):
    """Create an EcarEmitter with a mock format_def."""
    format_def = Mock()
    format_def.output.template = "{}"
    format_def.output.header_template = None
    format_def.output.footer_template = None
    format_def.output.encoding = "utf-8"
    return EcarEmitter(format_def, tmp_path, threaded=False)


@pytest.fixture
def ts():
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


@pytest.fixture
def windows_host():
    return HostContext(
        hostname="WKS-01",
        ip="10.0.0.50",
        os="Windows 10 Enterprise",
        os_category="windows",
        system_type="workstation",
        domain="corp.local",
        fqdn="WKS-01.corp.local",
        netbios_domain="CORP",
    )


class TestCreateRemoteThread:
    """Tests for eCAR THREAD/REMOTE_CREATE rendering."""

    def test_object_action(self, emitter, ts, windows_host, tmp_path):
        """THREAD/REMOTE_CREATE has correct object and action."""
        event = SecurityEvent(
            timestamp=ts,
            event_type="create_remote_thread",
            src_host=windows_host,
            process=ProcessContext(
                pid=2120,
                parent_pid=572,
                image=r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe",
                command_line="",
                username="SYSTEM",
            ),
            auth=AuthContext(
                username="SYSTEM",
                target_server=r"C:\Windows\System32\svchost.exe",
                source_port=4,
            ),
        )
        emitter.emit(event)
        emitter.close()

        output_file = tmp_path / "WKS-01.corp.local" / "ecar.json"
        assert output_file.exists()
        record = json.loads(output_file.read_text().strip().split("\n")[0])
        assert record["object"] == "THREAD"
        assert record["action"] == "REMOTE_CREATE"

    def test_source_target_pids_in_properties(self, emitter, ts, windows_host, tmp_path):
        """Properties should include src_pid and target_pid as strings."""
        event = SecurityEvent(
            timestamp=ts,
            event_type="create_remote_thread",
            src_host=windows_host,
            process=ProcessContext(
                pid=2120,
                parent_pid=572,
                image=r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe",
                command_line="",
                username="SYSTEM",
            ),
            auth=AuthContext(
                username="SYSTEM",
                target_server=r"C:\Windows\System32\svchost.exe",
                source_port=4,
            ),
        )
        emitter.emit(event)
        emitter.close()

        output_file = tmp_path / "WKS-01.corp.local" / "ecar.json"
        record = json.loads(output_file.read_text().strip().split("\n")[0])
        props = record["properties"]
        assert props["src_pid"] == "2120"
        assert props["target_pid"] == "4"
        assert "target_process_uuid" in props
        assert "start_address" in props

    def test_top_level_pid_is_source(self, emitter, ts, windows_host, tmp_path):
        """Top-level pid should be the source process PID."""
        event = SecurityEvent(
            timestamp=ts,
            event_type="create_remote_thread",
            src_host=windows_host,
            process=ProcessContext(
                pid=2120,
                parent_pid=572,
                image=r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe",
                command_line="",
                username="SYSTEM",
            ),
            auth=AuthContext(
                username="SYSTEM",
                target_server=r"C:\Windows\System32\svchost.exe",
                source_port=4,
            ),
        )
        emitter.emit(event)
        emitter.close()

        output_file = tmp_path / "WKS-01.corp.local" / "ecar.json"
        record = json.loads(output_file.read_text().strip().split("\n")[0])
        assert record["pid"] == 2120
        assert record["ppid"] == 572

    def test_properties_all_strings(self, emitter, ts, windows_host, tmp_path):
        """All property values must be strings per eCAR spec."""
        event = SecurityEvent(
            timestamp=ts,
            event_type="create_remote_thread",
            src_host=windows_host,
            process=ProcessContext(
                pid=2120,
                parent_pid=572,
                image=r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe",
                command_line="",
                username="SYSTEM",
            ),
            auth=AuthContext(
                username="SYSTEM",
                target_server=r"C:\Windows\System32\svchost.exe",
                source_port=4,
            ),
        )
        emitter.emit(event)
        emitter.close()

        output_file = tmp_path / "WKS-01.corp.local" / "ecar.json"
        record = json.loads(output_file.read_text().strip().split("\n")[0])
        for key, val in record["properties"].items():
            assert isinstance(val, str), f"Property {key} should be string, got {type(val)}"

    def test_can_handle_create_remote_thread(self, emitter, ts, windows_host):
        """eCAR emitter should handle create_remote_thread events."""
        event = SecurityEvent(
            timestamp=ts,
            event_type="create_remote_thread",
            src_host=windows_host,
            process=ProcessContext(
                pid=1,
                parent_pid=0,
                image="test.exe",
                command_line="",
                username="SYSTEM",
            ),
        )
        assert emitter.can_handle(event) is True


class TestProcessAccess:
    """Tests for eCAR PROCESS/OPEN rendering."""

    def _access_context(self) -> ProcessAccessContext:
        return ProcessAccessContext(
            source_pid=2064,
            source_image=r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
            source_thread_id=4321,
            target_pid=672,
            target_image=r"C:\Windows\System32\lsass.exe",
            target_process_object_id="target-process-uuid",
            granted_access="0x1410",
        )

    def test_object_action(self, emitter, ts, windows_host, tmp_path):
        """PROCESS/OPEN has correct object and action."""
        event = SecurityEvent(
            timestamp=ts,
            event_type="process_access",
            src_host=windows_host,
            process=ProcessContext(
                pid=2064,
                parent_pid=556,
                image=r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
                command_line="",
                username="SYSTEM",
            ),
            auth=AuthContext(
                username="SYSTEM",
            ),
            process_access=self._access_context(),
        )
        emitter.emit(event)
        emitter.close()

        output_file = tmp_path / "WKS-01.corp.local" / "ecar.json"
        record = json.loads(output_file.read_text().strip().split("\n")[0])
        assert record["object"] == "PROCESS"
        assert record["action"] == "OPEN"

    def test_granted_access_in_properties(self, emitter, ts, windows_host, tmp_path):
        """Properties should include granted_access mask."""
        event = SecurityEvent(
            timestamp=ts,
            event_type="process_access",
            src_host=windows_host,
            process=ProcessContext(
                pid=2064,
                parent_pid=556,
                image=r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
                command_line="",
                username="SYSTEM",
            ),
            auth=AuthContext(
                username="SYSTEM",
            ),
            process_access=self._access_context(),
        )
        emitter.emit(event)
        emitter.close()

        output_file = tmp_path / "WKS-01.corp.local" / "ecar.json"
        record = json.loads(output_file.read_text().strip().split("\n")[0])
        assert record["properties"]["granted_access"] == "0x1410"

    def test_target_process_fields_are_explicit(self, emitter, ts, windows_host, tmp_path):
        """Target process details should not be overloaded into command_line."""
        event = SecurityEvent(
            timestamp=ts,
            event_type="process_access",
            src_host=windows_host,
            process=ProcessContext(
                pid=2064,
                parent_pid=556,
                image=r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
                command_line=r"MsMpEng.exe -Scan",
                username="SYSTEM",
            ),
            auth=AuthContext(
                username="SYSTEM",
            ),
            process_access=self._access_context(),
        )
        emitter.emit(event)
        emitter.close()

        output_file = tmp_path / "WKS-01.corp.local" / "ecar.json"
        record = json.loads(output_file.read_text().strip().split("\n")[0])
        props = record["properties"]
        assert props["command_line"] == r"MsMpEng.exe -Scan"
        assert props["target_pid"] == "672"
        assert props["target_image_path"] == r"C:\Windows\System32\lsass.exe"

    def test_source_image_in_properties(self, emitter, ts, windows_host, tmp_path):
        """image_path in properties should be the source process image."""
        event = SecurityEvent(
            timestamp=ts,
            event_type="process_access",
            src_host=windows_host,
            process=ProcessContext(
                pid=2064,
                parent_pid=556,
                image=r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
                command_line="",
                username="SYSTEM",
            ),
            auth=AuthContext(
                username="SYSTEM",
            ),
            process_access=self._access_context(),
        )
        emitter.emit(event)
        emitter.close()

        output_file = tmp_path / "WKS-01.corp.local" / "ecar.json"
        record = json.loads(output_file.read_text().strip().split("\n")[0])
        assert "MsMpEng.exe" in record["properties"]["image_path"]

    def test_can_handle_process_access(self, emitter, ts, windows_host):
        """eCAR emitter should handle process_access events."""
        event = SecurityEvent(
            timestamp=ts,
            event_type="process_access",
            src_host=windows_host,
            process=ProcessContext(
                pid=1,
                parent_pid=0,
                image="test.exe",
                command_line="",
                username="SYSTEM",
            ),
        )
        assert emitter.can_handle(event) is True

    def test_properties_all_strings(self, emitter, ts, windows_host, tmp_path):
        """All property values must be strings per eCAR spec."""
        event = SecurityEvent(
            timestamp=ts,
            event_type="process_access",
            src_host=windows_host,
            process=ProcessContext(
                pid=2064,
                parent_pid=556,
                image=r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
                command_line="",
                username="SYSTEM",
            ),
            auth=AuthContext(
                username="SYSTEM",
            ),
            process_access=self._access_context(),
        )
        emitter.emit(event)
        emitter.close()

        output_file = tmp_path / "WKS-01.corp.local" / "ecar.json"
        record = json.loads(output_file.read_text().strip().split("\n")[0])
        for key, val in record["properties"].items():
            assert isinstance(val, str), f"Property {key} should be string, got {type(val)}"
