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

    def test_pid_none_becomes_negative_one(self, emitter, ts):
        """Explicit pid=None should become -1."""
        rendered = emitter._render_event(
            {"timestamp": ts, "object": "FILE", "action": "CREATE", "pid": None}
        )
        record = json.loads(rendered)
        assert record["pid"] == -1


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
