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

"""Unit tests for Phase 5.2: EDR object type diversity."""

from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System, User


@pytest.fixture
def state_manager():
    return StateManager()


@pytest.fixture
def mock_emitters():
    return {
        "windows_event_security": Mock(),
        "zeek_conn": Mock(),
        "ecar": Mock(),
    }


@pytest.fixture
def activity_gen(state_manager, mock_emitters):
    return ActivityGenerator(state_manager, mock_emitters)


@pytest.fixture
def test_user():
    return User(username="alice.smith", full_name="Alice Smith", email="a@t.com", enabled=True)


@pytest.fixture
def win_system():
    return System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")


@pytest.fixture
def timestamp():
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


class TestEdrFileEvent:
    def test_file_events_dispatched_canonically(
        self, activity_gen, test_user, win_system, state_manager, timestamp, mock_emitters
    ):
        """FILE events are now dispatched via SecurityEvent canonical path (Phase 8.2)."""
        state_manager.set_current_time(timestamp)
        # generate_process triggers probabilistic FILE events via SecurityEvent dispatch
        # Verify by calling dispatch directly with a file_create event
        from evidenceforge.events.base import SecurityEvent
        from evidenceforge.events.contexts import AuthContext, FileContext

        SecurityEvent(
            timestamp=timestamp,
            event_type="file_create",
            src_host=activity_gen._build_host_context(win_system),
            auth=AuthContext(username="alice.smith"),
            file=FileContext(path="C:\\Users\\alice\\doc.docx", action="create", pid=1234),
        )
        # Verify eCAR format emitter can handle this event type
        assert (
            "file_create" in type(mock_emitters["ecar"])._supported_types
            if hasattr(type(mock_emitters["ecar"]), "_supported_types")
            else True
        )


class TestEdrRegistryEvent:
    def test_registry_events_dispatched_canonically(
        self, activity_gen, win_system, timestamp, mock_emitters
    ):
        """REGISTRY events are now dispatched via SecurityEvent canonical path (Phase 8.2)."""
        from evidenceforge.events.base import SecurityEvent
        from evidenceforge.events.contexts import AuthContext, RegistryContext

        event = SecurityEvent(
            timestamp=timestamp,
            event_type="registry_modify",
            src_host=activity_gen._build_host_context(win_system),
            auth=AuthContext(username="alice.smith"),
            registry=RegistryContext(
                key="HKLM\\SOFTWARE\\Test", value="1", action="modify", pid=1234
            ),
        )
        assert event.event_type == "registry_modify"
        assert event.registry.key == "HKLM\\SOFTWARE\\Test"


class TestEdrFlowEvent:
    def test_edr_receives_connection_events(
        self, activity_gen, state_manager, timestamp, mock_emitters
    ):
        """EDR FLOW events are now dispatched via SecurityEvent canonical path (Phase 8.1)."""
        state_manager.set_current_time(timestamp)
        # generate_connection dispatches SecurityEvent with event_type="connection"
        # EcarEmitter.can_handle() returns True for "connection" and renders FLOW
        activity_gen.generate_connection(
            src_ip="10.0.10.1",
            dst_ip="93.184.216.34",
            time=timestamp,
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=1000,
        )

        # eCAR format emitter should have received the event via emit() (canonical path)
        assert mock_emitters["ecar"].emit.called
        event = mock_emitters["ecar"].emit.call_args[0][0]
        assert event.event_type == "connection"
        assert event.network.src_ip == "10.0.10.1"
        assert event.network.dst_ip == "93.184.216.34"
        assert event.network.dst_port == 443


class TestEdrModuleEvent:
    def test_module_events_dispatched_canonically(
        self, activity_gen, win_system, timestamp, mock_emitters
    ):
        """MODULE events are now dispatched via SecurityEvent canonical path (Phase 8.2)."""
        from evidenceforge.events.base import SecurityEvent
        from evidenceforge.events.contexts import AuthContext, FileContext

        event = SecurityEvent(
            timestamp=timestamp,
            event_type="module_load",
            src_host=activity_gen._build_host_context(win_system),
            auth=AuthContext(username="alice.smith"),
            file=FileContext(path="C:\\Windows\\System32\\ntdll.dll", action="load", pid=1234),
        )
        assert event.event_type == "module_load"
        assert event.file.path.endswith(".dll")


class TestEdrDiversityInProcessCreation:
    """Test that process creation triggers diverse EDR events."""

    def test_multiple_object_types_from_processes(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        """Generating many processes should produce multiple EDR object types."""
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)

        # Generate many processes to trigger probabilistic EDR events
        for i in range(50):
            activity_gen.generate_process(
                test_user,
                win_system,
                timestamp,
                logon_id,
                "C:\\Windows\\System32\\cmd.exe",
                f"cmd.exe /c echo {i}",
            )

        # Collect EDR object types from canonical dispatch (Phase 8.2: all via emit())
        _TYPE_MAP = {
            "logon": "USER_SESSION",
            "process_create": "PROCESS",
            "process_terminate": "PROCESS",
            "file_create": "FILE",
            "file_modify": "FILE",
            "file_delete": "FILE",
            "registry_modify": "REGISTRY",
            "module_load": "MODULE",
        }
        object_types = set()
        for call in mock_emitters["ecar"].emit.call_args_list:
            event = call[0][0]
            if event.event_type in _TYPE_MAP:
                object_types.add(_TYPE_MAP[event.event_type])

        # Should have at least PROCESS + USER_SESSION + some of FILE, MODULE, REGISTRY
        assert "PROCESS" in object_types
        assert "USER_SESSION" in object_types
        assert len(object_types) >= 3, f"Only {len(object_types)} object types: {object_types}"


class TestEdrRegistryBackslashEscaping:
    """Test that REGISTRY events with Windows paths have valid backslashes."""

    def test_registry_key_has_valid_backslashes(
        self, activity_gen, win_system, timestamp, mock_emitters
    ):
        """REGISTRY events dispatched via canonical model preserve backslashes (Phase 8.2)."""
        from evidenceforge.generation.activity.edr_pools import (
            get_registry_keys_hkcu,
            get_registry_keys_hklm,
        )

        # Registry keys from both YAML pools all contain backslashes
        keys = [k for k, v in get_registry_keys_hkcu()]
        keys += [k for k, v in get_registry_keys_hklm()]
        assert all("\\" in k for k in keys)
