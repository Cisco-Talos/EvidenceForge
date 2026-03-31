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

"""Tests for eCAR objectID/actorID graph persistence.

Verifies that:
- StateManager assigns ecar_object_id on session/process creation
- objectID persists across entity lifecycle (create/terminate pairs)
- actorID links to the acting entity's objectID
- EcarEmitter uses provided objectID/actorID instead of random UUIDs
"""

import json
import uuid
from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System, User

# ---- Fixtures ----


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


@pytest.fixture
def emitter(tmp_path):
    """Create an EcarEmitter for output testing."""
    format_def = Mock()
    format_def.output.template = "{}"
    format_def.output.header_template = None
    format_def.output.footer_template = None
    format_def.output.encoding = "utf-8"
    return EcarEmitter(format_def, tmp_path, threaded=False)


# ---- StateManager UUID Assignment ----


class TestStateManagerObjectIds:
    def test_session_gets_object_id(self, state_manager, timestamp):
        state_manager.set_current_time(timestamp)
        logon_id = state_manager.create_session("alice", "WKS-01", 2, "10.0.0.1")
        obj_id = state_manager.get_session_object_id(logon_id)
        assert obj_id != ""
        # Valid UUID format
        uuid.UUID(obj_id)

    def test_process_gets_object_id(self, state_manager, timestamp):
        state_manager.set_current_time(timestamp)
        pid = state_manager.create_process("WKS-01", 4, "cmd.exe", "cmd.exe", "alice", "Medium")
        obj_id = state_manager.get_process_object_id("WKS-01", pid)
        assert obj_id != ""
        uuid.UUID(obj_id)

    def test_session_object_id_stable(self, state_manager, timestamp):
        """Same session returns same objectID on repeated lookups."""
        state_manager.set_current_time(timestamp)
        logon_id = state_manager.create_session("alice", "WKS-01", 2, "10.0.0.1")
        id1 = state_manager.get_session_object_id(logon_id)
        id2 = state_manager.get_session_object_id(logon_id)
        assert id1 == id2

    def test_process_object_id_stable(self, state_manager, timestamp):
        """Same process returns same objectID on repeated lookups."""
        state_manager.set_current_time(timestamp)
        pid = state_manager.create_process("WKS-01", 4, "cmd.exe", "cmd.exe", "alice", "Medium")
        id1 = state_manager.get_process_object_id("WKS-01", pid)
        id2 = state_manager.get_process_object_id("WKS-01", pid)
        assert id1 == id2

    def test_missing_session_returns_empty(self, state_manager):
        assert state_manager.get_session_object_id("nonexistent") == ""

    def test_missing_process_returns_empty(self, state_manager):
        assert state_manager.get_process_object_id("WKS-01", 99999) == ""


# ---- Lifecycle Persistence ----


class TestObjectIdLifecycle:
    def test_logon_logoff_share_object_id(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        """LOGIN and LOGOUT for same session must share objectID."""
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)

        # Get objectID from the logon event
        logon_event = mock_emitters["ecar"].emit.call_args_list[0][0][0]
        logon_obj_id = logon_event.edr.object_id

        # Now logoff
        activity_gen.generate_logoff(test_user, win_system, timestamp, logon_id)
        logoff_event = mock_emitters["ecar"].emit.call_args_list[-1][0][0]
        logoff_obj_id = logoff_event.edr.object_id

        assert logon_obj_id == logoff_obj_id
        assert logon_obj_id != ""

    def test_process_create_terminate_share_object_id(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        """CREATE and TERMINATE for same process must share objectID."""
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)

        pid = activity_gen.generate_process(
            test_user, win_system, timestamp, logon_id, "C:\\Windows\\System32\\cmd.exe", "cmd.exe"
        )

        # Find the process_create event
        create_event = None
        for call in mock_emitters["ecar"].emit.call_args_list:
            evt = call[0][0]
            if evt.event_type == "process_create" and evt.process and evt.process.pid == pid:
                create_event = evt
                break
        assert create_event is not None
        create_obj_id = create_event.edr.object_id

        # Terminate
        activity_gen.generate_process_termination(
            test_user, win_system, timestamp, pid, "C:\\Windows\\System32\\cmd.exe", logon_id
        )
        terminate_event = mock_emitters["ecar"].emit.call_args_list[-1][0][0]
        assert terminate_event.event_type == "process_terminate"
        assert terminate_event.edr.object_id == create_obj_id


# ---- actorID Linkage ----


class TestActorIdLinkage:
    def test_process_create_actor_is_parent(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        """PROCESS/CREATE actorID should be the parent process's objectID."""
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)

        # Create a parent process
        parent_pid = activity_gen.generate_process(
            test_user, win_system, timestamp, logon_id, "C:\\Windows\\explorer.exe", "explorer.exe"
        )
        parent_obj_id = state_manager.get_process_object_id(win_system.hostname, parent_pid)

        # Create a child process
        child_pid = activity_gen.generate_process(
            test_user,
            win_system,
            timestamp,
            logon_id,
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe",
            parent_pid=parent_pid,
        )

        # Find the child's create event
        child_event = None
        for call in mock_emitters["ecar"].emit.call_args_list:
            evt = call[0][0]
            if evt.event_type == "process_create" and evt.process and evt.process.pid == child_pid:
                child_event = evt
                break
        assert child_event is not None
        assert child_event.edr.actor_id == parent_obj_id

    def test_failed_logon_gets_fresh_object_id(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        """Failed logon should get a fresh objectID (no session created)."""
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(test_user, win_system, timestamp)

        failed_event = mock_emitters["ecar"].emit.call_args_list[-1][0][0]
        assert failed_event.edr is not None
        assert failed_event.edr.object_id != ""
        # Verify it's a valid UUID
        uuid.UUID(failed_event.edr.object_id)
        # actor_id should be empty (no actor for failed logon)
        assert failed_event.edr.actor_id == ""


# ---- EcarEmitter Rendering ----


class TestEmitterUsesProvidedIds:
    def test_emitter_renders_object_id(self, emitter, timestamp):
        """EcarEmitter should use objectID from event_data, not generate random."""
        known_id = "12345678-1234-5678-1234-567812345678"
        rendered = emitter._render_event(
            {
                "timestamp": timestamp,
                "object": "PROCESS",
                "action": "CREATE",
                "pid": 100,
                "ppid": 4,
                "objectID": known_id,
            }
        )
        record = json.loads(rendered)
        assert record["objectID"] == known_id

    def test_emitter_renders_actor_id(self, emitter, timestamp):
        """EcarEmitter should include actorID when provided."""
        actor_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        rendered = emitter._render_event(
            {
                "timestamp": timestamp,
                "object": "FILE",
                "action": "CREATE",
                "pid": 100,
                "objectID": "11111111-2222-3333-4444-555555555555",
                "actorID": actor_id,
            }
        )
        record = json.loads(rendered)
        assert record["actorID"] == actor_id

    def test_emitter_omits_actor_id_when_empty(self, emitter, timestamp):
        """actorID should not appear in output when empty."""
        rendered = emitter._render_event(
            {
                "timestamp": timestamp,
                "object": "USER_SESSION",
                "action": "LOGIN",
            }
        )
        record = json.loads(rendered)
        assert "actorID" not in record

    def test_emitter_fallback_generates_object_id(self, emitter, timestamp):
        """When no objectID provided, emitter should generate one (fallback)."""
        rendered = emitter._render_event(
            {
                "timestamp": timestamp,
                "object": "USER_SESSION",
                "action": "LOGIN",
            }
        )
        record = json.loads(rendered)
        assert "objectID" in record
        uuid.UUID(record["objectID"])  # Should be valid UUID
