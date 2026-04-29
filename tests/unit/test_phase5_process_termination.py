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

"""Unit tests for Phase 5.2.3: Process termination events."""

from datetime import UTC, datetime, timedelta
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


class TestProcessTermination:
    """Test process termination event generation."""

    def test_emits_process_terminate(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)
        pid = activity_gen.generate_process(
            test_user,
            win_system,
            timestamp,
            logon_id,
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c dir",
        )
        process_start = state_manager.get_process(win_system.hostname, pid).start_time
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.generate_process_termination(
            test_user,
            win_system,
            timestamp + timedelta(seconds=30),
            pid,
            "C:\\Windows\\System32\\cmd.exe",
            logon_id,
        )

        assert mock_emitters["windows_event_security"].emit.called
        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "process_terminate"
        assert event.process.pid == pid
        assert event.process.image == "C:\\Windows\\System32\\cmd.exe"
        assert event.process.start_time == process_start

    def test_removes_process_from_state(
        self, activity_gen, test_user, win_system, timestamp, state_manager
    ):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)
        pid = activity_gen.generate_process(
            test_user,
            win_system,
            timestamp,
            logon_id,
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c dir",
        )

        assert state_manager.get_process(win_system.hostname, pid) is not None
        activity_gen.generate_process_termination(
            test_user, win_system, timestamp, pid, "C:\\Windows\\System32\\cmd.exe", logon_id
        )
        assert state_manager.get_process(win_system.hostname, pid) is None

    def test_emits_ecar_terminate(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)
        pid = activity_gen.generate_process(
            test_user,
            win_system,
            timestamp,
            logon_id,
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c dir",
        )
        mock_emitters["ecar"].reset_mock()

        activity_gen.generate_process_termination(
            test_user, win_system, timestamp, pid, "C:\\Windows\\System32\\cmd.exe", logon_id
        )

        # Find the process_terminate event dispatched via emit()
        terminate_calls = [
            c
            for c in mock_emitters["ecar"].emit.call_args_list
            if c[0][0].event_type == "process_terminate"
        ]
        assert len(terminate_calls) == 1
        event = terminate_calls[0][0][0]
        assert event.process.pid == pid

    def test_has_subject_sid(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        sid_registry = {"alice.smith": "S-1-5-21-123-456-789-1001"}
        gen = ActivityGenerator(state_manager, mock_emitters, sid_registry=sid_registry)
        state_manager.set_current_time(timestamp)
        logon_id = gen.generate_logon(test_user, win_system, timestamp)
        pid = gen.generate_process(
            test_user,
            win_system,
            timestamp,
            logon_id,
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c dir",
        )
        mock_emitters["windows_event_security"].reset_mock()

        gen.generate_process_termination(
            test_user, win_system, timestamp, pid, "C:\\Windows\\System32\\cmd.exe", logon_id
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.user_sid == "S-1-5-21-123-456-789-1001"
