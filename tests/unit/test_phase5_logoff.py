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

"""Unit tests for Phase 5.1.2: Baseline logoff generation."""

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
        "syslog": Mock(),
        "ecar": Mock(),
    }


@pytest.fixture
def activity_gen(state_manager, mock_emitters):
    return ActivityGenerator(state_manager, mock_emitters)


@pytest.fixture
def test_user():
    return User(
        username="alice.smith", full_name="Alice Smith", email="alice@corp.com", enabled=True
    )


@pytest.fixture
def win_system():
    return System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")


@pytest.fixture
def linux_system():
    return System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="workstation")


@pytest.fixture
def timestamp():
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


class TestLogoffWindows:
    """Test logoff event generation on Windows systems."""

    def test_logoff_emits_4634(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.generate_logoff(test_user, win_system, timestamp, logon_id)

        assert mock_emitters["windows_event_security"].emit.called
        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "logoff"
        assert event.auth.username == "alice.smith"
        assert event.auth.logon_id == logon_id

    def test_logoff_ends_session(
        self, activity_gen, test_user, win_system, timestamp, state_manager
    ):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)

        assert len(state_manager.get_sessions_for_user("alice.smith")) == 1
        activity_gen.generate_logoff(test_user, win_system, timestamp, logon_id)
        assert len(state_manager.get_sessions_for_user("alice.smith")) == 0

    def test_logoff_preserves_logon_type(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp, logon_type=3)
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.generate_logoff(test_user, win_system, timestamp, logon_id, logon_type=3)

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.logon_type == 3

    def test_logoff_emits_ecar_logout(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)
        mock_emitters["ecar"].reset_mock()

        activity_gen.generate_logoff(test_user, win_system, timestamp, logon_id)

        assert mock_emitters["ecar"].emit.called
        event = mock_emitters["ecar"].emit.call_args[0][0]
        assert event.event_type == "logoff"
        assert event.auth.username == "alice.smith"


class TestLogoffLinux:
    """Test logoff event generation on Linux systems."""

    def test_logoff_emits_syslog_session_closed(
        self, activity_gen, test_user, linux_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, linux_system, timestamp)
        mock_emitters["syslog"].reset_mock()

        activity_gen.generate_logoff(test_user, linux_system, timestamp, logon_id)

        assert mock_emitters["syslog"].emit.called
        event = mock_emitters["syslog"].emit.call_args[0][0]
        assert event.event_type == "logoff"
        assert event.auth.username == "alice.smith"

    def test_logoff_linux_does_not_emit_windows(
        self, test_user, linux_system, timestamp, state_manager
    ):
        """Logoff on Linux should not dispatch to Windows emitter."""
        # Use real emitter can_handle logic by setting return values on mocks
        win_mock = Mock()
        win_mock.can_handle = Mock(return_value=False)
        syslog_mock = Mock()
        syslog_mock.can_handle = Mock(return_value=True)
        ecar_mock = Mock()
        ecar_mock.can_handle = Mock(return_value=True)
        emitters = {
            "windows_event_security": win_mock,
            "syslog": syslog_mock,
            "ecar": ecar_mock,
            "zeek_conn": Mock(),
        }
        gen = ActivityGenerator(state_manager, emitters)
        state_manager.set_current_time(timestamp)
        logon_id = gen.generate_logon(test_user, linux_system, timestamp)
        win_mock.reset_mock()
        win_mock.can_handle = Mock(return_value=False)

        gen.generate_logoff(test_user, linux_system, timestamp, logon_id)

        assert not win_mock.emit.called

    def test_logoff_linux_emits_ecar_logout(
        self, activity_gen, test_user, linux_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, linux_system, timestamp)
        mock_emitters["ecar"].reset_mock()

        activity_gen.generate_logoff(test_user, linux_system, timestamp, logon_id)

        assert mock_emitters["ecar"].emit.called
        event = mock_emitters["ecar"].emit.call_args[0][0]
        assert event.event_type == "logoff"


class TestLogoffNoEcar:
    """Test logoff when eCAR is not available."""

    def test_logoff_without_ecar_emitter(self, state_manager, timestamp):
        """Logoff works when eCAR emitter is not present."""
        emitters = {"windows_event_security": Mock(), "zeek_conn": Mock()}
        gen = ActivityGenerator(state_manager, emitters)
        user = User(username="bob", full_name="Bob", email="bob@test.com", enabled=True)
        system = System(hostname="W1", ip="10.0.0.1", os="Windows 10", type="workstation")
        state_manager.set_current_time(timestamp)

        logon_id = gen.generate_logon(user, system, timestamp)
        gen.generate_logoff(user, system, timestamp, logon_id)

        # Should not raise, logoff SecurityEvent dispatched
        assert emitters["windows_event_security"].emit.called
