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

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.timing_profiles import sample_timing_delta
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


def _emitted_syslog_events(mock_emitters: dict[str, Any]) -> list[Any]:
    """Return syslog-dispatched events from the mocked syslog emitter."""
    return [
        call.args[0]
        for call in mock_emitters["syslog"].emit.call_args_list
        if call.args[0].syslog is not None
    ]


def _emitted_pam_close_event(mock_emitters: dict[str, Any]) -> Any:
    """Return the SSH PAM close event from mocked syslog calls."""
    return next(
        event
        for event in _emitted_syslog_events(mock_emitters)
        if event.syslog.message.startswith("pam_unix(sshd:session): session closed")
    )


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

    def test_logoff_leaves_margin_after_last_activity(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        """Logoff should leave room for source-native process-create offsets."""
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)
        session = state_manager.get_session(logon_id)
        assert session is not None
        session.last_activity_time = timestamp + timedelta(seconds=10)
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.generate_logoff(
            test_user,
            win_system,
            timestamp + timedelta(seconds=10, milliseconds=500),
            logon_id,
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        expected_delta = sample_timing_delta(
            "windows.logoff_after_last_activity",
            seed_parts=(win_system.hostname, logon_id, session.last_activity_time),
        )
        assert event.timestamp == session.last_activity_time + expected_delta

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

    def test_ssh_logoff_waits_for_transport_close(
        self, activity_gen, test_user, linux_system, timestamp, state_manager, mock_emitters
    ):
        """SSH disconnect syslog should not predate the Zeek connection close."""
        state_manager.set_current_time(timestamp)
        logon_id = state_manager.create_session(
            username=test_user.username,
            system=linux_system.hostname,
            logon_type=10,
            source_ip="10.0.10.50",
            source_port=51111,
            session_kind="ssh",
            transport_pid=6505,
        )
        close_time = timestamp + timedelta(minutes=8)
        state_manager.update_session_metadata(
            logon_id,
            network_close_time=close_time,
            session_id=12345,
        )
        session = state_manager.get_session(logon_id)
        assert session is not None
        expected_session_id = session.session_id
        session_obj_id = state_manager.get_session_object_id(logon_id)
        mock_emitters["syslog"].reset_mock()
        mock_emitters["ecar"].reset_mock()

        activity_gen.generate_logoff(
            test_user,
            linux_system,
            timestamp + timedelta(seconds=30),
            logon_id,
            logon_type=10,
        )

        event = _emitted_pam_close_event(mock_emitters)
        removed_event = next(
            event
            for event in _emitted_syslog_events(mock_emitters)
            if event.syslog.message == f"Removed session {expected_session_id}."
        )
        ecar_event = next(
            call.args[0]
            for call in mock_emitters["ecar"].emit.call_args_list
            if call.args[0].event_type == "logoff"
        )
        expected_delta = sample_timing_delta(
            "windows.logoff_after_last_activity",
            seed_parts=(linux_system.hostname, logon_id, close_time),
        )
        assert event.timestamp == close_time + expected_delta
        assert event.syslog.message == (
            "pam_unix(sshd:session): session closed for user alice.smith"
        )
        assert ecar_event.edr.object_id == session_obj_id
        assert ecar_event.auth.source_ip == "10.0.10.50"
        assert ecar_event.auth.source_port == 51111
        assert removed_event.timestamp > event.timestamp
        assert removed_event.timestamp <= event.timestamp + timedelta(seconds=1)

    def test_ssh_logoff_binds_late_cleanup_to_transport_close(
        self, activity_gen, test_user, linux_system, timestamp, state_manager, mock_emitters
    ):
        """Late SSH cleanup should render the close at the transport boundary."""
        state_manager.set_current_time(timestamp)
        logon_id = state_manager.create_session(
            username=test_user.username,
            system=linux_system.hostname,
            logon_type=10,
            source_ip="10.0.10.50",
            source_port=51111,
            session_kind="ssh",
            transport_pid=6505,
        )
        close_time = timestamp + timedelta(minutes=8)
        last_activity_time = timestamp + timedelta(hours=2)
        state_manager.update_session_metadata(logon_id, network_close_time=close_time)
        session = state_manager.get_session(logon_id)
        assert session is not None
        session.last_activity_time = last_activity_time
        mock_emitters["syslog"].reset_mock()

        activity_gen.generate_logoff(
            test_user,
            linux_system,
            timestamp + timedelta(hours=2, minutes=5),
            logon_id,
            logon_type=10,
        )

        event = _emitted_pam_close_event(mock_emitters)
        expected_delta = sample_timing_delta(
            "windows.logoff_after_last_activity",
            seed_parts=(linux_system.hostname, logon_id, close_time),
        )
        assert event.timestamp == close_time + expected_delta
        assert event.syslog.message == (
            "pam_unix(sshd:session): session closed for user alice.smith"
        )

    def test_storyline_ssh_logoff_binds_to_transport_close(
        self, activity_gen, test_user, linux_system, timestamp, state_manager, mock_emitters
    ):
        """Storyline cleanup should not extend an SSH session past the transport close."""
        state_manager.set_current_time(timestamp)
        logon_id = state_manager.create_session(
            username=test_user.username,
            system=linux_system.hostname,
            logon_type=10,
            source_ip="10.0.10.50",
            source_port=51111,
            session_kind="ssh",
            transport_pid=6505,
        )
        close_time = timestamp + timedelta(minutes=8)
        state_manager.update_session_metadata(logon_id, network_close_time=close_time)
        mock_emitters["syslog"].reset_mock()
        mock_emitters["ecar"].reset_mock()

        activity_gen.generate_logoff(
            test_user,
            linux_system,
            timestamp + timedelta(hours=2),
            logon_id,
            logon_type=10,
            from_storyline=True,
        )

        expected_delta = sample_timing_delta(
            "windows.logoff_after_last_activity",
            seed_parts=(linux_system.hostname, logon_id, close_time),
        )
        syslog_event = _emitted_pam_close_event(mock_emitters)
        ecar_event = mock_emitters["ecar"].emit.call_args[0][0]
        assert syslog_event.timestamp == close_time + expected_delta
        assert ecar_event.timestamp == close_time + expected_delta

    def test_storyline_ssh_logoff_preserves_time_before_transport_close(
        self, activity_gen, test_user, linux_system, timestamp, state_manager, mock_emitters
    ):
        """Storyline logout should stay authored when the SSH transport is still open."""
        state_manager.set_current_time(timestamp)
        logon_id = state_manager.create_session(
            username=test_user.username,
            system=linux_system.hostname,
            logon_type=10,
            source_ip="10.0.10.50",
            source_port=51111,
            session_kind="ssh",
            transport_pid=6505,
        )
        close_time = timestamp + timedelta(hours=2)
        logoff_time = timestamp + timedelta(minutes=30)
        state_manager.update_session_metadata(logon_id, network_close_time=close_time)
        mock_emitters["syslog"].reset_mock()
        mock_emitters["ecar"].reset_mock()

        activity_gen.generate_logoff(
            test_user,
            linux_system,
            logoff_time,
            logon_id,
            logon_type=10,
            from_storyline=True,
        )

        syslog_event = _emitted_pam_close_event(mock_emitters)
        ecar_event = mock_emitters["ecar"].emit.call_args[0][0]
        assert syslog_event.timestamp == logoff_time
        assert ecar_event.timestamp == logoff_time

    def test_linux_type10_logoff_gets_pam_close_even_when_kind_was_not_preserved(
        self, activity_gen, test_user, linux_system, timestamp, state_manager, mock_emitters
    ):
        """Linux type-10 eCAR SSH logout classification should match syslog close gating."""
        state_manager.set_current_time(timestamp)
        logon_id = state_manager.create_session(
            username=test_user.username,
            system=linux_system.hostname,
            logon_type=10,
            source_ip="10.0.10.50",
            source_port=51111,
            session_kind="logon",
            transport_pid=6505,
        )
        mock_emitters["syslog"].reset_mock()

        activity_gen.generate_logoff(
            test_user,
            linux_system,
            timestamp + timedelta(minutes=8),
            logon_id,
            logon_type=10,
        )

        event = _emitted_pam_close_event(mock_emitters)
        assert event.syslog.message == (
            "pam_unix(sshd:session): session closed for user alice.smith"
        )

    def test_ssh_logoff_suppresses_syslog_for_self_sourced_session(
        self, activity_gen, test_user, linux_system, timestamp, state_manager, mock_emitters
    ):
        """Self-sourced SSH session cleanup should not claim an external sshd close."""
        state_manager.set_current_time(timestamp)
        logon_id = state_manager.create_session(
            username=test_user.username,
            system=linux_system.hostname,
            logon_type=10,
            source_ip=linux_system.ip,
            source_port=51111,
            session_kind="ssh",
            transport_pid=6505,
        )
        state_manager.update_session_metadata(
            logon_id,
            network_close_time=timestamp + timedelta(minutes=8),
        )
        mock_emitters["syslog"].reset_mock()

        activity_gen.generate_logoff(
            test_user,
            linux_system,
            timestamp + timedelta(minutes=8),
            logon_id,
            logon_type=10,
        )

        event = mock_emitters["syslog"].emit.call_args[0][0]
        assert event.syslog is None


class TestLinuxLogonSyslog:
    """Test source-native Linux SSH auth syslog generation."""

    def test_self_sourced_linux_remote_logon_does_not_emit_accepted_password(
        self, activity_gen, test_user, linux_system, timestamp, state_manager, mock_emitters
    ):
        """Linux sshd auth logs should not claim a host accepted SSH from itself."""
        logon_id = activity_gen.generate_logon(
            test_user,
            linux_system,
            timestamp,
            logon_type=10,
            source_ip=linux_system.ip,
        )

        syslog_events = [
            call.args[0]
            for call in mock_emitters["syslog"].emit.call_args_list
            if call.args[0].syslog is not None
        ]
        ecar_event = mock_emitters["ecar"].emit.call_args[0][0]
        session = state_manager.get_session(logon_id)

        assert not any("Accepted password" in event.syslog.message for event in syslog_events)
        assert ecar_event.auth.logon_type == 2
        assert ecar_event.auth.source_ip == "-"
        assert session is not None
        assert session.session_kind == "interactive"


class TestLogoffNoEcar:
    """Test logoff when eCAR emitter is not present."""

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
