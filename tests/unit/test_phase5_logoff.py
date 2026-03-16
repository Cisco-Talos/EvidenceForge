"""Unit tests for Phase 5.1.2: Baseline logoff generation."""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import User, System


@pytest.fixture
def state_manager():
    return StateManager()


@pytest.fixture
def mock_emitters():
    return {
        'windows_event_security': Mock(),
        'zeek_conn': Mock(),
        'syslog': Mock(),
        'ecar': Mock(),
    }


@pytest.fixture
def activity_gen(state_manager, mock_emitters):
    return ActivityGenerator(state_manager, mock_emitters)


@pytest.fixture
def test_user():
    return User(username="alice.smith", full_name="Alice Smith", email="alice@corp.com", enabled=True)


@pytest.fixture
def win_system():
    return System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")


@pytest.fixture
def linux_system():
    return System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="workstation")


@pytest.fixture
def timestamp():
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=timezone.utc)


class TestLogoffWindows:
    """Test logoff event generation on Windows systems."""

    def test_logoff_emits_4634(self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)
        mock_emitters['windows_event_security'].reset_mock()

        activity_gen.generate_logoff(test_user, win_system, timestamp, logon_id)

        assert mock_emitters['windows_event_security'].emit_event.called
        event_data = mock_emitters['windows_event_security'].emit_event.call_args[0][0]
        assert event_data['EventID'] == 4634
        assert event_data['TargetUserName'] == 'alice.smith'
        assert event_data['TargetLogonId'] == logon_id

    def test_logoff_ends_session(self, activity_gen, test_user, win_system, timestamp, state_manager):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)

        assert len(state_manager.get_sessions_for_user('alice.smith')) == 1
        activity_gen.generate_logoff(test_user, win_system, timestamp, logon_id)
        assert len(state_manager.get_sessions_for_user('alice.smith')) == 0

    def test_logoff_preserves_logon_type(self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp, logon_type=3)
        mock_emitters['windows_event_security'].reset_mock()

        activity_gen.generate_logoff(test_user, win_system, timestamp, logon_id, logon_type=3)

        event_data = mock_emitters['windows_event_security'].emit_event.call_args[0][0]
        assert event_data['LogonType'] == 3

    def test_logoff_emits_ecar_logout(self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)
        mock_emitters['ecar'].reset_mock()

        activity_gen.generate_logoff(test_user, win_system, timestamp, logon_id)

        assert mock_emitters['ecar'].emit_event.called
        event_data = mock_emitters['ecar'].emit_event.call_args[0][0]
        assert event_data['object'] == 'USER_SESSION'
        assert event_data['action'] == 'LOGOUT'
        assert event_data['principal'] == 'alice.smith'


class TestLogoffLinux:
    """Test logoff event generation on Linux systems."""

    def test_logoff_emits_syslog_session_closed(self, activity_gen, test_user, linux_system, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, linux_system, timestamp)
        mock_emitters['syslog'].reset_mock()

        activity_gen.generate_logoff(test_user, linux_system, timestamp, logon_id)

        assert mock_emitters['syslog'].emit_event.called
        event_data = mock_emitters['syslog'].emit_event.call_args[0][0]
        assert 'session closed' in event_data['message']
        assert 'alice.smith' in event_data['message']

    def test_logoff_linux_does_not_emit_windows(self, activity_gen, test_user, linux_system, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, linux_system, timestamp)
        mock_emitters['windows_event_security'].reset_mock()

        activity_gen.generate_logoff(test_user, linux_system, timestamp, logon_id)

        assert not mock_emitters['windows_event_security'].emit_event.called

    def test_logoff_linux_emits_ecar_logout(self, activity_gen, test_user, linux_system, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, linux_system, timestamp)
        mock_emitters['ecar'].reset_mock()

        activity_gen.generate_logoff(test_user, linux_system, timestamp, logon_id)

        assert mock_emitters['ecar'].emit_event.called
        event_data = mock_emitters['ecar'].emit_event.call_args[0][0]
        assert event_data['action'] == 'LOGOUT'


class TestLogoffNoEcar:
    """Test logoff when eCAR is not available."""

    def test_logoff_without_ecar_emitter(self, state_manager, timestamp):
        """Logoff works when eCAR emitter is not present."""
        emitters = {'windows_event_security': Mock(), 'zeek_conn': Mock()}
        gen = ActivityGenerator(state_manager, emitters)
        user = User(username="bob", full_name="Bob", email="bob@test.com", enabled=True)
        system = System(hostname="W1", ip="10.0.0.1", os="Windows 10", type="workstation")
        state_manager.set_current_time(timestamp)

        logon_id = gen.generate_logon(user, system, timestamp)
        gen.generate_logoff(user, system, timestamp, logon_id)

        # Should not raise, 4634 should still be emitted
        assert emitters['windows_event_security'].emit_event.called
