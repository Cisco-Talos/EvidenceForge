"""Unit tests for Phase 5.2.3: Process termination events."""

import pytest
from datetime import datetime, timezone
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
        'ecar': Mock(),
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
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=timezone.utc)


class TestProcessTermination:
    """Test process termination event generation."""

    def test_emits_4689(self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)
        pid = activity_gen.generate_process(
            test_user, win_system, timestamp, logon_id,
            'C:\\Windows\\System32\\cmd.exe', 'cmd.exe /c dir'
        )
        mock_emitters['windows_event_security'].reset_mock()

        activity_gen.generate_process_termination(
            test_user, win_system, timestamp, pid,
            'C:\\Windows\\System32\\cmd.exe', logon_id
        )

        assert mock_emitters['windows_event_security'].emit_event.called
        event_data = mock_emitters['windows_event_security'].emit_event.call_args[0][0]
        assert event_data['EventID'] == 4689
        assert event_data['ProcessId'] == f'0x{pid:x}'
        assert event_data['ProcessName'] == 'C:\\Windows\\System32\\cmd.exe'
        assert event_data['Status'] == '0x0'

    def test_removes_process_from_state(self, activity_gen, test_user, win_system, timestamp, state_manager):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)
        pid = activity_gen.generate_process(
            test_user, win_system, timestamp, logon_id,
            'C:\\Windows\\System32\\cmd.exe', 'cmd.exe /c dir'
        )

        assert state_manager.get_process(win_system.hostname, pid) is not None
        activity_gen.generate_process_termination(
            test_user, win_system, timestamp, pid,
            'C:\\Windows\\System32\\cmd.exe', logon_id
        )
        assert state_manager.get_process(win_system.hostname, pid) is None

    def test_emits_ecar_terminate(self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)
        pid = activity_gen.generate_process(
            test_user, win_system, timestamp, logon_id,
            'C:\\Windows\\System32\\cmd.exe', 'cmd.exe /c dir'
        )
        mock_emitters['ecar'].reset_mock()

        activity_gen.generate_process_termination(
            test_user, win_system, timestamp, pid,
            'C:\\Windows\\System32\\cmd.exe', logon_id
        )

        # Find the TERMINATE call (filter out CREATE calls)
        terminate_calls = [
            c for c in mock_emitters['ecar'].emit_event.call_args_list
            if c[0][0].get('action') == 'TERMINATE'
        ]
        assert len(terminate_calls) == 1
        event_data = terminate_calls[0][0][0]
        assert event_data['object'] == 'PROCESS'
        assert event_data['action'] == 'TERMINATE'
        assert event_data['pid'] == pid

    def test_has_subject_sid(self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters):
        sid_registry = {'alice.smith': 'S-1-5-21-123-456-789-1001'}
        gen = ActivityGenerator(state_manager, mock_emitters, sid_registry=sid_registry)
        state_manager.set_current_time(timestamp)
        logon_id = gen.generate_logon(test_user, win_system, timestamp)
        pid = gen.generate_process(
            test_user, win_system, timestamp, logon_id,
            'C:\\Windows\\System32\\cmd.exe', 'cmd.exe /c dir'
        )
        mock_emitters['windows_event_security'].reset_mock()

        gen.generate_process_termination(
            test_user, win_system, timestamp, pid,
            'C:\\Windows\\System32\\cmd.exe', logon_id
        )

        event_data = mock_emitters['windows_event_security'].emit_event.call_args[0][0]
        assert event_data['SubjectUserSid'] == 'S-1-5-21-123-456-789-1001'
