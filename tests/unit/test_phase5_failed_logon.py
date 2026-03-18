"""Unit tests for Phase 5.2.2: Failed logon generation."""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock

from evidenceforge.formats.loader import load_format
from evidenceforge.formats.validator import validate_event
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
    return User(username="alice.smith", full_name="Alice Smith", email="a@t.com", enabled=True)


@pytest.fixture
def win_system():
    return System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")


@pytest.fixture
def linux_system():
    return System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="workstation")


@pytest.fixture
def timestamp():
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=timezone.utc)


class TestFailedLogonWindows:
    """Test failed logon event generation on Windows."""

    def test_emits_4625(self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(test_user, win_system, timestamp)

        assert mock_emitters['windows_event_security'].emit_event.called
        event_data = mock_emitters['windows_event_security'].emit_event.call_args[0][0]
        assert event_data['EventID'] == 4625
        assert event_data['TargetUserName'] == 'alice.smith'
        assert event_data['Status'] == '0xc000006d'
        # SubStatus is now varied: 0xc000006a (wrong password), 0xc0000064 (unknown user),
        # 0xc0000234 (locked out), 0xc0000072 (disabled)
        assert event_data['SubStatus'] in ('0xc000006a', '0xc0000064', '0xc0000234', '0xc0000072')

    def test_no_session_created(self, activity_gen, test_user, win_system, timestamp, state_manager):
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(test_user, win_system, timestamp)

        sessions = state_manager.get_sessions_for_user('alice.smith')
        assert len(sessions) == 0

    def test_subject_is_system(self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(test_user, win_system, timestamp)

        event_data = mock_emitters['windows_event_security'].emit_event.call_args[0][0]
        assert event_data['SubjectUserSid'] == 'S-1-5-18'


class TestFailedLogonLinux:
    """Test failed logon on Linux."""

    def test_emits_syslog_failed_password(self, activity_gen, test_user, linux_system, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(test_user, linux_system, timestamp, logon_type=3, source_ip="203.0.113.50")

        assert mock_emitters['syslog'].emit_event.called
        event_data = mock_emitters['syslog'].emit_event.call_args[0][0]
        assert 'Failed password' in event_data['message']
        assert 'alice.smith' in event_data['message']
        assert '203.0.113.50' in event_data['message']

    def test_does_not_emit_windows(self, activity_gen, test_user, linux_system, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(test_user, linux_system, timestamp)

        assert not mock_emitters['windows_event_security'].emit_event.called


class TestFailedLogonEcar:
    """Test eCAR emission for failed logon."""

    def test_emits_ecar_with_failure_reason(self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(test_user, win_system, timestamp)

        assert mock_emitters['ecar'].emit_event.called
        event_data = mock_emitters['ecar'].emit_event.call_args[0][0]
        assert event_data['object'] == 'USER_SESSION'
        assert event_data['action'] == 'LOGIN'
        assert event_data['failure_reason'] == 'bad_password'


class TestFailedLogonFormatValidation:
    """Test that 4625 events pass format validation with all fields."""

    def test_4625_with_all_fields_validates(self):
        """A 4625 event with TransmittedServices, LmPackageName, KeyLength, ProcessId, ProcessName should validate."""
        fmt_def = load_format("windows_event_security")
        event = {
            'EventID': 4625,
            'TimeCreated': '2024-03-15T10:00:00Z',
            'Computer': 'WKS-01.corp.local',
            'Channel': 'Security',
            'Level': 0,
            'EventRecordID': 1001,
            'ExecutionProcessID': 4,
            'ExecutionThreadID': 64,
            'SubjectUserSid': 'S-1-5-18',
            'SubjectUserName': '-',
            'SubjectDomainName': '-',
            'SubjectLogonId': '0x0',
            'TargetUserSid': 'S-1-0-0',
            'TargetUserName': 'alice.smith',
            'TargetDomainName': 'CORP',
            'Status': '0xc000006d',
            'SubStatus': '0xc0000064',
            'FailureReason': '%%2313',
            'LogonType': 3,
            'LogonProcessName': 'NtLmSsp',
            'AuthenticationPackageName': 'NTLM',
            'WorkstationName': 'WKS-02',
            'IpAddress': '10.0.10.2',
            'IpPort': 49152,
            'TransmittedServices': '-',
            'LmPackageName': '-',
            'KeyLength': 0,
            'ProcessId': '0x0',
            'ProcessName': '-',
        }
        result = validate_event(fmt_def, event, variant_name='failed_logon')
        assert result.valid, f"Validation errors: {result.errors}"


class TestFailedLogonRate:
    """Test that baseline activity includes ~10% failed logons."""

    def test_baseline_logon_failure_rate(self, state_manager, timestamp):
        """Over many logon attempts, ~10% should fail."""
        emitters = {'windows_event_security': Mock(), 'zeek_conn': Mock()}
        gen = ActivityGenerator(state_manager, emitters)
        user = User(username="test", full_name="Test", email="t@t.com", enabled=True)
        system = System(hostname="W1", ip="10.0.0.1", os="Windows 10", type="workstation")
        state_manager.set_current_time(timestamp)

        total = 0
        failed = 0
        for _ in range(200):
            emitters['windows_event_security'].reset_mock()
            gen.execute_baseline_activity(user, system, timestamp, 'logon')
            if emitters['windows_event_security'].emit_event.called:
                event_data = emitters['windows_event_security'].emit_event.call_args[0][0]
                total += 1
                if event_data['EventID'] == 4625:
                    failed += 1

        # Expect ~10% failure rate (allow 3-25% for statistical variation)
        assert total > 0
        failure_rate = failed / total
        assert 0.03 < failure_rate < 0.25, f"Failure rate {failure_rate:.2%} outside expected range"
