"""Unit tests for Phase 5.2.2: Failed logon generation."""

from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from evidenceforge.formats.loader import load_format
from evidenceforge.formats.validator import validate_event
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
    return User(username="alice.smith", full_name="Alice Smith", email="a@t.com", enabled=True)


@pytest.fixture
def win_system():
    return System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")


@pytest.fixture
def linux_system():
    return System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="workstation")


@pytest.fixture
def timestamp():
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


class TestFailedLogonWindows:
    """Test failed logon event generation on Windows."""

    def test_emits_failed_logon(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(test_user, win_system, timestamp)

        assert mock_emitters["windows_event_security"].emit.called
        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "failed_logon"
        assert event.auth.username == "alice.smith"
        assert event.auth.failure_status == "0xc000006d"
        assert event.auth.failure_substatus in (
            "0xc000006a",
            "0xc0000064",
            "0xc0000234",
            "0xc0000072",
        )

    def test_no_session_created(
        self, activity_gen, test_user, win_system, timestamp, state_manager
    ):
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(test_user, win_system, timestamp)

        sessions = state_manager.get_sessions_for_user("alice.smith")
        assert len(sessions) == 0

    def test_subject_is_system(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(test_user, win_system, timestamp)

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.subject_sid == "S-1-5-18"


class TestFailedLogonLinux:
    """Test failed logon on Linux."""

    def test_emits_syslog_failed_password(
        self, activity_gen, test_user, linux_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(
            test_user, linux_system, timestamp, logon_type=3, source_ip="203.0.113.50"
        )

        assert mock_emitters["syslog"].emit.called
        event = mock_emitters["syslog"].emit.call_args[0][0]
        assert event.event_type == "failed_logon"
        assert event.auth.username == "alice.smith"
        assert event.auth.source_ip == "203.0.113.50"


class TestFailedLogonEcar:
    """Test eCAR emission for failed logon."""

    def test_emits_ecar_failed_logon(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(test_user, win_system, timestamp)

        assert mock_emitters["ecar"].emit.called
        event = mock_emitters["ecar"].emit.call_args[0][0]
        assert event.event_type == "failed_logon"
        assert event.auth.result == "failure"


class TestFailedLogonFormatValidation:
    """Test that 4625 events pass format validation with all fields."""

    def test_4625_with_all_fields_validates(self):
        """A 4625 event with TransmittedServices, LmPackageName, KeyLength, ProcessId, ProcessName should validate."""
        fmt_def = load_format("windows_event_security")
        event = {
            "EventID": 4625,
            "TimeCreated": "2024-03-15T10:00:00Z",
            "Computer": "WKS-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "EventRecordID": 1001,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 64,
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "-",
            "SubjectDomainName": "-",
            "SubjectLogonId": "0x0",
            "TargetUserSid": "S-1-0-0",
            "TargetUserName": "alice.smith",
            "TargetDomainName": "CORP",
            "Status": "0xc000006d",
            "SubStatus": "0xc0000064",
            "FailureReason": "%%2313",
            "LogonType": 3,
            "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM",
            "WorkstationName": "WKS-02",
            "IpAddress": "10.0.10.2",
            "IpPort": 49152,
            "TransmittedServices": "-",
            "LmPackageName": "-",
            "KeyLength": 0,
            "ProcessId": "0x0",
            "ProcessName": "-",
        }
        result = validate_event(fmt_def, event, variant_name="failed_logon")
        assert result.valid, f"Validation errors: {result.errors}"


class TestFailedLogonRate:
    """Test that baseline activity includes ~10% failed logons."""

    def test_baseline_logon_failure_rate(self, state_manager, timestamp):
        """Over many logon attempts, ~10% should fail."""
        emitters = {"windows_event_security": Mock(), "zeek_conn": Mock()}
        gen = ActivityGenerator(state_manager, emitters)
        user = User(username="test", full_name="Test", email="t@t.com", enabled=True)
        system = System(hostname="W1", ip="10.0.0.1", os="Windows 10", type="workstation")
        state_manager.set_current_time(timestamp)

        total = 0
        failed = 0
        for _ in range(200):
            emitters["windows_event_security"].reset_mock()
            gen.execute_baseline_activity(user, system, timestamp, "logon")
            emitter = emitters["windows_event_security"]
            # Both successful and failed logons now dispatched via emit()
            if emitter.emit.called:
                event = emitter.emit.call_args[0][0]
                total += 1
                if event.event_type == "failed_logon":
                    failed += 1

        # Expect ~10% failure rate (allow 3-25% for statistical variation)
        assert total > 0
        failure_rate = failed / total
        assert 0.03 < failure_rate < 0.25, f"Failure rate {failure_rate:.2%} outside expected range"


class TestFailedLogonDC:
    """Test failed logon events are also emitted on the domain controller."""

    def test_failed_logon_emits_on_dc(self, state_manager, mock_emitters, timestamp):
        """Failed logon with dc_system should emit on both workstation and DC."""
        ag = ActivityGenerator(state_manager, mock_emitters)
        state_manager.set_current_time(timestamp)

        wks = System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")
        dc = System(
            hostname="DC-01", ip="10.0.10.100", os="Windows Server 2019", type="domain_controller"
        )
        user = User(username="alice", full_name="Alice", email="a@t.com", enabled=True)

        ag.generate_failed_logon(
            user=user,
            system=wks,
            time=timestamp,
            logon_type=3,
            source_ip="10.0.10.1",
            dc_system=dc,
        )

        # Windows emitter should receive multiple events (workstation + DC)
        win_emitter = mock_emitters["windows_event_security"]
        assert win_emitter.emit.call_count >= 2

        # Collect all emitted events
        events = [call[0][0] for call in win_emitter.emit.call_args_list]
        hosts = {e.dst_host.hostname for e in events}

        # Both workstation and DC should have events
        assert "WKS-01" in hosts, "Missing 4625 on workstation"
        assert "DC-01" in hosts, "Missing 4625/4776 on DC"

    def test_failed_logon_dc_gets_4776(self, state_manager, mock_emitters, timestamp):
        """DC should receive an NTLM validation (4776) event."""
        ag = ActivityGenerator(state_manager, mock_emitters)
        state_manager.set_current_time(timestamp)

        wks = System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")
        dc = System(
            hostname="DC-01", ip="10.0.10.100", os="Windows Server 2019", type="domain_controller"
        )
        user = User(username="alice", full_name="Alice", email="a@t.com", enabled=True)

        ag.generate_failed_logon(
            user=user, system=wks, time=timestamp, source_ip="10.0.10.1", dc_system=dc
        )

        # Check for ntlm_validation event type on DC
        win_emitter = mock_emitters["windows_event_security"]
        dc_events = [
            call[0][0]
            for call in win_emitter.emit.call_args_list
            if call[0][0].dst_host.hostname == "DC-01"
        ]
        event_types = {e.event_type for e in dc_events}
        assert "ntlm_validation" in event_types, "Missing 4776 on DC"

    def test_no_dc_no_extra_events(self, state_manager, mock_emitters, timestamp):
        """Without dc_system, only workstation events are emitted."""
        ag = ActivityGenerator(state_manager, mock_emitters)
        state_manager.set_current_time(timestamp)

        wks = System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")
        user = User(username="alice", full_name="Alice", email="a@t.com", enabled=True)

        ag.generate_failed_logon(user=user, system=wks, time=timestamp, source_ip="10.0.10.1")

        win_emitter = mock_emitters["windows_event_security"]
        hosts = {call[0][0].dst_host.hostname for call in win_emitter.emit.call_args_list}
        assert hosts == {"WKS-01"}, "Should only emit on workstation without DC"
