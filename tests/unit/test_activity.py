"""Unit tests for activity generation."""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, MagicMock, patch

from evidenceforge.generation.activity import (
    ActivityGenerator,
    _is_invalid_network_connection,
    BASELINE_PATTERNS,
    PROCESS_TEMPLATES,
    EXTERNAL_IPS
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import User, System


class TestNetworkValidation:
    """Tests for network connection validation."""

    def test_invalid_same_src_dst(self):
        """Connection with same source and destination should be invalid."""
        is_invalid, reason = _is_invalid_network_connection("10.0.0.1", "10.0.0.1")

        assert is_invalid is True
        assert "identical" in reason.lower()

    def test_invalid_localhost_src(self):
        """Connection with localhost source should be invalid."""
        is_invalid, reason = _is_invalid_network_connection("127.0.0.1", "10.0.0.1")

        assert is_invalid is True
        assert "localhost" in reason.lower()

    def test_invalid_localhost_dst(self):
        """Connection with localhost destination should be invalid."""
        is_invalid, reason = _is_invalid_network_connection("10.0.0.1", "127.0.0.5")

        assert is_invalid is True
        assert "localhost" in reason.lower()

    def test_invalid_link_local(self):
        """Connection with link-local address should be invalid."""
        is_invalid, reason = _is_invalid_network_connection("169.254.1.1", "10.0.0.1")

        assert is_invalid is True
        assert "link-local" in reason.lower()

    def test_invalid_multicast(self):
        """Connection with multicast address should be invalid."""
        is_invalid, reason = _is_invalid_network_connection("224.0.0.1", "10.0.0.1")

        assert is_invalid is True
        assert "multicast" in reason.lower() or "reserved" in reason.lower()

    def test_valid_connection(self):
        """Valid connection should pass validation."""
        is_invalid, reason = _is_invalid_network_connection("10.0.0.1", "93.184.216.34")

        assert is_invalid is False
        assert reason == ""


class TestActivityGenerator:
    """Tests for ActivityGenerator class."""

    @pytest.fixture
    def state_manager(self):
        """Create state manager for testing."""
        return StateManager()

    @pytest.fixture
    def mock_emitters(self):
        """Create mock emitters."""
        windows_emitter = Mock()
        zeek_emitter = Mock()
        return {
            'windows_event_security': windows_emitter,
            'zeek_conn': zeek_emitter
        }

    @pytest.fixture
    def activity_gen(self, state_manager, mock_emitters):
        """Create activity generator with mocked emitters."""
        return ActivityGenerator(state_manager, mock_emitters)

    @pytest.fixture
    def test_user(self):
        """Create test user."""
        return User(
            username="testuser",
            full_name="Test User",
            email="test@example.com",
            enabled=True
        )

    @pytest.fixture
    def test_system(self):
        """Create test system."""
        return System(
            hostname="TEST-01",
            ip="10.0.0.1",
            os="Windows 10",
            type="workstation"
        )

    def test_generate_logon_creates_session(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """generate_logon should create session and emit Windows 4624."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        logon_id = activity_gen.generate_logon(test_user, test_system, timestamp)

        # Verify session created in state manager
        sessions = state_manager.get_sessions_for_user(test_user.username)
        assert len(sessions) == 1
        assert sessions[0].logon_id == logon_id
        assert sessions[0].username == test_user.username

        # Verify Windows emitter received 4624 event
        assert mock_emitters['windows_event_security'].emit_event.called
        event_data = mock_emitters['windows_event_security'].emit_event.call_args[0][0]
        assert event_data['EventID'] == 4624
        assert event_data['TargetUserName'] == test_user.username
        assert event_data['TargetLogonId'] == logon_id

    def test_generate_logon_interactive_uses_system_ip(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """Interactive logon (type 2) should use system IP as source."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(test_user, test_system, timestamp, logon_type=2)

        event_data = mock_emitters['windows_event_security'].emit_event.call_args[0][0]
        assert event_data['LogonType'] == 2
        assert event_data['IpAddress'] == test_system.ip

    def test_generate_logon_network_allows_custom_ip(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """Network logon (type 3) should allow custom source IP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        source_ip = "203.0.113.50"
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(test_user, test_system, timestamp, logon_type=3, source_ip=source_ip)

        event_data = mock_emitters['windows_event_security'].emit_event.call_args[0][0]
        assert event_data['LogonType'] == 3
        assert event_data['IpAddress'] == source_ip

    def test_generate_logoff_ends_session(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """generate_logoff should end session and emit Windows 4634."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        # First create a session
        logon_id = activity_gen.generate_logon(test_user, test_system, timestamp)
        assert len(state_manager.get_sessions_for_user(test_user.username)) == 1

        # Then log off
        activity_gen.generate_logoff(test_user, test_system, timestamp, logon_id)

        # Verify session ended
        assert len(state_manager.get_sessions_for_user(test_user.username)) == 0

        # Verify Windows emitter received 4634 event
        logoff_call = mock_emitters['windows_event_security'].emit_event.call_args_list[-1]
        event_data = logoff_call[0][0]
        assert event_data['EventID'] == 4634
        assert event_data['TargetUserName'] == test_user.username
        assert event_data['TargetLogonId'] == logon_id

    def test_generate_process_creates_process(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """generate_process should create process and emit Windows 4688."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)
        logon_id = "0x12345"
        process_name = "C:\\Windows\\System32\\cmd.exe"
        command_line = "cmd.exe /c dir"

        pid = activity_gen.generate_process(
            test_user, test_system, timestamp, logon_id, process_name, command_line
        )

        # Verify process created with unique PID
        assert isinstance(pid, int)
        assert pid > 0

        # Verify Windows emitter received 4688 event
        assert mock_emitters['windows_event_security'].emit_event.called
        event_data = mock_emitters['windows_event_security'].emit_event.call_args[0][0]
        assert event_data['EventID'] == 4688
        assert event_data['SubjectUserName'] == test_user.username
        assert event_data['SubjectLogonId'] == logon_id
        assert event_data['NewProcessName'] == process_name
        assert event_data['CommandLine'] == command_line

    def test_generate_process_with_parent_pid(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """generate_process should accept parent PID."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)
        logon_id = "0x12345"

        # First create parent process to ensure it exists
        parent_pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,  # System process as grandparent
            image="explorer.exe",
            command_line="C:\\Windows\\explorer.exe",
            username=test_user.username,
            integrity_level='Medium'
        )

        activity_gen.generate_process(
            test_user, test_system, timestamp, logon_id,
            "notepad.exe", "notepad.exe", parent_pid=parent_pid
        )

        event_data = mock_emitters['windows_event_security'].emit_event.call_args[0][0]
        assert event_data['ProcessId'] == f'0x{parent_pid:x}'

    def test_generate_connection_emits_zeek(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should open connection and emit Zeek conn.log."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)
        src_ip = "10.0.0.1"
        dst_ip = "93.184.216.34"
        dst_port = 443

        uid = activity_gen.generate_connection(
            src_ip, dst_ip, timestamp, dst_port=dst_port, service="https"
        )

        # Verify UID returned
        assert uid
        assert len(uid) > 0

        # Verify Zeek emitter received conn.log event
        assert mock_emitters['zeek_conn'].emit_event.called
        event_data = mock_emitters['zeek_conn'].emit_event.call_args[0][0]
        assert event_data['uid'] == uid
        assert event_data['id.orig_h'] == src_ip
        assert event_data['id.resp_h'] == dst_ip
        assert event_data['id.resp_p'] == dst_port
        assert event_data['service'] == "https"

    def test_generate_connection_with_bytes(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should include byte counts."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)
        orig_bytes = 1000
        resp_bytes = 5000

        activity_gen.generate_connection(
            "10.0.0.1", "93.184.216.34", timestamp,
            orig_bytes=orig_bytes, resp_bytes=resp_bytes
        )

        event_data = mock_emitters['zeek_conn'].emit_event.call_args[0][0]
        assert event_data['orig_bytes'] == orig_bytes
        assert event_data['resp_bytes'] == resp_bytes
        assert event_data['orig_pkts'] is not None
        assert event_data['resp_pkts'] is not None

    def test_generate_connection_with_duration(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should include duration and set conn_state."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)
        duration = 2.5

        activity_gen.generate_connection(
            "10.0.0.1", "93.184.216.34", timestamp,
            duration=duration, orig_bytes=100, resp_bytes=200
        )

        event_data = mock_emitters['zeek_conn'].emit_event.call_args[0][0]
        assert event_data['duration'] == duration
        assert event_data['conn_state'] == 'SF'  # Normal termination

    def test_generate_connection_without_duration(self, activity_gen, state_manager, mock_emitters):
        """generate_connection without duration should set conn_state to S0."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            "10.0.0.1", "93.184.216.34", timestamp
        )

        event_data = mock_emitters['zeek_conn'].emit_event.call_args[0][0]
        assert event_data['conn_state'] == 'S0'  # Connection attempt, no reply

    def test_generate_connection_skips_invalid(self, activity_gen, mock_emitters):
        """generate_connection should skip invalid connections."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        # Try to create connection to same IP (localhost)
        uid = activity_gen.generate_connection(
            "127.0.0.1", "10.0.0.1", timestamp
        )

        # Should return empty UID
        assert uid == ""

        # Zeek emitter should NOT be called
        assert not mock_emitters['zeek_conn'].emit_event.called

    def test_get_baseline_pattern_developer(self, activity_gen):
        """Should return developer pattern for developer persona."""
        pattern = activity_gen.get_baseline_pattern("developer")

        assert pattern == BASELINE_PATTERNS['developer']
        assert ('logon', 0.8) in pattern
        assert ('process_code', 0.6) in pattern

    def test_get_baseline_pattern_executive(self, activity_gen):
        """Should return executive pattern for executive persona."""
        pattern = activity_gen.get_baseline_pattern("executive")

        assert pattern == BASELINE_PATTERNS['executive']
        assert ('logon', 0.9) in pattern
        assert ('connection_email', 0.6) in pattern

    def test_get_baseline_pattern_case_insensitive(self, activity_gen):
        """Persona name should be case-insensitive."""
        pattern1 = activity_gen.get_baseline_pattern("Developer")
        pattern2 = activity_gen.get_baseline_pattern("DEVELOPER")

        assert pattern1 == pattern2 == BASELINE_PATTERNS['developer']

    def test_get_baseline_pattern_default(self, activity_gen):
        """Should return default pattern for unknown persona."""
        pattern = activity_gen.get_baseline_pattern("unknown_persona")

        assert pattern == BASELINE_PATTERNS['default']

    def test_get_baseline_pattern_none(self, activity_gen):
        """Should return default pattern for None persona."""
        pattern = activity_gen.get_baseline_pattern(None)

        assert pattern == BASELINE_PATTERNS['default']

    def test_execute_baseline_activity_logon(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """execute_baseline_activity should handle logon activity."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, 'logon')

        # Verify Windows emitter received 4624 event
        assert mock_emitters['windows_event_security'].emit_event.called
        event_data = mock_emitters['windows_event_security'].emit_event.call_args[0][0]
        assert event_data['EventID'] == 4624

    def test_execute_baseline_activity_process_creates_session(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """execute_baseline_activity should create session before process if needed."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        # No active session yet
        assert len(state_manager.get_sessions_for_user(test_user.username)) == 0

        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, 'process_code')

        # Should have created session first
        assert len(state_manager.get_sessions_for_user(test_user.username)) == 1

        # Verify both logon (4624) and process (4688) events emitted
        calls = mock_emitters['windows_event_security'].emit_event.call_args_list
        event_ids = [call[0][0]['EventID'] for call in calls]
        assert 4624 in event_ids  # Logon
        assert 4688 in event_ids  # Process

    def test_execute_baseline_activity_process_uses_existing_session(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """execute_baseline_activity should use existing session for process."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        # Create session first
        logon_id = activity_gen.generate_logon(test_user, test_system, timestamp)
        mock_emitters['windows_event_security'].reset_mock()

        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, 'process_code')

        # Should NOT have created another session
        assert len(state_manager.get_sessions_for_user(test_user.username)) == 1

        # Verify only process event emitted (no additional logon)
        calls = mock_emitters['windows_event_security'].emit_event.call_args_list
        assert len(calls) == 1
        assert calls[0][0][0]['EventID'] == 4688

    def test_execute_baseline_activity_connection_web(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """execute_baseline_activity should handle web connection."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, 'connection_web')

        # Verify Zeek emitter called
        assert mock_emitters['zeek_conn'].emit_event.called
        event_data = mock_emitters['zeek_conn'].emit_event.call_args[0][0]
        assert event_data['service'] in ['http', 'https']
        assert event_data['id.resp_p'] in [80, 443]
        assert event_data['id.resp_h'] in EXTERNAL_IPS['connection_web']

    def test_execute_baseline_activity_connection_email(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """execute_baseline_activity should handle email connection."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, 'connection_email')

        event_data = mock_emitters['zeek_conn'].emit_event.call_args[0][0]
        assert event_data['service'] == 'smtp'
        assert event_data['id.resp_p'] == 587
        assert event_data['id.resp_h'] in EXTERNAL_IPS['connection_email']

    def test_execute_baseline_activity_connection_git(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """execute_baseline_activity should handle git connection."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, 'connection_git')

        event_data = mock_emitters['zeek_conn'].emit_event.call_args[0][0]
        assert event_data['service'] == 'https'
        assert event_data['id.resp_p'] == 443
        assert event_data['id.resp_h'] in EXTERNAL_IPS['connection_git']

    def test_execute_baseline_activity_connection_db(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """execute_baseline_activity should handle database connection."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, 'connection_db')

        event_data = mock_emitters['zeek_conn'].emit_event.call_args[0][0]
        assert event_data['service'] == 'mysql'
        assert event_data['id.resp_p'] == 3306
        assert event_data['id.resp_h'] in EXTERNAL_IPS['connection_db']

    def test_execute_baseline_activity_connection_excludes_src_ip(self, activity_gen, test_user, state_manager, mock_emitters):
        """execute_baseline_activity should not connect system to itself."""
        # Create system with IP matching one of the external IPs
        system = System(
            hostname="WEB-01",
            ip="93.184.216.34",  # Matches connection_web IP
            os="Windows Server 2019",
            type="server"
        )
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.execute_baseline_activity(test_user, system, timestamp, 'connection_web')

        # Should have chosen different IP
        event_data = mock_emitters['zeek_conn'].emit_event.call_args[0][0]
        assert event_data['id.resp_h'] != system.ip

    def test_execute_baseline_activity_connection_skips_if_all_match_src(self, activity_gen, test_user, mock_emitters):
        """execute_baseline_activity should skip connection if all destinations match source."""
        # Create system with IP that would match all destinations (hypothetical)
        system = System(
            hostname="TEST-01",
            ip="10.0.100.10",  # Matches connection_db IP
            os="Windows 10",
            type="workstation"
        )
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        # Mock EXTERNAL_IPS to have only one IP that matches source
        with patch('evidenceforge.generation.activity.EXTERNAL_IPS', {
            'connection_test': ["10.0.100.10"]  # Only IP matches source
        }):
            activity_gen.execute_baseline_activity(test_user, system, timestamp, 'connection_test')

        # Should NOT have called Zeek emitter
        assert not mock_emitters['zeek_conn'].emit_event.called

    def test_event_record_id_increments(self, activity_gen, test_user, test_system):
        """EventRecordID should increment for each Windows event."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        id1 = activity_gen._get_next_event_record_id()
        id2 = activity_gen._get_next_event_record_id()
        id3 = activity_gen._get_next_event_record_id()

        assert id2 == id1 + 1
        assert id3 == id2 + 1

    def test_event_record_id_starts_at_initial_value(self):
        """EventRecordID should start at specified initial value."""
        state_manager = StateManager()
        emitters = {'windows_event_security': Mock(), 'zeek_conn': Mock()}
        activity_gen = ActivityGenerator(state_manager, emitters, event_record_counter=50000)

        first_id = activity_gen._get_next_event_record_id()

        assert first_id == 50001

    def test_generate_connection_calculates_packet_counts(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should calculate packet counts from bytes."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)
        orig_bytes = 3000  # Should be ~2 packets (3000/1500)
        resp_bytes = 6000  # Should be ~4 packets (6000/1500)

        activity_gen.generate_connection(
            "10.0.0.1", "93.184.216.34", timestamp,
            orig_bytes=orig_bytes, resp_bytes=resp_bytes
        )

        event_data = mock_emitters['zeek_conn'].emit_event.call_args[0][0]
        assert event_data['orig_pkts'] >= 1
        assert event_data['resp_pkts'] >= 1
        # IP bytes should be application bytes + overhead
        assert event_data['orig_ip_bytes'] > orig_bytes
        assert event_data['resp_ip_bytes'] > resp_bytes

    def test_generate_connection_tcp_proto(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should set correct ip_proto for TCP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            "10.0.0.1", "93.184.216.34", timestamp, proto='tcp'
        )

        event_data = mock_emitters['zeek_conn'].emit_event.call_args[0][0]
        assert event_data['proto'] == 'tcp'
        assert event_data['ip_proto'] == 6

    def test_generate_connection_udp_proto(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should set correct ip_proto for UDP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            "10.0.0.1", "93.184.216.34", timestamp, proto='udp'
        )

        event_data = mock_emitters['zeek_conn'].emit_event.call_args[0][0]
        assert event_data['proto'] == 'udp'
        assert event_data['ip_proto'] == 17

    def test_generate_connection_icmp_proto(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should set correct ip_proto for ICMP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            "10.0.0.1", "93.184.216.34", timestamp, proto='icmp'
        )

        event_data = mock_emitters['zeek_conn'].emit_event.call_args[0][0]
        assert event_data['proto'] == 'icmp'
        assert event_data['ip_proto'] == 1
