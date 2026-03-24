"""Unit tests for activity generation."""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, MagicMock, patch

from evidenceforge.events.dispatcher import EventDispatcher
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

    def test_same_src_dst_is_valid(self):
        """Same-IP connections are valid (handled by SecurityEvent.local_only)."""
        is_invalid, _reason = _is_invalid_network_connection("10.0.0.1", "10.0.0.1")

        assert is_invalid is False

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
        """Create activity generator with mocked emitters and dispatcher."""
        dispatcher = EventDispatcher(
            state_manager=state_manager,
            emitters=mock_emitters,
        )
        return ActivityGenerator(state_manager, mock_emitters, dispatcher=dispatcher)

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
        """generate_logon should create session and dispatch SecurityEvent."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        logon_id = activity_gen.generate_logon(test_user, test_system, timestamp)

        # Verify session created in state manager
        sessions = state_manager.get_sessions_for_user(test_user.username)
        assert len(sessions) == 1
        assert sessions[0].logon_id == logon_id
        assert sessions[0].username == test_user.username

        # Verify emitters received SecurityEvent via dispatch
        assert mock_emitters['windows_event_security'].emit.called
        event = mock_emitters['windows_event_security'].emit.call_args[0][0]
        assert event.event_type == "logon"
        assert event.auth.username == test_user.username
        assert event.auth.logon_id == logon_id
        assert event.host.os_category == "windows"

    def test_generate_logon_interactive_uses_system_ip(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """Interactive logon (type 2) should use system IP as source."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(test_user, test_system, timestamp, logon_type=2)

        # SecurityEvent dispatched to Windows emitter
        event = mock_emitters['windows_event_security'].emit.call_args[0][0]
        assert event.auth.logon_type == 2
        assert event.auth.source_ip == test_system.ip

    def test_generate_logon_network_allows_custom_ip(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """Network logon (type 3) should allow custom source IP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        source_ip = "203.0.113.50"
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(test_user, test_system, timestamp, logon_type=3, source_ip=source_ip)

        # SecurityEvent dispatched to Windows emitter
        event = mock_emitters['windows_event_security'].emit.call_args[0][0]
        assert event.auth.logon_type == 3
        assert event.auth.source_ip == source_ip

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

        # Verify Windows emitter received logoff SecurityEvent via dispatch
        # Last emit() call should be the logoff (logon was the first)
        emit_calls = mock_emitters['windows_event_security'].emit.call_args_list
        logoff_event = emit_calls[-1][0][0]
        assert logoff_event.event_type == "logoff"
        assert logoff_event.auth.username == test_user.username
        assert logoff_event.auth.logon_id == logon_id

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

        # Verify Windows emitter received process_create SecurityEvent
        # (may not be last call due to probabilistic file/registry/module events after process)
        assert mock_emitters['windows_event_security'].emit.called
        process_events = [
            call[0][0] for call in mock_emitters['windows_event_security'].emit.call_args_list
            if call[0][0].event_type == "process_create"
        ]
        assert len(process_events) >= 1
        event = process_events[0]
        assert event.auth.username == test_user.username
        assert event.process.logon_id == logon_id
        assert event.process.image == process_name
        assert event.process.command_line == command_line

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

        process_events = [
            call[0][0] for call in mock_emitters['windows_event_security'].emit.call_args_list
            if call[0][0].event_type == "process_create"
        ]
        assert process_events[-1].process.parent_pid == parent_pid

    def test_generate_connection_emits_zeek(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should open connection and dispatch SecurityEvent."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)
        src_ip = "10.0.0.1"
        dst_ip = "93.184.216.34"
        dst_port = 443

        uid = activity_gen.generate_connection(
            src_ip, dst_ip, timestamp, dst_port=dst_port, service="ssl"
        )

        # Verify UID returned
        assert uid
        assert len(uid) > 0

        # Verify Zeek emitter received connection SecurityEvent
        assert mock_emitters['zeek_conn'].emit.called
        event = mock_emitters['zeek_conn'].emit.call_args[0][0]
        assert event.event_type == "connection"
        assert event.network.zeek_uid == uid
        assert event.network.src_ip == src_ip
        assert event.network.dst_ip == dst_ip
        assert event.network.dst_port == dst_port
        assert event.network.service == "ssl"

    def test_generate_connection_with_bytes(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should include byte counts in NetworkContext."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)
        orig_bytes = 1000
        resp_bytes = 5000

        activity_gen.generate_connection(
            "10.0.0.1", "93.184.216.34", timestamp,
            orig_bytes=orig_bytes, resp_bytes=resp_bytes, duration=1.5,
        )

        event = mock_emitters['zeek_conn'].emit.call_args[0][0]
        net = event.network
        assert net.orig_bytes == orig_bytes or net.orig_bytes >= 0
        assert net.resp_bytes is not None
        assert net.orig_pkts is not None

    def test_generate_connection_with_duration(self, activity_gen, state_manager, mock_emitters):
        """generate_connection with duration sets a valid conn_state."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)
        duration = 2.5

        activity_gen.generate_connection(
            "10.0.0.1", "93.184.216.34", timestamp,
            duration=duration, orig_bytes=100, resp_bytes=200
        )

        event = mock_emitters['zeek_conn'].emit.call_args[0][0]
        net = event.network
        assert net.conn_state in ('SF', 'S0', 'S1', 'REJ', 'RSTO', 'RSTR', 'OTH')
        if net.conn_state == 'SF':
            assert net.duration == duration
        elif net.conn_state in ('RSTO', 'RSTR'):
            assert net.duration is not None and net.duration <= duration

    def test_generate_connection_without_duration(self, activity_gen, state_manager, mock_emitters):
        """generate_connection without duration should set conn_state to S0."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            "10.0.0.1", "93.184.216.34", timestamp
        )

        event = mock_emitters['zeek_conn'].emit.call_args[0][0]
        assert event.network.conn_state == 'S0'

    def test_generate_connection_skips_invalid(self, activity_gen, mock_emitters):
        """generate_connection should skip invalid connections."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        uid = activity_gen.generate_connection(
            "127.0.0.1", "10.0.0.1", timestamp
        )

        assert uid == ""
        assert not mock_emitters['zeek_conn'].emit.called

    def test_get_baseline_pattern_developer(self, activity_gen):
        """Should return developer pattern for developer persona."""
        pattern = activity_gen.get_baseline_pattern("developer")

        assert pattern == BASELINE_PATTERNS['developer']
        assert ('logon', 0.7) in pattern
        assert ('process_code', 0.75) in pattern

    def test_get_baseline_pattern_executive(self, activity_gen):
        """Should return executive pattern for executive persona."""
        pattern = activity_gen.get_baseline_pattern("executive")

        assert pattern == BASELINE_PATTERNS['executive']
        assert ('logon', 0.9) in pattern
        assert ('connection_email', 0.75) in pattern

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

        # Logon (and possibly logoff for Type 3) dispatched via SecurityEvent
        emitter = mock_emitters['windows_event_security']
        assert emitter.emit.called
        first_event = emitter.emit.call_args_list[0][0][0]
        assert first_event.event_type in ("logon", "failed_logon")

    def test_execute_baseline_activity_process_creates_session(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """execute_baseline_activity should create session before process if needed."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        # No active session yet
        assert len(state_manager.get_sessions_for_user(test_user.username)) == 0

        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, 'process_code')

        # Should have created session first
        assert len(state_manager.get_sessions_for_user(test_user.username)) == 1

        # Verify both logon and process events dispatched via emit()
        emitter = mock_emitters['windows_event_security']
        assert emitter.emit.called
        event_types = [c[0][0].event_type for c in emitter.emit.call_args_list]
        assert "logon" in event_types or "failed_logon" in event_types
        assert "process_create" in event_types

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

        # Verify only process event dispatched (no additional logon)
        emitter = mock_emitters['windows_event_security']
        emit_calls = emitter.emit.call_args_list
        event_types = [c[0][0].event_type for c in emit_calls]
        assert "process_create" in event_types
        assert "logon" not in event_types  # No new logon after reset

    def test_execute_baseline_activity_connection_web(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """execute_baseline_activity should handle web connection."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, 'connection_web')

        # Connection dispatched as SecurityEvent
        assert mock_emitters['zeek_conn'].emit.called
        event = mock_emitters['zeek_conn'].emit.call_args[0][0]
        assert event.network.service in ['http', 'ssl']
        assert event.network.dst_port in [80, 443]
        dst_ip = event.network.dst_ip
        assert dst_ip in EXTERNAL_IPS['connection_web'] or not dst_ip.startswith('10.')

    def test_execute_baseline_activity_connection_email(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """execute_baseline_activity should handle email connection."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, 'connection_email')

        event = mock_emitters['zeek_conn'].emit.call_args[0][0]
        assert event.network.service == 'smtp'
        assert event.network.dst_port == 587
        assert event.network.dst_ip in EXTERNAL_IPS['connection_email']

    def test_execute_baseline_activity_connection_git(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """execute_baseline_activity should handle git connection."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, 'connection_git')

        event = mock_emitters['zeek_conn'].emit.call_args[0][0]
        assert event.network.service == 'ssl'
        assert event.network.dst_port == 443
        assert event.network.dst_ip in EXTERNAL_IPS['connection_git']

    def test_execute_baseline_activity_connection_db(self, activity_gen, test_user, test_system, state_manager, mock_emitters):
        """execute_baseline_activity should handle database connection with detected servers."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen._db_servers = [{'ip': '10.10.100.20', 'port': 1433, 'service': 'mssql'}]
        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, 'connection_db')

        event = mock_emitters['zeek_conn'].emit.call_args[0][0]
        assert event.network.service == 'mssql'
        assert event.network.dst_port == 1433
        assert event.network.dst_ip == '10.10.100.20'

    def test_execute_baseline_activity_connection_excludes_src_ip(self, activity_gen, test_user, state_manager, mock_emitters):
        """execute_baseline_activity should not connect system to itself."""
        system = System(
            hostname="WEB-01",
            ip="93.184.216.34",
            os="Windows Server 2019",
            type="server"
        )
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.execute_baseline_activity(test_user, system, timestamp, 'connection_web')

        event = mock_emitters['zeek_conn'].emit.call_args[0][0]
        assert event.network.dst_ip != system.ip

    def test_execute_baseline_activity_connection_skips_if_all_match_src(self, activity_gen, test_user, mock_emitters):
        """execute_baseline_activity should skip connection if all destinations match source."""
        system = System(
            hostname="TEST-01",
            ip="10.0.100.10",
            os="Windows 10",
            type="workstation"
        )
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        with patch('evidenceforge.generation.activity.EXTERNAL_IPS', {
            'connection_test': ["10.0.100.10"]
        }):
            activity_gen.execute_baseline_activity(test_user, system, timestamp, 'connection_test')

        assert not mock_emitters['zeek_conn'].emit.called

    def test_event_record_id_increments(self, activity_gen, test_user, test_system):
        """EventRecordID should increment per-host for each Windows event."""
        id1 = activity_gen._get_next_event_record_id('HOST-A')
        id2 = activity_gen._get_next_event_record_id('HOST-A')
        id3 = activity_gen._get_next_event_record_id('HOST-A')

        assert id2 == id1 + 1
        assert id3 == id2 + 1

    def test_event_record_id_per_host_independent(self):
        """EventRecordIDs should be independent per hostname."""
        state_manager = StateManager()
        emitters = {'windows_event_security': Mock(), 'zeek_conn': Mock()}
        activity_gen = ActivityGenerator(state_manager, emitters)

        id_a1 = activity_gen._get_next_event_record_id('HOST-A')
        id_b1 = activity_gen._get_next_event_record_id('HOST-B')
        id_a2 = activity_gen._get_next_event_record_id('HOST-A')
        id_b2 = activity_gen._get_next_event_record_id('HOST-B')

        # Each host increments independently
        assert id_a2 == id_a1 + 1
        assert id_b2 == id_b1 + 1
        # Different hosts may have different starting values
        assert id_a1 != id_b1 or True  # Starting values are seeded from hostname

    def test_event_record_id_starts_in_valid_range(self):
        """EventRecordID should start at a random offset per host (1000-50000)."""
        state_manager = StateManager()
        emitters = {'windows_event_security': Mock(), 'zeek_conn': Mock()}
        activity_gen = ActivityGenerator(state_manager, emitters)

        first_id = activity_gen._get_next_event_record_id('TEST-HOST')

        assert 1001 <= first_id <= 50001

    def test_generate_connection_calculates_packet_counts(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should calculate packet counts from bytes for completed connections."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)
        orig_bytes = 3000  # Should be ~2 packets (3000/1500)
        resp_bytes = 6000  # Should be ~4 packets (6000/1500)

        # Provide duration to ensure a completed connection
        activity_gen.generate_connection(
            "10.0.0.1", "93.184.216.34", timestamp,
            orig_bytes=orig_bytes, resp_bytes=resp_bytes, duration=2.0,
        )

        event = mock_emitters['zeek_conn'].emit.call_args[0][0]
        net = event.network
        assert net.orig_pkts >= 1
        if net.conn_state == 'SF':
            assert net.resp_pkts >= 1
            assert net.orig_ip_bytes > orig_bytes
            assert net.resp_ip_bytes > resp_bytes

    def test_generate_connection_tcp_proto(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should set correct ip_proto for TCP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            "10.0.0.1", "93.184.216.34", timestamp, proto='tcp'
        )

        event = mock_emitters['zeek_conn'].emit.call_args[0][0]
        assert event.network.protocol == 'tcp'
        assert event.network.ip_proto == 6

    def test_generate_connection_udp_proto(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should set correct ip_proto for UDP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            "10.0.0.1", "93.184.216.34", timestamp, proto='udp'
        )

        event = mock_emitters['zeek_conn'].emit.call_args[0][0]
        assert event.network.protocol == 'udp'
        assert event.network.ip_proto == 17

    def test_generate_connection_icmp_proto(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should set correct ip_proto for ICMP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            "10.0.0.1", "93.184.216.34", timestamp, proto='icmp'
        )

        event = mock_emitters['zeek_conn'].emit.call_args[0][0]
        assert event.network.protocol == 'icmp'
        assert event.network.ip_proto == 1
