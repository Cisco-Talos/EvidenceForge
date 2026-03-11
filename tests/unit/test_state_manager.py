"""Unit tests for StateManager."""

from datetime import datetime, timedelta, timezone

import pytest

from log_generator.generation.state_manager import StateManager
from log_generator.models.exceptions import StateError


class TestStateManagerInit:
    """Tests for StateManager initialization."""

    def test_init_creates_empty_state(self):
        """Test that new StateManager has empty state."""
        sm = StateManager()
        assert len(sm.state.active_sessions) == 0
        assert len(sm.state.running_processes) == 0
        assert len(sm.state.open_connections) == 0
        assert len(sm.state.dns_cache) == 0
        assert sm.state.current_time is None

    def test_init_sets_counters(self):
        """Test that counters are initialized correctly."""
        sm = StateManager()
        assert sm._logon_id_counter == 0x3E7  # 999 in hex
        assert sm._connection_id_counter == 0
        assert len(sm._pid_counters) == 0


class TestSessionManagement:
    """Tests for session lifecycle."""

    def test_create_session(self):
        """Test creating a new session."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        logon_id = sm.create_session(
            username="jdoe",
            system="WS-01",
            logon_type=2,
            source_ip="192.168.1.50",
        )

        assert logon_id == "0x3e7"
        session = sm.get_session(logon_id)
        assert session is not None
        assert session.username == "jdoe"
        assert session.system == "WS-01"
        assert session.logon_type == 2
        assert session.source_ip == "192.168.1.50"

    def test_create_session_increments_counter(self):
        """Test that creating sessions increments LogonID counter."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        id1 = sm.create_session("user1", "WS-01", 2, "192.168.1.1")
        id2 = sm.create_session("user2", "WS-02", 3, "192.168.1.2")

        assert id1 == "0x3e7"
        assert id2 == "0x3e8"

    def test_create_session_requires_current_time(self):
        """Test that creating session fails if current_time not set."""
        sm = StateManager()

        with pytest.raises(StateError, match="current_time not set"):
            sm.create_session("jdoe", "WS-01", 2, "192.168.1.1")

    def test_get_sessions_for_user(self):
        """Test getting all sessions for a user."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        sm.create_session("jdoe", "WS-01", 2, "192.168.1.1")
        sm.create_session("jdoe", "WS-02", 3, "192.168.1.1")
        sm.create_session("asmith", "WS-03", 2, "192.168.1.2")

        jdoe_sessions = sm.get_sessions_for_user("jdoe")
        assert len(jdoe_sessions) == 2
        assert all(s.username == "jdoe" for s in jdoe_sessions)

    def test_get_sessions_on_system(self):
        """Test getting all sessions on a system."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        sm.create_session("jdoe", "WS-01", 2, "192.168.1.1")
        sm.create_session("asmith", "WS-01", 3, "192.168.1.2")
        sm.create_session("bsmith", "WS-02", 2, "192.168.1.3")

        ws01_sessions = sm.get_sessions_on_system("WS-01")
        assert len(ws01_sessions) == 2
        assert all(s.system == "WS-01" for s in ws01_sessions)

    def test_end_session(self):
        """Test ending a session."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        logon_id = sm.create_session("jdoe", "WS-01", 2, "192.168.1.1")
        assert sm.get_session(logon_id) is not None

        result = sm.end_session(logon_id)
        assert result is True
        assert sm.get_session(logon_id) is None

    def test_end_nonexistent_session(self):
        """Test ending a non-existent session returns False."""
        sm = StateManager()
        result = sm.end_session("0xnonexistent")
        assert result is False

    def test_list_active_sessions(self):
        """Test listing all active sessions."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        sm.create_session("user1", "WS-01", 2, "192.168.1.1")
        sm.create_session("user2", "WS-02", 3, "192.168.1.2")

        sessions = sm.list_active_sessions()
        assert len(sessions) == 2


class TestProcessManagement:
    """Tests for process lifecycle."""

    def test_create_process(self):
        """Test creating a new process."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        pid = sm.create_process(
            system="WS-01",
            parent_pid=0,
            image="C:\\Windows\\System32\\explorer.exe",
            command_line="explorer.exe",
            username="jdoe",
            integrity_level="Medium",
        )

        assert pid == 1  # First PID on system
        process = sm.get_process("WS-01", pid)
        assert process is not None
        assert process.system == "WS-01"
        assert process.image == "C:\\Windows\\System32\\explorer.exe"
        assert process.username == "jdoe"

    def test_create_process_increments_per_system(self):
        """Test that PIDs increment per system."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        pid1 = sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")
        pid2 = sm.create_process("WS-01", 0, "cmd.exe", "cmd.exe", "jdoe", "Medium")
        pid3 = sm.create_process("WS-02", 0, "bash", "bash", "asmith", "Medium")

        assert pid1 == 1
        assert pid2 == 2
        assert pid3 == 1  # WS-02 starts at 1

    def test_create_process_requires_current_time(self):
        """Test that creating process fails if current_time not set."""
        sm = StateManager()

        with pytest.raises(StateError, match="current_time not set"):
            sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")

    def test_create_process_validates_parent_exists(self):
        """Test that creating process fails if parent doesn't exist."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        with pytest.raises(StateError, match="parent PID .* does not exist"):
            sm.create_process(
                "WS-01", 999, "cmd.exe", "cmd.exe", "jdoe", "Medium"
            )

    def test_create_process_allows_parent_zero(self):
        """Test that parent_pid=0 is allowed (system processes)."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        pid = sm.create_process("WS-01", 0, "System", "System", "SYSTEM", "System")
        assert pid == 1

    def test_create_process_with_valid_parent(self):
        """Test creating child process with valid parent."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        parent_pid = sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")
        child_pid = sm.create_process("WS-01", parent_pid, "cmd.exe", "cmd.exe", "jdoe", "Medium")

        assert child_pid == parent_pid + 1
        child = sm.get_process("WS-01", child_pid)
        assert child.parent_pid == parent_pid

    def test_get_processes_for_user(self):
        """Test getting all processes for a user."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")
        sm.create_process("WS-01", 0, "cmd.exe", "cmd.exe", "jdoe", "Medium")
        sm.create_process("WS-01", 0, "notepad.exe", "notepad.exe", "asmith", "Medium")

        jdoe_procs = sm.get_processes_for_user("jdoe")
        assert len(jdoe_procs) == 2
        assert all(p.username == "jdoe" for p in jdoe_procs)

    def test_get_processes_on_system(self):
        """Test getting all processes on a system."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")
        sm.create_process("WS-01", 0, "cmd.exe", "cmd.exe", "asmith", "Medium")
        sm.create_process("WS-02", 0, "bash", "bash", "jdoe", "Medium")

        ws01_procs = sm.get_processes_on_system("WS-01")
        assert len(ws01_procs) == 2
        assert all(p.system == "WS-01" for p in ws01_procs)

    def test_end_process(self):
        """Test ending a process."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        pid = sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")
        assert sm.get_process("WS-01", pid) is not None

        result = sm.end_process("WS-01", pid)
        assert result is True
        assert sm.get_process("WS-01", pid) is None

    def test_end_nonexistent_process(self):
        """Test ending non-existent process returns False."""
        sm = StateManager()
        result = sm.end_process("WS-01", 999)
        assert result is False

    def test_list_running_processes(self):
        """Test listing all running processes."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")
        sm.create_process("WS-02", 0, "bash", "bash", "asmith", "Medium")

        procs = sm.list_running_processes()
        assert len(procs) == 2


class TestConnectionManagement:
    """Tests for connection lifecycle."""

    def test_open_connection(self):
        """Test opening a new connection."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        conn_id = sm.open_connection(
            src_ip="192.168.1.100",
            src_port=50000,
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol="udp",
        )

        assert conn_id == "conn-0"
        conn = sm.get_connection(conn_id)
        assert conn is not None
        assert conn.src_ip == "192.168.1.100"
        assert conn.dst_ip == "8.8.8.8"
        assert conn.protocol == "udp"
        assert conn.state == "established"

    def test_open_connection_increments_counter(self):
        """Test that connection IDs increment."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        id1 = sm.open_connection("192.168.1.1", 50000, "8.8.8.8", 53, "udp")
        id2 = sm.open_connection("192.168.1.1", 50001, "8.8.4.4", 53, "udp")

        assert id1 == "conn-0"
        assert id2 == "conn-1"

    def test_open_connection_requires_current_time(self):
        """Test that opening connection fails if current_time not set."""
        sm = StateManager()

        with pytest.raises(StateError, match="current_time not set"):
            sm.open_connection("192.168.1.1", 50000, "8.8.8.8", 53, "udp")

    def test_update_connection_bytes(self):
        """Test updating connection byte counts."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        conn_id = sm.open_connection("192.168.1.1", 50000, "8.8.8.8", 53, "udp")
        result = sm.update_connection_bytes(conn_id, 1024, 2048)

        assert result is True
        conn = sm.get_connection(conn_id)
        assert conn.bytes_sent == 1024
        assert conn.bytes_received == 2048

    def test_update_nonexistent_connection(self):
        """Test updating non-existent connection returns False."""
        sm = StateManager()
        result = sm.update_connection_bytes("conn-999", 1024, 2048)
        assert result is False

    def test_close_connection(self):
        """Test closing a connection."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        conn_id = sm.open_connection("192.168.1.1", 50000, "8.8.8.8", 53, "udp")
        assert sm.get_connection(conn_id) is not None

        result = sm.close_connection(conn_id)
        assert result is True
        assert sm.get_connection(conn_id) is None

    def test_close_nonexistent_connection(self):
        """Test closing non-existent connection returns False."""
        sm = StateManager()
        result = sm.close_connection("conn-999")
        assert result is False

    def test_list_open_connections(self):
        """Test listing all open connections."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

        sm.open_connection("192.168.1.1", 50000, "8.8.8.8", 53, "udp")
        sm.open_connection("192.168.1.2", 50001, "8.8.4.4", 53, "udp")

        conns = sm.list_open_connections()
        assert len(conns) == 2


class TestDNSManagement:
    """Tests for DNS cache."""

    def test_register_hostname(self):
        """Test registering a hostname."""
        sm = StateManager()
        sm.register_hostname("google.com", "8.8.8.8")

        ip = sm.resolve_hostname("google.com")
        assert ip == "8.8.8.8"

    def test_register_duplicate_hostname_same_ip(self):
        """Test registering same hostname with same IP is allowed."""
        sm = StateManager()
        sm.register_hostname("google.com", "8.8.8.8")
        sm.register_hostname("google.com", "8.8.8.8")  # Should not raise

        ip = sm.resolve_hostname("google.com")
        assert ip == "8.8.8.8"

    def test_register_duplicate_hostname_different_ip(self):
        """Test registering same hostname with different IP raises error."""
        sm = StateManager()
        sm.register_hostname("google.com", "8.8.8.8")

        with pytest.raises(StateError, match="already mapped to"):
            sm.register_hostname("google.com", "8.8.4.4")

    def test_resolve_nonexistent_hostname(self):
        """Test resolving non-existent hostname returns None."""
        sm = StateManager()
        ip = sm.resolve_hostname("nonexistent.com")
        assert ip is None

    def test_list_dns_cache(self):
        """Test listing all DNS cache entries."""
        sm = StateManager()
        sm.register_hostname("google.com", "8.8.8.8")
        sm.register_hostname("cloudflare.com", "1.1.1.1")

        cache = sm.list_dns_cache()
        assert len(cache) == 2
        assert cache["google.com"] == "8.8.8.8"
        assert cache["cloudflare.com"] == "1.1.1.1"


class TestTimeManagement:
    """Tests for time tracking."""

    def test_set_current_time(self):
        """Test setting current time."""
        sm = StateManager()
        dt = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        sm.set_current_time(dt)
        assert sm.get_current_time() == dt

    def test_advance_time(self):
        """Test advancing time by delta."""
        sm = StateManager()
        dt = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        sm.set_current_time(dt)

        sm.advance_time(timedelta(hours=1))
        assert sm.get_current_time() == datetime(2024, 1, 15, 11, 0, 0, tzinfo=timezone.utc)

    def test_advance_time_requires_current_time(self):
        """Test that advancing time fails if current_time not set."""
        sm = StateManager()

        with pytest.raises(StateError, match="current_time not set"):
            sm.advance_time(timedelta(hours=1))


class TestStateQueries:
    """Tests for state query methods."""

    def test_get_state(self):
        """Test getting complete state."""
        sm = StateManager()
        state = sm.get_state()
        assert state is sm.state

    def test_get_state_summary(self):
        """Test getting state summary."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc))
        sm.create_session("jdoe", "WS-01", 2, "192.168.1.1")
        sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")

        summary = sm.get_state_summary()
        assert summary["active_sessions"] == 1
        assert summary["running_processes"] == 1
        assert summary["open_connections"] == 0
        assert summary["dns_cache_entries"] == 0
        assert "2024-01-15" in summary["current_time"]
