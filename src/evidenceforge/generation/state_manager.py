"""State management for log generation.

This module provides the StateManager class for tracking runtime state during
log generation, ensuring consistency across log formats.
"""

import logging
import random
import uuid
from datetime import datetime, timedelta
from threading import RLock

from evidenceforge.events.base import SecurityEvent
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.state import (
    ActiveSession,
    GeneratorState,
    OpenConnection,
    RunningProcess,
)
from evidenceforge.utils.ids import generate_zeek_uid

logger = logging.getLogger(__name__)


class StateManager:
    """Central state manager for log generation.

    Manages runtime state including active sessions, running processes,
    open connections, and DNS cache. Ensures uniqueness guarantees and
    maintains consistency for cross-log correlation.

    Thread Safety: Phase 2.1 implements thread-safe concurrent access using
    RLock. All public methods acquire the lock to ensure atomic operations
    and prevent data races. RLock allows reentrant calls within the same thread.

    Attributes:
        state: GeneratorState containing all active entities
        _logon_id_counter: Counter for generating unique LogonIDs
        _pid_counters: Per-system PID counters dict[system_hostname, int]
        _connection_id_counter: Counter for generating unique connection IDs
        _lock: Reentrant lock for thread-safe access to state and counters

    Note: Lock hold times are typically <1ms (fast dictionary operations).
    """

    def __init__(self) -> None:
        """Initialize StateManager with empty state."""
        self.state = GeneratorState()
        self._logon_id_rng = random.Random(42)  # Deterministic RNG for LogonID generation
        self._used_logon_ids: set[int] = set()
        # Well-known LogonIDs to avoid (SYSTEM=0x3e7, LOCAL SERVICE=0x3e5, NETWORK SERVICE=0x3e4)
        self._reserved_logon_ids = {0x3E4, 0x3E5, 0x3E6, 0x3E7}
        self._pid_counters: dict[str, int] = {}  # Per-system PID counters
        self._pid_os: dict[str, str] = {}  # Per-system OS type for PID allocation
        self._connection_id_counter = 0
        self._lock = RLock()  # Reentrant lock for thread safety

    # ========================================
    # Session Management
    # ========================================

    def create_session(
        self,
        username: str,
        system: str,
        logon_type: int,
        source_ip: str,
    ) -> str:
        """Create a new active session.

        Args:
            username: Username for the session
            system: System hostname where session is active
            logon_type: Windows logon type (2=interactive, 3=network, 10=RDP, etc.)
            source_ip: Source IP address for logon

        Returns:
            Generated LogonID (hex string like "0x3e7")

        Raises:
            StateError: If current_time is not set or LogonID counter exhausted
        """
        with self._lock:
            if self.state.current_time is None:
                raise StateError("Cannot create session: current_time not set")

            # Generate high-entropy LogonID (real LSASS uses random 32-bit values)
            for _ in range(100):
                val = self._logon_id_rng.randint(0x10000, 0xFFFFFFFF)
                if val not in self._used_logon_ids and val not in self._reserved_logon_ids:
                    break
            else:
                raise StateError("LogonID generation exhausted (100 collisions)")
            self._used_logon_ids.add(val)
            logon_id = f"0x{val:x}"

            # Create session
            session = ActiveSession(
                logon_id=logon_id,
                username=username,
                system=system,
                logon_type=logon_type,
                start_time=self.state.current_time,
                source_ip=source_ip,
                ecar_object_id=str(uuid.uuid4()),
            )

            self.state.active_sessions[logon_id] = session
            logger.debug(f"Created session {logon_id} for {username}@{system}")
            return logon_id

    def get_session(self, logon_id: str) -> ActiveSession | None:
        """Get an active session by LogonID.

        Args:
            logon_id: LogonID to look up

        Returns:
            ActiveSession if found, None otherwise
        """
        with self._lock:
            return self.state.active_sessions.get(logon_id)

    def get_sessions_for_user(self, username: str) -> list[ActiveSession]:
        """Get all active sessions for a user.

        Args:
            username: Username to search for

        Returns:
            List of active sessions for the user (may be empty)
        """
        with self._lock:
            return [s for s in self.state.active_sessions.values() if s.username == username]

    def get_sessions_on_system(self, system: str) -> list[ActiveSession]:
        """Get all active sessions on a system.

        Args:
            system: System hostname to search for

        Returns:
            List of active sessions on the system (may be empty)
        """
        with self._lock:
            return [s for s in self.state.active_sessions.values() if s.system == system]

    def end_session(self, logon_id: str) -> bool:
        """End an active session.

        Args:
            logon_id: LogonID of session to end

        Returns:
            True if session was found and removed, False if not found
        """
        with self._lock:
            if logon_id in self.state.active_sessions:
                del self.state.active_sessions[logon_id]
                logger.debug(f"Ended session {logon_id}")
                return True
            return False

    def list_active_sessions(self) -> list[ActiveSession]:
        """Get all active sessions.

        Returns:
            List of all active sessions
        """
        with self._lock:
            return list(self.state.active_sessions.values())

    # ========================================
    # Process Management
    # ========================================

    def create_process(
        self,
        system: str,
        parent_pid: int,
        image: str,
        command_line: str,
        username: str,
        integrity_level: str,
    ) -> int:
        """Create a new running process.

        Args:
            system: System hostname where process runs
            parent_pid: Parent process ID (0 for system processes)
            image: Process image path (e.g., "C:\\Windows\\System32\\cmd.exe")
            command_line: Full command line with arguments
            username: User running the process
            integrity_level: Windows integrity level (System, High, Medium, Low)

        Returns:
            Allocated PID for the process

        Raises:
            StateError: If current_time not set, parent doesn't exist, or PID exhausted
        """
        with self._lock:
            if self.state.current_time is None:
                raise StateError("Cannot create process: current_time not set")

            # Validate parent exists (unless parent_pid is 0 or 4 for system processes)
            # PID 0: Idle/System Idle Process
            # PID 4: System process (Windows)
            if parent_pid not in (0, 4):
                parent_key = (system, parent_pid)
                if parent_key not in self.state.running_processes:
                    raise StateError(
                        f"Cannot create process: parent PID {parent_pid} does not exist on {system}"
                    )

            # Allocate PID for this system — OS-aware allocation (Phase 6.0)
            if system not in self._pid_counters:
                import random as _rng

                # Detect OS from image path: backslash = Windows, forward slash = Linux
                is_windows = "\\" in image
                if is_windows:
                    # Windows: PIDs are multiples of 4, start in realistic range
                    start = _rng.randint(2000, 6000)
                    start = start - (start % 4)  # Align to multiple of 4
                    self._pid_counters[system] = start
                    self._pid_os[system] = "windows"
                else:
                    # Linux: PIDs increment by 1, start after boot processes
                    self._pid_counters[system] = _rng.randint(500, 2000)
                    self._pid_os[system] = "linux"

            pid = self._pid_counters[system]

            # Increment with OS-aware gaps
            import random as _rng

            if self._pid_os.get(system) == "windows":
                # Windows: multiples of 4 with irregular gaps
                self._pid_counters[system] += 4 * _rng.choice([1, 1, 1, 1, 2, 3, 5, 8])
            else:
                # Linux: sequential with occasional small gaps
                self._pid_counters[system] += _rng.choice([1, 1, 1, 1, 2, 3])

            # Check for PID exhaustion
            if pid > 65536:
                # Wrap around to simulate PID reuse
                self._pid_counters[system] = pid % 30000 + 4000

            # Create process
            process = RunningProcess(
                pid=pid,
                parent_pid=parent_pid,
                image=image,
                command_line=command_line,
                username=username,
                system=system,
                start_time=self.state.current_time,
                integrity_level=integrity_level,
                ecar_object_id=str(uuid.uuid4()),
            )

            key = (system, pid)
            self.state.running_processes[key] = process
            logger.debug(f"Created process {pid} on {system}: {image}")
            return pid

    def get_process(self, system: str, pid: int) -> RunningProcess | None:
        """Get a running process.

        Args:
            system: System hostname
            pid: Process ID

        Returns:
            RunningProcess if found, None otherwise
        """
        with self._lock:
            key = (system, pid)
            return self.state.running_processes.get(key)

    def get_session_object_id(self, logon_id: str) -> str:
        """Get the eCAR objectID for a session."""
        with self._lock:
            session = self.state.active_sessions.get(logon_id)
            return session.ecar_object_id if session else ""

    def get_process_object_id(self, system: str, pid: int) -> str:
        """Get the eCAR objectID for a running process."""
        with self._lock:
            proc = self.state.running_processes.get((system, pid))
            return proc.ecar_object_id if proc else ""

    def get_processes_for_user(self, username: str) -> list[RunningProcess]:
        """Get all running processes for a user.

        Args:
            username: Username to search for

        Returns:
            List of running processes for the user (may be empty)
        """
        with self._lock:
            return [p for p in self.state.running_processes.values() if p.username == username]

    def get_processes_on_system(self, system: str) -> list[RunningProcess]:
        """Get all running processes on a system.

        Args:
            system: System hostname to search for

        Returns:
            List of running processes on the system (may be empty)
        """
        with self._lock:
            return [p for p in self.state.running_processes.values() if p.system == system]

    def end_process(self, system: str, pid: int) -> bool:
        """End a running process.

        Args:
            system: System hostname
            pid: Process ID

        Returns:
            True if process was found and removed, False if not found
        """
        with self._lock:
            key = (system, pid)
            if key in self.state.running_processes:
                del self.state.running_processes[key]
                logger.debug(f"Ended process {pid} on {system}")
                return True
            return False

    def list_running_processes(self) -> list[RunningProcess]:
        """Get all running processes.

        Returns:
            List of all running processes
        """
        with self._lock:
            return list(self.state.running_processes.values())

    # ========================================
    # Connection Management
    # ========================================

    def open_connection(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
    ) -> str:
        """Open a new network connection.

        Args:
            src_ip: Source IP address
            src_port: Source port number
            dst_ip: Destination IP address
            dst_port: Destination port number
            protocol: Protocol ("tcp", "udp", etc.)

        Returns:
            Generated connection ID

        Raises:
            StateError: If current_time is not set or connection ID counter exhausted
        """
        with self._lock:
            if self.state.current_time is None:
                raise StateError("Cannot open connection: current_time not set")

            # Check for counter exhaustion
            if self._connection_id_counter > 999999999:
                raise StateError("Connection ID counter exhausted")

            # Generate connection ID
            conn_id = f"conn-{self._connection_id_counter}"
            self._connection_id_counter += 1

            # Create connection with Zeek UID for cross-log correlation
            connection = OpenConnection(
                conn_id=conn_id,
                zeek_uid=generate_zeek_uid("C"),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                state="established",
                start_time=self.state.current_time,
                bytes_sent=0,
                bytes_received=0,
            )

            self.state.open_connections[conn_id] = connection
            logger.debug(
                f"Opened connection {conn_id}: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol})"
            )
            return conn_id

    def get_zeek_uid(self, conn_id: str) -> str:
        """Get the Zeek UID for a connection.

        All Zeek log types sharing the same network session use this UID
        for cross-log correlation (conn.log, dns.log, http.log, etc.).

        Args:
            conn_id: Connection ID

        Returns:
            Zeek UID string, or empty string if connection not found
        """
        with self._lock:
            conn = self.state.open_connections.get(conn_id)
            return conn.zeek_uid if conn else ""

    def get_connection(self, conn_id: str) -> OpenConnection | None:
        """Get an open connection.

        Args:
            conn_id: Connection ID to look up

        Returns:
            OpenConnection if found, None otherwise
        """
        with self._lock:
            return self.state.open_connections.get(conn_id)

    def update_connection_bytes(self, conn_id: str, bytes_sent: int, bytes_received: int) -> bool:
        """Update cumulative byte counts for a connection.

        Args:
            conn_id: Connection ID
            bytes_sent: Bytes sent (cumulative, not delta)
            bytes_received: Bytes received (cumulative, not delta)

        Returns:
            True if connection was found and updated, False if not found
        """
        with self._lock:
            conn = self.state.open_connections.get(conn_id)
            if conn:
                conn.bytes_sent = bytes_sent
                conn.bytes_received = bytes_received
                return True
            return False

    def close_connection(self, conn_id: str) -> bool:
        """Close an open connection.

        Args:
            conn_id: Connection ID to close

        Returns:
            True if connection was found and removed, False if not found
        """
        with self._lock:
            if conn_id in self.state.open_connections:
                del self.state.open_connections[conn_id]
                logger.debug(f"Closed connection {conn_id}")
                return True
            return False

    def list_open_connections(self) -> list[OpenConnection]:
        """Get all open connections.

        Returns:
            List of all open connections
        """
        with self._lock:
            return list(self.state.open_connections.values())

    # ========================================
    # DNS Management
    # ========================================

    def register_hostname(self, hostname: str, ip: str) -> None:
        """Register a hostname → IP mapping in DNS cache.

        Args:
            hostname: Hostname to register
            ip: IP address to associate with hostname

        Raises:
            StateError: If hostname already mapped to different IP
        """
        with self._lock:
            existing = self.state.dns_cache.get(hostname)
            if existing and existing != ip:
                raise StateError(f"Cannot register {hostname} → {ip}: already mapped to {existing}")

            self.state.dns_cache[hostname] = ip
            logger.debug(f"Registered DNS: {hostname} → {ip}")

    def resolve_hostname(self, hostname: str) -> str | None:
        """Resolve a hostname to IP address using DNS cache.

        Args:
            hostname: Hostname to resolve

        Returns:
            IP address if found, None otherwise
        """
        with self._lock:
            return self.state.dns_cache.get(hostname)

    def list_dns_cache(self) -> dict[str, str]:
        """Get all DNS cache entries.

        Returns:
            Dict of hostname → IP mappings
        """
        with self._lock:
            return self.state.dns_cache.copy()

    # ========================================
    # Time Management
    # ========================================

    def set_current_time(self, dt: datetime) -> None:
        """Set the current simulation time.

        Args:
            dt: New current time
        """
        with self._lock:
            self.state.current_time = dt
            logger.debug(f"Set current time to {dt}")

    def get_current_time(self) -> datetime | None:
        """Get the current simulation time.

        Returns:
            Current time, or None if not set
        """
        with self._lock:
            return self.state.current_time

    def advance_time(self, delta: timedelta) -> None:
        """Advance the current simulation time by a delta.

        Args:
            delta: Time delta to advance by

        Raises:
            StateError: If current_time is not set
        """
        with self._lock:
            if self.state.current_time is None:
                raise StateError("Cannot advance time: current_time not set")

            self.state.current_time += delta
            logger.debug(f"Advanced time by {delta} to {self.state.current_time}")

    # ========================================
    # State Queries
    # ========================================

    def get_state(self) -> GeneratorState:
        """Get the complete generator state.

        Returns:
            GeneratorState object
        """
        with self._lock:
            return self.state

    def get_state_summary(self) -> dict:
        """Get a summary of current state for logging/debugging.

        Returns:
            Dict with counts and current time
        """
        with self._lock:
            return {
                "active_sessions": len(self.state.active_sessions),
                "running_processes": len(self.state.running_processes),
                "open_connections": len(self.state.open_connections),
                "dns_cache_entries": len(self.state.dns_cache),
                "current_time": str(self.state.current_time) if self.state.current_time else None,
            }

    def apply(self, event: SecurityEvent) -> None:
        """Record state changes from a fully-constructed SecurityEvent.

        IDs (logon_id, pid, conn_id, zeek_uid) are already allocated by the
        caller via create_session(), create_process(), open_connection() before
        building the SecurityEvent. This method handles only teardown (logoff,
        process termination) and updates (connection bytes).
        """
        with self._lock:
            if event.event_type == "logoff" and event.auth:
                self.end_session(event.auth.logon_id)
            elif event.event_type == "process_terminate" and event.process and event.src_host:
                self.end_process(event.src_host.hostname, event.process.pid)
            elif event.event_type == "connection" and event.network:
                if event.network.conn_id and (event.network.orig_bytes or event.network.resp_bytes):
                    self.update_connection_bytes(
                        event.network.conn_id,
                        event.network.orig_bytes,
                        event.network.resp_bytes,
                    )
