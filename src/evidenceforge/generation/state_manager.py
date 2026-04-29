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
from evidenceforge.utils.time import ensure_utc

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
        self._logon_id_rngs: dict[str, random.Random] = {}  # Per-host LogonID RNGs
        self._used_logon_ids: set[int] = set()
        # Well-known LogonIDs to avoid (SYSTEM=0x3e7, LOCAL SERVICE=0x3e5, NETWORK SERVICE=0x3e4)
        self._reserved_logon_ids = {0x3E4, 0x3E5, 0x3E6, 0x3E7}
        self._pid_counters: dict[str, int] = {}  # Per-system PID counters
        self._pid_os: dict[str, str] = {}  # Per-system OS type for PID allocation
        self._pid_rngs: dict[str, random.Random] = {}  # Per-system PID RNGs
        self._connection_id_counter = 0
        self._linux_logind_session_counters: dict[str, int] = {}
        self._linux_logind_session_initials: dict[str, int] = {}
        self._linux_logind_session_epochs: dict[str, datetime] = {}
        self._linux_logind_session_used: dict[str, set[int]] = {}
        self._lock = RLock()  # Reentrant lock for thread safety

        # Entity lifecycle: per-system boot times for temporal validation
        self._system_boot_times: dict[str, datetime] = {}

    # ========================================
    # Session Management
    # ========================================

    def create_session(
        self,
        username: str,
        system: str,
        logon_type: int,
        source_ip: str,
        source_port: int = 0,
        session_kind: str = "logon",
        transport_pid: int | None = None,
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
            # Per-host RNG ensures different hosts produce different LogonID sequences
            if system not in self._logon_id_rngs:
                from evidenceforge.utils.rng import _stable_seed

                self._logon_id_rngs[system] = random.Random(_stable_seed(f"logon_ids_{system}"))
            host_rng = self._logon_id_rngs[system]
            for _ in range(100):
                val = host_rng.randint(0x10000, 0xFFFFFFFF)
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
                start_time=ensure_utc(self.state.current_time),
                source_ip=source_ip,
                source_port=source_port,
                session_kind=session_kind,
                transport_pid=transport_pid,
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

    def register_session(
        self,
        logon_id: str,
        username: str,
        system: str,
        logon_type: int,
        source_ip: str,
        start_time: datetime,
        source_port: int = 0,
        session_kind: str = "logon",
        transport_pid: int | None = None,
    ) -> ActiveSession:
        """Register a pre-existing session in state.

        This is primarily used by compatibility paths where a mocked or
        external generator returns a LogonID without recording the session
        through ``create_session()``.
        """
        with self._lock:
            existing = self.state.active_sessions.get(logon_id)
            if existing is not None:
                return existing

            session = ActiveSession(
                logon_id=logon_id,
                username=username,
                system=system,
                logon_type=logon_type,
                start_time=ensure_utc(start_time),
                source_ip=source_ip,
                source_port=source_port,
                session_kind=session_kind,
                transport_pid=transport_pid,
                ecar_object_id=str(uuid.uuid4()),
            )
            self.state.active_sessions[logon_id] = session
            logger.debug("Registered external session %s for %s@%s", logon_id, username, system)
            return session

    def update_session_metadata(
        self,
        logon_id: str,
        *,
        source_port: int | None = None,
        session_kind: str | None = None,
        transport_pid: int | None = None,
    ) -> bool:
        """Update mutable metadata on an existing session."""
        with self._lock:
            session = self.state.active_sessions.get(logon_id)
            if session is None:
                return False
            if source_port is not None:
                session.source_port = source_port
            if session_kind is not None:
                session.session_kind = session_kind
            if transport_pid is not None:
                session.transport_pid = transport_pid
            return True

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

    def next_linux_logind_session_id(
        self,
        system: str,
        rng: random.Random,
        event_time: datetime | None = None,
    ) -> int:
        """Return the next monotonic systemd-logind session ID for a host.

        Linux syslog can be produced by multiple generation paths. Keeping the
        counter in StateManager prevents split-brain session sequences when
        baseline noise and explicit SSH/logon events both emit logind messages.
        """
        with self._lock:
            if event_time is not None:
                normalized_time = ensure_utc(event_time)
                initial = self._linux_logind_session_initials.setdefault(
                    system,
                    rng.randint(20, 250),
                )
                epoch = self._system_boot_times.get(system)
                if epoch is None:
                    epoch = self._linux_logind_session_epochs.setdefault(
                        system,
                        normalized_time,
                    )
                elapsed_seconds = max(0, int((normalized_time - ensure_utc(epoch)).total_seconds()))
                candidate = initial + elapsed_seconds
                used = self._linux_logind_session_used.setdefault(system, set())
                while candidate in used:
                    candidate += 1
                used.add(candidate)
                return candidate

            if system not in self._linux_logind_session_counters:
                self._linux_logind_session_counters[system] = rng.randint(20, 250)
            self._linux_logind_session_counters[system] += rng.randint(1, 4)
            return self._linux_logind_session_counters[system]

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
        logon_id: str = "",
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
                from evidenceforge.utils.rng import _stable_seed

                self._pid_rngs[system] = random.Random(_stable_seed(f"pid_alloc_{system}"))
                pid_rng = self._pid_rngs[system]
                # Detect OS from image path: backslash = Windows, forward slash = Linux
                is_windows = "\\" in image
                if is_windows:
                    # Windows: PIDs are multiples of 4, start in realistic range
                    start = pid_rng.randint(2000, 6000)
                    start = start - (start % 4)  # Align to multiple of 4
                    self._pid_counters[system] = start
                    self._pid_os[system] = "windows"
                else:
                    # Linux: PIDs increment by 1, start after boot processes
                    self._pid_counters[system] = pid_rng.randint(500, 2000)
                    self._pid_os[system] = "linux"

            pid = self._pid_counters[system]

            # Increment with OS-aware gaps
            if system not in self._pid_rngs:
                from evidenceforge.utils.rng import _stable_seed

                self._pid_rngs[system] = random.Random(_stable_seed(f"pid_alloc_{system}"))
            pid_rng = self._pid_rngs[system]
            if self._pid_os.get(system) == "windows":
                # Windows: multiples of 4 with lognormal gap distribution.
                # Lognormal produces mostly small gaps (4-20) with a heavy tail
                # (occasionally 100-800+) simulating background process churn
                # that consumes PIDs between our emitted events.
                gap = max(1, int(pid_rng.lognormvariate(1.2, 0.8)))
                self._pid_counters[system] += 4 * gap
            else:
                # Linux: lognormal with smaller parameters — mostly +1 with
                # occasional larger jumps from background daemon activity.
                gap = max(1, int(pid_rng.lognormvariate(0.5, 0.6)))
                self._pid_counters[system] += gap

            # Check for PID exhaustion — wrap around to a safe range,
            # skipping any PIDs still in use by running processes.
            if self._pid_counters[system] > 65536:
                base = 4000 if self._pid_os.get(system) == "windows" else 500
                self._pid_counters[system] = base
                # Skip past any PIDs still held by running processes
                running = {
                    p.pid for (s, _), p in self.state.running_processes.items() if s == system
                }
                while self._pid_counters[system] in running:
                    if self._pid_os.get(system) == "windows":
                        self._pid_counters[system] += 4
                    else:
                        self._pid_counters[system] += 1

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
                logon_id=logon_id,
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

    def mark_story_process(self, system: str, pid: int) -> None:
        """Mark a process as created by a storyline event.

        Story-created processes handle their own termination and should
        be skipped by baseline's _terminate_stale_processes().

        Args:
            system: System hostname
            pid: Process ID
        """
        with self._lock:
            proc = self.state.running_processes.get((system, pid))
            if proc:
                proc.story_created = True

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
        source_system: str = "",
        source_hostname: str = "",
        hostname: str = "",
        initiating_pid: int = -1,
        close_time: datetime | None = None,
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
                source_system=source_system,
                source_hostname=source_hostname,
                hostname=hostname,
                initiating_pid=initiating_pid,
                close_time=close_time,
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

    _TERMINAL_CONN_STATES = frozenset({"closed", "S0", "REJ", "S1", "SH", "SHR", "RSTO", "RSTR"})

    def sweep_closed_connections(self) -> int:
        """Evict completed/failed connections to bound memory growth.

        Call between generation phases (e.g., between hourly passes).
        Returns the number of connections evicted.
        """
        with self._lock:
            to_remove = [
                cid
                for cid, conn in self.state.open_connections.items()
                if conn.state in self._TERMINAL_CONN_STATES
            ]
            for cid in to_remove:
                del self.state.open_connections[cid]
            return len(to_remove)

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

    # ========================================
    # Entity Lifecycle Validation
    # ========================================

    def register_boot_time(self, system: str, boot_time: datetime) -> None:
        """Register a system's boot time for temporal validation.

        Called during process tree seeding. Events with timestamps before
        boot_time will generate warnings.
        """
        with self._lock:
            self._system_boot_times[system] = boot_time

    def get_boot_time(self, system: str) -> datetime | None:
        """Get a system's registered boot time."""
        with self._lock:
            return self._system_boot_times.get(system)

    def validate_event_time(self, system: str, event_time: datetime) -> bool:
        """Check if an event timestamp is after the system's boot time.

        Returns True if valid (or no boot time registered). Logs a warning
        if the event precedes boot time.
        """
        with self._lock:
            boot = self._system_boot_times.get(system)
            if boot is not None and event_time < boot:
                logger.warning(
                    "Event at %s precedes boot time %s on %s",
                    event_time,
                    boot,
                    system,
                )
                return False
            return True

    def validate_target_pid(self, system: str, pid: int) -> bool:
        """Check if a target PID exists as a running process.

        Used by process_access and create_remote_thread to validate
        that the target process actually exists. Logs a warning if not.

        Returns True if the PID exists (or is a well-known system PID).
        """
        with self._lock:
            # PIDs 0 (idle) and 4 (System) always exist on Windows
            if pid in (0, 4):
                return True
            exists = (system, pid) in self.state.running_processes
            if not exists:
                logger.warning(
                    "Target PID %d not found as running process on %s",
                    pid,
                    system,
                )
            return exists

    # ========================================
    # Event Application
    # ========================================

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
                if event.network.conn_id:
                    conn = self.state.open_connections.get(event.network.conn_id)
                    if conn is not None:
                        if event.network.orig_bytes is not None:
                            conn.bytes_sent = event.network.orig_bytes
                        if event.network.resp_bytes is not None:
                            conn.bytes_received = event.network.resp_bytes
                        conn.initiating_pid = event.network.initiating_pid
                        if event.src_host is not None:
                            conn.source_system = event.src_host.hostname
                            conn.source_hostname = event.src_host.fqdn or event.src_host.hostname
                        if event.http is not None and event.http.host:
                            conn.hostname = event.http.host
                        if event.ssl is not None and event.ssl.server_name:
                            conn.hostname = event.ssl.server_name
                        if event.network.duration is not None:
                            conn.close_time = event.timestamp + timedelta(
                                seconds=event.network.duration
                            )
                            conn.state = "closed"
                        elif event.network.conn_state:
                            conn.state = event.network.conn_state
