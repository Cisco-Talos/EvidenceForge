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

import hashlib
import logging
import random
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
from evidenceforge.utils.rng import _stable_seed, stable_uuid
from evidenceforge.utils.time import ensure_utc

logger = logging.getLogger(__name__)

_MIN_GENERATED_LOGON_LUID = 0x10000
_MAX_GENERATED_LOGON_LUID = 0xFFFFFFFF
_GENERATED_LOGON_LUID_SPAN = _MAX_GENERATED_LOGON_LUID - _MIN_GENERATED_LOGON_LUID + 1
_HOST_LOGON_BUCKET_SPACE = 0x01000000
_HOST_LOGON_BUCKET_STEP = 131071


def _normalize_generated_logon_luid(value: int) -> int:
    """Keep generated Windows LogonIDs in the ordinary rendered LUID range."""
    return _MIN_GENERATED_LOGON_LUID + (
        (value - _MIN_GENERATED_LOGON_LUID) % _GENERATED_LOGON_LUID_SPAN
    )


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
        _logon_id_host_bases: Per-host base ranges for Windows LogonID/LUID allocation
        _pid_counters: Per-system PID counters dict[system_hostname, int]
        _connection_id_counter: Counter for generating unique connection IDs
        _lock: Reentrant lock for thread-safe access to state and counters

    Note: Lock hold times are typically <1ms (fast dictionary operations).
    """

    def __init__(self) -> None:
        """Initialize StateManager with empty state."""
        self.state = GeneratorState()
        self._logon_id_host_bases: dict[str, int] = {}
        self._logon_id_used_host_bases: set[int] = set()
        self._logon_id_epochs: dict[str, datetime] = {}
        self._logon_id_second_ordinals: dict[tuple[str, int, int], int] = {}
        self._logon_id_block_offsets: dict[str, dict[int, int]] = {}
        self._used_logon_ids: set[int] = set()
        self._logon_id_aliases: dict[str, str] = {}
        # Well-known LogonIDs to avoid (SYSTEM=0x3e7, LOCAL SERVICE=0x3e5, NETWORK SERVICE=0x3e4)
        self._reserved_logon_ids = {0x3E4, 0x3E5, 0x3E6, 0x3E7}
        self._pid_counters: dict[str, int] = {}  # Per-system PID counters
        self._pid_os: dict[str, str] = {}  # Per-system OS type for PID allocation
        self._pid_rngs: dict[str, random.Random] = {}  # Per-system PID RNGs
        self._pid_time_epochs: dict[str, datetime] = {}
        self._pid_bucket_offsets: dict[tuple[str, int, int], int] = {}
        self._linux_pid_block_offsets: dict[str, dict[int, int]] = {}
        self._linux_pid_used_ids: dict[str, set[int]] = {}
        self._linux_pid_allocations: dict[str, list[tuple[datetime, int]]] = {}
        self._connection_id_counter = 0
        self._windows_session_id_counters: dict[str, int] = {}
        self._linux_logind_session_counters: dict[str, int] = {}
        self._linux_logind_session_initials: dict[str, int] = {}
        self._linux_logind_session_epochs: dict[str, datetime] = {}
        self._linux_logind_session_block_offsets: dict[str, dict[int, int]] = {}
        self._linux_logind_session_last_ids: dict[str, int] = {}
        self._linux_logind_session_used_ids: dict[str, set[int]] = {}
        self._linux_logind_session_allocations: dict[str, list[tuple[datetime, int]]] = {}
        self._lock = RLock()  # Reentrant lock for thread safety

        # Entity lifecycle: per-system boot times for temporal validation
        self._system_boot_times: dict[str, datetime] = {}
        self._ended_sessions: dict[str, tuple[ActiveSession, datetime]] = {}
        self._process_object_ids: dict[tuple[str, int], str] = {}

    # ========================================
    # Session Management
    # ========================================

    def _host_logon_base(self, system: str) -> int:
        """Return a stable host-local LUID phase offset.

        ``GeneratorState.active_sessions`` still keys sessions by LogonID, so each host
        receives a deterministic low-range offset and collision probes handle the rare
        cross-host overlap while preserving source-native-looking rendered values.
        """
        base = self._logon_id_host_bases.get(system)
        if base is not None:
            return base

        bucket = _stable_seed(f"logon_luid_host_{system}") % _HOST_LOGON_BUCKET_SPACE
        salt = 0
        while True:
            candidate = _MIN_GENERATED_LOGON_LUID + (
                (bucket + (salt * _HOST_LOGON_BUCKET_STEP)) % _HOST_LOGON_BUCKET_SPACE
            )
            if candidate not in self._logon_id_used_host_bases:
                self._logon_id_host_bases[system] = candidate
                self._logon_id_used_host_bases.add(candidate)
                return candidate
            salt += 1

    def _host_logon_epoch(self, system: str, current_time: datetime) -> datetime:
        """Return the boot/uptime epoch used for host-local LUID allocation."""
        boot_time = self._system_boot_times.get(system)
        if boot_time is not None:
            return ensure_utc(boot_time)

        epoch = self._logon_id_epochs.get(system)
        if epoch is not None:
            return epoch

        uptime_seconds = 3600 + (_stable_seed(f"logon_luid_uptime_{system}") % (3 * 86400))
        epoch = ensure_utc(current_time) - timedelta(seconds=uptime_seconds)
        self._logon_id_epochs[system] = epoch
        return epoch

    def _logon_luid_block_stride(self, system: str, block: int) -> int:
        """Return background LSA allocation churn for one minute-scale block."""
        return 56 + (_stable_seed(f"logon_luid_stride:{system}:{block}") % 73)

    def _logon_luid_block_offset(self, system: str, block: int) -> int:
        """Return deterministic per-host LUID churn before a minute-scale block.

        Scenario event times can be far outside the visible generation window.
        Compute the block offset directly instead of caching every elapsed
        minute, keeping allocation CPU and memory bounded by the number of
        emitted events rather than attacker-controlled wall-clock distance.
        """
        if block <= 0:
            return 0

        block_width = 8192
        jitter = _stable_seed(f"logon_luid_block_jitter:{system}:{block}") % 512
        return (block * block_width) + jitter

    def _allocate_logon_luid(self, system: str, event_time: datetime) -> int:
        """Allocate a deterministic host-local Windows LogonID.

        Real LSA LUIDs are host-local allocator values, not a direct wall-clock
        encoding. Generation can visit events out of visible order, so the
        allocator uses event-time buckets plus deterministic background churn to
        preserve chronological sanity without exposing a fixed per-second stride.
        """
        current_time = ensure_utc(event_time)
        base = self._host_logon_base(system)
        epoch = self._host_logon_epoch(system, current_time)
        elapsed_seconds = max(0, int((current_time - epoch).total_seconds()))
        block = elapsed_seconds // 60
        second_in_block = elapsed_seconds % 60
        subsecond_bucket = min(15, current_time.microsecond // 62500)
        ordinal_key = (system, elapsed_seconds, subsecond_bucket)
        ordinal = self._logon_id_second_ordinals.get(ordinal_key, 0)
        self._logon_id_second_ordinals[ordinal_key] = ordinal + 1

        stride = self._logon_luid_block_stride(system, block)
        candidate = base + self._logon_luid_block_offset(system, block)
        candidate += (second_in_block * stride) + (subsecond_bucket * 3) + ordinal
        candidate += (
            _stable_seed(f"logon_luid_low:{system}:{current_time.isoformat()}:{ordinal}") % 3
        )
        candidate = _normalize_generated_logon_luid(candidate)
        while candidate in self._used_logon_ids or candidate in self._reserved_logon_ids:
            candidate = _normalize_generated_logon_luid(candidate + 1)
        self._used_logon_ids.add(candidate)
        return candidate

    @staticmethod
    def _stable_logon_guid(system: str, logon_id: str) -> str:
        """Return a deterministic Windows LogonGuid for a host-local LogonID."""
        digest = bytearray(
            hashlib.sha256(f"windows_logon_guid:{system}:{logon_id}".encode()).digest()[:16]
        )
        digest[6] = (digest[6] & 0x0F) | 0x40
        digest[8] = (digest[8] & 0x3F) | 0x80
        hexed = digest.hex()
        return f"{{{hexed[:8]}-{hexed[8:12]}-{hexed[12:16]}-{hexed[16:20]}-{hexed[20:32]}}}"

    def allocate_logon_id(self, system: str, event_time: datetime | None = None) -> str:
        """Allocate a standalone host-local LogonID without registering a session."""
        with self._lock:
            if event_time is None:
                if self.state.current_time is None:
                    raise StateError("Cannot allocate LogonID: current_time not set")
                event_time = self.state.current_time
            return f"0x{self._allocate_logon_luid(system, event_time):x}"

    def _allocate_windows_session_id(
        self,
        system: str,
        username: str,
        logon_type: int,
        session_kind: str,
    ) -> int:
        """Allocate a host-local Windows terminal session ID for interactive sessions."""
        if logon_type not in {2, 7, 10, 11} or session_kind in {"network", "service", "ssh"}:
            return 0

        used_ids = {
            session.session_id
            for session in self.state.active_sessions.values()
            if session.system == system and session.session_id > 0
        }

        if logon_type in {2, 11} and session_kind in {"interactive", "logon"}:
            preferred = 1 + (_stable_seed(f"windows_console_session:{system}") % 2)
            if preferred not in used_ids:
                return preferred

        initial = self._windows_session_id_counters.get(
            system,
            3 + (_stable_seed(f"windows_session_initial:{system}") % 3),
        )
        candidate = initial
        while candidate in used_ids or candidate <= 0:
            candidate += 1 + (_stable_seed(f"windows_session_gap:{system}:{candidate}") % 2)
        self._windows_session_id_counters[system] = candidate + 1
        logger.debug(
            "Allocated Windows session ID %s for %s@%s type %s",
            candidate,
            username,
            system,
            logon_type,
        )
        return candidate

    def _mark_logon_id_used(self, logon_id: str) -> None:
        """Record externally supplied LogonIDs so generated sessions avoid reuse."""
        try:
            val = int(logon_id, 16)
        except (TypeError, ValueError):
            return
        self._used_logon_ids.add(val)

    def _resolve_logon_id(self, logon_id: str) -> str:
        """Resolve a preplanned session LogonID to its final rendered value."""
        return self._logon_id_aliases.get(logon_id, logon_id)

    def create_session(
        self,
        username: str,
        system: str,
        logon_type: int,
        source_ip: str,
        source_port: int = 0,
        session_kind: str = "logon",
        transport_pid: int | None = None,
        start_time: datetime | None = None,
        logon_guid: str = "",
        session_id: int | None = None,
    ) -> str:
        """Create a new active session.

        Args:
            username: Username for the session
            system: System hostname where session is active
            logon_type: Windows logon type (2=interactive, 3=network, 10=RDP, etc.)
            source_ip: Source IP address for logon
            source_port: Source port for remote logons
            session_kind: Semantic session category, such as interactive, network, rdp, or ssh
            transport_pid: Optional transport process PID tied to the session
            start_time: Optional session start time. Defaults to current generator time.

        Returns:
            Generated LogonID (hex string like "0x3e7")

        Raises:
            StateError: If current_time is not set or LogonID counter exhausted
        """
        with self._lock:
            if start_time is None and self.state.current_time is None:
                raise StateError("Cannot create session: current_time not set")

            session_start_time = ensure_utc(start_time or self.state.current_time)
            val = self._allocate_logon_luid(system, session_start_time)
            logon_id = f"0x{val:x}"

            # Create session
            windows_session_id = (
                session_id
                if session_id is not None
                else self._allocate_windows_session_id(
                    system,
                    username,
                    logon_type,
                    session_kind,
                )
            )
            session = ActiveSession(
                logon_id=logon_id,
                username=username,
                system=system,
                logon_type=logon_type,
                start_time=session_start_time,
                source_ip=source_ip,
                session_id=windows_session_id,
                source_port=source_port,
                session_kind=session_kind,
                transport_pid=transport_pid,
                ecar_object_id=stable_uuid(
                    "session",
                    system,
                    username,
                    logon_type,
                    session_kind,
                    source_ip,
                    source_port,
                    session_start_time.isoformat(),
                    logon_id,
                    windows_session_id,
                ),
                logon_guid=logon_guid,
            )

            self.state.active_sessions[logon_id] = session
            self._logon_id_aliases.pop(logon_id, None)
            self._ended_sessions.pop(logon_id, None)
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
            return self.state.active_sessions.get(logon_id) or self.state.active_sessions.get(
                self._resolve_logon_id(logon_id)
            )

    def get_sessions_for_user(self, username: str) -> list[ActiveSession]:
        """Get all active sessions for a user.

        Args:
            username: Username to search for

        Returns:
            List of active sessions for the user (may be empty)
        """
        with self._lock:
            return [s for s in self.state.active_sessions.values() if s.username == username]

    def get_sessions_for_user_at(self, username: str, at_time: datetime) -> list[ActiveSession]:
        """Get sessions that are active for a user at a specific event time.

        Generation can enqueue a long-lived session's logoff before later
        same-window activities are rendered. Those sessions are no longer in
        active state, but they are still valid for events before the visible
        logoff timestamp.
        """
        cutoff = ensure_utc(at_time)
        with self._lock:
            sessions: dict[str, ActiveSession] = {}
            for session in self.state.active_sessions.values():
                if session.username == username and ensure_utc(session.start_time) <= cutoff:
                    sessions[session.logon_id] = session
            for session, end_time in self._ended_sessions.values():
                if (
                    session.username == username
                    and ensure_utc(session.start_time) <= cutoff < end_time
                ):
                    sessions[session.logon_id] = session
            return list(sessions.values())

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
        logon_guid: str = "",
        session_id: int | None = None,
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
            self._mark_logon_id_used(logon_id)

            windows_session_id = (
                session_id
                if session_id is not None
                else self._allocate_windows_session_id(
                    system,
                    username,
                    logon_type,
                    session_kind,
                )
            )
            session = ActiveSession(
                logon_id=logon_id,
                username=username,
                system=system,
                logon_type=logon_type,
                start_time=ensure_utc(start_time),
                source_ip=source_ip,
                session_id=windows_session_id,
                source_port=source_port,
                session_kind=session_kind,
                transport_pid=transport_pid,
                ecar_object_id=stable_uuid(
                    "registered-session",
                    system,
                    username,
                    logon_type,
                    session_kind,
                    source_ip,
                    source_port,
                    ensure_utc(start_time).isoformat(),
                    logon_id,
                    windows_session_id,
                ),
                logon_guid=logon_guid,
            )
            self.state.active_sessions[logon_id] = session
            self._logon_id_aliases.pop(logon_id, None)
            self._ended_sessions.pop(logon_id, None)
            logger.debug("Registered external session %s for %s@%s", logon_id, username, system)
            return session

    def update_session_metadata(
        self,
        logon_id: str,
        *,
        username: str | None = None,
        start_time: datetime | None = None,
        source_ip: str | None = None,
        source_port: int | None = None,
        session_kind: str | None = None,
        transport_pid: int | None = None,
        network_close_time: datetime | None = None,
        source_ready_time: datetime | None = None,
        logon_guid: str | None = None,
        session_id: int | None = None,
    ) -> bool:
        """Update mutable metadata on an existing session."""
        with self._lock:
            session = self.state.active_sessions.get(self._resolve_logon_id(logon_id))
            if session is None:
                return False
            if username is not None:
                session.username = username
            if start_time is not None:
                session.start_time = ensure_utc(start_time)
            if source_ip is not None:
                session.source_ip = source_ip
            if source_port is not None:
                session.source_port = source_port
            if session_kind is not None:
                session.session_kind = session_kind
            if transport_pid is not None:
                session.transport_pid = transport_pid
            if network_close_time is not None:
                session.network_close_time = ensure_utc(network_close_time)
            if source_ready_time is not None:
                session.source_ready_time = ensure_utc(source_ready_time)
            if logon_guid is not None:
                session.logon_guid = logon_guid
            if session_id is not None:
                session.session_id = session_id
            return True

    def get_session_id(self, logon_id: str) -> int:
        """Return the canonical rendered session ID for an active or ended logon."""
        with self._lock:
            resolved_logon_id = self._resolve_logon_id(logon_id)
            session = self.state.active_sessions.get(resolved_logon_id)
            if session is not None:
                return session.session_id
            ended = self._ended_sessions.get(resolved_logon_id) or self._ended_sessions.get(
                logon_id
            )
            return ended[0].session_id if ended is not None else 0

    def get_or_create_session_logon_guid(
        self,
        logon_id: str,
        system: str,
        *,
        require_nonzero: bool = True,
    ) -> str:
        """Return the canonical LogonGuid for a session, creating it if needed."""
        null_guid = "{00000000-0000-0000-0000-000000000000}"
        if not require_nonzero:
            return null_guid
        with self._lock:
            resolved = self._resolve_logon_id(logon_id)
            session = self.state.active_sessions.get(resolved)
            if session is None:
                ended = self._ended_sessions.get(resolved) or self._ended_sessions.get(logon_id)
                session = ended[0] if ended is not None else None
            if session is not None and session.logon_guid:
                return session.logon_guid
            guid = self._stable_logon_guid(system, resolved or logon_id)
            if session is not None:
                session.logon_guid = guid
            return guid

    def reassign_session_logon_id(self, logon_id: str, event_time: datetime) -> str | None:
        """Re-key an active session after its final source-native start time is known."""
        with self._lock:
            session = self.state.active_sessions.pop(logon_id, None)
            if session is None:
                return None
            new_logon_id = f"0x{self._allocate_logon_luid(session.system, event_time):x}"
            session.logon_id = new_logon_id
            session.start_time = ensure_utc(event_time)
            self.state.active_sessions[new_logon_id] = session
            self._logon_id_aliases[logon_id] = new_logon_id
            self._ended_sessions.pop(logon_id, None)
            self._ended_sessions.pop(new_logon_id, None)
            return new_logon_id

    def end_session(self, logon_id: str, end_time: datetime | None = None) -> bool:
        """End an active session.

        Args:
            logon_id: LogonID of session to end
            end_time: Timestamp of the visible logoff/logout event

        Returns:
            True if session was found and removed, False if not found
        """
        with self._lock:
            resolved_logon_id = self._resolve_logon_id(logon_id)
            session = self.state.active_sessions.pop(resolved_logon_id, None)
            if session is not None:
                if end_time is None:
                    end_time = self.state.current_time
                if end_time is not None:
                    ended = (session, ensure_utc(end_time))
                    self._ended_sessions[resolved_logon_id] = ended
                    if resolved_logon_id != logon_id:
                        self._ended_sessions[logon_id] = ended
                logger.debug("Ended session %s", resolved_logon_id)
                return True
            return False

    def get_session_logon_type(self, logon_id: str) -> int | None:
        """Return the original logon type for an active or recently ended session."""
        with self._lock:
            resolved_logon_id = self._resolve_logon_id(logon_id)
            session = self.state.active_sessions.get(resolved_logon_id)
            if session is not None:
                return session.logon_type
            ended = self._ended_sessions.get(resolved_logon_id) or self._ended_sessions.get(
                logon_id
            )
            return ended[0].logon_type if ended is not None else None

    def get_session_end_time(self, logon_id: str) -> datetime | None:
        """Return the visible end time for a recently ended session."""
        with self._lock:
            resolved_logon_id = self._resolve_logon_id(logon_id)
            ended = self._ended_sessions.get(resolved_logon_id) or self._ended_sessions.get(
                logon_id
            )
            return ended[1] if ended is not None else None

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
                normalized_time = ensure_utc(event_time).replace(microsecond=0)
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
                elapsed_seconds = max(
                    0,
                    int((normalized_time - ensure_utc(epoch)).total_seconds()),
                )
                elapsed_quarters = elapsed_seconds // 900
                minute_in_quarter = (elapsed_seconds % 900) // 60
                block = elapsed_quarters // 16
                quarter_in_block = elapsed_quarters % 16
                block_offset = self._linux_logind_session_block_offset(system, block)
                stride = 4 + (_stable_seed(f"logind_session_stride:{system}:{block}") % 3)
                candidate = (
                    initial + block_offset + (quarter_in_block * stride) + (minute_in_quarter // 5)
                )
                used = self._linux_logind_session_used_ids.setdefault(system, set())
                allocations = self._linux_logind_session_allocations.setdefault(system, [])
                salt = 0
                while candidate in used or self._linux_logind_matches_elapsed_delta(
                    allocations,
                    normalized_time,
                    candidate,
                ):
                    candidate += 7 + (
                        _stable_seed(f"logind_session_collision:{system}:{candidate}:{salt}") % 7
                    )
                    salt += 1
                used.add(candidate)
                allocations.append((normalized_time, candidate))
                self._linux_logind_session_last_ids[system] = max(
                    candidate, self._linux_logind_session_last_ids.get(system, candidate)
                )
                return candidate

            if system not in self._linux_logind_session_counters:
                self._linux_logind_session_counters[system] = rng.randint(20, 250)
            self._linux_logind_session_counters[system] += rng.randint(1, 4)
            return self._linux_logind_session_counters[system]

    def _linux_logind_session_block_offset(self, system: str, block: int) -> int:
        """Return deterministic logind session churn before a four-hour block."""
        if block <= 0:
            return 0

        block_width = 128
        jitter = _stable_seed(f"logind_session_block_jitter:{system}:{block}") % 16
        return (block * block_width) + jitter

    @staticmethod
    def _linux_logind_matches_elapsed_delta(
        allocations: list[tuple[datetime, int]],
        event_time: datetime,
        candidate: int,
    ) -> bool:
        """Return True when a session ID would exactly encode elapsed seconds."""
        for allocated_time, allocated_id in allocations:
            elapsed_seconds = abs(int((event_time - allocated_time).total_seconds()))
            if elapsed_seconds > 0 and abs(candidate - allocated_id) == elapsed_seconds:
                return True
        return False

    # ========================================
    # Process Management
    # ========================================

    def _linux_pid_epoch(self, system: str, current_time: datetime) -> datetime:
        """Return the per-host epoch used for Linux time-aware PID allocation."""
        boot_time = self._system_boot_times.get(system)
        if boot_time is not None:
            return ensure_utc(boot_time)

        epoch = self._pid_time_epochs.get(system)
        if epoch is not None:
            return epoch

        epoch = ensure_utc(current_time)
        self._pid_time_epochs[system] = epoch
        return epoch

    def _linux_pid_block_stride(self, system: str, block: int) -> int:
        """Return background process churn for one coarse Linux PID time block."""
        return 997 + (_stable_seed(f"linux_pid_stride:{system}:{block}") % 311)

    def _linux_pid_block_offset(self, system: str, block: int) -> int:
        """Return deterministic per-host Linux PID churn before a coarse time block."""
        if block <= 0:
            return 0

        block_width = 96
        jitter = _stable_seed(f"linux_pid_block_jitter:{system}:{block}") % 32
        return (block * block_width) + jitter

    @staticmethod
    def _normalize_linux_pid(pid: int) -> int:
        """Keep a PID inside the ordinary Linux pid_max range."""
        linux_pid_max = 4_194_304
        if pid > linux_pid_max:
            return 500 + (pid % (linux_pid_max - 500))
        if pid <= 0:
            return 500
        return pid

    @staticmethod
    def _linux_pid_matches_elapsed_delta(
        allocations: list[tuple[datetime, int]],
        event_time: datetime,
        candidate: int,
    ) -> bool:
        """Return True when a PID would visibly encode elapsed wall-clock seconds."""
        for allocated_time, allocated_id in allocations:
            elapsed_seconds = abs((event_time - allocated_time).total_seconds())
            pid_delta = abs(candidate - allocated_id)
            if elapsed_seconds >= 1.0 and abs(pid_delta - elapsed_seconds) <= 1.0:
                return True
        return False

    def _initialize_pid_allocator(self, system: str, os_category: str) -> None:
        """Initialize a per-system PID allocator without creating a process."""
        if system in self._pid_counters:
            return

        self._pid_rngs[system] = random.Random(_stable_seed(f"pid_alloc_{system}"))
        pid_rng = self._pid_rngs[system]
        if os_category == "windows":
            start = pid_rng.randint(2000, 6000)
            self._pid_counters[system] = start - (start % 4)
            self._pid_os[system] = "windows"
        else:
            self._pid_counters[system] = pid_rng.randint(8000, 42000)
            self._pid_os[system] = "linux"

    def _allocate_linux_pid(
        self,
        system: str,
        pid_rng: random.Random,
        current_time: datetime | None = None,
        minimum_pid_exclusive: int | None = None,
    ) -> int:
        """Allocate a Linux PID without exposing wall-clock elapsed seconds."""
        current_time = ensure_utc(current_time or self.state.current_time)
        epoch = self._linux_pid_epoch(system, current_time)
        elapsed_seconds = max(0, int((current_time - epoch).total_seconds()))
        block = elapsed_seconds // 300
        slot = (elapsed_seconds % 300) // 10
        ordinal_key = (system, block, slot)
        ordinal = self._pid_bucket_offsets.get(ordinal_key, 0)
        gap = 23 + max(1, int(pid_rng.lognormvariate(0.7, 0.8)))
        self._pid_bucket_offsets[ordinal_key] = ordinal + gap

        pid = self._pid_counters[system] + self._linux_pid_block_offset(system, block)
        pid += (slot * 2) + ordinal
        pid = self._normalize_linux_pid(pid)

        running = {p.pid for (s, _), p in self.state.running_processes.items() if s == system}
        used = self._linux_pid_used_ids.setdefault(system, set())
        allocations = self._linux_pid_allocations.setdefault(system, [])
        prior_visible_pid = max(
            (
                allocated_pid
                for allocated_time, allocated_pid in allocations
                if allocated_time <= current_time
            ),
            default=None,
        )
        if prior_visible_pid is not None and (
            minimum_pid_exclusive is None or prior_visible_pid > minimum_pid_exclusive
        ):
            minimum_pid_exclusive = prior_visible_pid
        future_pid_exclusive = min(
            (
                allocated_pid
                for allocated_time, allocated_pid in allocations
                if allocated_time > current_time
            ),
            default=None,
        )

        def is_available(candidate: int) -> bool:
            return (
                candidate not in running
                and candidate not in used
                and (
                    minimum_pid_exclusive is None
                    or minimum_pid_exclusive >= 4_194_304
                    or candidate > minimum_pid_exclusive
                )
                and (future_pid_exclusive is None or candidate < future_pid_exclusive)
                and not self._linux_pid_matches_elapsed_delta(allocations, current_time, candidate)
            )

        def bounded_candidate(salt: int) -> int | None:
            if future_pid_exclusive is None:
                return None
            lower_bound = max(499, minimum_pid_exclusive or 499)
            if future_pid_exclusive <= lower_bound + 1:
                return None
            span = future_pid_exclusive - lower_bound - 1
            start = (
                _stable_seed(
                    f"linux_pid_future_bound:{system}:{current_time.isoformat()}:{pid}:{salt}"
                )
                % span
            )
            for offset in range(min(span, 4096)):
                candidate = future_pid_exclusive - 1 - ((start + offset) % span)
                if is_available(candidate):
                    return candidate
            return None

        if not is_available(pid):
            bounded = bounded_candidate(0)
            if bounded is not None:
                pid = bounded
        collision_salt = 0
        while not is_available(pid):
            bounded = bounded_candidate(collision_salt + 1)
            if bounded is not None:
                pid = bounded
                if is_available(pid):
                    break
            elif future_pid_exclusive is not None and pid >= future_pid_exclusive:
                future_pid_exclusive = None
            bump = 37 + (_stable_seed(f"linux_pid_collision:{system}:{pid}:{collision_salt}") % 41)
            pid = self._normalize_linux_pid(pid + bump)
            collision_salt += 1
        used.add(pid)
        allocations.append((current_time, pid))
        return pid

    def allocate_transient_linux_pid(self, system: str, event_time: datetime) -> int:
        """Allocate a Linux PID for syslog-only transient process observations.

        Syslog records such as ``sudo[pid]`` and per-session ``sshd[pid]`` can
        describe short-lived processes that are not emitted as canonical eCAR
        process-create events. They still belong to the same host PID namespace
        as canonical process evidence, so this method shares the Linux allocator
        and used-ID ledger without registering a durable RunningProcess.
        """
        with self._lock:
            self._initialize_pid_allocator(system, "linux")
            pid_rng = self._pid_rngs[system]
            return self._allocate_linux_pid(system, pid_rng, event_time)

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
                # Detect OS from image path: backslash = Windows, forward slash = Linux
                is_windows = "\\" in image
                self._initialize_pid_allocator(system, "windows" if is_windows else "linux")

            # Increment with OS-aware gaps
            if system not in self._pid_rngs:
                self._pid_rngs[system] = random.Random(_stable_seed(f"pid_alloc_{system}"))
            pid_rng = self._pid_rngs[system]
            if self._pid_os.get(system) == "windows":
                pid = self._pid_counters[system]
                # Windows: multiples of 4 with lognormal gap distribution.
                # Lognormal produces mostly small gaps (4-20) with a heavy tail
                # (occasionally 100-800+) simulating background process churn
                # that consumes PIDs between our emitted events.
                gap = max(1, int(pid_rng.lognormvariate(1.2, 0.8)))
                self._pid_counters[system] += 4 * gap

                # Check for PID exhaustion — wrap around to a safe range,
                # skipping any PIDs still in use by running processes.
                if self._pid_counters[system] > 65536:
                    self._pid_counters[system] = 4000
                    running = {
                        p.pid for (s, _), p in self.state.running_processes.items() if s == system
                    }
                    while self._pid_counters[system] in running:
                        self._pid_counters[system] += 4
            else:
                minimum_pid_exclusive = None
                parent = self.state.running_processes.get((system, parent_pid))
                if (
                    parent is not None
                    and parent.start_time <= self.state.current_time
                    and parent.pid > 1
                ):
                    minimum_pid_exclusive = parent.pid
                pid = self._allocate_linux_pid(
                    system,
                    pid_rng,
                    minimum_pid_exclusive=minimum_pid_exclusive,
                )

            # Create process
            ecar_object_id = stable_uuid(
                "process",
                system,
                pid,
                parent_pid,
                image,
                command_line,
                username,
                self.state.current_time.isoformat(),
                logon_id,
            )
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
                ecar_object_id=ecar_object_id,
            )

            key = (system, pid)
            self.state.running_processes[key] = process
            self._process_object_ids[key] = ecar_object_id
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
        """Get the eCAR objectID for a running or recently ended process."""
        with self._lock:
            key = (system, pid)
            proc = self.state.running_processes.get(key)
            if proc:
                return proc.ecar_object_id
            return self._process_object_ids.get(key, "")

    def update_process_activity_time(self, system: str, pid: int, activity_time: datetime) -> bool:
        """Record the latest dependent activity timestamp for a running process."""
        with self._lock:
            proc = self.state.running_processes.get((system, pid))
            if proc is None:
                return False
            activity_time = ensure_utc(activity_time)
            if proc.last_activity_time is None or activity_time > proc.last_activity_time:
                proc.last_activity_time = activity_time
            return True

    def update_session_activity_time(self, logon_id: str, activity_time: datetime) -> bool:
        """Record the latest dependent activity timestamp for an active session."""
        with self._lock:
            session = self.state.active_sessions.get(self._resolve_logon_id(logon_id))
            if session is None:
                return False
            activity_time = ensure_utc(activity_time)
            if session.last_activity_time is None or activity_time > session.last_activity_time:
                session.last_activity_time = activity_time
            return True

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

    def update_connection_interval(
        self,
        conn_id: str,
        start_time: datetime,
        close_time: datetime | None,
    ) -> bool:
        """Update the canonical source-visible interval for an open connection."""
        with self._lock:
            conn = self.state.open_connections.get(conn_id)
            if conn is None:
                return False
            conn.start_time = ensure_utc(start_time)
            conn.close_time = ensure_utc(close_time) if close_time is not None else None
            return True

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
            if event.event_type != "process_terminate" and event.process and event.src_host:
                proc = self.state.running_processes.get(
                    (event.src_host.hostname, event.process.pid)
                )
                if proc is not None:
                    activity_time = ensure_utc(event.timestamp)
                    if proc.last_activity_time is None or activity_time > proc.last_activity_time:
                        proc.last_activity_time = activity_time

            if event.event_type == "logoff" and event.auth:
                self.end_session(event.auth.logon_id, event.timestamp)
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
