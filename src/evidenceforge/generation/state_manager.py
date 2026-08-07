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
from evidenceforge.events.identity import ProcessIdentity, SessionIdentity, ThreadIdentity
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.events.network import NetworkTransactionPlan
from evidenceforge.generation.indexes import (
    ExpiringIndex,
    GroupedTemporalIndex,
    IndexedEntityStore,
    TemporalAllocationIndex,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.state import (
    ActiveSession,
    GeneratorState,
    OpenConnection,
    RunningProcess,
    RunningThread,
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
_NULL_LOGON_GUID = "{00000000-0000-0000-0000-000000000000}"
_LINUX_PID_BLOCK_SECONDS = 300
_LINUX_PID_RATE_DENOMINATOR = 10


def _session_valid_at(session: ActiveSession, cutoff: datetime) -> bool:
    """Return whether a session can own visible activity at cutoff."""
    if ensure_utc(session.start_time) > cutoff:
        return False
    end_plan = session.end_plan
    if end_plan is not None and end_plan.is_authoritative:
        return cutoff < ensure_utc(end_plan.canonical_end)
    network_close_time = session.network_close_time
    if (
        session.session_kind == "ssh"
        and network_close_time is not None
        and cutoff >= ensure_utc(network_close_time)
    ):
        return False
    if end_plan is not None and cutoff >= ensure_utc(end_plan.canonical_end):
        return False
    return True


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
        self._active_sessions: IndexedEntityStore[str, ActiveSession] = IndexedEntityStore(
            username=lambda session: session.username,
            system=lambda session: session.system,
        )
        self.state.active_sessions = self._active_sessions
        self._running_processes: IndexedEntityStore[tuple[str, int], RunningProcess] = (
            IndexedEntityStore(
                username=lambda process: process.username,
                system=lambda process: process.system,
                logon_id=lambda process: process.logon_id,
            )
        )
        self.state.running_processes = self._running_processes
        self._running_threads: IndexedEntityStore[tuple[str, str, int], RunningThread] = (
            IndexedEntityStore(
                system=lambda thread: thread.hostname,
                process_object_id=lambda thread: thread.process_object_id,
            )
        )
        self.state.running_threads = self._running_threads
        self._open_connections: IndexedEntityStore[str, OpenConnection] = IndexedEntityStore(
            exact_tuple=lambda connection: self._connection_tuple_key(
                connection.src_ip,
                connection.src_port,
                connection.dst_ip,
                connection.dst_port,
                connection.protocol,
            ),
            zeek_uid=lambda connection: connection.zeek_uid,
            transaction_id=lambda connection: connection.transaction_id,
        )
        self.state.open_connections = self._open_connections
        self._connection_expirations: ExpiringIndex[str, bool] = ExpiringIndex()
        self._terminal_connection_ids: dict[str, None] = {}
        self._logon_id_host_bases: dict[str, int] = {}
        self._logon_id_used_host_bases: set[int] = set()
        self._logon_id_epochs: dict[str, datetime] = {}
        self._logon_id_second_ordinals: dict[tuple[str, int, int], int] = {}
        self._semantic_peer_ordinals: dict[tuple[str, str], int] = {}
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
        self._linux_pid_allocations: dict[str, TemporalAllocationIndex] = {}
        self._connection_id_counter = 0
        self._thread_id_counters: dict[str, int] = {}
        self._thread_id_rngs: dict[str, random.Random] = {}
        self._windows_session_id_counters: dict[str, int] = {}
        self._linux_logind_session_counters: dict[str, int] = {}
        self._linux_logind_session_initials: dict[str, int] = {}
        self._linux_logind_session_epochs: dict[str, datetime] = {}
        self._linux_logind_session_block_offsets: dict[str, dict[int, int]] = {}
        self._linux_logind_session_last_ids: dict[str, int] = {}
        self._linux_logind_session_used_ids: dict[str, set[int]] = {}
        self._linux_logind_session_allocations: dict[str, TemporalAllocationIndex] = {}
        self._lock = RLock()  # Reentrant lock for thread safety

        # Entity lifecycle: per-system boot times for temporal validation
        self._system_boot_times: dict[str, datetime] = {}
        self._ended_sessions: IndexedEntityStore[str, tuple[ActiveSession, datetime]] = (
            IndexedEntityStore(
                username=lambda ended: ended[0].username,
                system=lambda ended: ended[0].system,
            )
        )
        self._ended_sessions_by_username_end: GroupedTemporalIndex[str, str] = (
            GroupedTemporalIndex()
        )
        self._ended_sessions_by_system_end: GroupedTemporalIndex[str, str] = GroupedTemporalIndex()
        self._authoritative_session_ends: GroupedTemporalIndex[tuple[str, str], str] = (
            GroupedTemporalIndex()
        )
        self._process_object_ids: dict[tuple[str, int], str] = {}
        self._processes_by_object_id: dict[str, RunningProcess] = {}
        self._ended_threads: dict[tuple[str, str, int], RunningThread] = {}

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

    def next_semantic_peer_ordinal(self, family: str, stable_key: str) -> int:
        """Allocate an ordinal scoped only to otherwise identical semantic peers."""

        if not family or not stable_key:
            raise ValueError("Semantic peer ordinals require a family and stable key")
        with self._lock:
            key = (family, stable_key)
            ordinal = self._semantic_peer_ordinals.get(key, 0)
            self._semantic_peer_ordinals[key] = ordinal + 1
            return ordinal

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
            for session in self._active_sessions.find("system", system)
            if session.session_id > 0
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

    def _remove_ended_session(self, logon_id: str) -> None:
        """Remove ended-session state and its canonical temporal indexes."""
        ended = self._ended_sessions.pop(logon_id, None)
        if ended is None:
            return
        session, _end_time = ended
        if logon_id != session.logon_id:
            return
        self._ended_sessions_by_username_end.remove(logon_id)
        self._ended_sessions_by_system_end.remove(logon_id)

    def _index_ended_session(
        self,
        logon_id: str,
        session: ActiveSession,
        end_time: datetime,
    ) -> None:
        """Index one canonical ended session by owner and visible end time."""
        self._ended_sessions_by_username_end.add(logon_id, session.username, end_time)
        self._ended_sessions_by_system_end.add(logon_id, session.system, end_time)

    def _index_authoritative_session_end(self, session: ActiveSession) -> None:
        """Index an authoritative end plan for constant-time rebootstrap checks."""
        plan = session.end_plan
        if plan is None or not plan.is_authoritative:
            return
        self._authoritative_session_ends.add(
            session.logon_id,
            (session.username, session.system),
            ensure_utc(plan.canonical_end),
        )

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
        logon_guid_required: bool | None = None,
        session_id: int | None = None,
        lifecycle_group_id: str = "",
        parent_lifecycle_group_id: str = "",
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
            session_object_id = stable_uuid(
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
            )
            if logon_guid_required is not None:
                logon_guid = (
                    self._stable_logon_guid(system, logon_id)
                    if logon_guid_required
                    else _NULL_LOGON_GUID
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
                ecar_object_id=session_object_id,
                logon_guid=logon_guid,
                lifecycle_group_id=lifecycle_group_id
                or stable_uuid("session-lifecycle", session_object_id),
                parent_lifecycle_group_id=parent_lifecycle_group_id,
            )

            self.state.active_sessions[logon_id] = session
            self._logon_id_aliases.pop(logon_id, None)
            self._remove_ended_session(logon_id)
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

    def get_session_at(self, logon_id: str, at_time: datetime) -> ActiveSession | None:
        """Get an active or ended session if it could own activity at an event time."""

        cutoff = ensure_utc(at_time)
        with self._lock:
            resolved_logon_id = self._resolve_logon_id(logon_id)
            session = self._active_sessions.get(resolved_logon_id)
            if session is not None:
                return session if _session_valid_at(session, cutoff) else None
            ended = self._ended_sessions.get(resolved_logon_id) or self._ended_sessions.get(
                logon_id
            )
            if ended is None:
                return None
            session, end_time = ended
            if _session_valid_at(session, cutoff) and cutoff < end_time:
                return session
            return None

    def get_sessions_for_user(self, username: str) -> list[ActiveSession]:
        """Get all active sessions for a user.

        Args:
            username: Username to search for

        Returns:
            List of active sessions for the user (may be empty)
        """
        with self._lock:
            return self._active_sessions.find("username", username)

    def get_sessions_for_user_at(self, username: str, at_time: datetime) -> list[ActiveSession]:
        """Get active or ended sessions valid for a user at an event time.

        Generation can enqueue a long-lived session's logoff before later
        same-window activities are rendered. Those sessions are no longer in
        active state, but they are still valid for events before the visible
        logoff timestamp.

        Call ``get_active_sessions_for_user_at()`` when the caller will mutate
        the session or attach newly generated state to it.
        """
        cutoff = ensure_utc(at_time)
        with self._lock:
            sessions = {
                session.logon_id: session
                for session in self.get_active_sessions_for_user_at(username, cutoff)
            }
            for logon_id in self._ended_sessions_by_username_end.keys_after(username, cutoff):
                ended = self._ended_sessions.get(logon_id)
                if ended is None:
                    continue
                session, end_time = ended
                if _session_valid_at(session, cutoff) and cutoff < end_time:
                    sessions[session.logon_id] = session
            return list(sessions.values())

    def get_active_sessions_for_user_at(
        self,
        username: str,
        at_time: datetime,
    ) -> list[ActiveSession]:
        """Get currently live user sessions that had started by an event time."""

        cutoff = ensure_utc(at_time)
        with self._lock:
            return [
                session
                for session in self._active_sessions.find("username", username)
                if _session_valid_at(session, cutoff)
            ]

    def authoritative_session_end_blocks_rebootstrap(
        self,
        username: str,
        system: str,
        at_time: datetime,
    ) -> bool:
        """Return whether an explicit end leaves no session able to own later activity."""

        cutoff = ensure_utc(at_time)
        with self._lock:
            sessions: dict[str, ActiveSession] = {
                session.logon_id: session
                for session in self._active_sessions.find("username", username)
                if session.system == system
            }
            for logon_id in self._ended_sessions_by_username_end.keys_after(username, cutoff):
                ended = self._ended_sessions.get(logon_id)
                if ended is None:
                    continue
                session, _end_time = ended
                if session.system == system:
                    sessions[session.logon_id] = session

            has_expired_authoritative_plan = bool(
                self._authoritative_session_ends.keys_at_or_before(
                    (username, system),
                    cutoff,
                )
            )
            if not has_expired_authoritative_plan:
                return False
            return not any(_session_valid_at(session, cutoff) for session in sessions.values())

    def get_sessions_on_system(self, system: str) -> list[ActiveSession]:
        """Get all active sessions on a system.

        Args:
            system: System hostname to search for

        Returns:
            List of active sessions on the system (may be empty)
        """
        with self._lock:
            return self._active_sessions.find("system", system)

    def get_sessions_on_system_at(
        self,
        system: str,
        at_time: datetime,
    ) -> list[ActiveSession]:
        """Get active or ended sessions valid on a system at an event time.

        Call ``get_active_sessions_on_system_at()`` when the caller will mutate
        the session or attach newly generated state to it.
        """

        cutoff = ensure_utc(at_time)
        with self._lock:
            sessions = {
                session.logon_id: session
                for session in self.get_active_sessions_on_system_at(system, cutoff)
            }
            for logon_id in self._ended_sessions_by_system_end.keys_after(system, cutoff):
                ended = self._ended_sessions.get(logon_id)
                if ended is None:
                    continue
                session, end_time = ended
                if _session_valid_at(session, cutoff) and cutoff < end_time:
                    sessions[session.logon_id] = session
            return list(sessions.values())

    def get_active_sessions_on_system_at(
        self,
        system: str,
        at_time: datetime,
    ) -> list[ActiveSession]:
        """Get currently live host sessions that had started by an event time."""

        cutoff = ensure_utc(at_time)
        with self._lock:
            return [
                session
                for session in self._active_sessions.find("system", system)
                if _session_valid_at(session, cutoff)
            ]

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
        logon_guid_required: bool | None = None,
        session_id: int | None = None,
        lifecycle_group_id: str = "",
        parent_lifecycle_group_id: str = "",
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
            session_object_id = stable_uuid(
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
            )
            if logon_guid_required is not None:
                logon_guid = (
                    self._stable_logon_guid(system, logon_id)
                    if logon_guid_required
                    else _NULL_LOGON_GUID
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
                ecar_object_id=session_object_id,
                logon_guid=logon_guid,
                lifecycle_group_id=lifecycle_group_id
                or stable_uuid("session-lifecycle", session_object_id),
                parent_lifecycle_group_id=parent_lifecycle_group_id,
            )
            self.state.active_sessions[logon_id] = session
            self._logon_id_aliases.pop(logon_id, None)
            self._remove_ended_session(logon_id)
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
        lifecycle_group_id: str | None = None,
        parent_lifecycle_group_id: str | None = None,
    ) -> bool:
        """Update mutable metadata on an existing session."""
        with self._lock:
            session = self.state.active_sessions.get(self._resolve_logon_id(logon_id))
            if session is None:
                return False
            if username is not None:
                self._authoritative_session_ends.remove(session.logon_id)
                session.username = username
                self._active_sessions.refresh(session.logon_id)
                self._index_authoritative_session_end(session)
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
                if session.logon_guid and session.logon_guid != logon_guid:
                    raise StateError(
                        "Cannot replace published session LogonGuid for "
                        f"{logon_id}: {session.logon_guid} -> {logon_guid}"
                    )
                session.logon_guid = logon_guid
            if session_id is not None:
                session.session_id = session_id
            if lifecycle_group_id is not None:
                session.lifecycle_group_id = lifecycle_group_id
            if parent_lifecycle_group_id is not None:
                session.parent_lifecycle_group_id = parent_lifecycle_group_id
            return True

    def plan_session_end(self, logon_id: str, plan: SessionEndPlan) -> bool:
        """Attach an immutable canonical end plan to an active session.

        An explicit storyline deadline cannot be silently replaced by another
        event. Re-applying the same plan is idempotent.
        """

        with self._lock:
            session = self.state.active_sessions.get(self._resolve_logon_id(logon_id))
            if session is None:
                return False
            existing = session.end_plan
            if existing is not None and existing != plan:
                if existing.is_authoritative:
                    raise StateError(
                        "Cannot replace authoritative session end plan for "
                        f"{logon_id}: {existing.canonical_end.isoformat()}"
                    )
            session.end_plan = plan
            self._index_authoritative_session_end(session)
            return True

    def get_session_end_plan(self, logon_id: str) -> SessionEndPlan | None:
        """Return the immutable end plan for an active or ended session."""

        with self._lock:
            resolved_logon_id = self._resolve_logon_id(logon_id)
            session = self.state.active_sessions.get(resolved_logon_id)
            if session is None:
                ended = self._ended_sessions.get(resolved_logon_id) or self._ended_sessions.get(
                    logon_id
                )
                session = ended[0] if ended is not None else None
            return session.end_plan if session is not None else None

    def process_session_end_plan(self, system: str, pid: int) -> SessionEndPlan | None:
        """Return the owning session end plan for a live process."""

        with self._lock:
            process = self.state.running_processes.get((system, pid))
            if process is None or not process.logon_id:
                return None
            session = self.state.active_sessions.get(self._resolve_logon_id(process.logon_id))
            return session.end_plan if session is not None else None

    def get_session_identity(self, logon_id: str) -> SessionIdentity | None:
        """Return an immutable snapshot of an active or ended session identity."""

        with self._lock:
            resolved_logon_id = self._resolve_logon_id(logon_id)
            session = self.state.active_sessions.get(resolved_logon_id)
            if session is None:
                ended = self._ended_sessions.get(resolved_logon_id) or self._ended_sessions.get(
                    logon_id
                )
                session = ended[0] if ended is not None else None
            if session is None:
                return None
            return SessionIdentity(
                hostname=session.system,
                object_id=session.ecar_object_id,
                logon_id=session.logon_id,
                session_id=session.session_id,
                principal=session.username,
                session_kind=session.session_kind,
                started_at=session.start_time,
                lifecycle_group_id=session.lifecycle_group_id,
                logon_guid=session.logon_guid,
                parent_lifecycle_group_id=session.parent_lifecycle_group_id,
            )

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
        with self._lock:
            resolved = self._resolve_logon_id(logon_id)
            session = self.state.active_sessions.get(resolved)
            if session is None:
                ended = self._ended_sessions.get(resolved) or self._ended_sessions.get(logon_id)
                session = ended[0] if ended is not None else None
            if session is not None and session.logon_guid:
                return session.logon_guid
            guid = (
                self._stable_logon_guid(system, resolved or logon_id)
                if require_nonzero
                else _NULL_LOGON_GUID
            )
            if session is not None:
                session.logon_guid = guid
            return guid

    def reassign_session_logon_id(self, logon_id: str, event_time: datetime) -> str | None:
        """Re-key an active session after its final source-native start time is known."""
        with self._lock:
            session = self._active_sessions.pop(logon_id, None)
            if session is None:
                return None
            new_logon_id = f"0x{self._allocate_logon_luid(session.system, event_time):x}"
            session.logon_id = new_logon_id
            session.start_time = ensure_utc(event_time)
            self._active_sessions[new_logon_id] = session
            self._authoritative_session_ends.remove(logon_id)
            self._index_authoritative_session_end(session)
            self._logon_id_aliases[logon_id] = new_logon_id
            self._remove_ended_session(logon_id)
            self._remove_ended_session(new_logon_id)
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
            session = self._active_sessions.pop(resolved_logon_id, None)
            if session is not None:
                if end_time is None:
                    end_time = self.state.current_time
                if end_time is not None:
                    ended = (session, ensure_utc(end_time))
                    self._ended_sessions[resolved_logon_id] = ended
                    self._index_ended_session(
                        resolved_logon_id,
                        session,
                        ensure_utc(end_time),
                    )
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
                elapsed_minutes = elapsed_seconds // 60
                second_slot = normalized_time.second // 10
                stride = 8 + (_stable_seed(f"logind_session_minute_stride:{system}") % 2)
                minute_jitter = (
                    _stable_seed(f"logind_session_minute_jitter:{system}:{elapsed_minutes}") % 2
                )
                candidate = initial + (elapsed_minutes * stride) + second_slot + minute_jitter
                used = self._linux_logind_session_used_ids.setdefault(system, set())
                allocations = self._linux_logind_session_allocations.setdefault(
                    system,
                    TemporalAllocationIndex(),
                )
                earlier_max = allocations.max_value_at_or_before(normalized_time)
                if earlier_max is not None and candidate <= earlier_max:
                    bump = 1 + (
                        _stable_seed(
                            f"logind_session_lower_bound:{system}:{normalized_time}:{candidate}"
                        )
                        % 3
                    )
                    candidate = earlier_max + bump
                salt = 0
                while candidate in used or allocations.matches_elapsed_delta(
                    normalized_time,
                    candidate,
                    tolerance=0.0,
                    integral_seconds=True,
                ):
                    candidate += 7 + (
                        _stable_seed(f"logind_session_collision:{system}:{candidate}:{salt}") % 7
                    )
                    salt += 1
                used.add(candidate)
                allocations.add(normalized_time, candidate)
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

    @staticmethod
    def _linux_pid_rate_numerator(system: str) -> int:
        """Return a stable host PID churn rate with room for deferred insertions."""
        return 18 + (_stable_seed(f"linux_pid_rate:{system}") % 5)

    def _linux_pid_block_offset(self, system: str, block: int) -> int:
        """Return deterministic per-host Linux PID churn before a coarse time block."""
        if block <= 0:
            return 0
        elapsed_seconds = block * _LINUX_PID_BLOCK_SECONDS
        return (
            elapsed_seconds * self._linux_pid_rate_numerator(system)
        ) // _LINUX_PID_RATE_DENOMINATOR

    @staticmethod
    def _normalize_linux_pid(pid: int) -> int:
        """Keep a PID inside the ordinary Linux pid_max range."""
        linux_pid_max = 4_194_304
        if pid > linux_pid_max:
            return 500 + (pid % (linux_pid_max - 500))
        if pid <= 0:
            return 500
        return pid

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
        rate_numerator = self._linux_pid_rate_numerator(system)
        time_offset = (elapsed_seconds * rate_numerator) // _LINUX_PID_RATE_DENOMINATOR
        ordinal_key = (system, time_offset, 0)
        ordinal = self._pid_bucket_offsets.get(ordinal_key, 0)
        gap = max(1, min(5, int(pid_rng.lognormvariate(0.3, 0.8))))
        self._pid_bucket_offsets[ordinal_key] = ordinal + gap

        pid = self._pid_counters[system] + time_offset + ordinal
        pid = self._normalize_linux_pid(pid)

        running = {process.pid for process in self._running_processes.find("system", system)}
        used = self._linux_pid_used_ids.setdefault(system, set())
        allocations = self._linux_pid_allocations.setdefault(
            system,
            TemporalAllocationIndex(),
        )
        prior_visible_pid = allocations.max_value_at_or_before(current_time)
        if prior_visible_pid is not None and (
            minimum_pid_exclusive is None or prior_visible_pid > minimum_pid_exclusive
        ):
            minimum_pid_exclusive = prior_visible_pid
        future_pid_exclusive = allocations.min_value_after(current_time)

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
            )

        def bounded_candidate() -> int | None:
            if future_pid_exclusive is None:
                return None
            lower_bound = max(499, minimum_pid_exclusive or 499)
            if future_pid_exclusive <= lower_bound + 1:
                return None
            span = future_pid_exclusive - lower_bound - 1
            # The time-derived PID is already the best estimate of where this
            # process belongs. Search outward from that point instead of choosing
            # a random midpoint: midpoint insertion repeatedly halves the room
            # below a preplanned future PID and exhausts otherwise adequate
            # capacity during dense deferred baseline generation.
            center = min(max(pid, lower_bound + 1), future_pid_exclusive - 1)
            for distance in range(min(span, 4096)):
                offsets = (0,) if distance == 0 else (distance, -distance)
                for offset in offsets:
                    candidate = center + offset
                    if lower_bound < candidate < future_pid_exclusive and is_available(candidate):
                        return candidate
            return None

        if not is_available(pid):
            bounded = bounded_candidate()
            if bounded is not None:
                pid = bounded
            elif minimum_pid_exclusive is not None and minimum_pid_exclusive < 4_194_304:
                jump = 23 + (
                    _stable_seed(
                        f"linux_pid_lower_bound:{system}:{current_time.isoformat()}:"
                        f"{minimum_pid_exclusive}"
                    )
                    % 47
                )
                pid = self._normalize_linux_pid(minimum_pid_exclusive + jump)

        collision_salt = 0
        max_retries = 64
        while not is_available(pid):
            if collision_salt >= max_retries:
                raise StateError(
                    "Unable to allocate Linux PID after bounded retries; "
                    "adjust scenario timing or reduce process contention."
                )
            bounded = bounded_candidate()
            if bounded is not None:
                pid = bounded
                if is_available(pid):
                    break
            elif future_pid_exclusive is not None:
                future_pid_exclusive = None
            lower_bound = max(pid, minimum_pid_exclusive or 499)
            bump = 23 + (
                _stable_seed(
                    f"linux_pid_collision:{system}:{current_time.isoformat()}:"
                    f"{lower_bound}:{collision_salt}"
                )
                % 47
            )
            pid = self._normalize_linux_pid(lower_bound + bump)
            collision_salt += 1
        used.add(pid)
        allocations.add(current_time, pid)
        return pid

    def allocate_transient_linux_pid(
        self,
        system: str,
        event_time: datetime,
        os_category: str = "linux",
    ) -> int:
        """Allocate a Linux PID for syslog-only transient process observations.

        Syslog records such as ``sudo[pid]`` and per-session ``sshd[pid]`` can
        describe short-lived processes that are not emitted as canonical eCAR
        process-create events. They still belong to the same host PID namespace
        as canonical process evidence, so this method shares the Linux allocator
        and used-ID ledger without registering a durable RunningProcess.
        """
        with self._lock:
            if os_category != "linux":
                raise StateError(f"Cannot allocate Linux transient PID for non-Linux host {system}")
            if self._pid_os.get(system) not in {None, "linux"}:
                raise StateError(
                    f"Cannot allocate Linux transient PID in {self._pid_os[system]} "
                    f"PID namespace for {system}"
                )
            self._initialize_pid_allocator(system, "linux")
            pid_rng = self._pid_rngs[system]
            return self._allocate_linux_pid(system, pid_rng, event_time)

    def register_process(
        self,
        system: str,
        pid: int,
        parent_pid: int,
        image: str,
        command_line: str,
        username: str,
        integrity_level: str,
        *,
        os_category: str,
        start_time: datetime | None = None,
        logon_id: str = "",
        lifecycle_group_id: str = "",
        parent_lifecycle_group_id: str = "",
    ) -> RunningProcess:
        """Register a fixed host-native process through the canonical state boundary.

        This is reserved for kernel/bootstrap identities such as Windows PID 4
        and Linux PID 1 that cannot use the ordinary PID allocator.
        """

        with self._lock:
            effective_start = start_time or self.state.current_time
            if effective_start is None:
                raise StateError("Cannot register process: current_time not set")
            if pid < 0:
                raise StateError("Cannot register process: PID must be non-negative")
            if (system, pid) in self.state.running_processes:
                raise StateError(f"Cannot register process: PID {pid} already exists on {system}")
            if (
                parent_pid not in {0, 4}
                and (system, parent_pid) not in self.state.running_processes
            ):
                raise StateError(
                    f"Cannot register process: parent PID {parent_pid} does not exist on {system}"
                )

            normalized_start = ensure_utc(effective_start)
            self._initialize_pid_allocator(system, os_category)
            if os_category == "linux":
                self._linux_pid_used_ids.setdefault(system, set()).add(pid)
                self._linux_pid_allocations.setdefault(
                    system,
                    TemporalAllocationIndex(),
                ).add(normalized_start, pid)
            object_id = stable_uuid(
                "registered-process",
                system,
                pid,
                parent_pid,
                image,
                command_line,
                username,
                normalized_start.isoformat(),
                logon_id,
            )
            owning_session = self.get_session(logon_id) if logon_id else None
            process_lifecycle_group_id = lifecycle_group_id or stable_uuid(
                "process-lifecycle", object_id
            )
            process_parent_group_id = self._process_parent_lifecycle_group(
                process_lifecycle_group_id,
                parent_lifecycle_group_id,
                owning_session,
            )
            process = RunningProcess(
                pid=pid,
                parent_pid=parent_pid,
                image=image,
                command_line=command_line,
                username=username,
                system=system,
                start_time=normalized_start,
                integrity_level=integrity_level,
                logon_id=logon_id,
                ecar_object_id=object_id,
                lifecycle_group_id=process_lifecycle_group_id,
                parent_lifecycle_group_id=process_parent_group_id,
            )
            self.state.running_processes[(system, pid)] = process
            self._process_object_ids[(system, pid)] = object_id
            self._processes_by_object_id[object_id] = process
            primary_tid = (
                pid
                if os_category == "linux"
                else self._allocate_thread_id(
                    system,
                    object_id,
                    pid,
                )
            )
            thread = self._register_thread(
                process,
                tid=primary_tid,
                kind="primary",
                start_time=normalized_start,
            )
            process.primary_tid = thread.tid
            return process

    def create_process(
        self,
        system: str,
        parent_pid: int,
        image: str,
        command_line: str,
        username: str,
        integrity_level: str,
        logon_id: str = "",
        lifecycle_group_id: str = "",
        parent_lifecycle_group_id: str = "",
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
                        process.pid for process in self._running_processes.find("system", system)
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
            owning_session = self.get_session(logon_id) if logon_id else None
            process_lifecycle_group_id = lifecycle_group_id or stable_uuid(
                "process-lifecycle", ecar_object_id
            )
            process_parent_group_id = self._process_parent_lifecycle_group(
                process_lifecycle_group_id,
                parent_lifecycle_group_id,
                owning_session,
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
                lifecycle_group_id=process_lifecycle_group_id,
                parent_lifecycle_group_id=process_parent_group_id,
            )

            key = (system, pid)
            self.state.running_processes[key] = process
            self._process_object_ids[key] = ecar_object_id
            self._processes_by_object_id[ecar_object_id] = process
            primary_tid = (
                pid
                if self._pid_os.get(system) == "linux"
                else self._allocate_thread_id(
                    system,
                    ecar_object_id,
                    pid,
                )
            )
            primary_thread = self._register_thread(
                process,
                tid=primary_tid,
                kind="primary",
                start_time=self.state.current_time,
            )
            process.primary_tid = primary_thread.tid
            logger.debug(f"Created process {pid} on {system}: {image}")
            return pid

    @staticmethod
    def _process_parent_lifecycle_group(
        lifecycle_group_id: str,
        explicit_parent_group_id: str,
        owning_session: ActiveSession | None,
    ) -> str:
        """Return process lifecycle parentage without a self-parenting group.

        Ordinary processes are children of their owning session. Session-bootstrap
        helpers intentionally share the session group so their parent is instead
        the session's parent, if one exists.
        """

        if explicit_parent_group_id and explicit_parent_group_id != lifecycle_group_id:
            return explicit_parent_group_id
        if owning_session is None:
            return ""
        if owning_session.lifecycle_group_id == lifecycle_group_id:
            return owning_session.parent_lifecycle_group_id
        return owning_session.lifecycle_group_id

    def _allocate_thread_id(self, system: str, process_object_id: str, pid: int) -> int:
        """Allocate a deterministic host-native TID for an explicitly modeled thread."""

        os_category = self._pid_os.get(system, "windows")
        if os_category == "linux":
            candidate = pid + 1 + (_stable_seed(f"linux_tid:{system}:{process_object_id}") % 1024)
            used = {
                thread.tid
                for thread in self._running_threads.find("process_object_id", process_object_id)
            }
            while candidate in used:
                candidate += 1
            return candidate

        counter = self._thread_id_counters.get(
            system,
            2000 + (4 * (_stable_seed(f"windows_tid_initial:{system}") % 5000)),
        )
        rng = self._thread_id_rngs.setdefault(
            system,
            random.Random(_stable_seed(f"windows_tid_alloc:{system}")),
        )
        used = {thread.tid for thread in self._running_threads.find("system", system)}
        candidate = counter - (counter % 4)
        while candidate in used or candidate <= 0:
            candidate += 4
        self._thread_id_counters[system] = candidate + (4 * rng.randint(1, 17))
        return candidate

    def _register_thread(
        self,
        process: RunningProcess,
        *,
        tid: int,
        kind: str,
        start_time: datetime,
    ) -> RunningThread:
        """Register a thread after its live owning process has been validated."""

        key = (process.system, process.ecar_object_id, tid)
        existing = self.state.running_threads.get(key)
        if existing is not None:
            return existing
        thread = RunningThread(
            hostname=process.system,
            process_object_id=process.ecar_object_id,
            pid=process.pid,
            tid=tid,
            object_id=stable_uuid(
                "thread",
                process.system,
                process.ecar_object_id,
                process.pid,
                tid,
                ensure_utc(start_time).isoformat(),
                kind,
            ),
            start_time=ensure_utc(start_time),
            kind=kind,
        )
        self.state.running_threads[key] = thread
        self._ended_threads.pop(key, None)
        return thread

    def create_thread(
        self,
        system: str,
        process_object_id: str,
        *,
        tid: int | None = None,
        kind: str = "worker",
        start_time: datetime | None = None,
    ) -> ThreadIdentity:
        """Create an explicit thread owned by a live canonical process."""

        with self._lock:
            process = self._processes_by_object_id.get(process_object_id)
            if (
                process is None
                or process.system != system
                or self.state.running_processes.get((system, process.pid)) is not process
            ):
                raise StateError(
                    f"Cannot create thread: owning process object is not live on {system}"
                )
            thread_id = tid
            if thread_id is None:
                thread_id = self._allocate_thread_id(system, process_object_id, process.pid)
            if thread_id < 0:
                raise StateError("Cannot create thread: TID must be non-negative")
            effective_start = start_time or self.state.current_time
            if effective_start is None:
                raise StateError("Cannot create thread: current_time not set")
            thread = self._register_thread(
                process,
                tid=thread_id,
                kind=kind,
                start_time=effective_start,
            )
            return self._thread_identity(thread)

    @staticmethod
    def _thread_identity(thread: RunningThread) -> ThreadIdentity:
        """Project mutable runtime thread state to an immutable identity snapshot."""

        return ThreadIdentity(
            hostname=thread.hostname,
            process_object_id=thread.process_object_id,
            pid=thread.pid,
            tid=thread.tid,
            object_id=thread.object_id,
            started_at=thread.start_time,
            kind=thread.kind,
        )

    def get_thread(
        self,
        system: str,
        process_object_id: str,
        tid: int,
    ) -> ThreadIdentity | None:
        """Resolve an active thread by its collision-safe canonical key."""

        with self._lock:
            thread = self.state.running_threads.get((system, process_object_id, tid))
            return self._thread_identity(thread) if thread is not None else None

    def get_primary_thread(self, system: str, pid: int) -> ThreadIdentity | None:
        """Return the immutable primary-thread identity for a live process."""

        with self._lock:
            process = self.state.running_processes.get((system, pid))
            if process is None or process.primary_tid < 0:
                return None
            return self.get_thread(system, process.ecar_object_id, process.primary_tid)

    def end_thread(
        self,
        system: str,
        process_object_id: str,
        tid: int,
        end_time: datetime | None = None,
    ) -> bool:
        """End one explicit thread without affecting identically numbered threads."""

        with self._lock:
            key = (system, process_object_id, tid)
            thread = self.state.running_threads.pop(key, None)
            if thread is None:
                return False
            effective_end = end_time or self.state.current_time
            thread.end_time = ensure_utc(effective_end) if effective_end is not None else None
            self._ended_threads[key] = thread
            return True

    def get_process_identity(self, system: str, pid: int) -> ProcessIdentity | None:
        """Return an immutable snapshot for the currently live process at a host-local PID."""

        with self._lock:
            process = self.state.running_processes.get((system, pid))
            if process is None:
                return None
            return self._process_identity(process)

    def get_process_identity_by_object_id(self, object_id: str) -> ProcessIdentity | None:
        """Resolve a live or ended process by its durable process object identity."""

        with self._lock:
            process = self._processes_by_object_id.get(object_id)
            return self._process_identity(process) if process is not None else None

    def _process_identity(self, process: RunningProcess) -> ProcessIdentity:
        """Project mutable runtime process state to an immutable identity snapshot."""

        primary_thread = None
        if process.primary_tid >= 0:
            key = (process.system, process.ecar_object_id, process.primary_tid)
            thread = self.state.running_threads.get(key) or self._ended_threads.get(key)
            if thread is not None:
                primary_thread = self._thread_identity(thread)
        return ProcessIdentity(
            hostname=process.system,
            object_id=process.ecar_object_id,
            pid=process.pid,
            parent_pid=process.parent_pid,
            image=process.image,
            command_line=process.command_line,
            principal=process.username,
            logon_id=process.logon_id,
            started_at=process.start_time,
            lifecycle_group_id=process.lifecycle_group_id,
            parent_lifecycle_group_id=process.parent_lifecycle_group_id,
            primary_thread=primary_thread,
        )

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
            resolved_logon_id = self._resolve_logon_id(logon_id)
            session = self.state.active_sessions.get(resolved_logon_id)
            if session is not None:
                return session.ecar_object_id
            ended = self._ended_sessions.get(resolved_logon_id) or self._ended_sessions.get(
                logon_id
            )
            return ended[0].ecar_object_id if ended is not None else ""

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
            return self._running_processes.find("username", username)

    def get_processes_on_system(self, system: str) -> list[RunningProcess]:
        """Get all running processes on a system.

        Args:
            system: System hostname to search for

        Returns:
            List of running processes on the system (may be empty)
        """
        with self._lock:
            return self._running_processes.find("system", system)

    def get_processes_for_session(
        self,
        logon_id: str,
        system: str | None = None,
    ) -> list[RunningProcess]:
        """Get running processes owned by one session.

        Args:
            logon_id: Canonical or aliased LogonID to search for.
            system: Optional hostname constraint.

        Returns:
            Running processes owned by the session.
        """
        with self._lock:
            resolved_logon_id = self._resolve_logon_id(logon_id)
            logon_ids = {logon_id, resolved_logon_id}
            processes: dict[tuple[str, int], RunningProcess] = {}
            for candidate_logon_id in logon_ids:
                for process in self._running_processes.find("logon_id", candidate_logon_id):
                    if system is None or process.system == system:
                        processes[(process.system, process.pid)] = process
            return list(processes.values())

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

    def end_process(
        self,
        system: str,
        pid: int,
        end_time: datetime | None = None,
    ) -> bool:
        """End a running process.

        Args:
            system: System hostname
            pid: Process ID

        Returns:
            True if process was found and removed, False if not found
        """
        with self._lock:
            key = (system, pid)
            process = self.state.running_processes.get(key)
            if process is not None:
                thread_keys = [
                    (thread.hostname, thread.process_object_id, thread.tid)
                    for thread in self._running_threads.find(
                        "process_object_id",
                        process.ecar_object_id,
                    )
                ]
                for thread_key in thread_keys:
                    self.end_thread(*thread_key, end_time=end_time)
                del self.state.running_processes[key]
                self._clear_session_process_references(system, pid)
                logger.debug(f"Ended process {pid} on {system}")
                return True
            return False

    def _clear_session_process_references(self, system: str, pid: int) -> None:
        """Clear active-session pointers to a process that has ended."""
        for session in self._active_sessions.find("system", system):
            if session.explorer_pid == pid:
                session.explorer_pid = None
            if session.session_user_manager_pid == pid:
                session.session_user_manager_pid = None
            if session.session_winlogon_pid == pid:
                session.session_winlogon_pid = None
            if session.session_shell_pid == pid:
                session.session_shell_pid = None
            if session.process_tree_root == pid:
                session.process_tree_root = None
            if session.transport_pid == pid:
                session.transport_pid = None

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

    @staticmethod
    def _connection_tuple_key(
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
    ) -> tuple[str, int, str, int, str]:
        """Return the normalized key used to index an exact network tuple."""
        return (
            src_ip.removeprefix("::ffff:"),
            src_port,
            dst_ip.removeprefix("::ffff:"),
            dst_port,
            protocol,
        )

    def _index_connection(self, connection: OpenConnection) -> None:
        """Add a connection to the exact-tuple lookup index."""
        self._open_connections.refresh(connection.conn_id)
        self._refresh_connection_lifecycle(connection)

    def _refresh_connection_lifecycle(self, connection: OpenConnection) -> None:
        """Refresh close-time and terminal-state indexes for a connection."""
        if connection.close_time is None:
            self._connection_expirations.pop(connection.conn_id, None)
        else:
            self._connection_expirations.set(
                connection.conn_id,
                True,
                ensure_utc(connection.close_time).timestamp(),
            )
        if connection.state in self._TERMINAL_CONN_STATES:
            self._terminal_connection_ids[connection.conn_id] = None
        else:
            self._terminal_connection_ids.pop(connection.conn_id, None)

    def _remove_connection(self, conn_id: str) -> bool:
        """Remove a connection and its exact-tuple index entry."""
        removed = self._open_connections.pop(conn_id, None)
        if removed is None:
            return False
        self._connection_expirations.pop(conn_id, None)
        self._terminal_connection_ids.pop(conn_id, None)
        return True

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

            conn_id, zeek_uid = self.reserve_connection_identity()

            # Create connection with Zeek UID for cross-log correlation
            connection = OpenConnection(
                conn_id=conn_id,
                zeek_uid=zeek_uid,
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
            self._index_connection(connection)
            logger.debug(
                f"Opened connection {conn_id}: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol})"
            )
            return conn_id

    def reserve_connection_identity(self) -> tuple[str, str]:
        """Reserve deterministic connection and Zeek identities without opening state.

        Application transactions on a reused transport still occupy one logical
        connection-request identity in the deterministic stream, but they reuse the
        parent's rendered tuple and UID instead of creating a shadow OpenConnection.
        """

        with self._lock:
            if self._connection_id_counter > 999999999:
                raise StateError("Connection ID counter exhausted")
            conn_id = f"conn-{self._connection_id_counter}"
            self._connection_id_counter += 1
            return conn_id, generate_zeek_uid("C")

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

    def get_connection_by_zeek_uid(self, zeek_uid: str) -> OpenConnection | None:
        """Return the canonical connection with a Zeek UID."""
        with self._lock:
            matches = self._open_connections.find("zeek_uid", zeek_uid)
            return matches[0] if matches else None

    def get_connection_by_transaction_id(
        self,
        transaction_id: str,
    ) -> OpenConnection | None:
        """Return the unique canonical connection for a transaction ID."""
        with self._lock:
            matches = self._open_connections.find("transaction_id", transaction_id)
            return matches[0] if len(matches) == 1 else None

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
            self._refresh_connection_lifecycle(conn)
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

    def update_connection_transaction(
        self,
        conn_id: str,
        transaction: NetworkTransactionPlan,
    ) -> bool:
        """Persist finalized canonical connection truth in runtime state."""

        with self._lock:
            conn = self.state.open_connections.get(conn_id)
            if conn is None:
                return False
            conn.start_time = ensure_utc(transaction.started_at)
            conn.close_time = (
                ensure_utc(transaction.closed_at) if transaction.closed_at is not None else None
            )
            conn.conn_state = transaction.conn_state
            conn.state = "closed" if transaction.closed_at is not None else transaction.conn_state
            conn.history = transaction.history
            conn.duration = transaction.duration
            conn.traffic_ledger = transaction.traffic
            conn.bytes_sent = transaction.traffic.orig.payload_bytes
            conn.bytes_received = transaction.traffic.resp.payload_bytes
            self._open_connections.refresh(conn_id)
            self._refresh_connection_lifecycle(conn)
            return True

    def connection_tuple_recently_used(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        time: datetime,
        *,
        reuse_window: float,
    ) -> bool:
        """Return whether indexed live state contains a recent exact tuple.

        Lookup cost depends on the number of connections sharing the requested
        tuple, rather than the total number of retained connections.
        """
        with self._lock:
            key = self._connection_tuple_key(src_ip, src_port, dst_ip, dst_port, protocol)
            connections = self._open_connections.find("exact_tuple", key)
            if not connections:
                return False

            timestamp = ensure_utc(time).timestamp()
            for connection in connections:
                if connection.state in self._TERMINAL_CONN_STATES:
                    continue
                observed_times = [ensure_utc(connection.start_time)]
                if connection.close_time is not None:
                    observed_times.append(ensure_utc(connection.close_time))
                if any(
                    abs(timestamp - observed.timestamp()) <= reuse_window
                    for observed in observed_times
                ):
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
            if self._remove_connection(conn_id):
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

    def sweep_closed_connections(self, cutoff: datetime | None = None) -> int:
        """Evict completed/failed connections to bound memory growth.

        Call between generation phases (e.g., between hourly passes). Connections
        with a known close time are retained until that simulated time has passed,
        even when generation order reserves future activity early.

        Args:
            cutoff: Simulated time through which completed connections can be removed.
                Defaults to the state manager's current time.

        Returns:
            Number of connections evicted.
        """
        with self._lock:
            effective_cutoff = (
                ensure_utc(cutoff)
                if cutoff is not None
                else (
                    ensure_utc(self.state.current_time)
                    if self.state.current_time is not None
                    else None
                )
            )
            to_remove: dict[str, None] = dict(self._terminal_connection_ids)
            if effective_cutoff is not None:
                for conn_id, _marker in self._connection_expirations.expire_before(
                    effective_cutoff.timestamp(),
                    inclusive=True,
                ):
                    to_remove[conn_id] = None
            for cid in to_remove:
                self._remove_connection(cid)
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
            process_pid = -1
            process_host = ""
            if event.process is not None and event.src_host is not None:
                process_pid = event.process.pid
                process_host = event.src_host.hostname
            elif event.identity_plan is not None and isinstance(
                event.identity_plan.actor, ProcessIdentity
            ):
                process_pid = event.identity_plan.actor.pid
                process_host = event.identity_plan.actor.hostname
            if event.event_type != "process_terminate" and process_pid >= 0 and process_host:
                proc = self.state.running_processes.get((process_host, process_pid))
                if proc is not None:
                    activity_time = ensure_utc(event.timestamp)
                    if event.network is not None and event.network.transaction is not None:
                        closed_at = event.network.transaction.closed_at
                        if closed_at is not None:
                            activity_time = max(activity_time, ensure_utc(closed_at))
                    if proc.last_activity_time is None or activity_time > proc.last_activity_time:
                        proc.last_activity_time = activity_time

            if event.event_type == "logoff" and event.auth:
                self.end_session(event.auth.logon_id, event.timestamp)
            elif event.event_type == "process_terminate" and event.process and event.src_host:
                self.end_process(event.src_host.hostname, event.process.pid, event.timestamp)
            elif event.event_type == "connection" and event.network:
                event.network.validate_finalized_transaction()
                if event.network.conn_id:
                    conn = self.state.open_connections.get(event.network.conn_id)
                    if conn is not None:
                        transaction = event.network.transaction
                        if transaction is not None:
                            conn.transaction_id = transaction.stable_id
                            if event.network.application_layer_only:
                                conn.traffic_ledger = conn.traffic_ledger.accumulate(
                                    transaction.traffic
                                )
                            else:
                                conn.traffic_ledger = transaction.traffic
                            conn.bytes_sent = transaction.traffic.orig.payload_bytes
                            conn.bytes_received = transaction.traffic.resp.payload_bytes
                            if event.network.application_layer_only:
                                conn.bytes_sent = conn.traffic_ledger.orig.payload_bytes
                                conn.bytes_received = conn.traffic_ledger.resp.payload_bytes
                                if transaction.closed_at is not None and (
                                    conn.close_time is None
                                    or ensure_utc(transaction.closed_at) > conn.close_time
                                ):
                                    conn.close_time = ensure_utc(transaction.closed_at)
                                if conn.close_time is not None:
                                    conn.duration = max(
                                        0.0,
                                        (conn.close_time - conn.start_time).total_seconds(),
                                    )
                            else:
                                conn.history = transaction.history
                                conn.duration = transaction.duration
                                conn.start_time = ensure_utc(transaction.started_at)
                                conn.close_time = (
                                    ensure_utc(transaction.closed_at)
                                    if transaction.closed_at is not None
                                    else None
                                )
                                conn.conn_state = transaction.conn_state
                                conn.state = (
                                    "closed"
                                    if transaction.closed_at is not None
                                    else transaction.conn_state
                                )
                        else:
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
                        if transaction is None and event.network.duration is not None:
                            conn.close_time = event.timestamp + timedelta(
                                seconds=event.network.duration
                            )
                            conn.state = "closed"
                        elif transaction is None and event.network.conn_state:
                            conn.state = event.network.conn_state
                        self._open_connections.refresh(conn.conn_id)
                        self._refresh_connection_lifecycle(conn)
