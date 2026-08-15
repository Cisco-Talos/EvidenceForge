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

from evidenceforge.events.authentication import windows_logon_can_own_desktop
from evidenceforge.events.base import CanonicalOccurrence
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
    SmbFileState,
    SmbHandleState,
    SmbSessionState,
    SmbTreeState,
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
_LINUX_PID_MIN = 500
_LINUX_PID_MAX_EXCLUSIVE = 4_194_304
_LINUX_PID_REORDER_LANE_SECONDS = 30
_LINUX_PID_REORDER_LANE_WIDTH = 47
_LINUX_PID_REORDER_LANE_HEADROOM = 11
_WINDOWS_PID_MIN = 4_000
_WINDOWS_PID_MAX = 65_532
_WINDOWS_PID_STEP = 4
_MINUTES_PER_WEEK = 7 * 24 * 60
_ENDED_IDENTITY_RETENTION = timedelta(hours=48)
_MAX_RETAINED_PROCESS_IDENTITIES = 500_000
_MAX_RETAINED_THREAD_IDENTITIES = 1_000_000
_MAX_SMB_MUTATION_OVERLAY = 100_000


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
        self._pid_bucket_offsets: dict[tuple[str, datetime], int] = {}
        self._linux_pid_weekly_churn_prefixes: dict[str, tuple[int, ...]] = {}
        self._linux_pid_allocations: dict[str, TemporalAllocationIndex] = {}
        self._pid_allocation_watermark: datetime | None = None
        self._pid_sealed_logical_positions: dict[str, int] = {}
        self._fixed_pid_reservations: dict[str, set[int]] = {}
        self._active_pid_reservation_counts: dict[str, int] = {}
        self._transient_pid_reservations: dict[str, dict[int, list[tuple[datetime, datetime]]]] = {}
        self._transient_pid_reservation_counts: dict[str, int] = {}
        self._pid_candidate_probe_count = 0
        self._pid_allocation_count = 0
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
        self._ended_processes_by_key: ExpiringIndex[tuple[str, int], RunningProcess] = (
            ExpiringIndex()
        )
        self._ended_processes_by_object_id: ExpiringIndex[str, RunningProcess] = ExpiringIndex()
        self._ended_threads: ExpiringIndex[tuple[str, str, int], RunningThread] = ExpiringIndex()
        self._smb_sessions: dict[str, SmbSessionState] = {}
        self._smb_session_affinity: dict[tuple[str, str, str, str, str, str], str] = {}
        self._smb_trees: dict[str, SmbTreeState] = {}
        self._smb_tree_by_session_share: dict[tuple[str, str], str] = {}
        self._smb_handles: dict[str, SmbHandleState] = {}
        self._smb_file_overlay: dict[str, SmbFileState] = {}
        self._smb_file_by_share_path: dict[tuple[str, str], str] = {}

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
        if not windows_logon_can_own_desktop(logon_type) or session_kind in {
            "network",
            "new_credentials",
            "service",
            "ssh",
        }:
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
        auth_protocol: str = "",
        smb_principal: str = "",
        account_scope: str = "",
        auth_session_ref: str = "",
        effective_uid: int | None = None,
        effective_gid: int | None = None,
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
                auth_protocol=auth_protocol,
                smb_principal=smb_principal,
                account_scope=account_scope,
                auth_session_ref=auth_session_ref,
                effective_uid=effective_uid,
                effective_gid=effective_gid,
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
        auth_protocol: str = "",
        smb_principal: str = "",
        account_scope: str = "",
        auth_session_ref: str = "",
        effective_uid: int | None = None,
        effective_gid: int | None = None,
    ) -> ActiveSession:
        """Register a pre-existing session in state.

        This is primarily used by compatibility paths where a mocked or
        external generator returns a LogonID without recording the session
        through ``create_session()``.
        """
        with self._lock:
            resolved_logon_id = self._resolve_logon_id(logon_id)
            existing = self.state.active_sessions.get(logon_id) or self.state.active_sessions.get(
                resolved_logon_id
            )
            if existing is not None:
                return existing
            if logon_id in self._ended_sessions or resolved_logon_id in self._ended_sessions:
                raise StateError(
                    "Cannot register a new session with ended LogonID "
                    f"{logon_id}; allocate a fresh canonical LogonID"
                )
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
                auth_protocol=auth_protocol,
                smb_principal=smb_principal,
                account_scope=account_scope,
                auth_session_ref=auth_session_ref,
                effective_uid=effective_uid,
                effective_gid=effective_gid,
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
        closure_owned_by_bundle: bool | None = None,
        network_close_time: datetime | None = None,
        source_ready_time: datetime | None = None,
        logon_guid: str | None = None,
        session_id: int | None = None,
        lifecycle_group_id: str | None = None,
        parent_lifecycle_group_id: str | None = None,
        auth_protocol: str | None = None,
        smb_principal: str | None = None,
        account_scope: str | None = None,
        auth_session_ref: str | None = None,
        effective_uid: int | None = None,
        effective_gid: int | None = None,
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
            if closure_owned_by_bundle is not None:
                session.closure_owned_by_bundle = closure_owned_by_bundle
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
                if session.session_id not in {0, session_id}:
                    raise StateError(
                        "Cannot replace published session ID for "
                        f"{logon_id}: {session.session_id} -> {session_id}"
                    )
                session.session_id = session_id
            if lifecycle_group_id is not None:
                session.lifecycle_group_id = lifecycle_group_id
            if parent_lifecycle_group_id is not None:
                session.parent_lifecycle_group_id = parent_lifecycle_group_id
            if auth_protocol is not None:
                session.auth_protocol = auth_protocol
            if smb_principal is not None:
                session.smb_principal = smb_principal
            if account_scope is not None:
                session.account_scope = account_scope
            if auth_session_ref is not None:
                session.auth_session_ref = auth_session_ref
            if effective_uid is not None:
                session.effective_uid = effective_uid
            if effective_gid is not None:
                session.effective_gid = effective_gid
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

    def _linux_pid_weekly_churn_prefix(self, system: str) -> tuple[int, ...]:
        """Return cached hidden process churn at each minute boundary in a week.

        Real Linux hosts consume PIDs for short-lived processes that may never be
        represented in collected endpoint telemetry. A fixed elapsed-seconds
        multiplier exposes generator time directly, so model that hidden churn as
        a stable host-specific weekly schedule. The prefix table trades bounded
        memory for O(1) lookup, including for far-future timestamps.
        """
        cached = self._linux_pid_weekly_churn_prefixes.get(system)
        if cached is not None:
            return cached

        rng = random.Random(_stable_seed(f"linux_pid_hidden_churn:{system}"))
        prefix = [0]
        hourly_factor = 1.0
        hourly_regimes = [0.20, 0.40, 0.70, 1.00, 1.50, 2.80]
        for minute_of_week in range(_MINUTES_PER_WEEK):
            day = minute_of_week // (24 * 60)
            minute_of_day = minute_of_week % (24 * 60)
            hour = minute_of_day // 60
            if minute_of_day % 60 == 0:
                if hour % len(hourly_regimes) == 0:
                    rng.shuffle(hourly_regimes)
                hourly_factor = hourly_regimes[hour % len(hourly_regimes)]
            if day >= 5:
                base_churn = 76
            elif 8 <= hour < 18:
                base_churn = 116
            else:
                base_churn = 92
            hourly_target = round(base_churn * hourly_factor)
            lower = max(48, round(hourly_target * 0.45))
            upper = min(720, max(lower, round(hourly_target * 1.55)))
            churn = rng.randint(lower, upper)
            if rng.random() < 0.04:
                churn += rng.randint(90, 480)
            # Baseline families can discover process starts out of traversal
            # order. Reserve two disjoint 30-second logical lanes per minute so
            # every later lane remains numerically above every earlier lane.
            # Forty-seven positions gives the measured 36-position dense SSH
            # bootstrap burst eleven positions of deterministic headroom without materially
            # changing the workload-shaped churn when it is already larger.
            lane_floor = 2 * _LINUX_PID_REORDER_LANE_WIDTH
            churn = max(churn, lane_floor)
            prefix.append(prefix[-1] + churn)

        frozen = tuple(prefix)
        self._linux_pid_weekly_churn_prefixes[system] = frozen
        return frozen

    def _linux_pid_hidden_churn_offset(self, system: str, elapsed_seconds: int) -> int:
        """Return hidden PID consumption before an elapsed host-runtime offset."""
        if elapsed_seconds <= 0:
            return 0

        prefix = self._linux_pid_weekly_churn_prefix(system)
        elapsed_minutes, second_in_minute = divmod(elapsed_seconds, 60)
        full_weeks, minute_of_week = divmod(elapsed_minutes, _MINUTES_PER_WEEK)
        weekly_churn = prefix[-1]
        minute_churn = prefix[minute_of_week + 1] - prefix[minute_of_week]
        partial_churn = (second_in_minute * minute_churn) // 60
        return (full_weeks * weekly_churn) + prefix[minute_of_week] + partial_churn

    def _linux_pid_reorder_lane(
        self,
        system: str,
        epoch: datetime,
        elapsed_seconds: int,
    ) -> tuple[datetime, datetime, int, int]:
        """Return time and logical-offset bounds for one 30-second PID lane."""

        lane_start_seconds = (
            max(0, elapsed_seconds) // _LINUX_PID_REORDER_LANE_SECONDS
        ) * _LINUX_PID_REORDER_LANE_SECONDS
        lane_end_seconds = lane_start_seconds + _LINUX_PID_REORDER_LANE_SECONDS
        lane_start = epoch + timedelta(seconds=lane_start_seconds)
        lane_end = epoch + timedelta(seconds=lane_end_seconds)
        logical_start = self._linux_pid_hidden_churn_offset(system, lane_start_seconds)
        logical_end = self._linux_pid_hidden_churn_offset(system, lane_end_seconds)
        if logical_end - logical_start < _LINUX_PID_REORDER_LANE_WIDTH:
            raise StateError(
                "Linux PID reorder lane is narrower than its configured capacity "
                f"(host={system}, start={lane_start.isoformat()}, "
                f"width={logical_end - logical_start}, "
                f"required={_LINUX_PID_REORDER_LANE_WIDTH})"
            )
        return lane_start, lane_end, logical_start, logical_end

    def _linux_pid_block_offset(self, system: str, block: int) -> int:
        """Return hidden churn at a coarse block without materializing block history."""
        if block <= 0:
            return 0
        return self._linux_pid_hidden_churn_offset(
            system,
            block * _LINUX_PID_BLOCK_SECONDS,
        )

    @staticmethod
    def _normalize_linux_pid(pid: int) -> int:
        """Render an unbounded logical position in Linux's PID ring.

        Linux treats ``pid_max`` as an exclusive wrap boundary, so the largest
        rendered PID is 4,194,303.
        """
        return _LINUX_PID_MIN + (
            (pid - _LINUX_PID_MIN) % (_LINUX_PID_MAX_EXCLUSIVE - _LINUX_PID_MIN)
        )

    @staticmethod
    def _normalize_windows_pid(pid: int) -> int:
        """Render an unbounded logical position in the modeled Windows PID ring."""
        slots = ((_WINDOWS_PID_MAX - _WINDOWS_PID_MIN) // _WINDOWS_PID_STEP) + 1
        slot = ((pid - _WINDOWS_PID_MIN) // _WINDOWS_PID_STEP) % slots
        return _WINDOWS_PID_MIN + (slot * _WINDOWS_PID_STEP)

    def _allocate_windows_pid(
        self,
        system: str,
        pid_rng: random.Random,
        current_time: datetime,
    ) -> tuple[int, int]:
        """Allocate a Windows PID without overwriting a live process instance."""
        logical_position = self._pid_counters[system]
        gap = max(1, int(pid_rng.lognormvariate(1.2, 0.8)))
        next_logical_position = logical_position + (_WINDOWS_PID_STEP * gap)
        occupied = self._reserved_pid_count(system)
        for _probe in range(occupied + 1):
            self._pid_candidate_probe_count += 1
            if logical_position <= _WINDOWS_PID_MAX:
                pid = logical_position
            else:
                pid = self._normalize_windows_pid(logical_position)
            if not self._pid_is_reserved(system, pid, current_time, None):
                self._pid_counters[system] = max(
                    next_logical_position,
                    logical_position + _WINDOWS_PID_STEP,
                )
                self._pid_allocation_count += 1
                return pid, logical_position
            logical_position += _WINDOWS_PID_STEP
        raise StateError("Windows PID namespace is fully occupied by active reservations")

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

    def _pid_is_reserved(
        self,
        system: str,
        pid: int,
        start_time: datetime,
        release_time: datetime | None,
    ) -> bool:
        """Return whether a rendered PID overlaps any live reservation."""
        if (system, pid) in self.state.running_processes:
            return True
        if pid in self._fixed_pid_reservations.get(system, set()):
            return True
        candidate_end = release_time or datetime.max.replace(tzinfo=start_time.tzinfo)
        ended = self._ended_processes_by_key.get((system, pid))
        if ended is not None and ended.end_time is not None:
            ended_start = ensure_utc(ended.start_time)
            ended_end = ensure_utc(ended.end_time)
            if ensure_utc(start_time) <= ended_end and ended_start <= ensure_utc(candidate_end):
                return True
        for reserved_start, reserved_end in self._transient_pid_reservations.get(system, {}).get(
            pid, ()
        ):
            if start_time <= reserved_end and reserved_start <= candidate_end:
                return True
        return False

    def _reserved_pid_count(self, system: str) -> int:
        """Return an upper bound on occupied rendered PIDs for bounded probing."""
        return (
            self._active_pid_reservation_counts.get(system, 0)
            + len(self._fixed_pid_reservations.get(system, ()))
            + self._transient_pid_reservation_counts.get(system, 0)
        )

    def advance_pid_allocation_watermark(self, cutoff: datetime) -> None:
        """Seal PID allocation history before an authoritative engine boundary.

        Detailed temporal records exist only for the still-open scheduling window.
        Sealed history is represented by one greatest logical position per host.
        """
        normalized_cutoff = ensure_utc(cutoff)
        with self._lock:
            if (
                self._pid_allocation_watermark is not None
                and normalized_cutoff < self._pid_allocation_watermark
            ):
                raise StateError("PID allocation watermark cannot move backward")
            for system, allocations in self._linux_pid_allocations.items():
                discarded = allocations.discard_before(normalized_cutoff)
                if discarded is not None:
                    self._pid_sealed_logical_positions[system] = max(
                        discarded,
                        self._pid_sealed_logical_positions.get(system, discarded),
                    )
            self._pid_bucket_offsets = {
                key: value
                for key, value in self._pid_bucket_offsets.items()
                if key[1] >= normalized_cutoff
            }
            for system, reservations in tuple(self._transient_pid_reservations.items()):
                retained: dict[int, list[tuple[datetime, datetime]]] = {}
                for pid, intervals in reservations.items():
                    live = [interval for interval in intervals if interval[1] >= normalized_cutoff]
                    if live:
                        retained[pid] = live
                if retained:
                    self._transient_pid_reservations[system] = retained
                    self._transient_pid_reservation_counts[system] = sum(
                        len(intervals) for intervals in retained.values()
                    )
                else:
                    del self._transient_pid_reservations[system]
                    self._transient_pid_reservation_counts.pop(system, None)
            self._pid_allocation_watermark = normalized_cutoff

    def pid_allocator_census(self) -> dict[str, int]:
        """Return stable allocator-state and operation counters for probes."""
        with self._lock:
            return {
                "open_allocations": sum(
                    len(index) for index in self._linux_pid_allocations.values()
                ),
                "open_ordinals": len(self._pid_bucket_offsets),
                "sealed_hosts": len(self._pid_sealed_logical_positions),
                "active_reservations": sum(self._active_pid_reservation_counts.values()),
                "fixed_reservations": sum(
                    len(reservations) for reservations in self._fixed_pid_reservations.values()
                ),
                "transient_reservations": sum(
                    len(intervals)
                    for reservations in self._transient_pid_reservations.values()
                    for intervals in reservations.values()
                ),
                "allocations": self._pid_allocation_count,
                "candidate_probes": self._pid_candidate_probe_count,
            }

    def _allocate_linux_pid(
        self,
        system: str,
        pid_rng: random.Random,
        current_time: datetime | None = None,
        minimum_logical_exclusive: int | None = None,
        reservation_end: datetime | None = None,
    ) -> tuple[int, int]:
        """Allocate a Linux PID from an unbounded logical sequence."""
        current_time = ensure_utc(current_time or self.state.current_time)
        if (
            self._pid_allocation_watermark is not None
            and current_time < self._pid_allocation_watermark
        ):
            raise StateError(
                "Cannot allocate PID before the sealed allocation watermark: "
                f"{current_time.isoformat()} < {self._pid_allocation_watermark.isoformat()}"
            )
        epoch = self._linux_pid_epoch(system, current_time)
        elapsed_seconds = max(0, int((current_time - epoch).total_seconds()))
        time_offset = self._linux_pid_hidden_churn_offset(system, elapsed_seconds)
        lane_start, lane_end, lane_start_offset, lane_end_offset = self._linux_pid_reorder_lane(
            system, epoch, elapsed_seconds
        )
        lane_lower_bound = self._pid_counters[system] + lane_start_offset
        lane_upper_bound = self._pid_counters[system] + lane_end_offset
        ordinal_key = (system, current_time)
        ordinal = self._pid_bucket_offsets.get(ordinal_key, 0)
        gap = max(1, min(5, int(pid_rng.lognormvariate(0.3, 0.8))))

        # Keep timestamp-shaped placement inside the lane, but cap the natural
        # position below its upper edge. A burst discovered at second 29 then
        # retains the same measured headroom instead of seeing the lane as
        # already consumed merely because wall-clock time advanced.
        lane_width = lane_upper_bound - lane_lower_bound
        natural_offset = min(
            max(0, time_offset - lane_start_offset),
            lane_width - _LINUX_PID_REORDER_LANE_HEADROOM - 1,
        )
        natural_lane_position = lane_lower_bound + natural_offset
        logical_position = natural_lane_position + ordinal
        natural_logical_position = logical_position
        allocations = self._linux_pid_allocations.setdefault(
            system,
            TemporalAllocationIndex(),
        )
        prior_logical = allocations.max_value_at_or_before(current_time)
        sealed_logical = self._pid_sealed_logical_positions.get(system)
        lower_bound = max(
            value
            for value in (minimum_logical_exclusive, prior_logical, sealed_logical, 0)
            if value is not None
        )
        future_logical = allocations.min_value_after(current_time)
        future_record = allocations.first_record_after(current_time)
        future_lane_record = allocations.first_record_after(lane_end - timedelta(microseconds=1))
        logical_position = max(logical_position, lower_bound + 1, lane_lower_bound)
        if future_logical is not None and logical_position >= future_logical:
            logical_position = max(lower_bound + 1, lane_lower_bound)
        if future_logical is not None and logical_position >= future_logical:
            future_time = future_record[0] if future_record is not None else None
            if future_time is not None and future_time < lane_end:
                # The rendered chronology gate permits only this bounded
                # same-lane traversal reordering. Never escape into a later
                # lane: that was the source of multi-minute PID reversals.
                logical_position = max(natural_logical_position, lower_bound, future_logical) + 1
                future_logical = None
            else:
                raise StateError(
                    "Cannot allocate Linux PID inside its bounded 30-second reorder lane; "
                    f"(host={system}, time={current_time.isoformat()}, lower={lower_bound}, "
                    f"candidate={logical_position}, future={future_logical}, "
                    f"future_time={future_time}, lane_start={lane_start.isoformat()}, "
                    f"lane_end={lane_end.isoformat()})."
                )

        if logical_position >= lane_upper_bound and future_lane_record is not None:
            raise StateError(
                "Linux PID 30-second reorder lane capacity exhausted "
                f"(host={system}, time={current_time.isoformat()}, "
                f"lane_start={lane_start.isoformat()}, lane_end={lane_end.isoformat()}, "
                f"capacity={lane_upper_bound - lane_lower_bound})."
            )

        occupied = self._reserved_pid_count(system) + len(allocations)
        available_positions = max(0, lane_upper_bound - logical_position)
        probe_budget = (
            min(occupied + 1, available_positions)
            if future_lane_record is not None
            else occupied + 1
        )
        for _probe in range(probe_budget):
            self._pid_candidate_probe_count += 1
            pid = self._normalize_linux_pid(logical_position)
            if not allocations.contains_value(logical_position) and not self._pid_is_reserved(
                system,
                pid,
                current_time,
                reservation_end,
            ):
                allocations.add(current_time, logical_position)
                consumed = logical_position - natural_lane_position
                self._pid_bucket_offsets[ordinal_key] = max(ordinal + gap, consumed + gap)
                self._pid_allocation_count += 1
                return pid, logical_position
            logical_position += 1
            if logical_position >= lane_upper_bound and future_lane_record is not None:
                break
            if future_logical is not None and logical_position >= future_logical:
                future_time = future_record[0] if future_record is not None else None
                if future_time is not None and future_time < lane_end:
                    logical_position = future_logical + 1
                    future_logical = None
                    continue
                raise StateError(
                    "Cannot allocate Linux PID before a future lane; "
                    "the current 30-second lane contains only reserved candidates."
                )
        raise StateError(
            "Linux PID 30-second reorder lane contains only reserved candidates "
            f"(host={system}, time={current_time.isoformat()}, "
            f"lane_start={lane_start.isoformat()}, lane_end={lane_end.isoformat()})."
        )

    def allocate_transient_linux_pid(
        self,
        system: str,
        event_time: datetime,
        os_category: str = "linux",
        release_time: datetime | None = None,
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
            normalized_event_time = ensure_utc(event_time)
            normalized_release_time = ensure_utc(
                release_time or (normalized_event_time + timedelta(seconds=1))
            )
            if normalized_release_time < normalized_event_time:
                raise StateError("Transient PID release time cannot precede its allocation")
            pid, _logical_position = self._allocate_linux_pid(
                system,
                pid_rng,
                normalized_event_time,
                reservation_end=normalized_release_time,
            )
            self._transient_pid_reservations.setdefault(system, {}).setdefault(pid, []).append(
                (normalized_event_time, normalized_release_time)
            )
            self._transient_pid_reservation_counts[system] = (
                self._transient_pid_reservation_counts.get(system, 0) + 1
            )
            return pid

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
            self._fixed_pid_reservations.setdefault(system, set()).add(pid)
            if os_category == "linux":
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
                pid_logical_position=pid,
            )
            self.state.running_processes[(system, pid)] = process
            self._active_pid_reservation_counts[system] = (
                self._active_pid_reservation_counts.get(system, 0) + 1
            )
            self._process_object_ids[(system, pid)] = object_id
            self._processes_by_object_id[object_id] = process
            self._ended_processes_by_key.pop((system, pid), None)
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
                pid, pid_logical_position = self._allocate_windows_pid(
                    system,
                    pid_rng,
                    self.state.current_time,
                )
            else:
                minimum_logical_exclusive = None
                parent = self.state.running_processes.get((system, parent_pid))
                if (
                    parent is not None
                    and parent.start_time <= self.state.current_time
                    and parent.pid > 1
                ):
                    minimum_logical_exclusive = parent.pid_logical_position
                pid, pid_logical_position = self._allocate_linux_pid(
                    system,
                    pid_rng,
                    minimum_logical_exclusive=minimum_logical_exclusive,
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
                pid_logical_position=pid_logical_position,
            )

            key = (system, pid)
            if key in self.state.running_processes:
                raise StateError(f"Cannot create process: PID {pid} already exists on {system}")
            self.state.running_processes[key] = process
            self._active_pid_reservation_counts[system] = (
                self._active_pid_reservation_counts.get(system, 0) + 1
            )
            self._process_object_ids[key] = ecar_object_id
            self._processes_by_object_id[ecar_object_id] = process
            self._ended_processes_by_key.pop(key, None)
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
            if thread.end_time is not None:
                deadline = (thread.end_time + _ENDED_IDENTITY_RETENTION).timestamp()
                self._ended_threads.set(key, thread, deadline)
                self._trim_retained_thread_identities()
            return True

    def get_process_identity(self, system: str, pid: int) -> ProcessIdentity | None:
        """Return the latest immutable process identity at a host-local PID."""

        with self._lock:
            process = self.state.running_processes.get((system, pid))
            if process is None:
                process = self._ended_processes_by_key.get((system, pid))
            if process is None:
                return None
            return self._process_identity(process)

    def get_process_identity_by_object_id(self, object_id: str) -> ProcessIdentity | None:
        """Resolve a live or ended process by its durable process object identity."""

        with self._lock:
            process = self._processes_by_object_id.get(
                object_id
            ) or self._ended_processes_by_object_id.get(object_id)
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

    def is_process_active_at(self, system: str, pid: int, time: datetime) -> bool:
        """Return whether a live or retained process identity spans ``time``."""
        with self._lock:
            process = self.state.running_processes.get((system, pid))
            if process is None:
                process = self._ended_processes_by_key.get((system, pid))
            if process is None:
                return False
            effective_time = ensure_utc(time)
            return process.start_time <= effective_time and (
                process.end_time is None or effective_time < process.end_time
            )

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
            ended = self._ended_processes_by_key.get(key)
            return ended.ecar_object_id if ended is not None else ""

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

    def assign_process_to_session(self, system: str, pid: int, logon_id: str) -> bool:
        """Attach a running process to its owning active session.

        This is used when a tuple-scoped responder must be materialized before
        authentication has finished allocating the session identity. Secondary
        indexes are refreshed so later session closure can find the process.
        """
        with self._lock:
            key = (system, pid)
            process = self.state.running_processes.get(key)
            resolved_logon_id = self._resolve_logon_id(logon_id)
            session = self.state.active_sessions.get(resolved_logon_id)
            if process is None or session is None or session.system != system:
                return False
            if process.logon_id:
                current_logon_id = self._resolve_logon_id(process.logon_id)
                if current_logon_id != resolved_logon_id and current_logon_id not in {
                    "0x3e4",
                    "0x3e5",
                    "0x3e7",
                }:
                    raise StateError(
                        f"Process {pid} on {system} already belongs to session "
                        f"{process.logon_id}, not {logon_id}"
                    )
            process.logon_id = resolved_logon_id
            self._running_processes.refresh(key)
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
                effective_end = ensure_utc(
                    end_time or self.state.current_time or process.start_time
                )
                thread_keys = [
                    (thread.hostname, thread.process_object_id, thread.tid)
                    for thread in self._running_threads.find(
                        "process_object_id",
                        process.ecar_object_id,
                    )
                ]
                for thread_key in thread_keys:
                    self.end_thread(*thread_key, end_time=effective_end)
                del self.state.running_processes[key]
                remaining = self._active_pid_reservation_counts.get(system, 1) - 1
                if remaining > 0:
                    self._active_pid_reservation_counts[system] = remaining
                else:
                    self._active_pid_reservation_counts.pop(system, None)
                process.end_time = effective_end
                self._process_object_ids.pop(key, None)
                self._processes_by_object_id.pop(process.ecar_object_id, None)
                deadline = (effective_end + _ENDED_IDENTITY_RETENTION).timestamp()
                self._ended_processes_by_key.set(key, process, deadline)
                self._ended_processes_by_object_id.set(
                    process.ecar_object_id,
                    process,
                    deadline,
                )
                self._trim_retained_process_identities()
                self._clear_session_process_references(system, pid)
                logger.debug(f"Ended process {pid} on {system}")
                return True
            return False

    def _trim_retained_process_identities(self) -> None:
        """Enforce a hard cap while preserving the newest ended process identities."""

        removed = self._ended_processes_by_object_id.trim_earliest(
            _MAX_RETAINED_PROCESS_IDENTITIES,
        )
        for _object_id, process in removed:
            key = (process.system, process.pid)
            if self._ended_processes_by_key.get(key) is process:
                self._ended_processes_by_key.pop(key, None)

    def _trim_retained_thread_identities(self) -> None:
        """Enforce a hard cap while preserving the newest ended thread identities."""

        self._ended_threads.trim_earliest(_MAX_RETAINED_THREAD_IDENTITIES)

    def _expire_retained_identities(self, current_time: datetime) -> None:
        """Expire ended identity snapshots outside the explicit late-reference window."""

        cutoff = ensure_utc(current_time).timestamp()
        expired = self._ended_processes_by_object_id.expire_before(cutoff, inclusive=True)
        for _object_id, process in expired:
            key = (process.system, process.pid)
            if self._ended_processes_by_key.get(key) is process:
                self._ended_processes_by_key.pop(key, None)
        for _key, process in self._ended_processes_by_key.expire_before(cutoff, inclusive=True):
            if self._ended_processes_by_object_id.get(process.ecar_object_id) is process:
                self._ended_processes_by_object_id.pop(process.ecar_object_id, None)
        self._ended_threads.expire_before(cutoff, inclusive=True)

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
            self._expire_retained_identities(dt)
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
            self._expire_retained_identities(self.state.current_time)
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

    # ========================================
    # Canonical SMB Runtime State
    # ========================================

    def open_smb_session(
        self,
        *,
        client_ip: str,
        principal: str,
        server: str,
        security_policy: str,
        logon_id: str,
        transport_uid: str,
        started_at: datetime,
        auth_session_ref: str = "",
        auth_protocol: str = "",
        account_scope: str = "",
        effective_uid: int | None = None,
        effective_gid: int | None = None,
        client_access: str = "",
        idle_timeout: timedelta = timedelta(minutes=15),
        reuse: bool = False,
    ) -> SmbSessionState:
        """Create or reuse one bounded SMB application session."""

        started_at = ensure_utc(started_at)
        key = (
            client_ip,
            principal.casefold(),
            server.casefold(),
            security_policy,
            auth_protocol.casefold(),
            account_scope.casefold(),
        )
        with self._lock:
            if reuse:
                session_id = self._smb_session_affinity.get(key)
                session = self._smb_sessions.get(session_id or "")
                if (
                    session is not None
                    and session.closed_at is None
                    and session.expires_at >= started_at
                    and session.started_at + timedelta(hours=1) >= started_at
                    and session.transport_uid == transport_uid
                    and session.auth_session_ref == auth_session_ref
                ):
                    session.expires_at = min(
                        session.started_at + timedelta(hours=1),
                        started_at + idle_timeout,
                    )
                    return session
            session_id = stable_uuid(
                "smb-session",
                client_ip,
                principal,
                server,
                security_policy,
                transport_uid,
                started_at.isoformat(),
            )
            session = SmbSessionState(
                session_id=session_id,
                client_ip=client_ip,
                principal=principal,
                server=server,
                security_policy=security_policy,
                logon_id=logon_id,
                transport_uid=transport_uid,
                started_at=started_at,
                expires_at=min(started_at + timedelta(hours=1), started_at + idle_timeout),
                auth_session_ref=auth_session_ref,
                auth_protocol=auth_protocol,
                account_scope=account_scope,
                effective_uid=effective_uid,
                effective_gid=effective_gid,
                client_access=client_access,
            )
            self._smb_sessions[session_id] = session
            self._smb_session_affinity[key] = session_id
            return session

    def get_smb_session(self, session_id: str) -> SmbSessionState | None:
        """Return one active SMB session without exposing mutable indexes."""

        with self._lock:
            return self._smb_sessions.get(session_id)

    def close_smb_session(self, session_id: str, timestamp: datetime) -> None:
        """Close an SMB session and its active trees and handles."""

        timestamp = ensure_utc(timestamp)
        with self._lock:
            session = self._smb_sessions.get(session_id)
            if session is None:
                return
            session.closed_at = timestamp
            for tree in self._smb_trees.values():
                if tree.session_id != session_id or tree.closed_at is not None:
                    continue
                tree.closed_at = timestamp
                for handle in self._smb_handles.values():
                    if handle.tree_id == tree.tree_id and handle.closed_at is None:
                        handle.closed_at = timestamp

    def get_or_open_smb_tree(
        self,
        session_id: str,
        share: str,
        timestamp: datetime,
    ) -> SmbTreeState:
        """Return the active tree for a session/share pair or create it."""

        timestamp = ensure_utc(timestamp)
        key = (session_id, share.casefold())
        with self._lock:
            tree_id = self._smb_tree_by_session_share.get(key)
            tree = self._smb_trees.get(tree_id or "")
            if tree is not None and tree.closed_at is None:
                tree.last_activity_at = timestamp
                return tree
            tree_id = stable_uuid("smb-tree", session_id, share.casefold())
            tree = SmbTreeState(
                tree_id=tree_id,
                session_id=session_id,
                share=share,
                connected_at=timestamp,
                last_activity_at=timestamp,
            )
            self._smb_trees[tree_id] = tree
            self._smb_tree_by_session_share[key] = tree_id
            return tree

    def get_smb_tree(self, tree_id: str) -> SmbTreeState | None:
        """Return one active SMB tree without exposing mutable indexes to callers."""

        with self._lock:
            return self._smb_trees.get(tree_id)

    def smb_file_is_available(self, file: object) -> bool:
        """Return whether a compiled catalog entry still exists at its original path."""

        with self._lock:
            state = self._smb_file_overlay.get(file.file_id)
            if state is None:
                return True
            return (
                not state.deleted
                and state.share.casefold() == file.share.casefold()
                and state.path.casefold() == file.path.casefold()
            )

    def smb_file_size(self, file: object) -> int:
        """Return the current size for a compiled catalog entry without touching it."""

        with self._lock:
            state = self._smb_file_overlay.get(file.file_id)
            if state is None:
                return max(0, int(file.size_bytes))
            return 0 if state.deleted else state.size_bytes

    def open_smb_handle(
        self,
        *,
        tree_id: str,
        file_id: str,
        timestamp: datetime,
        access: str,
        deny_write: bool = False,
    ) -> SmbHandleState:
        """Open one minimal SMB handle."""

        timestamp = ensure_utc(timestamp)
        with self._lock:
            handle_id = stable_uuid(
                "smb-handle",
                tree_id,
                file_id,
                access,
                timestamp.isoformat(),
                len(self._smb_handles),
            )
            handle = SmbHandleState(
                handle_id=handle_id,
                tree_id=tree_id,
                file_id=file_id,
                opened_at=timestamp,
                access=access,
                deny_write=deny_write,
            )
            self._smb_handles[handle_id] = handle
            return handle

    def has_smb_write_conflict(self, file_id: str) -> bool:
        """Return whether an active handle denies writes to a file."""

        with self._lock:
            return any(
                handle.file_id == file_id and handle.closed_at is None and handle.deny_write
                for handle in self._smb_handles.values()
            )

    def close_smb_handle(self, handle_id: str, timestamp: datetime) -> None:
        """Close and evict one SMB handle."""

        with self._lock:
            handle = self._smb_handles.get(handle_id)
            if handle is not None:
                handle.closed_at = ensure_utc(timestamp)
                self._smb_handles.pop(handle_id, None)

    def touch_smb_file(self, file: object) -> SmbFileState:
        """Return a mutable overlay view for one compiled storage file."""

        with self._lock:
            existing = self._smb_file_overlay.get(file.file_id)
            if existing is not None:
                return existing
            if len(self._smb_file_overlay) >= _MAX_SMB_MUTATION_OVERLAY:
                raise StateError(
                    f"SMB mutation overlay exceeds {_MAX_SMB_MUTATION_OVERLAY} touched files"
                )
            state = SmbFileState(
                file_id=file.file_id,
                share=file.share,
                path=file.path,
                version=file.version,
                size_bytes=file.size_bytes,
                mime_type=file.mime_type,
                tags=tuple(file.tags),
            )
            self._smb_file_overlay[state.file_id] = state
            self._smb_file_by_share_path[(state.share.casefold(), state.path.casefold())] = (
                state.file_id
            )
            return state

    def create_smb_file(
        self,
        *,
        share: str,
        path: str,
        size_bytes: int,
        mime_type: str,
        timestamp: datetime,
        tags: tuple[str, ...] = (),
    ) -> SmbFileState:
        """Create a new file identity in the mutation overlay."""

        with self._lock:
            if len(self._smb_file_overlay) >= _MAX_SMB_MUTATION_OVERLAY:
                raise StateError(
                    f"SMB mutation overlay exceeds {_MAX_SMB_MUTATION_OVERLAY} touched files"
                )
            key = (share.casefold(), path.casefold())
            prior_id = self._smb_file_by_share_path.get(key)
            prior = self._smb_file_overlay.get(prior_id or "")
            if prior is not None and not prior.deleted:
                raise StateError(f"SMB path already exists: {share}:{path}")
            file_id = f"file-{stable_uuid('smb-created-file', share, path, ensure_utc(timestamp))}"
            state = SmbFileState(
                file_id=file_id,
                share=share,
                path=path,
                version=1,
                size_bytes=max(0, size_bytes),
                mime_type=mime_type,
                tags=tags,
            )
            self._smb_file_overlay[file_id] = state
            self._smb_file_by_share_path[key] = file_id
            return state

    def update_smb_file(self, file_id: str, *, size_bytes: int) -> SmbFileState:
        """Advance a file content version and size."""

        with self._lock:
            state = self._smb_file_overlay[file_id]
            if state.deleted:
                raise StateError(f"cannot update deleted SMB file {file_id}")
            state.version += 1
            state.size_bytes = max(0, size_bytes)
            return state

    def move_smb_file(self, file_id: str, *, share: str, path: str) -> SmbFileState:
        """Move a file while preserving its durable identity."""

        with self._lock:
            state = self._smb_file_overlay[file_id]
            destination_key = (share.casefold(), path.casefold())
            destination_id = self._smb_file_by_share_path.get(destination_key)
            destination = self._smb_file_overlay.get(destination_id or "")
            if destination is not None and not destination.deleted and destination_id != file_id:
                raise StateError(f"SMB path already exists: {share}:{path}")
            old_key = (state.share.casefold(), state.path.casefold())
            self._smb_file_by_share_path.pop(old_key, None)
            state.prior_paths = (*state.prior_paths, state.path)
            state.share = share
            state.path = path
            self._smb_file_by_share_path[destination_key] = file_id
            return state

    def delete_smb_file(self, file_id: str) -> SmbFileState:
        """Tombstone a file identity."""

        with self._lock:
            state = self._smb_file_overlay[file_id]
            state.deleted = True
            self._smb_file_by_share_path.pop(
                (state.share.casefold(), state.path.casefold()),
                None,
            )
            return state

    def sweep_smb_state(self, cutoff: datetime) -> None:
        """Expire SMB sessions, trees, and handles at the hourly state barrier."""

        cutoff = ensure_utc(cutoff)
        with self._lock:
            expired_sessions = {
                session_id
                for session_id, session in self._smb_sessions.items()
                if session.expires_at < cutoff or session.closed_at is not None
            }
            for session_id in expired_sessions:
                session = self._smb_sessions.pop(session_id)
                key = (
                    session.client_ip,
                    session.principal.casefold(),
                    session.server.casefold(),
                    session.security_policy,
                    session.auth_protocol.casefold(),
                    session.account_scope.casefold(),
                )
                if self._smb_session_affinity.get(key) == session_id:
                    self._smb_session_affinity.pop(key, None)
            expired_trees = {
                tree_id
                for tree_id, tree in self._smb_trees.items()
                if tree.session_id in expired_sessions or tree.closed_at is not None
            }
            for tree_id in expired_trees:
                tree = self._smb_trees.pop(tree_id)
                self._smb_tree_by_session_share.pop(
                    (tree.session_id, tree.share.casefold()),
                    None,
                )
            for handle_id, handle in list(self._smb_handles.items()):
                if handle.tree_id in expired_trees or handle.closed_at is not None:
                    self._smb_handles.pop(handle_id, None)

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
                "smb_sessions": len(self._smb_sessions),
                "smb_trees": len(self._smb_trees),
                "smb_handles": len(self._smb_handles),
                "smb_mutations": len(self._smb_file_overlay),
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

    def apply(self, event: CanonicalOccurrence) -> None:
        """Record state changes from a fully-constructed CanonicalOccurrence.

        IDs (logon_id, pid, conn_id, zeek_uid) are already allocated by the
        caller via create_session(), create_process(), open_connection() before
        building the CanonicalOccurrence. This method handles only teardown (logoff,
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
                    if event.network is not None:
                        closed_at = event.network.closed_at
                        if closed_at is not None:
                            activity_time = max(activity_time, ensure_utc(closed_at))
                    if proc.last_activity_time is None or activity_time > proc.last_activity_time:
                        proc.last_activity_time = activity_time

            if event.event_type == "logoff" and event.auth:
                self.end_session(event.auth.logon_id, event.timestamp)
            elif event.event_type == "process_terminate" and event.process and event.src_host:
                self.end_process(event.src_host.hostname, event.process.pid, event.timestamp)
            elif event.event_type == "connection" and event.network:
                if event.network.conn_id:
                    conn = self.state.open_connections.get(event.network.conn_id)
                    if conn is not None:
                        transaction = event.network
                        conn.transaction_id = transaction.stable_id
                        if transaction.application_layer_only:
                            conn.traffic_ledger = conn.traffic_ledger.accumulate(
                                transaction.traffic
                            )
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
                            conn.traffic_ledger = transaction.traffic
                            conn.bytes_sent = transaction.traffic.orig.payload_bytes
                            conn.bytes_received = transaction.traffic.resp.payload_bytes
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
                        conn.initiating_pid = transaction.initiating_pid
                        if event.src_host is not None:
                            conn.source_system = event.src_host.hostname
                            conn.source_hostname = event.src_host.fqdn or event.src_host.hostname
                        if event.protocol.http is not None and event.protocol.http.host:
                            conn.hostname = event.protocol.http.host
                        if event.protocol.ssl is not None and event.protocol.ssl.server_name:
                            conn.hostname = event.protocol.ssl.server_name
                        self._open_connections.refresh(conn.conn_id)
                        self._refresh_connection_lifecycle(conn)
