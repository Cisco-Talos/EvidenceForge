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
import heapq
import hmac
import logging
import math
import random
import secrets
from bisect import bisect_left
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, fields, is_dataclass, replace
from datetime import datetime, timedelta
from enum import Enum, StrEnum
from threading import RLock, Thread, current_thread, get_ident

from evidenceforge.events.authentication import windows_logon_can_own_desktop
from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.events.identity import ProcessIdentity, SessionIdentity, ThreadIdentity
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.events.network import NetworkTrafficLedger, NetworkTransactionPlan
from evidenceforge.generation.deferred_session_preseal import (
    DeferredSessionBindingDisposition,
    DeferredSessionProtocol,
)
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
)
from evidenceforge.utils.ids import generate_zeek_uid_from_rng
from evidenceforge.utils.rng import _get_rng, _stable_seed, stable_uuid
from evidenceforge.utils.time import ensure_utc

logger = logging.getLogger(__name__)

_MIN_GENERATED_LOGON_LUID = 0x10000
_MAX_GENERATED_LOGON_LUID = 0xFFFFFFFF
_GENERATED_LOGON_LUID_SPAN = _MAX_GENERATED_LOGON_LUID - _MIN_GENERATED_LOGON_LUID + 1
_HOST_LOGON_BUCKET_SPACE = 0x01000000
_HOST_LOGON_BUCKET_STEP = 131071
_NULL_LOGON_GUID = "{00000000-0000-0000-0000-000000000000}"
_LINUX_PID_BLOCK_SECONDS = 300


def _freeze_materialization_digest_value(
    value: object,
    active: set[int],
) -> object:
    """Return a deterministic test snapshot for one StateManager-owned value."""

    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        return value
    if isinstance(value, datetime):
        return ("datetime", ensure_utc(value).isoformat())
    if isinstance(value, Enum):
        return (type(value).__qualname__, value.value)
    if isinstance(value, random.Random):
        return ("random.Random", value.getstate())
    if callable(value):
        return (
            "callable",
            getattr(value, "__module__", ""),
            getattr(value, "__qualname__", type(value).__qualname__),
        )

    object_id = id(value)
    if object_id in active:
        return ("cycle", type(value).__module__, type(value).__qualname__)
    active.add(object_id)
    try:
        if is_dataclass(value) and not isinstance(value, type):
            return (
                type(value).__module__,
                type(value).__qualname__,
                tuple(
                    (
                        item.name,
                        _freeze_materialization_digest_value(getattr(value, item.name), active),
                    )
                    for item in fields(value)
                ),
            )
        if isinstance(value, Mapping):
            frozen_items = [
                (
                    _freeze_materialization_digest_value(key, active),
                    _freeze_materialization_digest_value(item, active),
                )
                for key, item in value.items()
            ]
            return ("mapping", tuple(sorted(frozen_items, key=repr)))
        if isinstance(value, (set, frozenset)):
            frozen = [_freeze_materialization_digest_value(item, active) for item in value]
            return ("set", tuple(sorted(frozen, key=repr)))
        if isinstance(value, (list, tuple)):
            return (
                type(value).__qualname__,
                tuple(_freeze_materialization_digest_value(item, active) for item in value),
            )
        attributes = getattr(value, "__dict__", None)
        if isinstance(attributes, dict):
            return (
                type(value).__module__,
                type(value).__qualname__,
                tuple(
                    sorted(
                        (
                            name,
                            _freeze_materialization_digest_value(item, active),
                        )
                        for name, item in attributes.items()
                        if name != "_lock"
                    )
                ),
            )
        if hasattr(value, "tolist"):
            return (
                type(value).__qualname__,
                _freeze_materialization_digest_value(value.tolist(), active),
            )
        return (type(value).__module__, type(value).__qualname__, repr(value))
    finally:
        active.remove(object_id)


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
_MAX_RETAINED_SESSION_IDENTITIES = 500_000
_MAX_RETAINED_PROCESS_IDENTITIES = 500_000
_MAX_RETAINED_THREAD_IDENTITIES = 1_000_000
_MAX_SMB_MUTATION_OVERLAY = 100_000
_MAX_ACTIVE_SMB_FILE_MUTATION_JOURNALS = 4_096
_MAX_SMB_FILE_MUTATION_JOURNAL_ENTRIES = 1_024
_MAX_ACTION_COHORT_LIVE_SESSION_PROCESS_ROLE_PATCHES = 256
_SESSION_PROCESS_REFERENCE_FIELDS = (
    "explorer_pid",
    "session_user_manager_pid",
    "session_winlogon_pid",
    "session_shell_pid",
    "process_tree_root",
    "transport_pid",
)


@dataclass(frozen=True, slots=True)
class SmbFileMutationJournal:
    """Opaque bounded owner for one transactional SMB file-state mutation set."""

    _journal_id: str
    _operation_id: str
    _integrity_token: str = field(repr=False)

    @property
    def operation_id(self) -> str:
        """Return the exact semantic SMB operation owned by this journal."""

        return self._operation_id


@dataclass(frozen=True, slots=True)
class _SmbFileStatePreimage:
    """Exact object and value snapshot for one journal-owned overlay identity."""

    original: SmbFileState | None
    snapshot: SmbFileState | None


@dataclass(slots=True)
class _SmbFileMutationJournalCapability:
    """StateManager-retained preimages for one live SMB mutation transaction."""

    journal: SmbFileMutationJournal
    file_preimages: dict[str, _SmbFileStatePreimage] = field(default_factory=dict)
    path_preimages: dict[tuple[str, str], str | None] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _LinuxLogindAllocatorPatch:
    system: str
    event_time: datetime
    session_id: int
    initial: int | None
    epoch: datetime | None
    rng_state_after: object


@dataclass(frozen=True, slots=True)
class _SessionAllocatorPatch:
    host_base: tuple[str, int] | None
    host_epoch: tuple[str, datetime] | None
    ordinal: tuple[tuple[str, int, int], int] | None
    used_logon_id: int | None
    windows_session_counter: tuple[str, int] | None
    linux_logind: _LinuxLogindAllocatorPatch | None


@dataclass(frozen=True, slots=True)
class _SessionMaterializationPayload:
    """Immutable primitive inputs used to construct one runtime session."""

    logon_type: int
    source_ip: str
    source_port: int
    transport_pid: int | None
    auth_protocol: str
    smb_principal: str
    account_scope: str
    auth_session_ref: str
    effective_uid: int | None
    effective_gid: int | None
    state_time: datetime
    network_close_time: datetime | None = None
    source_ready_time: datetime | None = None
    closure_owned_by_bundle: bool = False
    end_plan: SessionEndPlan | None = None


@dataclass(frozen=True, slots=True)
class SessionMaterializationPlan:
    """Integrity-authenticated allocation-free plan for one session start.

    Runtime state is intentionally absent. Callers may inspect only the immutable
    canonical identity; StateManager constructs the mutable ``ActiveSession``
    inside the guarded no-sampling commit.
    """

    _expected_version: int
    _identity: SessionIdentity
    _payload: _SessionMaterializationPayload
    _allocator_patch: _SessionAllocatorPatch
    _integrity_token: str = field(repr=False)

    @property
    def expected_version(self) -> int:
        """Return the StateManager version against which this plan was prepared."""

        return self._expected_version

    @property
    def identity(self) -> SessionIdentity:
        """Return the immutable canonical session identity."""

        return self._identity

    @property
    def publication_token(self) -> str:
        """Return the authenticated token bound to downstream prepared work."""

        return self._integrity_token

    @property
    def logon_type(self) -> int:
        """Return the immutable source-native logon type required by lifecycle token plans."""

        return self._payload.logon_type

    @property
    def end_plan(self) -> SessionEndPlan | None:
        """Return the immutable session-closure plan carried by this start."""

        return self._payload.end_plan

    @property
    def external_rng_state_after(self) -> object | None:
        """Return the action RNG state to install only after a successful commit."""

        patch = self._allocator_patch.linux_logind
        return patch.rng_state_after if patch is not None else None


@dataclass(frozen=True, slots=True)
class _ProcessAllocatorPatch:
    pid_counter: tuple[str, int] | None
    pid_os: tuple[str, str] | None
    pid_rng_state: tuple[str, object] | None
    pid_epoch: tuple[str, datetime] | None
    pid_weekly_prefix: tuple[str, tuple[int, ...]] | None
    linux_allocation: tuple[str, datetime, int] | None
    pid_bucket_offset: tuple[tuple[str, datetime], int] | None
    fixed_pid: tuple[str, int] | None
    pid_allocation_count_delta: int
    pid_candidate_probe_delta: int
    thread_counter: tuple[str, int] | None
    thread_rng_state: tuple[str, object] | None


@dataclass(frozen=True, slots=True)
class _ProcessMaterializationPayload:
    """Immutable primitive inputs used to construct one runtime process."""

    integrity_level: str
    concurrency_group_id: str
    pid_logical_position: int
    state_time: datetime
    parent_activity_time: datetime | None
    auth_session_id: int | None
    auth_logon_type: int | None
    require_session: bool


@dataclass(frozen=True, slots=True)
class ProcessMaterializationPlan:
    """Integrity-authenticated allocation-free process/thread start plan."""

    _expected_version: int
    _identity: ProcessIdentity
    _payload: _ProcessMaterializationPayload
    _allocator_patch: _ProcessAllocatorPatch
    _integrity_token: str = field(repr=False)

    @property
    def expected_version(self) -> int:
        """Return the StateManager version against which this plan was prepared."""

        return self._expected_version

    @property
    def identity(self) -> ProcessIdentity:
        """Return the immutable canonical process and primary-thread identity."""

        return self._identity

    @property
    def publication_token(self) -> str:
        """Return the authenticated token bound to downstream prepared work."""

        return self._integrity_token

    @property
    def integrity_level(self) -> str:
        """Return the immutable process-token integrity level."""

        return self._payload.integrity_level

    @property
    def auth_session_id(self) -> int | None:
        """Return the prepublished process token's exact session identifier."""

        return self._payload.auth_session_id

    @property
    def auth_logon_type(self) -> int | None:
        """Return the prepublished process token's exact logon type."""

        return self._payload.auth_logon_type


@dataclass(frozen=True, slots=True)
class _ProcessTerminationSessionReference:
    """Exact active-session fields cleared by one process termination."""

    logon_id: str
    object_id: str
    fields: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ProcessTerminationMaterializationPayload:
    """Immutable StateManager writes owned by one process termination."""

    end_time: datetime
    threads: tuple[ThreadIdentity, ...]
    parent_identity: ProcessIdentity | None
    parent_activity_time: datetime | None
    session_references: tuple[_ProcessTerminationSessionReference, ...]


@dataclass(frozen=True, slots=True)
class ProcessTerminationMaterializationPlan:
    """Authenticated allocation-free plan for one exact live process termination."""

    _expected_version: int
    _identity: ProcessIdentity
    _payload: _ProcessTerminationMaterializationPayload
    _integrity_token: str = field(repr=False)

    @property
    def expected_version(self) -> int:
        """Return the StateManager version against which this plan was prepared."""

        return self._expected_version

    @property
    def identity(self) -> ProcessIdentity:
        """Return the exact immutable identity of the process being terminated."""

        return self._identity

    @property
    def publication_token(self) -> str:
        """Return the authenticated token bound to downstream prepared work."""

        return self._integrity_token

    @property
    def end_time(self) -> datetime:
        """Return the exact canonical termination time."""

        return self._payload.end_time

    @property
    def parent_activity_time(self) -> datetime | None:
        """Return the optional exact parent-activity frontier."""

        return self._payload.parent_activity_time


@dataclass(frozen=True, slots=True)
class ConnectionIdentityPlan:
    """Authenticated allocation-free reservation of one connection ID and Zeek UID."""

    _expected_version: int
    _conn_id: str
    _zeek_uid: str
    _counter_after: int
    _rng_state_before: object
    _rng_state_after_identity: object
    _integrity_token: str = field(repr=False)

    @property
    def expected_version(self) -> int:
        """Return the StateManager version against which identity was planned."""

        return self._expected_version

    @property
    def conn_id(self) -> str:
        """Return the reserved logical connection identifier."""

        return self._conn_id

    @property
    def zeek_uid(self) -> str:
        """Return the reserved source-native Zeek UID."""

        return self._zeek_uid

    @property
    def publication_token(self) -> str:
        """Return the authenticated identity-plan token."""

        return self._integrity_token

    def continuation_rng(self) -> random.Random:
        """Return an isolated RNG positioned immediately after UID allocation."""

        rng = random.Random()
        rng.setstate(self._rng_state_after_identity)
        return rng


class _ConnectionPlanningRandom:
    """Revocable Random-compatible view over a cursor-owned isolated stream."""

    __slots__ = ("_cursor",)

    def __init__(self, cursor: "ConnectionPlanningCursor") -> None:
        self._cursor = cursor

    def __getattr__(self, name: str) -> object:
        if name.startswith("_") or name in {"seed", "setstate"}:
            raise AttributeError(name)
        target = self._cursor._rng_attribute(name)
        if not callable(target):
            return target

        def _call(*args: object, **kwargs: object) -> object:
            method = self._cursor._rng_attribute(name)
            return method(*args, **kwargs)

        return _call


class ConnectionPlanningCursor:
    """Opaque one-shot owner for allocation-free connection-planning draws.

    The caller's RNG remains unchanged while planning.  Sampling occurs only on
    a private clone exposed through a revocable proxy; successful composite
    materialization advances the real owner directly from its authenticated
    entry state to the sealed final state.
    """

    __slots__ = (
        "_manager",
        "_expected_version",
        "_expected_state_time",
        "_expected_connection_counter",
        "_admission_epoch",
        "_owner_rng",
        "_owner_identity",
        "_rng_state_entry",
        "_preview_rng",
        "_proxy",
        "_identity",
        "_identity_binding_token",
        "_cursor_token",
        "_sealed",
        "_cancelled",
    )

    def __init__(
        self,
        manager: "StateManager",
        *,
        expected_version: int,
        expected_state_time: datetime | None,
        expected_connection_counter: int,
        admission_epoch: int,
        owner_rng: random.Random,
        rng_state_entry: object,
        cursor_token: str,
    ) -> None:
        self._manager = manager
        self._expected_version = expected_version
        self._expected_state_time = expected_state_time
        self._expected_connection_counter = expected_connection_counter
        self._admission_epoch = admission_epoch
        self._owner_rng = owner_rng
        self._owner_identity = id(owner_rng)
        self._rng_state_entry = rng_state_entry
        preview_rng = random.Random()
        preview_rng.setstate(self._rng_state_entry)
        self._preview_rng: random.Random | None = preview_rng
        self._proxy = _ConnectionPlanningRandom(self)
        self._identity: ConnectionIdentityPlan | None = None
        self._identity_binding_token = ""
        self._cursor_token = cursor_token
        self._sealed = False
        self._cancelled = False

    @property
    def rng(self) -> _ConnectionPlanningRandom:
        """Return the revocable isolated planning stream."""

        self._require_active()
        return self._proxy

    @property
    def expected_version(self) -> int:
        """Return the StateManager fence captured at transaction entry."""

        return self._expected_version

    def reserve_identity(self) -> ConnectionIdentityPlan:
        """Perform the one historical physical connection-ID/UID draw."""

        self._require_active()
        return self._manager._reserve_connection_cursor_identity(self)

    def cancel(self) -> None:
        """Revoke the cursor without changing its RNG owner or StateManager."""

        if self._cancelled:
            raise StateError("Connection planning cursor is already cancelled")
        if self._sealed:
            raise StateError("Connection planning cursor is already sealed")
        self._cancelled = True
        self._preview_rng = None

    def _require_active(self) -> None:
        if self._cancelled:
            raise StateError("Connection planning cursor is cancelled")
        if self._sealed:
            raise StateError("Connection planning cursor is already sealed")

    def _rng_attribute(self, name: str) -> object:
        self._require_active()
        rng = self._preview_rng
        if rng is None:
            raise StateError("Connection planning cursor has no active RNG")
        return getattr(rng, name)

    def _seal(self) -> object:
        self._require_active()
        rng = self._preview_rng
        if rng is None:
            raise StateError("Connection planning cursor has no active RNG")
        final_state = rng.getstate()
        self._sealed = True
        self._preview_rng = None
        return final_state


@dataclass(frozen=True, slots=True)
class _ConnectionMaterializationPayload:
    """Final immutable connection row and compatibility allocation semantics."""

    transaction: NetworkTransactionPlan
    source_system: str
    source_hostname: str
    hostname: str
    initiating_pid: int
    materialize_connection: bool
    final_rng_state: object


@dataclass(frozen=True, slots=True)
class ConnectionMaterializationPlan:
    """Authenticated final connection state ready for one primitive commit."""

    _expected_version: int
    _identity: ConnectionIdentityPlan
    _payload: _ConnectionMaterializationPayload
    _integrity_token: str = field(repr=False)

    @property
    def expected_version(self) -> int:
        """Return the StateManager version against which this plan was finalized."""

        return self._expected_version

    @property
    def identity(self) -> ConnectionIdentityPlan:
        """Return the allocation-free connection identity reservation."""

        return self._identity

    @property
    def transaction(self) -> NetworkTransactionPlan:
        """Return the final canonical connection transaction."""

        return self._payload.transaction

    @property
    def publication_token(self) -> str:
        """Return the authenticated final plan token."""

        return self._integrity_token

    @property
    def materializes_connection(self) -> bool:
        """Return whether commit creates a new retained OpenConnection row."""

        return self._payload.materialize_connection


@dataclass(frozen=True, slots=True)
class _SessionProcessMaterializationLinks:
    """Process-member indexes installed into the new session at batch commit."""

    transport: int = -1
    shell: int = -1
    user_manager: int = -1
    winlogon: int = -1
    explorer: int = -1
    process_tree_root: int = -1


@dataclass(frozen=True, slots=True)
class MaterializationBatchPlan:
    """Authenticated allocation-free session/process start transaction.

    A batch owns at most one new session and an arbitrary parent-ordered process
    tree plus exact host boot-time metadata. Every member is planned against the
    same StateManager version and the primitive commit advances that version
    exactly once.
    """

    _expected_version: int
    _expected_state_time: datetime | None
    _admission_epoch: int
    _final_state_time: datetime
    _session: SessionMaterializationPlan | None
    _processes: tuple[ProcessMaterializationPlan, ...]
    _boot_times: tuple[tuple[str, datetime], ...]
    _session_process_links: _SessionProcessMaterializationLinks
    _integrity_token: str = field(repr=False)

    @property
    def expected_version(self) -> int:
        """Return the single StateManager fence consumed by this batch."""

        return self._expected_version

    @property
    def admission_epoch(self) -> int:
        """Return the prepared-State lane epoch captured by this batch."""

        return self._admission_epoch

    @property
    def session(self) -> SessionMaterializationPlan | None:
        """Return the optional session member."""

        return self._session

    @property
    def final_state_time(self) -> datetime:
        """Return the authenticated final StateManager time frontier."""

        return self._final_state_time

    @property
    def processes(self) -> tuple[ProcessMaterializationPlan, ...]:
        """Return process members in parent-before-child commit order."""

        return self._processes

    @property
    def boot_times(self) -> tuple[tuple[str, datetime], ...]:
        """Return exact host boot-time replacements in canonical host order."""

        return self._boot_times

    @property
    def publication_token(self) -> str:
        """Return the authenticated token bound to the complete batch."""

        return self._integrity_token


class MaterializationBatchBuilder:
    """Allocation-free builder for one session and its bootstrap process tree."""

    def __init__(self, manager: "StateManager", expected_version: int) -> None:
        with manager._capability_minting_guard("MaterializationBatchBuilder"):
            self._manager = manager
            self._expected_version = expected_version
            self._expected_state_time = manager.state.current_time
            self._admission_epoch = manager._prepared_state_admission_epoch
        self._session: SessionMaterializationPlan | None = None
        self._processes: list[ProcessMaterializationPlan] = []
        self._boot_times: dict[str, datetime] = {}
        self._session_process_plans: dict[str, ProcessMaterializationPlan] = {}
        self._sealed = False
        self._pid_counters: dict[str, int] = {}
        self._pid_rng_states: dict[str, object] = {}
        self._pid_os: dict[str, str] = {}
        self._new_pid_namespaces: set[str] = set()
        self._pid_namespace_patch_emitted: set[str] = set()
        self._pid_epochs: dict[str, datetime] = {}
        self._pid_prefixes: dict[str, tuple[int, ...]] = {}
        self._pid_bucket_offsets: dict[tuple[str, datetime], int] = {}
        self._linux_allocations: dict[str, list[tuple[datetime, int]]] = {}
        self._planned_pids: dict[str, set[int]] = {}
        self._thread_counters: dict[str, int] = {}
        self._thread_rng_states: dict[str, object] = {}
        self._planned_tids: dict[str, set[int]] = {}

    @property
    def expected_version(self) -> int:
        """Return the StateManager fence captured when the builder was created."""

        return self._expected_version

    def _require_open(self) -> None:
        if (
            self._manager._active_prepared_state_claim is not None
            or self._admission_epoch != self._manager._prepared_state_admission_epoch
        ):
            raise StateError("Materialization batch builder crossed an active prepared-State claim")
        if self._sealed:
            raise StateError("Materialization batch builder is already sealed")

    def plan_session(self, **kwargs: object) -> SessionMaterializationPlan:
        """Plan the batch's optional session without changing canonical state."""

        self._require_open()
        if self._session is not None:
            raise StateError("Materialization batch may contain only one session")
        if self._processes:
            raise StateError("Materialization batch session must be planned before processes")
        plan = self._manager._plan_batch_session(self, kwargs)
        self._session = plan
        return plan

    def enrich_linux_logind_session(
        self,
        plan: SessionMaterializationPlan,
        *,
        rng: random.Random,
        event_time: datetime,
    ) -> SessionMaterializationPlan:
        """Attach one allocation-free logind identity to the planned session."""

        self._require_open()
        if self._session is not plan or self._processes:
            raise StateError("Linux logind enrichment must precede batch process planning")
        enriched = self._manager._enrich_batch_linux_logind_session(
            self,
            plan,
            rng=rng,
            event_time=event_time,
        )
        self._session = enriched
        return enriched

    def plan_process(
        self,
        *,
        system: str,
        parent_pid: int,
        image: str,
        command_line: str,
        username: str,
        integrity_level: str,
        os_category: str,
        logon_id: str = "",
        lifecycle_group_id: str = "",
        parent_lifecycle_group_id: str = "",
        concurrency_group_id: str = "",
        start_time: datetime | None = None,
        fixed_pid: int | None = None,
        require_session: bool = False,
        parent_activity_time: datetime | None = None,
        auth_session_id: int | None = None,
        auth_logon_type: int | None = None,
        parent_plan: ProcessMaterializationPlan | None = None,
        session_plan: SessionMaterializationPlan | None = None,
    ) -> ProcessMaterializationPlan:
        """Plan one process member using prior batch members as exact owners."""

        self._require_open()
        plan = self._manager._plan_batch_process(
            self,
            system=system,
            parent_pid=parent_pid,
            image=image,
            command_line=command_line,
            username=username,
            integrity_level=integrity_level,
            os_category=os_category,
            logon_id=logon_id,
            lifecycle_group_id=lifecycle_group_id,
            parent_lifecycle_group_id=parent_lifecycle_group_id,
            concurrency_group_id=concurrency_group_id,
            start_time=start_time,
            fixed_pid=fixed_pid,
            require_session=require_session,
            parent_activity_time=parent_activity_time,
            auth_session_id=auth_session_id,
            auth_logon_type=auth_logon_type,
            parent_plan=parent_plan,
            session_plan=session_plan,
        )
        self._processes.append(plan)
        return plan

    def plan_boot_time(self, system: str, boot_time: datetime) -> datetime:
        """Stage one exact host boot-time replacement without changing State."""

        self._require_open()
        if type(system) is not str or not system.strip():
            raise StateError("Materialization batch boot time requires a non-empty host")
        if type(boot_time) is not datetime:
            raise StateError("Materialization batch boot time requires an exact datetime")
        normalized = ensure_utc(boot_time)
        prior = self._boot_times.get(system)
        if prior is not None and prior != normalized:
            raise StateError(f"Materialization batch repeats boot time for {system}")
        self._boot_times[system] = normalized
        return normalized

    def bind_session_processes(
        self,
        session: SessionMaterializationPlan,
        *,
        transport_plan: ProcessMaterializationPlan | None = None,
        shell_plan: ProcessMaterializationPlan | None = None,
        user_manager_plan: ProcessMaterializationPlan | None = None,
        winlogon_plan: ProcessMaterializationPlan | None = None,
        explorer_plan: ProcessMaterializationPlan | None = None,
        process_tree_root_plan: ProcessMaterializationPlan | None = None,
    ) -> None:
        """Bind exact planned process roles into the session's primitive commit."""

        self._require_open()
        if self._session is not session:
            raise StateError("Session process links require this batch's session member")
        values = {
            "transport": transport_plan,
            "shell": shell_plan,
            "user_manager": user_manager_plan,
            "winlogon": winlogon_plan,
            "explorer": explorer_plan,
            "process_tree_root": process_tree_root_plan,
        }
        for role, process in values.items():
            if process is None:
                continue
            if process not in self._processes:
                raise StateError(f"Session {role} link must reference a planned batch process")
            self._session_process_plans[role] = process

    def seal(self) -> MaterializationBatchPlan:
        """Freeze and authenticate the complete allocation-free batch."""

        self._require_open()
        if self._session is None and not self._processes and not self._boot_times:
            raise StateError("Materialization batch cannot be empty")
        self._sealed = True
        return self._manager._seal_materialization_batch(self)


@dataclass(frozen=True, slots=True)
class ProcessActivityPatch:
    """Exact process-object activity frontier installed by a composite commit."""

    identity: ProcessIdentity
    activity_time: datetime


@dataclass(frozen=True, slots=True)
class SessionActivityPatch:
    """Exact session-object activity frontier installed by a composite commit."""

    identity: SessionIdentity
    activity_time: datetime


class ConnectionExistingSessionLifecycleDisposition(StrEnum):
    """Lifecycle treatment for an existing State session bound to a transport."""

    START = "start"
    EXISTING = "existing"


@dataclass(frozen=True, slots=True)
class ConnectionExistingSessionState:
    """Exact RDP-relevant projection of one already-live State session."""

    identity: SessionIdentity
    logon_type: int
    source_ip: str
    source_port: int
    transport_pid: int | None
    network_close_time: datetime | None
    source_ready_time: datetime | None
    closure_owned_by_bundle: bool
    end_plan: SessionEndPlan | None = None

    def __post_init__(self) -> None:
        """Normalize times and reject ambiguous values at the typed boundary."""

        if type(self.identity) is not SessionIdentity:
            raise TypeError("Connection session state requires an exact session identity")
        if type(self.logon_type) is not int or self.logon_type <= 0:
            raise TypeError("Connection session state requires a positive logon type")
        if type(self.source_ip) is not str or not self.source_ip:
            raise TypeError("Connection session state requires a source address")
        if type(self.source_port) is not int or not 0 <= self.source_port <= 65_535:
            raise TypeError("Connection session state requires a valid source port")
        if self.transport_pid is not None and (
            type(self.transport_pid) is not int or self.transport_pid <= 0
        ):
            raise TypeError("Connection session state transport PID must be positive")
        for name in ("network_close_time", "source_ready_time"):
            value = getattr(self, name)
            if value is not None:
                if type(value) is not datetime:
                    raise TypeError(f"Connection session {name} requires an exact datetime")
                object.__setattr__(self, name, ensure_utc(value))
        if type(self.closure_owned_by_bundle) is not bool:
            raise TypeError("Connection session closure ownership requires an exact bool")
        if self.end_plan is not None:
            if type(self.end_plan) is not SessionEndPlan:
                raise TypeError("Connection session end plan requires an exact SessionEndPlan")
            object.__setattr__(
                self,
                "end_plan",
                replace(
                    self.end_plan,
                    canonical_end=ensure_utc(self.end_plan.canonical_end),
                ),
            )


@dataclass(frozen=True, slots=True)
class ConnectionExistingSessionPatch:
    """Authenticated old-to-new RDP session transition owned by one transport."""

    before: ConnectionExistingSessionState
    after: ConnectionExistingSessionState
    lifecycle_disposition: ConnectionExistingSessionLifecycleDisposition
    _expected_version: int
    _expected_state_time: datetime | None
    _admission_epoch: int
    _integrity_token: str = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        """Keep immutable session identity fields stable across the transition."""

        if (
            type(self.before) is not ConnectionExistingSessionState
            or type(self.after) is not ConnectionExistingSessionState
        ):
            raise TypeError("Connection session patch requires exact before/after states")
        if type(self.lifecycle_disposition) is not ConnectionExistingSessionLifecycleDisposition:
            raise TypeError("Connection session patch requires an exact lifecycle disposition")
        if type(self._expected_version) is not int or self._expected_version < 0:
            raise TypeError("Connection session patch requires an exact State version")
        if self._expected_state_time is not None:
            if type(self._expected_state_time) is not datetime:
                raise TypeError("Connection session patch State time must be an exact datetime")
            object.__setattr__(self, "_expected_state_time", ensure_utc(self._expected_state_time))
        if type(self._admission_epoch) is not int or self._admission_epoch < 0:
            raise TypeError("Connection session patch requires an exact admission epoch")
        before = self.before.identity
        after = self.after.identity
        if (
            before.hostname,
            before.object_id,
            before.logon_id,
            before.session_id,
            before.parent_lifecycle_group_id,
        ) != (
            after.hostname,
            after.object_id,
            after.logon_id,
            after.session_id,
            after.parent_lifecycle_group_id,
        ):
            raise ValueError("Connection session patch changed immutable session identity")
        if before.logon_guid and before.logon_guid != after.logon_guid:
            raise ValueError("Connection session patch replaced a finalized LogonGuid")
        if self.before.logon_type != self.after.logon_type:
            raise ValueError("Connection session patch changed its logon type")
        if (
            self.lifecycle_disposition is ConnectionExistingSessionLifecycleDisposition.EXISTING
            and self.before.identity != self.after.identity
        ):
            raise ValueError("Existing lifecycle session patch changed immutable identity")


@dataclass(frozen=True, slots=True)
class ConnectionExistingSessionProcessRolesState:
    """Closed process-role projection for one patched protocol session."""

    transport_pid: int | None = None
    session_shell_pid: int | None = None
    session_user_manager_pid: int | None = None
    session_winlogon_pid: int | None = None
    explorer_pid: int | None = None
    initial_explorer_pid: int | None = None
    process_tree_root: int | None = None
    windows_shell_bootstrapped: bool = False

    def __post_init__(self) -> None:
        """Reject ambiguous PID and shell-bootstrap values."""

        for name in (
            "transport_pid",
            "session_shell_pid",
            "session_user_manager_pid",
            "session_winlogon_pid",
            "explorer_pid",
            "initial_explorer_pid",
            "process_tree_root",
        ):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value <= 0):
                raise TypeError(f"Connection session role {name} requires a positive PID")
        if type(self.windows_shell_bootstrapped) is not bool:
            raise TypeError("Connection session shell bootstrap requires an exact bool")


class _ConnectionExistingSessionProcessRolesCapability:
    """Process-local identity that rejects copied role-patch wrappers."""

    __slots__ = ("patch",)

    def __init__(self) -> None:
        self.patch: ConnectionExistingSessionProcessRolesPatch | None = None

    def bind(self, patch: "ConnectionExistingSessionProcessRolesPatch") -> None:
        """Bind exactly once to the manager-issued wrapper."""

        if self.patch is not None:
            raise StateError("Connection session process-role capability is already bound")
        self.patch = patch


@dataclass(frozen=True, slots=True)
class ConnectionExistingSessionProcessRolesPatch:
    """Authenticated exact role transition backed by one process-only batch."""

    target: SessionIdentity
    before: ConnectionExistingSessionProcessRolesState
    after: ConnectionExistingSessionProcessRolesState
    transport_plan: ProcessMaterializationPlan | None
    shell_plan: ProcessMaterializationPlan | None
    user_manager_plan: ProcessMaterializationPlan | None
    winlogon_plan: ProcessMaterializationPlan | None
    explorer_plan: ProcessMaterializationPlan | None
    process_tree_root_plan: ProcessMaterializationPlan | None
    _expected_version: int
    _expected_state_time: datetime | None
    _admission_epoch: int
    _capability: _ConnectionExistingSessionProcessRolesCapability = field(
        repr=False,
        compare=False,
    )
    _integrity_token: str = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate the inert public shape before manager authentication."""

        if type(self.target) is not SessionIdentity:
            raise TypeError("Connection session role patch requires an exact target identity")
        if (
            type(self.before) is not ConnectionExistingSessionProcessRolesState
            or type(self.after) is not ConnectionExistingSessionProcessRolesState
        ):
            raise TypeError("Connection session role patch requires exact before/after states")
        for name in (
            "transport_plan",
            "shell_plan",
            "user_manager_plan",
            "winlogon_plan",
            "explorer_plan",
            "process_tree_root_plan",
        ):
            value = getattr(self, name)
            if value is not None and type(value) is not ProcessMaterializationPlan:
                raise TypeError(f"Connection session role {name} requires an exact process plan")
        if type(self._expected_version) is not int or self._expected_version < 0:
            raise TypeError("Connection session role patch requires an exact State version")
        if self._expected_state_time is not None:
            if type(self._expected_state_time) is not datetime:
                raise TypeError("Connection session role patch State time must be exact")
            object.__setattr__(self, "_expected_state_time", ensure_utc(self._expected_state_time))
        if type(self._admission_epoch) is not int or self._admission_epoch < 0:
            raise TypeError("Connection session role patch requires an exact admission epoch")
        if type(self._capability) is not _ConnectionExistingSessionProcessRolesCapability:
            raise TypeError("Connection session role patch capability has an unsupported type")

    @property
    def publication_token(self) -> str:
        """Return the manager-authenticated exact role transition token."""

        return self._integrity_token


class _DeferredSessionStateAuthorityCapability:
    """Exact identity for one State-issued deferred-session handoff."""

    __slots__ = ("outer_authority", "outer_integrity", "payload")

    def __init__(self) -> None:
        self.payload: DeferredSessionStateAuthority | None = None
        self.outer_authority: object | None = None
        self.outer_integrity = ""

    def bind_payload(self, payload: "DeferredSessionStateAuthority") -> None:
        """Bind the capability to exactly one manager-issued payload."""

        if self.payload is not None:
            raise StateError("Deferred session State capability is already bound")
        self.payload = payload

    def bind_outer(self, outer_authority: object, integrity: str) -> None:
        """Bind exactly once to the final resolved network-authority wrapper."""

        if self.outer_authority is not None:
            raise StateError("Deferred session State authority already owns a network handoff")
        self.outer_authority = outer_authority
        self.outer_integrity = integrity


@dataclass(frozen=True, slots=True)
class DeferredSessionStateAuthority:
    """Exact State-owned batch/patch handoff for one deferred protocol root."""

    protocol: DeferredSessionProtocol
    binding_disposition: DeferredSessionBindingDisposition
    bound_at: datetime
    batch: MaterializationBatchPlan
    existing_session_patch: ConnectionExistingSessionPatch | None
    existing_session_process_roles_patch: ConnectionExistingSessionProcessRolesPatch | None
    _owner: "StateManager" = field(repr=False, compare=False)
    _owner_identity: int = field(repr=False)
    _admission_epoch: int
    _capability: _DeferredSessionStateAuthorityCapability = field(repr=False, compare=False)
    _integrity_token: str = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        """Reject freely shaped wrappers before owner authentication."""

        if type(self.protocol) is not DeferredSessionProtocol:
            raise TypeError("Deferred session State authority requires an exact protocol")
        if type(self.binding_disposition) is not DeferredSessionBindingDisposition:
            raise TypeError("Deferred session State authority requires an exact disposition")
        if type(self.bound_at) is not datetime:
            raise TypeError("Deferred session State authority requires an exact binding time")
        object.__setattr__(self, "bound_at", ensure_utc(self.bound_at))
        if type(self.batch) is not MaterializationBatchPlan:
            raise TypeError("Deferred session State authority requires an exact batch")
        if self.existing_session_patch is not None and (
            type(self.existing_session_patch) is not ConnectionExistingSessionPatch
        ):
            raise TypeError("Deferred session State authority has an unsupported session patch")
        if self.existing_session_process_roles_patch is not None and (
            type(self.existing_session_process_roles_patch)
            is not ConnectionExistingSessionProcessRolesPatch
        ):
            raise TypeError("Deferred session State authority has an unsupported role patch")
        if type(self._owner_identity) is not int or self._owner_identity <= 0:
            raise TypeError("Deferred session State authority requires its exact owner identity")
        if type(self._admission_epoch) is not int or self._admission_epoch < 0:
            raise TypeError("Deferred session State authority requires an admission epoch")
        if type(self._capability) is not _DeferredSessionStateAuthorityCapability:
            raise TypeError("Deferred session State authority capability has an unsupported type")
        if type(self._integrity_token) is not str or not self._integrity_token:
            raise TypeError("Deferred session State authority requires an integrity token")

    @property
    def publication_token(self) -> str:
        """Return the State-owner proof over every exact nested plan identity."""

        return self._integrity_token

    @property
    def outer_bound(self) -> bool:
        """Return whether the exact final network authority consumed this handoff."""

        return self._capability.outer_authority is not None


def _connection_existing_session_patch_integrity_token(
    authority_secret: bytes,
    before: ConnectionExistingSessionState,
    after: ConnectionExistingSessionState,
    *,
    lifecycle_disposition: ConnectionExistingSessionLifecycleDisposition,
    expected_version: int,
    expected_state_time: datetime | None,
    admission_epoch: int,
) -> str:
    """Authenticate one exact old-to-new existing-session transition."""

    canonical = repr(
        (
            "connection-existing-session-patch-v2",
            before,
            after,
            lifecycle_disposition,
            expected_version,
            expected_state_time,
            admission_epoch,
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


def _connection_existing_session_process_roles_integrity_token(
    authority_secret: bytes,
    patch: ConnectionExistingSessionProcessRolesPatch,
) -> str:
    """Authenticate one exact existing-session process-role transition."""

    canonical = repr(
        (
            "connection-existing-session-process-roles-v1",
            patch.target,
            patch.before,
            patch.after,
            tuple(
                (id(plan), plan.publication_token) if plan is not None else (0, "")
                for plan in (
                    patch.transport_plan,
                    patch.shell_plan,
                    patch.user_manager_plan,
                    patch.winlogon_plan,
                    patch.explorer_plan,
                    patch.process_tree_root_plan,
                )
            ),
            patch._expected_version,
            patch._expected_state_time,
            patch._admission_epoch,
            id(patch._capability),
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


def _deferred_session_state_authority_integrity_token(
    authority_secret: bytes,
    *,
    protocol: DeferredSessionProtocol,
    binding_disposition: DeferredSessionBindingDisposition,
    bound_at: datetime,
    batch: MaterializationBatchPlan,
    existing_session_patch: ConnectionExistingSessionPatch | None,
    existing_session_process_roles_patch: ConnectionExistingSessionProcessRolesPatch | None,
    owner_identity: int,
    admission_epoch: int,
    capability: _DeferredSessionStateAuthorityCapability,
) -> str:
    """Authenticate exact nested State plan identities and their stable order."""

    canonical = repr(
        (
            "deferred-session-state-authority-v1",
            protocol,
            binding_disposition,
            ensure_utc(bound_at),
            owner_identity,
            admission_epoch,
            id(capability),
            id(batch),
            batch.publication_token,
            (
                (id(batch.session), batch.session.publication_token)
                if batch.session is not None
                else (0, "")
            ),
            tuple((id(plan), plan.publication_token) for plan in batch.processes),
            (
                (
                    id(existing_session_patch),
                    existing_session_patch._integrity_token,
                )
                if existing_session_patch is not None
                else (0, "")
            ),
            (
                (
                    id(existing_session_process_roles_patch),
                    existing_session_process_roles_patch.publication_token,
                )
                if existing_session_process_roles_patch is not None
                else (0, "")
            ),
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


def _deferred_session_outer_authority_integrity_token(
    authority_secret: bytes,
    payload: DeferredSessionStateAuthority,
    outer_authority: object,
) -> str:
    """Bind one State payload to the exact final network-authority wrapper."""

    batch = getattr(outer_authority, "state_batch", None)
    patch = getattr(outer_authority, "existing_state_patch", None)
    application_token = getattr(outer_authority, "application_token", None)
    canonical = repr(
        (
            "deferred-session-state-outer-authority-v1",
            id(payload),
            payload.publication_token,
            id(outer_authority),
            getattr(outer_authority, "kind", None),
            id(getattr(outer_authority, "coordinator", None)),
            getattr(getattr(outer_authority, "coordinator", None), "coordinator_id", ""),
            getattr(outer_authority, "bound_at", None),
            getattr(outer_authority, "binding_disposition", None),
            id(getattr(outer_authority, "strict_state_authority", None)),
            getattr(outer_authority, "session_object_id", ""),
            (id(batch), getattr(batch, "publication_token", "")),
            (
                id(patch),
                getattr(patch, "_integrity_token", ""),
            ),
            id(getattr(outer_authority, "state_intent", None)),
            id(getattr(outer_authority, "existing_state_intent", None)),
            id(getattr(outer_authority, "live_state_intent", None)),
            id(getattr(outer_authority, "application_intent", None)),
            id(getattr(outer_authority, "application_manager", None)),
            (
                id(application_token),
                getattr(application_token, "publication_token", ""),
            ),
            repr(getattr(outer_authority, "application_process_activity", ())),
            repr(getattr(outer_authority, "application_session_activity", ())),
            repr(getattr(outer_authority, "application_process_holds", ())),
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class PhysicalTransportFingerprint:
    """Immutable State-authenticated identity of one physical network transport."""

    transport_id: str
    conn_id: str
    zeek_uid: str
    tuple_key: tuple[str, int, str, int, str]
    started_at: datetime
    closed_at: datetime | None


@dataclass(frozen=True, slots=True)
class _ConnectionParentSnapshot:
    """Immutable fingerprint of a physical parent before child accounting."""

    conn_id: str
    zeek_uid: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    state: str
    start_time: datetime
    source_system: str
    source_hostname: str
    hostname: str
    initiating_pid: int
    close_time: datetime | None
    bytes_sent: int
    bytes_received: int
    traffic_ledger: NetworkTrafficLedger
    transaction_id: str
    conn_state: str
    history: str
    duration: float | None


@dataclass(frozen=True, slots=True)
class _ConnectionParentAccountingPatch:
    """Authenticated one-shot traffic delta for an application child."""

    before: _ConnectionParentSnapshot
    after_traffic: NetworkTrafficLedger


class ConnectionMaterializationMode(StrEnum):
    """State publication disposition for one canonical network transaction."""

    PHYSICAL = "physical"
    APPLICATION_CHILD = "application_child"


@dataclass(frozen=True, slots=True)
class ConnectionCompositeMaterializationPlan:
    """Authenticated State-only transaction for connection and optional starts."""

    _expected_version: int
    _expected_state_time: datetime | None
    _expected_connection_counter: int
    _owner_rng: random.Random = field(repr=False, compare=False)
    _owner_identity: int
    _rng_state_entry: object = field(repr=False)
    _rng_state_final: object = field(repr=False)
    _cursor_token: str = field(repr=False)
    _identity: ConnectionIdentityPlan | None
    _transaction: NetworkTransactionPlan
    _source_system: str
    _source_hostname: str
    _hostname: str
    _initiating_pid: int
    _mode: ConnectionMaterializationMode
    _parent_patch: _ConnectionParentAccountingPatch | None
    _batch: MaterializationBatchPlan | None
    _existing_session_patch: ConnectionExistingSessionPatch | None
    _existing_session_process_roles_patch: ConnectionExistingSessionProcessRolesPatch | None
    _process_activity: tuple[ProcessActivityPatch, ...]
    _session_activity: tuple[SessionActivityPatch, ...]
    _final_state_time: datetime
    _integrity_token: str = field(repr=False)

    @property
    def expected_version(self) -> int:
        """Return the StateManager fence consumed by this composite."""

        return self._expected_version

    @property
    def publication_token(self) -> str:
        """Return the manager-authenticated composite publication token."""

        return self._integrity_token

    @property
    def transaction(self) -> NetworkTransactionPlan:
        """Return the exact final canonical network transaction."""

        return self._transaction

    @property
    def materializes_connection(self) -> bool:
        """Return whether this transaction creates a physical State row."""

        return self._mode is ConnectionMaterializationMode.PHYSICAL

    @property
    def mode(self) -> ConnectionMaterializationMode:
        """Return the explicit physical/application-child disposition."""

        return self._mode

    @property
    def physical_transport_id(self) -> str:
        """Return the authenticated physical transport owning this transaction."""

        return self.physical_transport_fingerprint.transport_id

    @property
    def physical_transport_fingerprint(self) -> PhysicalTransportFingerprint:
        """Return immutable physical identity for lifecycle/app authority matching."""

        if self._mode is ConnectionMaterializationMode.PHYSICAL:
            transaction = self._transaction
            return PhysicalTransportFingerprint(
                transport_id=transaction.stable_id,
                conn_id=transaction.conn_id,
                zeek_uid=transaction.zeek_uid,
                tuple_key=(
                    transaction.src_ip,
                    transaction.src_port,
                    transaction.dst_ip,
                    transaction.dst_port,
                    transaction.protocol.casefold(),
                ),
                started_at=transaction.started_at,
                closed_at=transaction.closed_at,
            )
        parent_patch = self._parent_patch
        if parent_patch is None:
            raise StateError("Application-child composite has no physical parent")
        parent = parent_patch.before
        return PhysicalTransportFingerprint(
            transport_id=parent.transaction_id,
            conn_id=parent.conn_id,
            zeek_uid=parent.zeek_uid,
            tuple_key=(
                parent.src_ip,
                parent.src_port,
                parent.dst_ip,
                parent.dst_port,
                parent.protocol.casefold(),
            ),
            started_at=parent.start_time,
            closed_at=parent.close_time,
        )

    @property
    def batch(self) -> MaterializationBatchPlan | None:
        """Return the optional session/process start batch."""

        return self._batch

    @property
    def existing_session_patch(self) -> ConnectionExistingSessionPatch | None:
        """Return the optional exact protocol-session transition."""

        return self._existing_session_patch

    @property
    def existing_session_process_roles_patch(
        self,
    ) -> ConnectionExistingSessionProcessRolesPatch | None:
        """Return the optional exact target-session process-role transition."""

        return self._existing_session_process_roles_patch

    @property
    def process_activity(self) -> tuple[ProcessActivityPatch, ...]:
        """Return normalized exact process activity patches."""

        return self._process_activity

    @property
    def session_activity(self) -> tuple[SessionActivityPatch, ...]:
        """Return normalized exact session activity patches."""

        return self._session_activity

    @property
    def final_state_time(self) -> datetime:
        """Return the authenticated post-commit StateManager frontier."""

        return self._final_state_time


@dataclass(frozen=True, slots=True)
class ConnectionCompositeMaterializationResult:
    """Rows published by one successful connection composite."""

    connection: OpenConnection | None
    session: ActiveSession | None
    processes: tuple[RunningProcess, ...]


@dataclass(frozen=True, slots=True)
class ActionCohortSessionMetadataState:
    """Closed mutable-session projection owned by one action cohort.

    Identity-bearing session fields remain immutable.  This projection contains
    only the bounded runtime metadata that action bundles may transition as part
    of the same authoritative State publication as their starts and closes.
    """

    source_ready_time: datetime | None = None
    network_close_time: datetime | None = None
    closure_owned_by_bundle: bool = False
    login_occurrence_emitted: bool = False
    storyline_protected: bool = False
    end_plan: SessionEndPlan | None = None

    def __post_init__(self) -> None:
        """Normalize every canonical timestamp in the closed projection."""

        if self.source_ready_time is not None:
            if type(self.source_ready_time) is not datetime:
                raise TypeError("Action cohort session readiness requires an exact datetime")
            object.__setattr__(self, "source_ready_time", ensure_utc(self.source_ready_time))
        if self.network_close_time is not None:
            if type(self.network_close_time) is not datetime:
                raise TypeError("Action cohort session network close requires an exact datetime")
            object.__setattr__(self, "network_close_time", ensure_utc(self.network_close_time))
        for name in (
            "closure_owned_by_bundle",
            "login_occurrence_emitted",
            "storyline_protected",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"Action cohort session metadata {name} requires an exact bool")
        if self.end_plan is not None and type(self.end_plan) is not SessionEndPlan:
            raise TypeError("Action cohort session metadata requires an exact SessionEndPlan")
        if self.end_plan is not None:
            object.__setattr__(
                self,
                "end_plan",
                replace(
                    self.end_plan,
                    canonical_end=ensure_utc(self.end_plan.canonical_end),
                ),
            )


@dataclass(frozen=True, slots=True)
class ActionCohortLiveSessionProcessRolesState:
    """Closed process-role projection for one already-live session."""

    transport_pid: int | None = None
    session_shell_pid: int | None = None
    session_user_manager_pid: int | None = None
    session_winlogon_pid: int | None = None
    explorer_pid: int | None = None
    initial_explorer_pid: int | None = None
    process_tree_root: int | None = None
    windows_shell_bootstrapped: bool = False

    def __post_init__(self) -> None:
        """Reject ambiguous PID and bootstrap values at the public boundary."""

        for name in (
            "transport_pid",
            "session_shell_pid",
            "session_user_manager_pid",
            "session_winlogon_pid",
            "explorer_pid",
            "initial_explorer_pid",
            "process_tree_root",
        ):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value <= 0):
                raise TypeError(f"Action cohort live-session role {name} requires a positive PID")
        if type(self.windows_shell_bootstrapped) is not bool:
            raise TypeError("Action cohort live-session shell bootstrap requires an exact bool")


class _ActionCohortCapability:
    """Unforgeable process-local identity for one ephemeral HMAC member."""

    __slots__ = ()


@dataclass(frozen=True, slots=True)
class ActionCohortSessionMetadataPatch:
    """Exact before/after metadata transition for one staged or live session."""

    target: SessionMaterializationPlan | SessionIdentity
    before: ActionCohortSessionMetadataState
    after: ActionCohortSessionMetadataState
    _capability: _ActionCohortCapability = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ActionCohortLiveSessionProcessRolesPatch:
    """Exact live-session shell-role transition backed by staged processes."""

    target: SessionIdentity
    before: ActionCohortLiveSessionProcessRolesState
    after: ActionCohortLiveSessionProcessRolesState
    winlogon_plan: ProcessMaterializationPlan | None
    explorer_plan: ProcessMaterializationPlan
    process_tree_root_plan: ProcessMaterializationPlan | None
    _capability: _ActionCohortCapability = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ActionCohortProcessActivityPatch:
    """Exact activity frontier for one staged or live process."""

    target: ProcessMaterializationPlan | ProcessIdentity
    activity_time: datetime
    _capability: _ActionCohortCapability = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        """Normalize the canonical activity time."""

        if type(self.activity_time) is not datetime:
            raise TypeError("Action cohort process activity requires an exact datetime")
        object.__setattr__(self, "activity_time", ensure_utc(self.activity_time))


@dataclass(frozen=True, slots=True)
class ActionCohortSessionActivityPatch:
    """Exact activity frontier for one staged or live session."""

    target: SessionMaterializationPlan | SessionIdentity
    activity_time: datetime
    _capability: _ActionCohortCapability = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        """Normalize the canonical activity time."""

        if type(self.activity_time) is not datetime:
            raise TypeError("Action cohort session activity requires an exact datetime")
        object.__setattr__(self, "activity_time", ensure_utc(self.activity_time))


@dataclass(frozen=True, slots=True)
class ActionCohortProcessTermination:
    """Exact live or same-cohort process terminalization member."""

    target: ProcessTerminationMaterializationPlan | ProcessMaterializationPlan
    end_time: datetime
    parent_activity: ActionCohortProcessActivityPatch | None
    staged_session_references: tuple[_ProcessTerminationSessionReference, ...]
    _capability: _ActionCohortCapability = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        """Normalize the canonical terminal time."""

        if type(self.end_time) is not datetime:
            raise TypeError("Action cohort process close requires an exact datetime")
        object.__setattr__(self, "end_time", ensure_utc(self.end_time))

    @property
    def identity(self) -> ProcessIdentity:
        """Return the exact process identity being terminalized."""

        return self.target.identity


@dataclass(frozen=True, slots=True)
class ActionCohortSessionTerminalization:
    """Exact live or same-cohort session terminalization member."""

    target: SessionMaterializationPlan | SessionIdentity
    end_time: datetime
    _capability: _ActionCohortCapability = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        """Normalize the canonical terminal time."""

        if type(self.end_time) is not datetime:
            raise TypeError("Action cohort session close requires an exact datetime")
        object.__setattr__(self, "end_time", ensure_utc(self.end_time))

    @property
    def identity(self) -> SessionIdentity:
        """Return the exact session identity being terminalized."""

        if type(self.target) is SessionMaterializationPlan:
            return self.target.identity
        return self.target


@dataclass(frozen=True, slots=True)
class _ActionCohortSessionProcessLinks:
    """Exact per-session role bindings into the ordered process-start tuple."""

    session_index: int
    links: _SessionProcessMaterializationLinks


@dataclass(frozen=True, slots=True)
class ActionCohortMaterializationPlan:
    """Authenticated State-only transaction for one complete action cohort."""

    _expected_version: int
    _expected_state_time: datetime | None
    _final_state_time: datetime
    _sessions: tuple[SessionMaterializationPlan, ...]
    _processes: tuple[ProcessMaterializationPlan, ...]
    _session_process_links: tuple[_ActionCohortSessionProcessLinks, ...]
    _live_session_process_roles: tuple[ActionCohortLiveSessionProcessRolesPatch, ...]
    _session_metadata: tuple[ActionCohortSessionMetadataPatch, ...]
    _process_activity: tuple[ActionCohortProcessActivityPatch, ...]
    _session_activity: tuple[ActionCohortSessionActivityPatch, ...]
    _process_terminations: tuple[ActionCohortProcessTermination, ...]
    _session_terminalizations: tuple[ActionCohortSessionTerminalization, ...]
    _semantic_id: str
    _capability: _ActionCohortCapability = field(repr=False, compare=False)
    _integrity_token: str = field(repr=False, compare=False)

    @property
    def expected_version(self) -> int:
        """Return the single State version consumed by this cohort."""

        return self._expected_version

    @property
    def final_state_time(self) -> datetime:
        """Return the authenticated post-commit State time frontier."""

        return self._final_state_time

    @property
    def sessions(self) -> tuple[SessionMaterializationPlan, ...]:
        """Return exact session starts in canonical publication order."""

        return self._sessions

    @property
    def processes(self) -> tuple[ProcessMaterializationPlan, ...]:
        """Return exact parent-before-child process starts."""

        return self._processes

    @property
    def live_session_process_role_patches(
        self,
    ) -> tuple[ActionCohortLiveSessionProcessRolesPatch, ...]:
        """Return exact live-session role transitions for authority projection."""

        return self._live_session_process_roles

    @property
    def session_metadata_patches(self) -> tuple[ActionCohortSessionMetadataPatch, ...]:
        """Return exact staged/live session metadata transitions."""

        return self._session_metadata

    @property
    def process_activity_patches(self) -> tuple[ActionCohortProcessActivityPatch, ...]:
        """Return exact staged/live process activity transitions."""

        return self._process_activity

    @property
    def session_activity_patches(self) -> tuple[ActionCohortSessionActivityPatch, ...]:
        """Return exact staged/live session activity transitions."""

        return self._session_activity

    @property
    def process_terminations(self) -> tuple[ActionCohortProcessTermination, ...]:
        """Return exact child-before-parent process terminalizations."""

        return self._process_terminations

    @property
    def session_terminalizations(self) -> tuple[ActionCohortSessionTerminalization, ...]:
        """Return exact session terminalizations."""

        return self._session_terminalizations

    @property
    def semantic_id(self) -> str:
        """Return the deterministic public identity of the semantic transaction."""

        return self._semantic_id

    @property
    def publication_token(self) -> str:
        """Return the manager-issued ephemeral HMAC capability."""

        return self._integrity_token


@dataclass(frozen=True, slots=True)
class ActionCohortMaterializationResult:
    """Immutable identity-only result from one action cohort commit."""

    semantic_id: str
    prior_version: int
    committed_version: int
    started_sessions: tuple[SessionIdentity, ...]
    started_processes: tuple[ProcessIdentity, ...]
    terminated_processes: tuple[ProcessIdentity, ...]
    terminalized_sessions: tuple[SessionIdentity, ...]


@dataclass(frozen=True, slots=True)
class _PreparedActionCohortSessionStart:
    """Runtime row and optional allocator defaults built before claim publication."""

    plan: SessionMaterializationPlan
    session: ActiveSession
    linux_logind_used_ids_default: set[int] | None
    linux_logind_allocations_default: TemporalAllocationIndex | None


@dataclass(frozen=True, slots=True)
class _PreparedActionCohortProcessStart:
    """Runtime process/thread rows and allocator defaults built before publication."""

    plan: ProcessMaterializationPlan
    process: RunningProcess
    thread: RunningThread
    pid_rng_replacement: random.Random | None
    linux_pid_allocations_default: TemporalAllocationIndex | None
    fixed_pid_reservations_default: set[int] | None
    thread_rng_replacement: random.Random | None


@dataclass(frozen=True, slots=True)
class _PreparedActionCohortProcessTermination:
    """Exact primitive process-close projection built before claim publication."""

    plan: ProcessTerminationMaterializationPlan
    process_key: tuple[str, int]
    thread_keys: tuple[tuple[str, str, int], ...]
    thread_deadline: float
    process_deadline: float


@dataclass(frozen=True, slots=True)
class _PreparedActionCohortSessionTerminalization:
    """Exact primitive session-close projection built before claim publication."""

    terminalization: ActionCohortSessionTerminalization
    resolved_logon_id: str
    ended: tuple[ActiveSession, datetime]
    retention_deadline: float


@dataclass(frozen=True, slots=True)
class _ActionCohortMappingSavepoint:
    """One bounded mapping key captured before cohort mutation."""

    mapping: dict[object, object]
    key: object
    present: bool
    value: object


@dataclass(frozen=True, slots=True)
class _ActionCohortSetSavepoint:
    """One bounded set member captured before cohort mutation."""

    values: set[object]
    value: object
    present: bool


@dataclass(frozen=True, slots=True)
class _ActionCohortMappedSetSavepoint:
    """One member of one mapping-owned set captured before mutation."""

    mapping: dict[object, object]
    key: object
    mapping_present: bool
    values: set[object] | None
    value: object
    value_present: bool


@dataclass(frozen=True, slots=True)
class _ActionCohortIndexedStoreSavepoint:
    """One exact IndexedEntityStore key and its prior bucket ownership."""

    store: IndexedEntityStore[object, object]
    key: object
    present: bool
    value: object
    indexed_values: dict[str, object] | None
    buckets: tuple[tuple[str, object, dict[object, None]], ...]


@dataclass(frozen=True, slots=True)
class _ActionCohortExpiringKeySavepoint:
    """One exact ExpiringIndex key before mutation."""

    key: object
    present: bool
    value: object
    deadline: float | None
    order: int | None
    version: int | None


@dataclass(frozen=True, slots=True)
class _ActionCohortExpiringIndexSavepoint:
    """Bounded logical and allocator savepoint for touched expiry keys."""

    index: ExpiringIndex[object, object]
    keys: tuple[_ActionCohortExpiringKeySavepoint, ...]
    next_order: int
    high_water_mark: int


@dataclass(frozen=True, slots=True)
class _ActionCohortGroupedTemporalSavepoint:
    """One bounded GroupedTemporalIndex key before a known mutation."""

    index: GroupedTemporalIndex[object, object]
    key: object
    prior_current: tuple[object, datetime, int, int] | None
    prior_next_sequence: int
    prior_stale_counts: tuple[tuple[object, int | None], ...]
    added_record: tuple[object, datetime, int, int] | None


@dataclass(frozen=True, slots=True)
class _ActionCohortObjectSavepoint:
    """One mutable runtime entity's bounded field state."""

    target: ActiveSession | RunningProcess | RunningThread
    fields: tuple[tuple[str, object], ...]


@dataclass(frozen=True, slots=True)
class _ActionCohortTemporalAllocationSavepoint:
    """One reversible temporal allocation addition."""

    mapping: dict[str, TemporalAllocationIndex]
    host: str
    index_was_present: bool
    index: TemporalAllocationIndex | None
    event_time: datetime
    value: int
    sequence: int


@dataclass(frozen=True, slots=True)
class _ActionCohortRollbackJournal:
    """Cohort-bounded per-owner undo journal captured under the State lock."""

    mapping_entries: tuple[_ActionCohortMappingSavepoint, ...]
    set_entries: tuple[_ActionCohortSetSavepoint, ...]
    mapped_set_entries: tuple[_ActionCohortMappedSetSavepoint, ...]
    indexed_store_entries: tuple[_ActionCohortIndexedStoreSavepoint, ...]
    expiring_indexes: tuple[_ActionCohortExpiringIndexSavepoint, ...]
    grouped_temporal_entries: tuple[_ActionCohortGroupedTemporalSavepoint, ...]
    temporal_allocations: tuple[_ActionCohortTemporalAllocationSavepoint, ...]
    object_entries: tuple[_ActionCohortObjectSavepoint, ...]
    scalar_entries: tuple[tuple[str, object], ...]
    retention_mapping_entries: list[_ActionCohortMappingSavepoint]
    retention_mapped_set_entries: list[_ActionCohortMappedSetSavepoint]
    retention_expiring_indexes: list[_ActionCohortExpiringIndexSavepoint]
    retention_grouped_temporal_entries: list[_ActionCohortGroupedTemporalSavepoint]
    state_time: datetime | None
    materialization_version: int


@dataclass(frozen=True, slots=True)
class _MaterializationBatchRollbackProjection:
    """Empty action-only patch surface for a start-batch rollback journal."""

    _live_session_process_roles: tuple[()] = ()
    _session_metadata: tuple[()] = ()
    _process_activity: tuple[()] = ()
    _session_activity: tuple[()] = ()


@dataclass(frozen=True, slots=True)
class _PreparedActionCohortCommitPlan:
    """Every explicit object needed by the action-cohort primitive tail."""

    plan: ActionCohortMaterializationPlan
    committed_version: int
    sessions: tuple[_PreparedActionCohortSessionStart, ...]
    processes: tuple[_PreparedActionCohortProcessStart, ...]
    process_terminations: tuple[_PreparedActionCohortProcessTermination, ...]
    session_terminalizations: tuple[_PreparedActionCohortSessionTerminalization, ...]
    rollback_journal: _ActionCohortRollbackJournal
    claim_version: int
    claim_state_time: datetime | None
    claim_preimage: object


@dataclass(slots=True)
class _ActionCohortPreparationRecord:
    """Manager-owned exact locator for one active prepared capability."""

    preparation: "PreparedActionCohortMaterialization"
    expected_result: ActionCohortMaterializationResult
    expected_result_publication_token: str
    commit_plan: _PreparedActionCohortCommitPlan
    claim_thread_id: int
    claim_epoch: int
    certified: bool = False
    provisional: bool = False
    committed: bool = False
    failed: bool = False
    terminal: bool = False
    provisional_postimage: object | None = None


@dataclass(slots=True)
class _PreparedConnectionMaterializationRecord:
    """Manager-owned exact authority for one yielded connection preparation."""

    preparation: "PreparedConnectionMaterialization"
    plan: ConnectionMaterializationPlan
    rng: random.Random
    claim_thread_id: int
    claim_epoch: int
    claim_version: int
    claim_state_time: datetime | None
    rng_state: object
    committed: bool = False
    failed: bool = False
    terminal: bool = False
    result: OpenConnection | None = None


@dataclass(slots=True)
class _PreparedConnectionCompositeMaterializationRecord:
    """Manager-owned exact authority for one yielded connection composite."""

    preparation: "PreparedConnectionCompositeMaterialization"
    plan: ConnectionCompositeMaterializationPlan
    owner_rng: random.Random
    claim_thread_id: int
    claim_epoch: int
    claim_version: int
    claim_state_time: datetime | None
    rng_state: object
    committed: bool = False
    failed: bool = False
    terminal: bool = False
    result: ConnectionCompositeMaterializationResult | None = None


@dataclass(slots=True)
class _PreparedMaterializationBatchRecord:
    """Manager-owned exact authority for one claimed start batch."""

    preparation: "PreparedMaterializationBatch"
    plan: MaterializationBatchPlan
    claim_thread: Thread
    claim_epoch: int
    claim_version: int
    claim_state_time: datetime | None
    rollback_journal: _ActionCohortRollbackJournal
    claim_preimage: object
    certified: bool = False
    provisional: bool = False
    committed: bool = False
    failed: bool = False
    terminal: bool = False
    provisional_postimage: object | None = None
    result: tuple[ActiveSession | None, tuple[RunningProcess, ...]] | None = None


class ActionCohortMaterializationBuilder(MaterializationBatchBuilder):
    """Allocation-free builder for one ordered multi-session action cohort."""

    def __init__(self, manager: "StateManager", expected_version: int) -> None:
        super().__init__(manager, expected_version)
        self._action_sessions: list[SessionMaterializationPlan] = []
        self._action_session_process_plans: dict[int, dict[str, ProcessMaterializationPlan]] = {}
        self._live_session_process_roles_patches: list[
            ActionCohortLiveSessionProcessRolesPatch
        ] = []
        self._session_metadata_patches: list[ActionCohortSessionMetadataPatch] = []
        self._process_activity_patches: list[ActionCohortProcessActivityPatch] = []
        self._session_activity_patches: list[ActionCohortSessionActivityPatch] = []
        self._process_termination_drafts: list[ActionCohortProcessTermination] = []
        self._session_terminalization_drafts: list[ActionCohortSessionTerminalization] = []
        self._cancelled = False
        self._planned_host_bases: dict[str, int] = {}
        self._planned_host_epochs: dict[str, datetime] = {}
        self._planned_logon_ordinals: dict[tuple[str, int, int], int] = {}
        self._planned_logon_ids: set[str] = set()
        self._planned_logon_luids: set[int] = set()
        self._planned_windows_session_ids: dict[str, set[int]] = {}
        self._planned_windows_session_counters: dict[str, int] = {}

    def _require_open(self) -> None:
        if self._cancelled:
            raise StateError("Action cohort materialization builder is cancelled")
        super()._require_open()

    def cancel(self) -> None:
        """Idempotently discard an open builder without changing StateManager."""

        if self._sealed:
            raise StateError("Sealed action cohort materialization cannot be cancelled")
        if self._cancelled:
            return
        self._cancelled = True
        self._action_sessions.clear()
        self._processes.clear()
        self._action_session_process_plans.clear()
        self._live_session_process_roles_patches.clear()
        self._session_metadata_patches.clear()
        self._process_activity_patches.clear()
        self._session_activity_patches.clear()
        self._process_termination_drafts.clear()
        self._session_terminalization_drafts.clear()
        self._session_process_plans.clear()

    def plan_session(
        self,
        *,
        username: str,
        system: str,
        logon_type: int,
        source_ip: str,
        source_port: int = 0,
        session_kind: str = "logon",
        transport_pid: int | None = None,
        start_time: datetime | None = None,
        logon_id: str | None = None,
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
    ) -> SessionMaterializationPlan:
        """Plan one exact session using this builder's private allocator overlay."""

        self._require_open()
        plan = self._manager._plan_action_cohort_session(
            self,
            username=username,
            system=system,
            logon_type=logon_type,
            source_ip=source_ip,
            source_port=source_port,
            session_kind=session_kind,
            transport_pid=transport_pid,
            start_time=start_time,
            logon_id=logon_id,
            logon_guid=logon_guid,
            logon_guid_required=logon_guid_required,
            session_id=session_id,
            lifecycle_group_id=lifecycle_group_id,
            parent_lifecycle_group_id=parent_lifecycle_group_id,
            auth_protocol=auth_protocol,
            smb_principal=smb_principal,
            account_scope=account_scope,
            auth_session_ref=auth_session_ref,
            effective_uid=effective_uid,
            effective_gid=effective_gid,
        )
        self._action_sessions.append(plan)
        return plan

    def plan_process(
        self,
        *,
        system: str,
        parent_pid: int,
        image: str,
        command_line: str,
        username: str,
        integrity_level: str,
        os_category: str,
        logon_id: str = "",
        lifecycle_group_id: str = "",
        parent_lifecycle_group_id: str = "",
        concurrency_group_id: str = "",
        start_time: datetime | None = None,
        fixed_pid: int | None = None,
        require_session: bool = False,
        parent_activity_time: datetime | None = None,
        auth_session_id: int | None = None,
        auth_logon_type: int | None = None,
        parent_plan: ProcessMaterializationPlan | None = None,
        session_plan: SessionMaterializationPlan | None = None,
    ) -> ProcessMaterializationPlan:
        """Plan one parent-ordered process against live or staged owners."""

        self._require_open()
        if parent_plan is not None and not any(
            parent_plan is candidate for candidate in self._processes
        ):
            raise StateError("Action cohort process parent belongs to another builder")
        resolved_session = session_plan
        if resolved_session is None and logon_id:
            matches = [
                candidate
                for candidate in self._action_sessions
                if candidate.identity.logon_id == logon_id and candidate.identity.hostname == system
            ]
            if len(matches) > 1:
                raise StateError("Action cohort process has an ambiguous staged session owner")
            resolved_session = matches[0] if matches else None
        if resolved_session is not None and not any(
            resolved_session is candidate for candidate in self._action_sessions
        ):
            raise StateError("Action cohort process session belongs to another builder")

        previous_session = self._session
        self._session = resolved_session
        try:
            return super().plan_process(
                system=system,
                parent_pid=parent_pid,
                image=image,
                command_line=command_line,
                username=username,
                integrity_level=integrity_level,
                os_category=os_category,
                logon_id=logon_id,
                lifecycle_group_id=lifecycle_group_id,
                parent_lifecycle_group_id=parent_lifecycle_group_id,
                concurrency_group_id=concurrency_group_id,
                start_time=start_time,
                fixed_pid=fixed_pid,
                require_session=require_session,
                parent_activity_time=parent_activity_time,
                auth_session_id=auth_session_id,
                auth_logon_type=auth_logon_type,
                parent_plan=parent_plan,
                session_plan=resolved_session,
            )
        finally:
            self._session = previous_session

    def bind_session_processes(
        self,
        session: SessionMaterializationPlan,
        *,
        transport_plan: ProcessMaterializationPlan | None = None,
        shell_plan: ProcessMaterializationPlan | None = None,
        user_manager_plan: ProcessMaterializationPlan | None = None,
        winlogon_plan: ProcessMaterializationPlan | None = None,
        explorer_plan: ProcessMaterializationPlan | None = None,
        process_tree_root_plan: ProcessMaterializationPlan | None = None,
    ) -> None:
        """Bind exact process roles to any staged session in this cohort."""

        self._require_open()
        if not any(session is candidate for candidate in self._action_sessions):
            raise StateError("Action cohort session process links use another builder")
        values = {
            "transport": transport_plan,
            "shell": shell_plan,
            "user_manager": user_manager_plan,
            "winlogon": winlogon_plan,
            "explorer": explorer_plan,
            "process_tree_root": process_tree_root_plan,
        }
        links = self._action_session_process_plans.setdefault(id(session), {})
        for role, process in values.items():
            if process is None:
                continue
            if not any(process is candidate for candidate in self._processes):
                raise StateError(f"Action cohort session {role} uses another process builder")
            current = links.get(role)
            if current is not None and current is not process:
                raise StateError(f"Action cohort session {role} is already bound")
            links[role] = process

    def bind_live_windows_session_shell(
        self,
        target: SessionIdentity,
        *,
        winlogon_plan: ProcessMaterializationPlan | None,
        explorer_plan: ProcessMaterializationPlan,
        process_tree_root_plan: ProcessMaterializationPlan | None,
    ) -> None:
        """Bind a staged Windows shell into one exact already-live desktop session."""

        self._require_open()
        if len(self._live_session_process_roles_patches) >= (
            _MAX_ACTION_COHORT_LIVE_SESSION_PROCESS_ROLE_PATCHES
        ):
            raise StateError("Action cohort live-session role patch limit exceeded")
        patch = self._manager._prepare_action_cohort_live_windows_session_shell_patch(
            self,
            target=target,
            winlogon_plan=winlogon_plan,
            explorer_plan=explorer_plan,
            process_tree_root_plan=process_tree_root_plan,
        )
        target_key = self._manager._action_session_target_key(patch.target)
        if any(
            self._manager._action_session_target_key(candidate.target) == target_key
            for candidate in self._live_session_process_roles_patches
        ):
            raise StateError("Action cohort repeats a live-session process-role patch")
        self._live_session_process_roles_patches.append(patch)

    def session_metadata(
        self,
        target: SessionMaterializationPlan | SessionIdentity,
    ) -> ActionCohortSessionMetadataState:
        """Return the exact current staged/live metadata projection."""

        self._require_open()
        normalized = self._manager._normalize_action_cohort_session_target(self, target)
        for patch in reversed(self._session_metadata_patches):
            if self._manager._action_session_target_key(patch.target) == (
                self._manager._action_session_target_key(normalized)
            ):
                return patch.after
        return self._manager._action_cohort_session_metadata(normalized)

    def transition_session_metadata(
        self,
        target: SessionMaterializationPlan | SessionIdentity,
        after: ActionCohortSessionMetadataState,
    ) -> None:
        """Stage one exact closed metadata transition for a session."""

        self._require_open()
        if type(after) is not ActionCohortSessionMetadataState:
            raise TypeError("Action cohort metadata transition requires an exact state")
        normalized = self._manager._normalize_action_cohort_session_target(self, target)
        key = self._manager._action_session_target_key(normalized)
        if any(
            self._manager._action_session_target_key(patch.target) == key
            for patch in self._session_metadata_patches
        ):
            raise StateError("Action cohort repeats a session metadata transition")
        before = self._manager._action_cohort_session_metadata(normalized)
        self._session_metadata_patches.append(
            ActionCohortSessionMetadataPatch(
                target=normalized,
                before=before,
                after=after,
                _capability=_ActionCohortCapability(),
            )
        )

    def patch_process_activity(
        self,
        target: ProcessMaterializationPlan | ProcessIdentity,
        activity_time: datetime,
    ) -> None:
        """Stage one exact process activity frontier."""

        self._require_open()
        normalized = self._manager._normalize_action_cohort_process_target(self, target)
        key = self._manager._action_process_target_key(normalized)
        if any(
            self._manager._action_process_target_key(patch.target) == key
            for patch in self._process_activity_patches
        ):
            raise StateError("Action cohort repeats a process activity patch")
        self._process_activity_patches.append(
            ActionCohortProcessActivityPatch(
                target=normalized,
                activity_time=activity_time,
                _capability=_ActionCohortCapability(),
            )
        )

    def patch_session_activity(
        self,
        target: SessionMaterializationPlan | SessionIdentity,
        activity_time: datetime,
    ) -> None:
        """Stage one exact session activity frontier."""

        self._require_open()
        normalized = self._manager._normalize_action_cohort_session_target(self, target)
        key = self._manager._action_session_target_key(normalized)
        if any(
            self._manager._action_session_target_key(patch.target) == key
            for patch in self._session_activity_patches
        ):
            raise StateError("Action cohort repeats a session activity patch")
        self._session_activity_patches.append(
            ActionCohortSessionActivityPatch(
                target=normalized,
                activity_time=activity_time,
                _capability=_ActionCohortCapability(),
            )
        )

    def terminate_process(
        self,
        target: ProcessMaterializationPlan | ProcessIdentity,
        *,
        end_time: datetime,
        parent_activity_time: datetime | None = None,
    ) -> None:
        """Stage one live or same-cohort process terminalization."""

        self._require_open()
        normalized = self._manager._normalize_action_cohort_process_target(self, target)
        key = self._manager._action_process_target_key(normalized)
        if any(
            self._manager._action_process_target_key(termination.target) == key
            for termination in self._process_termination_drafts
        ):
            raise StateError("Action cohort repeats a process terminalization")
        if type(normalized) is ProcessIdentity:
            close_plan = self._manager.plan_process_termination_materialization(
                system=normalized.hostname,
                pid=normalized.pid,
                end_time=end_time,
                parent_activity_time=parent_activity_time,
            )
            if close_plan.identity != normalized:
                raise StateError("Action cohort live process identity drifted before close")
            target_plan: ProcessTerminationMaterializationPlan | ProcessMaterializationPlan = (
                close_plan
            )
            parent_activity = None
            effective_end = close_plan.end_time
        else:
            target_plan = normalized
            effective_end = ensure_utc(end_time)
            parent_activity = None
            if parent_activity_time is not None:
                parent_target = self._manager._action_cohort_process_parent_target(
                    self,
                    normalized,
                )
                parent_activity = ActionCohortProcessActivityPatch(
                    target=parent_target,
                    activity_time=parent_activity_time,
                    _capability=_ActionCohortCapability(),
                )
        self._process_termination_drafts.append(
            ActionCohortProcessTermination(
                target=target_plan,
                end_time=effective_end,
                parent_activity=parent_activity,
                staged_session_references=(),
                _capability=_ActionCohortCapability(),
            )
        )

    def terminalize_session(
        self,
        target: SessionMaterializationPlan | SessionIdentity,
        *,
        end_time: datetime,
    ) -> None:
        """Stage one live or same-cohort session terminalization."""

        self._require_open()
        normalized = self._manager._normalize_action_cohort_session_target(self, target)
        key = self._manager._action_session_target_key(normalized)
        if any(
            self._manager._action_session_target_key(terminalization.target) == key
            for terminalization in self._session_terminalization_drafts
        ):
            raise StateError("Action cohort repeats a session terminalization")
        self._session_terminalization_drafts.append(
            ActionCohortSessionTerminalization(
                target=normalized,
                end_time=end_time,
                _capability=_ActionCohortCapability(),
            )
        )

    def seal(self) -> ActionCohortMaterializationPlan:
        """Freeze and authenticate the complete allocation-free cohort."""

        self._require_open()
        plan = self._manager._seal_action_cohort_materialization(self)
        self._sealed = True
        return plan


_MaterializationPlan = (
    SessionMaterializationPlan
    | ProcessMaterializationPlan
    | ProcessTerminationMaterializationPlan
    | ConnectionMaterializationPlan
    | MaterializationBatchPlan
    | ConnectionCompositeMaterializationPlan
    | ActionCohortMaterializationPlan
)


def _materialization_integrity_token(
    authority_secret: bytes,
    kind: str,
    expected_version: int,
    identity: SessionIdentity | ProcessIdentity,
    payload: _SessionMaterializationPayload | _ProcessMaterializationPayload,
    allocator_patch: _SessionAllocatorPatch | _ProcessAllocatorPatch,
) -> str:
    """Authenticate every immutable plan and allocator-patch field."""

    canonical = repr((kind, expected_version, identity, payload, allocator_patch)).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


def _process_termination_materialization_integrity_token(
    authority_secret: bytes,
    *,
    expected_version: int,
    identity: ProcessIdentity,
    payload: _ProcessTerminationMaterializationPayload,
) -> str:
    """Authenticate every immutable field in one process-termination plan."""

    canonical = repr(
        (
            "process-termination-materialization",
            expected_version,
            identity,
            payload,
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


def _connection_identity_integrity_token(
    authority_secret: bytes,
    *,
    expected_version: int,
    conn_id: str,
    zeek_uid: str,
    counter_after: int,
    rng_state_before: object,
    rng_state_after_identity: object,
) -> str:
    """Authenticate every connection identity reservation field."""

    canonical = repr(
        (
            "connection-identity",
            expected_version,
            conn_id,
            zeek_uid,
            counter_after,
            rng_state_before,
            rng_state_after_identity,
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


def _connection_materialization_integrity_token(
    authority_secret: bytes,
    *,
    expected_version: int,
    identity: ConnectionIdentityPlan,
    payload: _ConnectionMaterializationPayload,
) -> str:
    """Authenticate one final connection payload and its reserved identity."""

    canonical = repr(
        (
            "connection-materialization",
            expected_version,
            identity.publication_token,
            payload,
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


def _connection_cursor_integrity_token(
    authority_secret: bytes,
    *,
    expected_version: int,
    expected_state_time: datetime | None,
    expected_connection_counter: int,
    owner_identity: int,
    rng_state_entry: object,
) -> str:
    """Authenticate one RNG-owner and StateManager transaction entry fence."""

    canonical = repr(
        (
            "connection-planning-cursor",
            expected_version,
            expected_state_time,
            expected_connection_counter,
            owner_identity,
            rng_state_entry,
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


def _connection_cursor_identity_binding_token(
    authority_secret: bytes,
    *,
    cursor_token: str,
    identity_token: str,
) -> str:
    """Bind the historical UID draw to the exact cursor that performed it."""

    canonical = repr(
        (
            "connection-cursor-identity",
            cursor_token,
            identity_token,
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


def _connection_composite_integrity_token(
    authority_secret: bytes,
    *,
    expected_version: int,
    expected_state_time: datetime | None,
    expected_connection_counter: int,
    owner_identity: int,
    rng_state_entry: object,
    rng_state_final: object,
    cursor_token: str,
    identity: ConnectionIdentityPlan | None,
    transaction: NetworkTransactionPlan,
    source_system: str,
    source_hostname: str,
    hostname: str,
    initiating_pid: int,
    mode: ConnectionMaterializationMode,
    parent_patch: _ConnectionParentAccountingPatch | None,
    batch: MaterializationBatchPlan | None,
    existing_session_patch: ConnectionExistingSessionPatch | None,
    existing_session_process_roles_patch: ConnectionExistingSessionProcessRolesPatch | None,
    process_activity: tuple[ProcessActivityPatch, ...],
    session_activity: tuple[SessionActivityPatch, ...],
    final_state_time: datetime,
) -> str:
    """Authenticate every State-owned field in one connection composite."""

    canonical = repr(
        (
            "connection-composite",
            expected_version,
            expected_state_time,
            expected_connection_counter,
            owner_identity,
            rng_state_entry,
            rng_state_final,
            cursor_token,
            identity.publication_token if identity is not None else "",
            transaction,
            source_system,
            source_hostname,
            hostname,
            initiating_pid,
            mode,
            parent_patch,
            batch.publication_token if batch is not None else "",
            existing_session_patch,
            (
                existing_session_process_roles_patch.publication_token
                if existing_session_process_roles_patch is not None
                else ""
            ),
            process_activity,
            session_activity,
            final_state_time,
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


def _materialization_batch_integrity_token(
    authority_secret: bytes,
    *,
    expected_version: int,
    expected_state_time: datetime | None,
    admission_epoch: int,
    final_state_time: datetime,
    session: SessionMaterializationPlan | None,
    processes: tuple[ProcessMaterializationPlan, ...],
    boot_times: tuple[tuple[str, datetime], ...],
    session_process_links: _SessionProcessMaterializationLinks,
) -> str:
    """Authenticate the exact ordered membership of one start batch."""

    canonical = repr(
        (
            "materialization-batch",
            expected_version,
            expected_state_time,
            admission_epoch,
            final_state_time,
            session.publication_token if session is not None else "",
            tuple(plan.publication_token for plan in processes),
            boot_times,
            session_process_links,
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


_ACTION_COHORT_SAFE_RECORD_TYPES = frozenset(
    {
        SessionIdentity,
        ProcessIdentity,
        ThreadIdentity,
        SessionEndPlan,
        _LinuxLogindAllocatorPatch,
        _SessionAllocatorPatch,
        _SessionMaterializationPayload,
        SessionMaterializationPlan,
        _ProcessAllocatorPatch,
        _ProcessMaterializationPayload,
        ProcessMaterializationPlan,
        _ProcessTerminationSessionReference,
        _ProcessTerminationMaterializationPayload,
        ProcessTerminationMaterializationPlan,
        _SessionProcessMaterializationLinks,
        ActionCohortSessionMetadataState,
        ActionCohortSessionMetadataPatch,
        ActionCohortLiveSessionProcessRolesState,
        ActionCohortLiveSessionProcessRolesPatch,
        ActionCohortProcessActivityPatch,
        ActionCohortSessionActivityPatch,
        ActionCohortProcessTermination,
        ActionCohortSessionTerminalization,
        _ActionCohortSessionProcessLinks,
    }
)


def _validate_action_cohort_safe_value(value: object, active: set[int]) -> None:
    """Reject values that could run caller code during cohort authentication."""

    if value is None or type(value) in {bool, int, float, str, bytes, datetime}:
        return
    if type(value) is _ActionCohortCapability:
        return
    if type(value) is tuple:
        object_id = id(value)
        if object_id in active:
            raise StateError("Action cohort capability contains a recursive tuple")
        active.add(object_id)
        try:
            for item in value:
                _validate_action_cohort_safe_value(item, active)
        finally:
            active.remove(object_id)
        return
    if type(value) in _ACTION_COHORT_SAFE_RECORD_TYPES:
        object_id = id(value)
        if object_id in active:
            raise StateError("Action cohort capability contains a recursive record")
        active.add(object_id)
        try:
            for item in fields(value):
                _validate_action_cohort_safe_value(getattr(value, item.name), active)
        finally:
            active.remove(object_id)
        return
    raise StateError(
        "Action cohort capability contains an unsupported value type: "
        f"{type(value).__module__}.{type(value).__qualname__}"
    )


def _action_cohort_session_target_semantic(
    target: SessionMaterializationPlan | SessionIdentity,
) -> tuple[object, ...]:
    """Return semantic-only State truth for one session target."""

    if type(target) is SessionMaterializationPlan:
        return (
            "staged-session",
            target._expected_version,
            target._identity,
            target._payload,
            target._allocator_patch,
        )
    return ("live-session", target)


def _action_cohort_process_target_semantic(
    target: ProcessMaterializationPlan | ProcessIdentity,
) -> tuple[object, ...]:
    """Return semantic-only State truth for one process target."""

    if type(target) is ProcessMaterializationPlan:
        return (
            "staged-process",
            target._expected_version,
            target._identity,
            target._payload,
            target._allocator_patch,
        )
    return ("live-process", target)


def _action_cohort_semantic_preimage(
    *,
    expected_version: int,
    expected_state_time: datetime | None,
    final_state_time: datetime,
    sessions: tuple[SessionMaterializationPlan, ...],
    processes: tuple[ProcessMaterializationPlan, ...],
    session_process_links: tuple[_ActionCohortSessionProcessLinks, ...],
    live_session_process_roles: tuple[ActionCohortLiveSessionProcessRolesPatch, ...],
    session_metadata: tuple[ActionCohortSessionMetadataPatch, ...],
    process_activity: tuple[ActionCohortProcessActivityPatch, ...],
    session_activity: tuple[ActionCohortSessionActivityPatch, ...],
    process_terminations: tuple[ActionCohortProcessTermination, ...],
    session_terminalizations: tuple[ActionCohortSessionTerminalization, ...],
) -> tuple[object, ...]:
    """Return deterministic semantics without secrets or object addresses."""

    return (
        "action-cohort-materialization-v2",
        expected_version,
        expected_state_time,
        final_state_time,
        tuple(_action_cohort_session_target_semantic(plan) for plan in sessions),
        tuple(_action_cohort_process_target_semantic(plan) for plan in processes),
        session_process_links,
        tuple(
            (
                _action_cohort_session_target_semantic(patch.target),
                patch.before,
                patch.after,
                (
                    _action_cohort_process_target_semantic(patch.winlogon_plan)
                    if patch.winlogon_plan is not None
                    else None
                ),
                _action_cohort_process_target_semantic(patch.explorer_plan),
                (
                    _action_cohort_process_target_semantic(patch.process_tree_root_plan)
                    if patch.process_tree_root_plan is not None
                    else None
                ),
            )
            for patch in live_session_process_roles
        ),
        tuple(
            (
                _action_cohort_session_target_semantic(patch.target),
                patch.before,
                patch.after,
            )
            for patch in session_metadata
        ),
        tuple(
            (_action_cohort_process_target_semantic(patch.target), patch.activity_time)
            for patch in process_activity
        ),
        tuple(
            (_action_cohort_session_target_semantic(patch.target), patch.activity_time)
            for patch in session_activity
        ),
        tuple(
            (
                (
                    "live-process-termination",
                    termination.target._expected_version,
                    termination.target._identity,
                    termination.target._payload,
                )
                if type(termination.target) is ProcessTerminationMaterializationPlan
                else _action_cohort_process_target_semantic(termination.target),
                termination.end_time,
                (
                    (
                        _action_cohort_process_target_semantic(termination.parent_activity.target),
                        termination.parent_activity.activity_time,
                    )
                    if termination.parent_activity is not None
                    else None
                ),
                termination.staged_session_references,
            )
            for termination in process_terminations
        ),
        tuple(
            (
                _action_cohort_session_target_semantic(terminalization.target),
                terminalization.end_time,
            )
            for terminalization in session_terminalizations
        ),
    )


def _action_cohort_semantic_id(**kwargs: object) -> str:
    """Hash one safe, exact action-cohort semantic preimage."""

    frozen = _freeze_materialization_digest_value(
        _action_cohort_semantic_preimage(**kwargs),  # type: ignore[arg-type]
        set(),
    )
    return hashlib.sha256(repr(frozen).encode()).hexdigest()


def _action_cohort_target_capability(
    target: SessionMaterializationPlan
    | ProcessMaterializationPlan
    | ProcessTerminationMaterializationPlan
    | SessionIdentity
    | ProcessIdentity,
) -> tuple[object, ...]:
    """Bind only ephemeral manager-issued plan objects by Python identity."""

    if type(target) in {
        SessionMaterializationPlan,
        ProcessMaterializationPlan,
        ProcessTerminationMaterializationPlan,
    }:
        return (id(target), target.publication_token)
    return ()


def _action_cohort_integrity_token(
    authority_secret: bytes,
    *,
    semantic_id: str,
    capability: _ActionCohortCapability,
    sessions: tuple[SessionMaterializationPlan, ...],
    processes: tuple[ProcessMaterializationPlan, ...],
    live_session_process_roles: tuple[ActionCohortLiveSessionProcessRolesPatch, ...],
    session_metadata: tuple[ActionCohortSessionMetadataPatch, ...],
    process_activity: tuple[ActionCohortProcessActivityPatch, ...],
    session_activity: tuple[ActionCohortSessionActivityPatch, ...],
    process_terminations: tuple[ActionCohortProcessTermination, ...],
    session_terminalizations: tuple[ActionCohortSessionTerminalization, ...],
) -> str:
    """Authenticate the exact ephemeral capabilities and their tuple order."""

    canonical = (
        "action-cohort-capability-v2",
        semantic_id,
        id(capability),
        tuple((id(plan), plan.publication_token) for plan in sessions),
        tuple((id(plan), plan.publication_token) for plan in processes),
        tuple(
            (
                id(patch),
                id(patch._capability),
                _action_cohort_target_capability(patch.target),
                (
                    _action_cohort_target_capability(patch.winlogon_plan)
                    if patch.winlogon_plan is not None
                    else ()
                ),
                _action_cohort_target_capability(patch.explorer_plan),
                (
                    _action_cohort_target_capability(patch.process_tree_root_plan)
                    if patch.process_tree_root_plan is not None
                    else ()
                ),
            )
            for patch in live_session_process_roles
        ),
        tuple(
            (
                id(patch._capability),
                _action_cohort_target_capability(patch.target),
            )
            for patch in session_metadata
        ),
        tuple(
            (
                id(patch._capability),
                _action_cohort_target_capability(patch.target),
            )
            for patch in process_activity
        ),
        tuple(
            (
                id(patch._capability),
                _action_cohort_target_capability(patch.target),
            )
            for patch in session_activity
        ),
        tuple(
            (
                id(termination._capability),
                _action_cohort_target_capability(termination.target),
                (
                    id(termination.parent_activity._capability),
                    _action_cohort_target_capability(termination.parent_activity.target),
                )
                if termination.parent_activity is not None
                else (),
            )
            for termination in process_terminations
        ),
        tuple(
            (
                id(terminalization._capability),
                _action_cohort_target_capability(terminalization.target),
            )
            for terminalization in session_terminalizations
        ),
    )
    return hmac.new(authority_secret, repr(canonical).encode(), hashlib.sha256).hexdigest()


def _action_cohort_result_publication_token(
    authority_secret: bytes,
    *,
    plan: ActionCohortMaterializationPlan,
    result: ActionCohortMaterializationResult,
    commit_plan: _PreparedActionCohortCommitPlan,
) -> str:
    """Authenticate one exact claim-owned precomputed result."""

    canonical = (
        "action-cohort-state-result-v1",
        id(plan),
        plan.publication_token,
        id(result),
        commit_plan.claim_version,
        commit_plan.claim_state_time,
        repr(result),
    )
    return hmac.new(authority_secret, repr(canonical).encode(), hashlib.sha256).hexdigest()


def _session_valid_at(session: ActiveSession, cutoff: datetime) -> bool:
    """Return whether a session can own visible activity at cutoff."""
    if ensure_utc(session.start_time) > cutoff:
        return False
    end_plan = session.end_plan
    if end_plan is not None and end_plan.is_hard_deadline:
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


@dataclass(slots=True)
class PreparedConnectionMaterialization:
    """State-lock-scoped connection commit ticket with no remaining validation."""

    _manager: "StateManager"
    _plan: ConnectionMaterializationPlan
    _rng: random.Random
    _active: bool = True
    _committed: bool = False
    _result: OpenConnection | None = None

    @property
    def committed(self) -> bool:
        """Return whether connection allocator/state truth was published."""

        return self._manager._prepared_connection_materialization_committed(self)

    def commit(self) -> OpenConnection | None:
        """Publish the fully validated plan using primitive writes only."""

        return self._manager._commit_claimed_connection_materialization(self)


@dataclass(slots=True)
class PreparedConnectionCompositeMaterialization:
    """State-guard-scoped one-shot composite commit capability."""

    _manager: "StateManager"
    _plan: ConnectionCompositeMaterializationPlan
    _owner_rng: random.Random
    _active: bool = True
    _committed: bool = False
    _result: ConnectionCompositeMaterializationResult | None = None

    @property
    def committed(self) -> bool:
        """Return whether the complete State transaction was published."""

        return self._manager._prepared_connection_composite_materialization_committed(self)

    def commit(self) -> ConnectionCompositeMaterializationResult:
        """Publish the fully prevalidated composite exactly once."""

        return self._manager._commit_claimed_connection_composite_materialization(self)


@dataclass(slots=True)
class PreparedMaterializationBatch:
    """State-guard-scoped one-shot start-batch commit capability."""

    _manager: "StateManager"
    _plan: MaterializationBatchPlan
    _claim_thread: Thread
    _active: bool = True
    _committed: bool = False
    _result: tuple[ActiveSession | None, tuple[RunningProcess, ...]] | None = None

    @property
    def committed(self) -> bool:
        """Return whether this exact claimed batch reached canonical State."""

        return self._manager._prepared_materialization_batch_committed(self)

    @property
    def provisionally_applied(self) -> bool:
        """Return whether exact reversible State writes are currently installed."""

        return self._manager._prepared_materialization_batch_provisionally_applied(self)

    def apply_provisional(self) -> tuple[ActiveSession | None, tuple[RunningProcess, ...]]:
        """Apply and certify reversible State writes under the retained claim."""

        return self._manager._apply_claimed_materialization_batch(self)

    def finalize_no_fail(self) -> tuple[ActiveSession | None, tuple[RunningProcess, ...]]:
        """Make an already-certified provisional State batch terminal."""

        return self._manager._finalize_claimed_materialization_batch_no_fail(self)

    def commit_no_fail(self) -> tuple[ActiveSession | None, tuple[RunningProcess, ...]]:
        """Compatibility commit as one provisional apply and terminal finalize pair."""

        self.apply_provisional()
        return self.finalize_no_fail()

    def commit(self) -> tuple[ActiveSession | None, tuple[RunningProcess, ...]]:
        """Compatibility alias for :meth:`commit_no_fail`."""

        return self.commit_no_fail()


@dataclass(slots=True)
class PreparedActionCohortMaterialization:
    """State-guard-scoped one-shot action-cohort commit capability."""

    _manager: "StateManager"
    _plan: ActionCohortMaterializationPlan
    _expected_result: ActionCohortMaterializationResult
    _claim_thread_id: int
    _active: bool = True
    _committed: bool = False
    _result: ActionCohortMaterializationResult | None = None

    @property
    def committed(self) -> bool:
        """Return whether the complete State cohort was published."""

        return self._manager._action_cohort_preparation_committed(self)

    @property
    def expected_result(self) -> ActionCohortMaterializationResult:
        """Return the exact immutable result authenticated by this active claim."""

        return self._manager._expected_action_cohort_result_for(self)

    @property
    def expected_result_publication_token(self) -> str:
        """Return the owner-precomputed token for this exact expected result."""

        return self._manager._expected_action_cohort_result_publication_token_for(self)

    def certify_composite_commit(
        self,
        expected_result: ActionCohortMaterializationResult,
    ) -> None:
        """Authenticate this exact claim once for a later composite commit tail."""

        self._manager._certify_expected_action_cohort_result(
            expected_result,
            preparation=self,
        )

    def commit_no_fail(self) -> ActionCohortMaterializationResult:
        """Publish the fully prevalidated primitive transaction exactly once."""

        self._result = self._manager._commit_claimed_action_cohort_materialization(self)
        self._committed = True
        return self._result

    def apply_provisional(self) -> None:
        """Apply certified State writes while this claim retains rollback ownership."""

        self._manager._apply_claimed_action_cohort_materialization(
            self,
            require_certified=True,
        )

    def finalize_no_fail(self) -> ActionCohortMaterializationResult:
        """Make a provisionally applied cohort terminal and return its exact result."""

        result = self._manager._finalize_claimed_action_cohort_materialization(self)
        self._result = result
        self._committed = True
        return result

    def commit(self) -> ActionCohortMaterializationResult:
        """Compatibility alias for :meth:`commit_no_fail`."""

        return self.commit_no_fail()


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
        self._logon_id_aliases_by_target: dict[str, set[str]] = {}
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
        self._materialization_version = 0
        self._materialization_secret = secrets.token_bytes(32)
        self._active_connection_preparations: dict[
            int, _PreparedConnectionMaterializationRecord
        ] = {}
        self._active_connection_composite_preparations: dict[
            int, _PreparedConnectionCompositeMaterializationRecord
        ] = {}
        self._active_materialization_batch_preparations: dict[
            int, _PreparedMaterializationBatchRecord
        ] = {}
        self._active_action_cohort_preparations: dict[int, _ActionCohortPreparationRecord] = {}
        self._active_action_cohort_claim: _ActionCohortPreparationRecord | None = None
        self._active_prepared_state_claim: (
            _PreparedConnectionMaterializationRecord
            | _PreparedConnectionCompositeMaterializationRecord
            | _PreparedMaterializationBatchRecord
            | _ActionCohortPreparationRecord
            | None
        ) = None
        self._prepared_state_admission_epoch = 0

        # Entity lifecycle: per-system boot times for temporal validation
        self._system_boot_times: dict[str, datetime] = {}
        self._ended_sessions: ExpiringIndex[str, tuple[ActiveSession, datetime]] = ExpiringIndex(
            deadline=lambda ended: (ensure_utc(ended[1]) + _ENDED_IDENTITY_RETENTION).timestamp()
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
        self._smb_file_overlay: dict[str, SmbFileState] = {}
        self._smb_file_by_share_path: dict[tuple[str, str], str] = {}
        self._smb_file_mutation_journals: dict[
            str,
            _SmbFileMutationJournalCapability,
        ] = {}
        self._smb_file_mutation_journal_by_operation: dict[str, str] = {}
        self._smb_file_mutation_owner_by_file_id: dict[str, str] = {}
        self._smb_file_mutation_owner_by_path: dict[tuple[str, str], str] = {}

    @property
    def materialization_version(self) -> int:
        """Return the monotonic start-publication fence for prepared dispatches."""

        with self._lock:
            return self._materialization_version

    def authenticates_materialization_plan(self, plan: _MaterializationPlan) -> bool:
        """Verify an opaque plan's keyed integrity without applying its version fence."""

        with self._lock:
            try:
                if isinstance(plan, SessionMaterializationPlan):
                    self._validate_session_materialization_plan(plan)
                elif isinstance(plan, ProcessMaterializationPlan):
                    self._validate_process_materialization_plan(plan)
                elif isinstance(plan, ProcessTerminationMaterializationPlan):
                    self._validate_process_termination_materialization_plan(plan)
                elif isinstance(plan, ConnectionMaterializationPlan):
                    self._validate_connection_materialization_plan(plan)
                elif isinstance(plan, MaterializationBatchPlan):
                    self._validate_materialization_batch_plan(plan)
                elif isinstance(plan, ConnectionCompositeMaterializationPlan):
                    self._validate_connection_composite_plan_integrity(plan)
                elif type(plan) is ActionCohortMaterializationPlan:
                    self._validate_action_cohort_plan_integrity(plan)
                else:
                    return False
            except StateError:
                return False
            return True

    def authenticates_action_cohort_plan(self, plan: object) -> bool:
        """Totally verify one exact action-cohort HMAC capability."""

        if type(plan) is not ActionCohortMaterializationPlan:
            return False
        with self._lock:
            try:
                self._validate_action_cohort_plan_integrity(plan)
            except (AttributeError, RecursionError, StateError, TypeError, ValueError):
                return False
            return True

    def authenticates_expected_action_cohort_result(
        self,
        result: object,
        *,
        preparation: object,
    ) -> bool:
        """Authenticate one active claim's exact precomputed result object."""

        if (
            type(result) is not ActionCohortMaterializationResult
            or type(preparation) is not PreparedActionCohortMaterialization
        ):
            return False
        record = self._active_action_cohort_preparations.get(id(preparation))
        if (
            record is None
            or record.preparation is not preparation
            or preparation._manager is not self
            or preparation._plan is not record.commit_plan.plan
            or preparation._expected_result is not record.expected_result
            or preparation._claim_thread_id != record.claim_thread_id
            or record.claim_thread_id != get_ident()
        ):
            return False
        with self._lock:
            return (
                self._active_action_cohort_preparations.get(id(preparation)) is record
                and self._active_action_cohort_claim is record
                and self._active_prepared_state_claim is record
                and preparation._manager is self
                and preparation._plan is record.commit_plan.plan
                and preparation._expected_result is record.expected_result
                and preparation._claim_thread_id == record.claim_thread_id
                and record.claim_epoch == self._prepared_state_admission_epoch
                and not record.terminal
                and not record.committed
                and not record.failed
                and record.expected_result is result
                and record.commit_plan.claim_version == self._materialization_version
                and record.commit_plan.claim_state_time == self.state.current_time
            )

    def _action_cohort_record_for(
        self,
        preparation: PreparedActionCohortMaterialization,
    ) -> _ActionCohortPreparationRecord:
        """Resolve and validate one exact active claim locator."""

        record = self._active_action_cohort_preparations.get(id(preparation))
        if (
            record is None
            or record.preparation is not preparation
            or preparation._manager is not self
            or preparation._plan is not record.commit_plan.plan
            or preparation._expected_result is not record.expected_result
            or preparation._claim_thread_id != record.claim_thread_id
            or self._active_action_cohort_claim is not record
            or self._active_prepared_state_claim is not record
            or record.claim_epoch != self._prepared_state_admission_epoch
            or record.terminal
        ):
            raise StateError("Prepared action cohort materialization is no longer active")
        if record.claim_thread_id != get_ident():
            raise StateError(
                "Prepared action cohort materialization belongs to its claiming thread"
            )
        return record

    def _certify_expected_action_cohort_result(
        self,
        result: ActionCohortMaterializationResult,
        *,
        preparation: PreparedActionCohortMaterialization,
    ) -> None:
        """Certify one exact result while retaining manager-owned claim authority."""

        record = self._action_cohort_record_for(preparation)
        with self._lock:
            if record.committed:
                raise StateError("Prepared action cohort materialization is already committed")
            if record.failed:
                raise StateError("Prepared action cohort materialization has already failed")
            if record.certified:
                raise StateError(
                    "Prepared action cohort materialization is already composite-certified"
                )
            if not self.authenticates_expected_action_cohort_result(
                result,
                preparation=preparation,
            ):
                raise StateError(
                    "Prepared action cohort expected result failed exact claim authentication"
                )
            record.certified = True

    def _expected_action_cohort_result_for(
        self,
        preparation: PreparedActionCohortMaterialization,
    ) -> ActionCohortMaterializationResult:
        """Resolve one expected result from the manager-owned active locator."""

        return self._action_cohort_record_for(preparation).expected_result

    def _expected_action_cohort_result_publication_token_for(
        self,
        preparation: PreparedActionCohortMaterialization,
    ) -> str:
        """Resolve the precomputed result token from exact owner state."""

        return self._action_cohort_record_for(preparation).expected_result_publication_token

    def _action_cohort_preparation_committed(
        self,
        preparation: PreparedActionCohortMaterialization,
    ) -> bool:
        """Return manager-owned terminal truth while a preparation remains active."""

        record = self._active_action_cohort_preparations.get(id(preparation))
        if record is not None and record.preparation is preparation:
            return record.committed
        return preparation._committed

    def _apply_claimed_action_cohort_materialization(
        self,
        preparation: PreparedActionCohortMaterialization,
        *,
        require_certified: bool,
    ) -> None:
        """Apply claim-owned primitives while retaining exact rollback authority."""

        record = self._action_cohort_record_for(preparation)
        with self._lock:
            if (
                self._active_action_cohort_claim is not record
                or self._active_prepared_state_claim is not record
                or record.claim_epoch != self._prepared_state_admission_epoch
            ):
                raise StateError("Prepared action cohort no longer owns the State mutation lane")
            if record.committed:
                raise StateError("Prepared action cohort materialization is already committed")
            if record.failed:
                raise StateError("Prepared action cohort materialization has already failed")
            if record.provisional:
                raise StateError(
                    "Prepared action cohort materialization is already provisionally applied"
                )
            if require_certified and not record.certified:
                raise StateError(
                    "Prepared action cohort materialization must be composite-certified "
                    "before provisional apply"
                )
            try:
                if not record.certified:
                    if not self.authenticates_expected_action_cohort_result(
                        record.expected_result,
                        preparation=preparation,
                    ):
                        raise StateError(
                            "Prepared action cohort expected result failed exact claim "
                            "authentication"
                        )
                    record.certified = True
                commit_plan = record.commit_plan
                if commit_plan.claim_version != self._materialization_version:
                    raise StateError("Prepared action cohort State version changed before apply")
                if commit_plan.claim_state_time != self.state.current_time:
                    raise StateError("Prepared action cohort State time changed before apply")
                if (
                    self._action_cohort_rollback_observation(commit_plan.rollback_journal)
                    != commit_plan.claim_preimage
                ):
                    raise StateError("Prepared action cohort touched State changed before apply")
            except StateError:
                record.failed = True
                raise
            record.provisional = True
            try:
                self._commit_prevalidated_action_cohort(commit_plan)
            except BaseException:
                record.failed = True
                record.provisional_postimage = self._action_cohort_rollback_observation(
                    commit_plan.rollback_journal
                )
                try:
                    self._restore_claimed_action_cohort_rollback(record)
                finally:
                    record.provisional = False
                    record.provisional_postimage = None
                raise
            record.provisional_postimage = self._action_cohort_rollback_observation(
                commit_plan.rollback_journal
            )

    def _finalize_claimed_action_cohort_materialization(
        self,
        preparation: PreparedActionCohortMaterialization,
    ) -> ActionCohortMaterializationResult:
        """Make a provisionally applied claim terminal without additional State writes."""

        record = self._action_cohort_record_for(preparation)
        with self._lock:
            if (
                self._active_action_cohort_claim is not record
                or self._active_prepared_state_claim is not record
                or record.claim_epoch != self._prepared_state_admission_epoch
            ):
                raise StateError("Prepared action cohort no longer owns the State mutation lane")
            if record.committed:
                raise StateError("Prepared action cohort materialization is already committed")
            if record.failed:
                raise StateError("Prepared action cohort materialization has already failed")
            if not record.provisional:
                raise StateError(
                    "Prepared action cohort materialization is not provisionally applied"
                )
            try:
                if self._materialization_version != record.commit_plan.committed_version:
                    raise StateError("Prepared action cohort State version drifted before finalize")
                if self.state.current_time != record.commit_plan.plan.final_state_time:
                    raise StateError("Prepared action cohort State time drifted before finalize")
                if (
                    record.provisional_postimage is None
                    or self._action_cohort_rollback_observation(record.commit_plan.rollback_journal)
                    != record.provisional_postimage
                ):
                    raise StateError("Prepared action cohort touched State drifted before finalize")
            except StateError:
                record.failed = True
                raise
            record.committed = True
            record.provisional = False
            record.provisional_postimage = None
            preparation._committed = True
            preparation._result = record.expected_result
            return record.expected_result

    def _commit_claimed_action_cohort_materialization(
        self,
        preparation: PreparedActionCohortMaterialization,
    ) -> ActionCohortMaterializationResult:
        """Compatibility commit as one provisional apply and terminal finalize pair."""

        self._apply_claimed_action_cohort_materialization(
            preparation,
            require_certified=False,
        )
        return self._finalize_claimed_action_cohort_materialization(preparation)

    def _prepared_connection_materialization_record_for(
        self,
        preparation: PreparedConnectionMaterialization,
    ) -> _PreparedConnectionMaterializationRecord:
        """Resolve one exact active connection preparation and claiming thread."""

        record = self._active_connection_preparations.get(id(preparation))
        if (
            record is None
            or record.preparation is not preparation
            or record.terminal
            or self._active_prepared_state_claim is not record
            or preparation._manager is not self
            or preparation._plan is not record.plan
            or preparation._rng is not record.rng
        ):
            raise StateError("Prepared connection materialization is no longer active")
        if record.claim_thread_id != get_ident():
            raise StateError("Prepared connection materialization belongs to its claiming thread")
        return record

    def _prepared_connection_composite_materialization_record_for(
        self,
        preparation: PreparedConnectionCompositeMaterialization,
    ) -> _PreparedConnectionCompositeMaterializationRecord:
        """Resolve one exact active connection-composite preparation and thread."""

        record = self._active_connection_composite_preparations.get(id(preparation))
        if (
            record is None
            or record.preparation is not preparation
            or record.terminal
            or self._active_prepared_state_claim is not record
            or preparation._manager is not self
            or preparation._plan is not record.plan
            or preparation._owner_rng is not record.owner_rng
        ):
            raise StateError("Prepared connection composite is no longer active")
        if record.claim_thread_id != get_ident():
            raise StateError("Prepared connection composite belongs to its claiming thread")
        return record

    def _materialization_batch_preparation_record_for(
        self,
        preparation: PreparedMaterializationBatch,
    ) -> _PreparedMaterializationBatchRecord:
        """Resolve one exact active batch preparation and claiming thread."""

        record = self._active_materialization_batch_preparations.get(id(preparation))
        if (
            record is None
            or record.preparation is not preparation
            or record.terminal
            or self._active_prepared_state_claim is not record
            or preparation._manager is not self
            or preparation._plan is not record.plan
        ):
            raise StateError("Prepared materialization batch is no longer active")
        if record.claim_thread is not current_thread():
            raise StateError("Prepared materialization batch belongs to its claiming thread")
        return record

    def _prepared_connection_materialization_committed(
        self,
        preparation: PreparedConnectionMaterialization,
    ) -> bool:
        """Return exact manager-owned commit truth while a preparation is active."""

        record = self._active_connection_preparations.get(id(preparation))
        if record is not None and record.preparation is preparation and not record.terminal:
            return record.committed
        return preparation._committed

    def _prepared_connection_composite_materialization_committed(
        self,
        preparation: PreparedConnectionCompositeMaterialization,
    ) -> bool:
        """Return exact manager-owned composite commit truth while active."""

        record = self._active_connection_composite_preparations.get(id(preparation))
        if record is not None and record.preparation is preparation and not record.terminal:
            return record.committed
        return preparation._committed

    def _prepared_materialization_batch_committed(
        self,
        preparation: PreparedMaterializationBatch,
    ) -> bool:
        """Return exact manager-owned batch commit truth while active."""

        record = self._active_materialization_batch_preparations.get(id(preparation))
        if record is not None and record.preparation is preparation and not record.terminal:
            return record.committed
        return preparation._committed

    def _prepared_materialization_batch_provisionally_applied(
        self,
        preparation: PreparedMaterializationBatch,
    ) -> bool:
        """Return exact reversible-apply truth while the batch claim is active."""

        record = self._materialization_batch_preparation_record_for(preparation)
        return record.provisional

    def _commit_claimed_connection_materialization(
        self,
        preparation: PreparedConnectionMaterialization,
    ) -> OpenConnection | None:
        """Publish one exact connection preparation after immediate preimage checks."""

        record = self._prepared_connection_materialization_record_for(preparation)
        with self._lock:
            record = self._prepared_connection_materialization_record_for(preparation)
            if record.committed:
                raise StateError("Prepared connection materialization is already committed")
            if record.failed:
                raise StateError("Prepared connection materialization has already failed")
            try:
                if record.claim_epoch != self._prepared_state_admission_epoch:
                    raise StateError("Prepared connection materialization claim epoch changed")
                if (
                    record.plan.expected_version != record.claim_version
                    or self._materialization_version != record.claim_version
                ):
                    raise StateError(
                        "Prepared connection materialization became stale before commit"
                    )
                if self.state.current_time != record.claim_state_time:
                    raise StateError(
                        "Prepared connection materialization State time changed before commit"
                    )
                if record.rng.getstate() != record.rng_state:
                    raise StateError(
                        "Prepared connection materialization RNG changed before commit"
                    )
                self.validate_connection_materialization(record.plan, record.rng)
            except StateError:
                record.failed = True
                raise
            result = self._commit_prevalidated_connection_materialization(
                record.plan,
                record.rng,
            )
            record.result = result
            record.committed = True
            preparation._result = result
            preparation._committed = True
            return result

    def _commit_claimed_connection_composite_materialization(
        self,
        preparation: PreparedConnectionCompositeMaterialization,
    ) -> ConnectionCompositeMaterializationResult:
        """Publish one exact composite preparation after immediate preimage checks."""

        record = self._prepared_connection_composite_materialization_record_for(preparation)
        with self._lock:
            record = self._prepared_connection_composite_materialization_record_for(preparation)
            if record.committed:
                raise StateError("Prepared connection composite is already committed")
            if record.failed:
                raise StateError("Prepared connection composite has already failed")
            try:
                if record.claim_epoch != self._prepared_state_admission_epoch:
                    raise StateError("Prepared connection composite claim epoch changed")
                if (
                    record.plan.expected_version != record.claim_version
                    or self._materialization_version != record.claim_version
                ):
                    raise StateError("Connection composite became stale before commit")
                if self.state.current_time != record.claim_state_time:
                    raise StateError("Connection composite State time changed before commit")
                if record.owner_rng.getstate() != record.rng_state:
                    raise StateError("Connection composite RNG owner changed before commit")
                self._validate_connection_composite_semantics(record.plan, record.owner_rng)
            except StateError:
                record.failed = True
                raise
            result = self._commit_prevalidated_connection_composite(
                record.plan,
                record.owner_rng,
            )
            record.result = result
            record.committed = True
            preparation._result = result
            preparation._committed = True
            return result

    def _apply_claimed_materialization_batch(
        self,
        preparation: PreparedMaterializationBatch,
    ) -> tuple[ActiveSession | None, tuple[RunningProcess, ...]]:
        """Apply and certify one reversible batch under the unified State claim."""

        record = self._materialization_batch_preparation_record_for(preparation)
        with self._lock:
            record = self._materialization_batch_preparation_record_for(preparation)
            if record.committed:
                raise StateError("Prepared materialization batch is already committed")
            if record.failed:
                raise StateError("Prepared materialization batch has already failed")
            if record.provisional:
                raise StateError("Prepared materialization batch is already provisionally applied")
            try:
                if record.claim_epoch != self._prepared_state_admission_epoch:
                    raise StateError("Prepared materialization batch claim epoch changed")
                if (
                    record.plan.expected_version != record.claim_version
                    or self._materialization_version != record.claim_version
                ):
                    raise StateError("Prepared materialization batch became stale before commit")
                if self.state.current_time != record.claim_state_time:
                    raise StateError(
                        "Prepared materialization batch State time changed before commit"
                    )
                self.validate_materialization_batch(record.plan)
                if (
                    self._action_cohort_rollback_observation(record.rollback_journal)
                    != record.claim_preimage
                ):
                    raise StateError("Prepared materialization batch touched State changed")
            except StateError:
                record.failed = True
                raise
            record.provisional = True
            try:
                result = self._commit_prevalidated_materialization_batch(record.plan)
            except BaseException:
                record.failed = True
                record.provisional_postimage = self._action_cohort_rollback_observation(
                    record.rollback_journal
                )
                try:
                    self._restore_materialization_batch_rollback(record)
                finally:
                    record.provisional = False
                    record.provisional_postimage = None
                raise
            record.provisional_postimage = self._action_cohort_rollback_observation(
                record.rollback_journal
            )
            try:
                if self._materialization_version != record.claim_version + 1:
                    raise StateError("Prepared materialization batch State version drifted")
                if self.state.current_time != record.plan.final_state_time:
                    raise StateError("Prepared materialization batch State time drifted")
                if record.provisional_postimage is None:
                    raise StateError("Prepared materialization batch has no rollback postimage")
            except StateError:
                record.failed = True
                try:
                    self._restore_materialization_batch_rollback(record)
                finally:
                    record.provisional = False
                    record.provisional_postimage = None
                raise
            record.result = result
            preparation._result = result
            record.certified = True
            return result

    def _restore_materialization_batch_rollback(
        self,
        record: _PreparedMaterializationBatchRecord,
    ) -> None:
        """Restore exact touched State while one provisional batch owns the lane."""

        preparation = record.preparation
        if (
            self._active_prepared_state_claim is not record
            or self._active_materialization_batch_preparations.get(id(preparation)) is not record
            or record.claim_thread is not current_thread()
            or record.claim_epoch != self._prepared_state_admission_epoch
            or record.terminal
            or not record.provisional
            or record.provisional_postimage is None
        ):
            raise StateError("Prepared materialization batch no longer owns rollback authority")
        if (
            self._action_cohort_rollback_observation(record.rollback_journal)
            != record.provisional_postimage
        ):
            raise StateError(
                "Prepared materialization batch touched State drifted after provisional apply"
            )
        self._restore_action_cohort_rollback_journal(record.rollback_journal)

    def _finalize_claimed_materialization_batch_no_fail(
        self,
        preparation: PreparedMaterializationBatch,
    ) -> tuple[ActiveSession | None, tuple[RunningProcess, ...]]:
        """Terminalize an already-certified provisional batch using scalar writes only."""

        record = self._materialization_batch_preparation_record_for(preparation)
        with self._lock:
            record = self._materialization_batch_preparation_record_for(preparation)
            if not record.certified or not record.provisional or record.result is None:
                raise StateError("Prepared materialization batch is not certified for finalize")
            record.committed = True
            record.provisional = False
            record.provisional_postimage = None
            preparation._committed = True
            preparation._result = record.result
            return record.result

    def _reject_mutation_during_action_cohort_claim(
        self,
        operation: str,
        *,
        admitted_at: int | None = None,
    ) -> int:
        """Admit or recheck one public mutation against the prepared-State lane."""

        current_epoch = self._prepared_state_admission_epoch
        if self._active_prepared_state_claim is not None or (
            admitted_at is not None and admitted_at != current_epoch
        ):
            raise StateError(
                f"State mutation {operation} is unavailable during an active action-cohort "
                "claim or prepared-State claim"
            )
        return current_epoch

    @contextmanager
    def _capability_minting_guard(self, operation: str) -> Iterator[None]:
        """Fence one public State-derived capability mint across the prepared lane."""

        admission_epoch = self._reject_mutation_during_action_cohort_claim(operation)
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                operation,
                admitted_at=admission_epoch,
            )
            yield

    def authenticates_process_termination_plan(
        self,
        plan: ProcessTerminationMaterializationPlan,
    ) -> bool:
        """Verify a process-termination plan's keyed integrity without its version fence."""

        with self._lock:
            if not isinstance(plan, ProcessTerminationMaterializationPlan):
                return False
            try:
                self._validate_process_termination_materialization_plan(plan)
            except StateError:
                return False
            return True

    def materialization_digest(self) -> str:
        """Return an exact immutable digest of StateManager publication authority.

        This intentionally expensive diagnostic is for atomicity tests and offline
        audit only. It covers canonical live/ended state, current time, every LUID,
        PID, thread, session-ID and connection allocator, reservations, reverse maps,
        temporal indexes, RNG states, and the materialization version. Production hot
        paths must use the constant-time censuses instead.
        """

        with self._lock:
            payload = tuple(
                sorted(
                    (
                        name,
                        _freeze_materialization_digest_value(value, set()),
                    )
                    for name, value in self.__dict__.items()
                    if name
                    not in {
                        "_lock",
                        "_materialization_secret",
                        "_active_connection_preparations",
                        "_active_connection_composite_preparations",
                        "_active_materialization_batch_preparations",
                        "_active_action_cohort_preparations",
                        "_active_action_cohort_claim",
                        "_active_prepared_state_claim",
                        "_prepared_state_admission_epoch",
                        "state",
                    }
                )
            )
            state_payload = (
                ("current_time", self.state.current_time),
                ("dns_cache", self.state.dns_cache),
            )
            frozen = _freeze_materialization_digest_value(
                (payload, state_payload),
                set(),
            )
            return hashlib.sha256(repr(frozen).encode()).hexdigest()

    @contextmanager
    def prepared_materialization_batch(
        self,
        plan: MaterializationBatchPlan,
    ) -> Iterator[PreparedMaterializationBatch]:
        """Claim the unified public State lane for one exact start batch."""

        claim_admission_epoch = self._prepared_state_admission_epoch
        if self._active_prepared_state_claim is not None:
            raise StateError("StateManager already has an active prepared-State claim")
        with self._lock:
            if self._active_prepared_state_claim is not None:
                raise StateError("StateManager already has an active prepared-State claim")
            if claim_admission_epoch != self._prepared_state_admission_epoch:
                raise StateError("Materialization-batch claim overlapped another State claim")
            self.validate_materialization_batch(plan)
            prepared_sessions = (
                (self._prepare_action_cohort_session_start(plan.session),)
                if plan.session is not None
                else ()
            )
            prepared_processes = tuple(
                self._prepare_action_cohort_process_start(item) for item in plan.processes
            )
            rollback_journal = self._prepare_action_cohort_rollback_journal(
                _MaterializationBatchRollbackProjection(),
                sessions=prepared_sessions,
                processes=prepared_processes,
                process_terminations=(),
                session_terminalizations=(),
                boot_times=plan.boot_times,
            )
            prepared = PreparedMaterializationBatch(
                _manager=self,
                _plan=plan,
                _claim_thread=current_thread(),
            )
            claim_epoch = self._prepared_state_admission_epoch + 1
            record = _PreparedMaterializationBatchRecord(
                preparation=prepared,
                plan=plan,
                claim_thread=prepared._claim_thread,
                claim_epoch=claim_epoch,
                claim_version=self._materialization_version,
                claim_state_time=self.state.current_time,
                rollback_journal=rollback_journal,
                claim_preimage=self._action_cohort_rollback_observation(rollback_journal),
            )
            locator = id(prepared)
            self._active_materialization_batch_preparations[locator] = record
            self._prepared_state_admission_epoch = claim_epoch
            self._active_prepared_state_claim = record
            primary_error: BaseException | None = None
            try:
                yield prepared
            except BaseException as error:
                primary_error = error
                raise
            finally:
                cleanup_error: BaseException | None = None
                if (
                    self._active_materialization_batch_preparations.get(locator) is record
                    and self._active_prepared_state_claim is record
                    and record.provisional
                    and not record.committed
                ):
                    try:
                        self._restore_materialization_batch_rollback(record)
                    except BaseException as error:
                        cleanup_error = error
                    finally:
                        record.provisional = False
                        record.provisional_postimage = None
                if (
                    self._active_materialization_batch_preparations.get(locator) is not record
                    or self._active_prepared_state_claim is not record
                ):
                    if cleanup_error is None:
                        cleanup_error = StateError(
                            "Prepared materialization batch no longer owns its State lane"
                        )
                if self._active_materialization_batch_preparations.get(locator) is record:
                    self._active_materialization_batch_preparations.pop(locator)
                if self._active_prepared_state_claim is record:
                    self._active_prepared_state_claim = None
                    self._prepared_state_admission_epoch += 1
                record.terminal = True
                prepared._active = False
                prepared._committed = record.committed
                if not record.committed:
                    prepared._result = None
                if cleanup_error is not None and primary_error is None:
                    raise cleanup_error

    @contextmanager
    def materialization_guard(self, plan: _MaterializationPlan | int) -> Iterator[None]:
        """Hold the state-start lane after authenticating one opaque plan.

        Global prepared-publication lock order is artifact publication (when an
        occurrence owns one), then this StateManager guard, then the LifecycleRegistry
        prepared-start ticket. No registry path may acquire this guard while retaining
        a registry lock, and StateManager never acquires artifact-registry ownership.

        The integer form remains a private compatibility seam for callers that have
        not yet adopted an opaque plan; production start publication passes the plan.
        """

        admission_epoch = self._reject_mutation_during_action_cohort_claim("materialization_guard")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "materialization_guard",
                admitted_at=admission_epoch,
            )
            expected_version = plan if isinstance(plan, int) else plan.expected_version
            if expected_version != self._materialization_version:
                raise StateError(
                    "State materialization plan is stale: "
                    f"expected version {expected_version}, current "
                    f"{self._materialization_version}"
                )
            if isinstance(plan, SessionMaterializationPlan):
                self._validate_session_materialization_plan(plan)
            elif isinstance(plan, ProcessMaterializationPlan):
                self._validate_process_materialization_plan(plan)
            elif isinstance(plan, ProcessTerminationMaterializationPlan):
                self._validate_process_termination_materialization_plan(plan)
            elif isinstance(plan, ConnectionMaterializationPlan):
                self._validate_connection_materialization_plan(plan)
            elif isinstance(plan, MaterializationBatchPlan):
                self._validate_materialization_batch_plan(plan)
            elif isinstance(plan, ConnectionCompositeMaterializationPlan):
                self._validate_connection_composite_plan_integrity(plan)
            elif type(plan) is ActionCohortMaterializationPlan:
                self._validate_action_cohort_plan_integrity(plan)
            yield

    @contextmanager
    def process_termination_materialization_guard(
        self,
        plan: ProcessTerminationMaterializationPlan,
    ) -> Iterator[None]:
        """Hold the StateManager lane after fully validating one termination plan."""

        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "process_termination_materialization_guard"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "process_termination_materialization_guard",
                admitted_at=admission_epoch,
            )
            self.validate_process_termination_materialization(plan)
            yield

    def _validate_session_materialization_plan(self, plan: SessionMaterializationPlan) -> None:
        expected = _materialization_integrity_token(
            self._materialization_secret,
            "session",
            plan._expected_version,
            plan._identity,
            plan._payload,
            plan._allocator_patch,
        )
        if not hmac.compare_digest(plan._integrity_token, expected):
            raise StateError("Session materialization plan integrity validation failed")

    def _validate_process_materialization_plan(self, plan: ProcessMaterializationPlan) -> None:
        expected = _materialization_integrity_token(
            self._materialization_secret,
            "process",
            plan._expected_version,
            plan._identity,
            plan._payload,
            plan._allocator_patch,
        )
        if not hmac.compare_digest(plan._integrity_token, expected):
            raise StateError("Process materialization plan integrity validation failed")

    def _validate_process_termination_materialization_plan(
        self,
        plan: ProcessTerminationMaterializationPlan,
    ) -> None:
        expected = _process_termination_materialization_integrity_token(
            self._materialization_secret,
            expected_version=plan._expected_version,
            identity=plan._identity,
            payload=plan._payload,
        )
        if not hmac.compare_digest(plan._integrity_token, expected):
            raise StateError("Process termination materialization plan integrity validation failed")

    def _validate_connection_identity_plan(self, plan: ConnectionIdentityPlan) -> None:
        expected = _connection_identity_integrity_token(
            self._materialization_secret,
            expected_version=plan._expected_version,
            conn_id=plan._conn_id,
            zeek_uid=plan._zeek_uid,
            counter_after=plan._counter_after,
            rng_state_before=plan._rng_state_before,
            rng_state_after_identity=plan._rng_state_after_identity,
        )
        if not hmac.compare_digest(plan._integrity_token, expected):
            raise StateError("Connection identity plan integrity validation failed")

    def _validate_connection_materialization_plan(
        self,
        plan: ConnectionMaterializationPlan,
    ) -> None:
        self._validate_connection_identity_plan(plan._identity)
        expected = _connection_materialization_integrity_token(
            self._materialization_secret,
            expected_version=plan._expected_version,
            identity=plan._identity,
            payload=plan._payload,
        )
        if not hmac.compare_digest(plan._integrity_token, expected):
            raise StateError("Connection materialization plan integrity validation failed")

    def _validate_connection_composite_plan_integrity(
        self,
        plan: ConnectionCompositeMaterializationPlan,
    ) -> None:
        expected_cursor = _connection_cursor_integrity_token(
            self._materialization_secret,
            expected_version=plan._expected_version,
            expected_state_time=plan._expected_state_time,
            expected_connection_counter=plan._expected_connection_counter,
            owner_identity=plan._owner_identity,
            rng_state_entry=plan._rng_state_entry,
        )
        if not hmac.compare_digest(plan._cursor_token, expected_cursor):
            raise StateError("Connection composite cursor integrity validation failed")
        if plan._identity is not None:
            self._validate_connection_identity_plan(plan._identity)
        if plan._batch is not None:
            self._validate_materialization_batch_plan(plan._batch)
        expected = _connection_composite_integrity_token(
            self._materialization_secret,
            expected_version=plan._expected_version,
            expected_state_time=plan._expected_state_time,
            expected_connection_counter=plan._expected_connection_counter,
            owner_identity=plan._owner_identity,
            rng_state_entry=plan._rng_state_entry,
            rng_state_final=plan._rng_state_final,
            cursor_token=plan._cursor_token,
            identity=plan._identity,
            transaction=plan._transaction,
            source_system=plan._source_system,
            source_hostname=plan._source_hostname,
            hostname=plan._hostname,
            initiating_pid=plan._initiating_pid,
            mode=plan._mode,
            parent_patch=plan._parent_patch,
            batch=plan._batch,
            existing_session_patch=plan._existing_session_patch,
            existing_session_process_roles_patch=(plan._existing_session_process_roles_patch),
            process_activity=plan._process_activity,
            session_activity=plan._session_activity,
            final_state_time=plan._final_state_time,
        )
        if not hmac.compare_digest(plan._integrity_token, expected):
            raise StateError("Connection composite plan integrity validation failed")

    def _validate_materialization_batch_plan(self, plan: MaterializationBatchPlan) -> None:
        if type(plan) is not MaterializationBatchPlan:
            raise StateError("Materialization batch requires an exact plan type")
        if type(plan._admission_epoch) is not int or plan._admission_epoch < 0:
            raise StateError("Materialization batch admission epoch is malformed")
        session = plan._session
        if session is not None:
            self._validate_session_materialization_plan(session)
            if session.expected_version != plan.expected_version:
                raise StateError("Materialization batch session uses another state version")
        for process in plan._processes:
            self._validate_process_materialization_plan(process)
            if process.expected_version != plan.expected_version:
                raise StateError("Materialization batch process uses another state version")
        if type(plan._boot_times) is not tuple:
            raise StateError("Materialization batch boot times must be an exact tuple")
        boot_times: dict[str, datetime] = {}
        for member in plan._boot_times:
            if (
                type(member) is not tuple
                or len(member) != 2
                or type(member[0]) is not str
                or not member[0].strip()
                or type(member[1]) is not datetime
            ):
                raise StateError("Materialization batch contains a malformed boot time")
            hostname, boot_time = member
            if ensure_utc(boot_time) != boot_time or hostname in boot_times:
                raise StateError("Materialization batch boot times are not canonical")
            boot_times[hostname] = boot_time
        if tuple(sorted(boot_times.items())) != plan._boot_times:
            raise StateError("Materialization batch boot times are not in canonical order")
        for process in plan._processes:
            boot_time = boot_times.get(process.identity.hostname)
            if boot_time is not None and process.identity.started_at < boot_time:
                raise StateError("Materialization batch process starts before its host boot time")
        expected = _materialization_batch_integrity_token(
            self._materialization_secret,
            expected_version=plan._expected_version,
            expected_state_time=plan._expected_state_time,
            admission_epoch=plan._admission_epoch,
            final_state_time=plan._final_state_time,
            session=session,
            processes=plan._processes,
            boot_times=plan._boot_times,
            session_process_links=plan._session_process_links,
        )
        if not hmac.compare_digest(plan._integrity_token, expected):
            raise StateError("Materialization batch plan integrity validation failed")

    def _validate_action_cohort_plan_integrity(
        self,
        plan: ActionCohortMaterializationPlan,
    ) -> None:
        """Validate exact structure and every nested action-cohort capability."""

        if type(plan) is not ActionCohortMaterializationPlan:
            raise StateError("Action cohort materialization requires an exact plan type")
        if type(plan._expected_version) is not int:
            raise StateError("Action cohort materialization version is malformed")
        if (
            plan._expected_state_time is not None
            and type(plan._expected_state_time) is not datetime
        ):
            raise StateError("Action cohort materialization state-time fence is malformed")
        if type(plan._final_state_time) is not datetime:
            raise StateError("Action cohort materialization final time is malformed")
        if type(plan._semantic_id) is not str or len(plan._semantic_id) != 64:
            raise StateError("Action cohort materialization semantic identity is malformed")
        if type(plan._integrity_token) is not str or len(plan._integrity_token) != 64:
            raise StateError("Action cohort materialization integrity token is malformed")
        if type(plan._capability) is not _ActionCohortCapability:
            raise StateError("Action cohort materialization capability is malformed")

        tuple_fields = (
            plan._sessions,
            plan._processes,
            plan._session_process_links,
            plan._live_session_process_roles,
            plan._session_metadata,
            plan._process_activity,
            plan._session_activity,
            plan._process_terminations,
            plan._session_terminalizations,
        )
        if any(type(value) is not tuple for value in tuple_fields):
            raise StateError("Action cohort materialization members must be exact tuples")
        if len(plan._live_session_process_roles) > (
            _MAX_ACTION_COHORT_LIVE_SESSION_PROCESS_ROLE_PATCHES
        ):
            raise StateError("Action cohort live-session role patch limit exceeded")
        expected_types = (
            (plan._sessions, SessionMaterializationPlan),
            (plan._processes, ProcessMaterializationPlan),
            (plan._session_process_links, _ActionCohortSessionProcessLinks),
            (
                plan._live_session_process_roles,
                ActionCohortLiveSessionProcessRolesPatch,
            ),
            (plan._session_metadata, ActionCohortSessionMetadataPatch),
            (plan._process_activity, ActionCohortProcessActivityPatch),
            (plan._session_activity, ActionCohortSessionActivityPatch),
            (plan._process_terminations, ActionCohortProcessTermination),
            (plan._session_terminalizations, ActionCohortSessionTerminalization),
        )
        for values, expected_type in expected_types:
            if any(type(value) is not expected_type for value in values):
                raise StateError(
                    "Action cohort materialization contains an unsupported exact member type"
                )
        _validate_action_cohort_safe_value(
            (
                plan._sessions,
                plan._processes,
                plan._session_process_links,
                plan._live_session_process_roles,
                plan._session_metadata,
                plan._process_activity,
                plan._session_activity,
                plan._process_terminations,
                plan._session_terminalizations,
            ),
            set(),
        )

        for session in plan._sessions:
            self._validate_session_materialization_plan(session)
            if session.expected_version != plan.expected_version:
                raise StateError("Action cohort session uses another State version")
        for process in plan._processes:
            self._validate_process_materialization_plan(process)
            if process.expected_version != plan.expected_version:
                raise StateError("Action cohort process uses another State version")
        for termination in plan._process_terminations:
            if type(termination._capability) is not _ActionCohortCapability:
                raise StateError("Action cohort process termination capability is malformed")
            if type(termination.target) is ProcessTerminationMaterializationPlan:
                self._validate_process_termination_materialization_plan(termination.target)
                if termination.target.expected_version != plan.expected_version:
                    raise StateError("Action cohort process close uses another State version")
                if termination.end_time != termination.target.end_time:
                    raise StateError("Action cohort live process close time drifted")
                if termination.parent_activity is not None:
                    raise StateError("Action cohort live process close duplicates parent activity")
                if termination.staged_session_references:
                    raise StateError("Action cohort live process close has staged references")
            elif type(termination.target) is ProcessMaterializationPlan:
                if not any(termination.target is member for member in plan._processes):
                    raise StateError("Action cohort staged process close replaced its start plan")
                if (
                    termination.parent_activity is not None
                    and type(termination.parent_activity) is not ActionCohortProcessActivityPatch
                ):
                    raise StateError("Action cohort process parent activity is malformed")
            else:
                raise StateError("Action cohort process close target type is unsupported")
            if type(termination.staged_session_references) is not tuple or any(
                type(reference) is not _ProcessTerminationSessionReference
                for reference in termination.staged_session_references
            ):
                raise StateError("Action cohort staged session references are malformed")
        for patch in plan._live_session_process_roles:
            if (
                type(patch.target) is not SessionIdentity
                or type(patch.before) is not ActionCohortLiveSessionProcessRolesState
                or type(patch.after) is not ActionCohortLiveSessionProcessRolesState
                or type(patch.explorer_plan) is not ProcessMaterializationPlan
                or (
                    patch.winlogon_plan is not None
                    and type(patch.winlogon_plan) is not ProcessMaterializationPlan
                )
                or (
                    patch.process_tree_root_plan is not None
                    and type(patch.process_tree_root_plan) is not ProcessMaterializationPlan
                )
            ):
                raise StateError("Action cohort live-session role patch is malformed")
        for patch in (
            *plan._live_session_process_roles,
            *plan._session_metadata,
            *plan._process_activity,
            *plan._session_activity,
        ):
            if type(patch._capability) is not _ActionCohortCapability:
                raise StateError("Action cohort patch capability is malformed")
        for terminalization in plan._session_terminalizations:
            if type(terminalization._capability) is not _ActionCohortCapability:
                raise StateError("Action cohort session terminalization capability is malformed")
            if type(terminalization.target) is SessionMaterializationPlan and not any(
                terminalization.target is member for member in plan._sessions
            ):
                raise StateError("Action cohort staged session close replaced its start plan")
            if type(terminalization.target) not in {
                SessionMaterializationPlan,
                SessionIdentity,
            }:
                raise StateError("Action cohort session close target type is unsupported")

        semantic_kwargs = {
            "expected_version": plan._expected_version,
            "expected_state_time": plan._expected_state_time,
            "final_state_time": plan._final_state_time,
            "sessions": plan._sessions,
            "processes": plan._processes,
            "session_process_links": plan._session_process_links,
            "live_session_process_roles": plan._live_session_process_roles,
            "session_metadata": plan._session_metadata,
            "process_activity": plan._process_activity,
            "session_activity": plan._session_activity,
            "process_terminations": plan._process_terminations,
            "session_terminalizations": plan._session_terminalizations,
        }
        semantic_id = _action_cohort_semantic_id(**semantic_kwargs)
        if not hmac.compare_digest(plan._semantic_id, semantic_id):
            raise StateError("Action cohort materialization semantic identity validation failed")
        integrity = _action_cohort_integrity_token(
            self._materialization_secret,
            semantic_id=semantic_id,
            capability=plan._capability,
            sessions=plan._sessions,
            processes=plan._processes,
            live_session_process_roles=plan._live_session_process_roles,
            session_metadata=plan._session_metadata,
            process_activity=plan._process_activity,
            session_activity=plan._session_activity,
            process_terminations=plan._process_terminations,
            session_terminalizations=plan._session_terminalizations,
        )
        if not hmac.compare_digest(plan._integrity_token, integrity):
            raise StateError("Action cohort materialization integrity validation failed")

    def begin_materialization_batch(self) -> MaterializationBatchBuilder:
        """Return an allocation-free builder bound to the current state fence."""

        with self._capability_minting_guard("begin_materialization_batch"):
            return MaterializationBatchBuilder(self, self._materialization_version)

    def begin_action_cohort_materialization(self) -> ActionCohortMaterializationBuilder:
        """Return an allocation-free multi-session action-cohort builder."""

        with self._capability_minting_guard("begin_action_cohort_materialization"):
            return ActionCohortMaterializationBuilder(self, self._materialization_version)

    def _action_cohort_preview_host_base(
        self,
        builder: ActionCohortMaterializationBuilder,
        system: str,
    ) -> tuple[int, tuple[str, int] | None]:
        existing = self._logon_id_host_bases.get(system)
        if existing is not None:
            return existing, None
        planned = builder._planned_host_bases.get(system)
        if planned is not None:
            return planned, None
        occupied = self._logon_id_used_host_bases | set(builder._planned_host_bases.values())
        bucket = _stable_seed(f"logon_luid_host_{system}") % _HOST_LOGON_BUCKET_SPACE
        salt = 0
        while True:
            candidate = _MIN_GENERATED_LOGON_LUID + (
                (bucket + (salt * _HOST_LOGON_BUCKET_STEP)) % _HOST_LOGON_BUCKET_SPACE
            )
            if candidate not in occupied:
                builder._planned_host_bases[system] = candidate
                return candidate, (system, candidate)
            salt += 1

    def _action_cohort_preview_host_epoch(
        self,
        builder: ActionCohortMaterializationBuilder,
        system: str,
        current_time: datetime,
    ) -> tuple[datetime, tuple[str, datetime] | None]:
        boot_time = self._system_boot_times.get(system)
        if boot_time is not None:
            return ensure_utc(boot_time), None
        existing = self._logon_id_epochs.get(system)
        if existing is not None:
            return existing, None
        planned = builder._planned_host_epochs.get(system)
        if planned is not None:
            return planned, None
        uptime_seconds = 3600 + (_stable_seed(f"logon_luid_uptime_{system}") % (3 * 86400))
        epoch = ensure_utc(current_time) - timedelta(seconds=uptime_seconds)
        builder._planned_host_epochs[system] = epoch
        return epoch, (system, epoch)

    def _action_cohort_preview_logon_luid(
        self,
        builder: ActionCohortMaterializationBuilder,
        system: str,
        event_time: datetime,
    ) -> tuple[
        int,
        tuple[str, int] | None,
        tuple[str, datetime] | None,
        tuple[tuple[str, int, int], int],
    ]:
        current_time = ensure_utc(event_time)
        base, host_base_patch = self._action_cohort_preview_host_base(builder, system)
        epoch, host_epoch_patch = self._action_cohort_preview_host_epoch(
            builder,
            system,
            current_time,
        )
        elapsed_seconds = max(0, int((current_time - epoch).total_seconds()))
        block = elapsed_seconds // 60
        second_in_block = elapsed_seconds % 60
        subsecond_bucket = min(15, current_time.microsecond // 62500)
        ordinal_key = (system, elapsed_seconds, subsecond_bucket)
        ordinal = builder._planned_logon_ordinals.get(
            ordinal_key,
            self._logon_id_second_ordinals.get(ordinal_key, 0),
        )
        stride = self._logon_luid_block_stride(system, block)
        candidate = base + self._logon_luid_block_offset(system, block)
        candidate += (second_in_block * stride) + (subsecond_bucket * 3) + ordinal
        candidate += (
            _stable_seed(f"logon_luid_low:{system}:{current_time.isoformat()}:{ordinal}") % 3
        )
        candidate = _normalize_generated_logon_luid(candidate)
        occupied = self._used_logon_ids | self._reserved_logon_ids | builder._planned_logon_luids
        while candidate in occupied:
            candidate = _normalize_generated_logon_luid(candidate + 1)
        builder._planned_logon_ordinals[ordinal_key] = ordinal + 1
        builder._planned_logon_luids.add(candidate)
        return candidate, host_base_patch, host_epoch_patch, (ordinal_key, ordinal + 1)

    def _action_cohort_preview_windows_session_id(
        self,
        builder: ActionCohortMaterializationBuilder,
        *,
        system: str,
        username: str,
        logon_type: int,
        session_kind: str,
    ) -> tuple[int, tuple[str, int] | None]:
        if not windows_logon_can_own_desktop(logon_type) or session_kind in {
            "network",
            "new_credentials",
            "service",
            "ssh",
        }:
            return 0, None
        used_ids = {
            session.session_id
            for session in self._active_sessions.find("system", system)
            if session.session_id > 0
        }
        used_ids.update(builder._planned_windows_session_ids.get(system, ()))
        if logon_type in {2, 11} and session_kind in {"interactive", "logon"}:
            preferred = 1 + (_stable_seed(f"windows_console_session:{system}") % 2)
            if preferred not in used_ids:
                builder._planned_windows_session_ids.setdefault(system, set()).add(preferred)
                return preferred, None
        initial = builder._planned_windows_session_counters.get(
            system,
            self._windows_session_id_counters.get(
                system,
                3 + (_stable_seed(f"windows_session_initial:{system}") % 3),
            ),
        )
        candidate = initial
        while candidate in used_ids or candidate <= 0:
            candidate += 1 + (_stable_seed(f"windows_session_gap:{system}:{candidate}") % 2)
        successor = candidate + 1
        builder._planned_windows_session_counters[system] = successor
        builder._planned_windows_session_ids.setdefault(system, set()).add(candidate)
        return candidate, (system, successor)

    def _plan_action_cohort_session(
        self,
        builder: ActionCohortMaterializationBuilder,
        *,
        username: str,
        system: str,
        logon_type: int,
        source_ip: str,
        source_port: int,
        session_kind: str,
        transport_pid: int | None,
        start_time: datetime | None,
        logon_id: str | None,
        logon_guid: str,
        logon_guid_required: bool | None,
        session_id: int | None,
        lifecycle_group_id: str,
        parent_lifecycle_group_id: str,
        auth_protocol: str,
        smb_principal: str,
        account_scope: str,
        auth_session_ref: str,
        effective_uid: int | None,
        effective_gid: int | None,
    ) -> SessionMaterializationPlan:
        """Plan one session against a private cohort-local allocator overlay."""

        with self._capability_minting_guard("ActionCohortMaterializationBuilder.plan_session"):
            if (
                builder._manager is not self
                or builder._admission_epoch != self._prepared_state_admission_epoch
            ):
                raise StateError("Action cohort builder belongs to another StateManager")
            if builder.expected_version != self._materialization_version:
                raise StateError("Action cohort builder became stale during session planning")
            if self.state.current_time != builder._expected_state_time:
                raise StateError("Action cohort State time changed during session planning")
            if start_time is None and self.state.current_time is None:
                raise StateError("Cannot plan action cohort session: current_time not set")
            session_start = ensure_utc(start_time or self.state.current_time)
            provided_logon_id = logon_id is not None
            host_base_patch: tuple[str, int] | None = None
            host_epoch_patch: tuple[str, datetime] | None = None
            ordinal_patch: tuple[tuple[str, int, int], int] | None = None
            used_logon_id: int | None = None
            if logon_id is None:
                (
                    used_logon_id,
                    host_base_patch,
                    host_epoch_patch,
                    ordinal_patch,
                ) = self._action_cohort_preview_logon_luid(builder, system, session_start)
                logon_id = f"0x{used_logon_id:x}"
            else:
                resolved = self._resolve_logon_id(logon_id)
                if (
                    logon_id in builder._planned_logon_ids
                    or resolved in builder._planned_logon_ids
                    or logon_id in self._ended_sessions
                    or resolved in self._ended_sessions
                    or resolved in self.state.active_sessions
                ):
                    raise StateError(f"Action cohort session LogonID is already used: {logon_id}")
                try:
                    used_logon_id = int(logon_id, 16)
                except (TypeError, ValueError):
                    used_logon_id = None
                if used_logon_id is not None:
                    if (
                        used_logon_id in self._used_logon_ids
                        or used_logon_id in builder._planned_logon_luids
                    ):
                        raise StateError(
                            f"Action cohort session LogonID is already used: {logon_id}"
                        )
                    builder._planned_logon_luids.add(used_logon_id)
            builder._planned_logon_ids.add(logon_id)

            if session_id is None:
                session_id, session_counter_patch = self._action_cohort_preview_windows_session_id(
                    builder,
                    system=system,
                    username=username,
                    logon_type=logon_type,
                    session_kind=session_kind,
                )
            else:
                if session_id > 0:
                    used_session_ids = builder._planned_windows_session_ids.setdefault(
                        system,
                        set(),
                    )
                    if session_id in used_session_ids or any(
                        current.session_id == session_id
                        for current in self._active_sessions.find("system", system)
                    ):
                        raise StateError(
                            f"Action cohort Windows session ID is already live: {session_id}"
                        )
                    used_session_ids.add(session_id)
                session_counter_patch = None
            object_id = stable_uuid(
                "registered-session" if provided_logon_id else "session",
                system,
                username,
                logon_type,
                session_kind,
                source_ip,
                source_port,
                session_start.isoformat(),
                logon_id,
                session_id,
            )
            if logon_guid_required is not None:
                logon_guid = (
                    self._stable_logon_guid(system, logon_id)
                    if logon_guid_required
                    else _NULL_LOGON_GUID
                )
            lifecycle_id = lifecycle_group_id or stable_uuid("session-lifecycle", object_id)
            identity = SessionIdentity(
                hostname=system,
                object_id=object_id,
                logon_id=logon_id,
                session_id=session_id,
                principal=username,
                session_kind=session_kind,
                started_at=session_start,
                lifecycle_group_id=lifecycle_id,
                logon_guid=logon_guid,
                parent_lifecycle_group_id=parent_lifecycle_group_id,
            )
            payload = _SessionMaterializationPayload(
                logon_type=logon_type,
                source_ip=source_ip,
                source_port=source_port,
                transport_pid=transport_pid,
                auth_protocol=auth_protocol,
                smb_principal=smb_principal,
                account_scope=account_scope,
                auth_session_ref=auth_session_ref,
                effective_uid=effective_uid,
                effective_gid=effective_gid,
                state_time=session_start,
            )
            allocator_patch = _SessionAllocatorPatch(
                host_base=host_base_patch,
                host_epoch=host_epoch_patch,
                ordinal=ordinal_patch,
                used_logon_id=used_logon_id,
                windows_session_counter=session_counter_patch,
                linux_logind=None,
            )
            return SessionMaterializationPlan(
                _expected_version=builder.expected_version,
                _identity=identity,
                _payload=payload,
                _allocator_patch=allocator_patch,
                _integrity_token=_materialization_integrity_token(
                    self._materialization_secret,
                    "session",
                    builder.expected_version,
                    identity,
                    payload,
                    allocator_patch,
                ),
            )

    @staticmethod
    def _action_session_target_key(
        target: SessionMaterializationPlan | SessionIdentity,
    ) -> tuple[str, str]:
        identity = target.identity if type(target) is SessionMaterializationPlan else target
        return (identity.hostname, identity.object_id)

    @staticmethod
    def _action_process_target_key(
        target: ProcessMaterializationPlan
        | ProcessTerminationMaterializationPlan
        | ProcessIdentity,
    ) -> tuple[str, str]:
        identity = (
            target.identity
            if type(target) in {ProcessMaterializationPlan, ProcessTerminationMaterializationPlan}
            else target
        )
        return (identity.hostname, identity.object_id)

    def _normalize_action_cohort_session_target(
        self,
        builder: ActionCohortMaterializationBuilder,
        target: SessionMaterializationPlan | SessionIdentity,
    ) -> SessionMaterializationPlan | SessionIdentity:
        """Require an exact staged member or exact currently live session identity."""

        with self._capability_minting_guard("ActionCohortMaterializationBuilder.session_target"):
            if (
                builder._manager is not self
                or builder._admission_epoch != self._prepared_state_admission_epoch
                or builder.expected_version != self._materialization_version
            ):
                raise StateError("Action cohort session target uses a stale or foreign builder")
            if type(target) is SessionMaterializationPlan:
                if not any(target is member for member in builder._action_sessions):
                    raise StateError(
                        "Action cohort staged session target belongs to another builder"
                    )
                return target
            if type(target) is not SessionIdentity:
                raise TypeError("Action cohort session target has an unsupported exact type")
            session = self._active_sessions.get(self._resolve_logon_id(target.logon_id))
            if session is None or self.get_session_identity(session.logon_id) != target:
                raise StateError("Action cohort live session target is absent or drifted")
            return target

    def _normalize_action_cohort_process_target(
        self,
        builder: ActionCohortMaterializationBuilder,
        target: ProcessMaterializationPlan | ProcessIdentity,
    ) -> ProcessMaterializationPlan | ProcessIdentity:
        """Require an exact staged member or exact currently live process identity."""

        with self._capability_minting_guard("ActionCohortMaterializationBuilder.process_target"):
            if (
                builder._manager is not self
                or builder._admission_epoch != self._prepared_state_admission_epoch
                or builder.expected_version != self._materialization_version
            ):
                raise StateError("Action cohort process target uses a stale or foreign builder")
            if type(target) is ProcessMaterializationPlan:
                if not any(target is member for member in builder._processes):
                    raise StateError(
                        "Action cohort staged process target belongs to another builder"
                    )
                return target
            if type(target) is not ProcessIdentity:
                raise TypeError("Action cohort process target has an unsupported exact type")
            process = self._processes_by_object_id.get(target.object_id)
            if (
                process is None
                or self.state.running_processes.get((target.hostname, target.pid)) is not process
                or self._process_identity(process) != target
            ):
                raise StateError("Action cohort live process target is absent or drifted")
            return target

    def _action_cohort_session_metadata(
        self,
        target: SessionMaterializationPlan | SessionIdentity,
    ) -> ActionCohortSessionMetadataState:
        """Snapshot the closed metadata projection for a staged or live target."""

        if type(target) is SessionMaterializationPlan:
            return ActionCohortSessionMetadataState()
        session = self._active_sessions.get(self._resolve_logon_id(target.logon_id))
        if session is None or self.get_session_identity(session.logon_id) != target:
            raise StateError("Action cohort session metadata target drifted")
        return ActionCohortSessionMetadataState(
            source_ready_time=session.source_ready_time,
            network_close_time=session.network_close_time,
            closure_owned_by_bundle=session.closure_owned_by_bundle,
            login_occurrence_emitted=session.login_occurrence_emitted,
            storyline_protected=session.storyline_protected,
            end_plan=session.end_plan,
        )

    def _action_cohort_live_session_process_roles(
        self,
        target: SessionIdentity,
    ) -> ActionCohortLiveSessionProcessRolesState:
        """Snapshot every mutable process-role field for one exact live session."""

        session = self._validate_action_live_session_identity(target)
        return ActionCohortLiveSessionProcessRolesState(
            transport_pid=session.transport_pid,
            session_shell_pid=session.session_shell_pid,
            session_user_manager_pid=session.session_user_manager_pid,
            session_winlogon_pid=session.session_winlogon_pid,
            explorer_pid=session.explorer_pid,
            initial_explorer_pid=session.initial_explorer_pid,
            process_tree_root=session.process_tree_root,
            windows_shell_bootstrapped=session.windows_shell_bootstrapped,
        )

    @staticmethod
    def _action_cohort_windows_process_basename(plan: ProcessMaterializationPlan) -> str:
        """Return a case-folded Windows basename without platform-dependent path rules."""

        return plan.identity.image.replace("/", "\\").rsplit("\\", 1)[-1].casefold()

    def _action_cohort_process_pid_namespaces(
        self,
        processes: list[ProcessMaterializationPlan] | tuple[ProcessMaterializationPlan, ...],
    ) -> dict[int, str]:
        """Resolve each staged process to its authenticated host PID namespace."""

        namespaces = dict(self._pid_os)
        resolved: dict[int, str] = {}
        for process in processes:
            identity = process.identity
            patch = process._allocator_patch.pid_os
            if patch is not None:
                host, category = patch
                if host != identity.hostname or category not in {"linux", "windows"}:
                    raise StateError("Action cohort process PID namespace patch is malformed")
                existing = namespaces.get(host)
                if existing is not None and existing != category:
                    raise StateError("Action cohort process PID namespace changed within a cohort")
                namespaces[host] = category
            category = namespaces.get(identity.hostname)
            if category not in {"linux", "windows"}:
                raise StateError("Action cohort process has no exact PID namespace")
            resolved[id(process)] = category
        return resolved

    @staticmethod
    def _action_cohort_is_valid_windows_pid(pid: int) -> bool:
        """Return whether a PID lies in the modeled Windows rendered namespace."""

        return type(pid) is int and 0 < pid <= _WINDOWS_PID_MAX and pid % _WINDOWS_PID_STEP == 0

    def _prepare_action_cohort_live_windows_session_shell_patch(
        self,
        builder: ActionCohortMaterializationBuilder,
        *,
        target: SessionIdentity,
        winlogon_plan: ProcessMaterializationPlan | None,
        explorer_plan: ProcessMaterializationPlan,
        process_tree_root_plan: ProcessMaterializationPlan | None,
    ) -> ActionCohortLiveSessionProcessRolesPatch:
        """Build one manager-issued live desktop role transition without mutation."""

        with self._capability_minting_guard(
            "ActionCohortMaterializationBuilder.bind_live_windows_session_shell"
        ):
            if type(target) is not SessionIdentity:
                raise TypeError("Live Windows session shell target requires an exact identity")
            normalized = self._normalize_action_cohort_session_target(builder, target)
            assert type(normalized) is SessionIdentity
            for name, process in (
                ("winlogon", winlogon_plan),
                ("explorer", explorer_plan),
                ("process-tree root", process_tree_root_plan),
            ):
                if process is None:
                    continue
                if type(process) is not ProcessMaterializationPlan or not any(
                    process is candidate for candidate in builder._processes
                ):
                    raise StateError(
                        f"Live Windows session {name} must be an exact same-cohort process plan"
                    )
            if (winlogon_plan is None) != (process_tree_root_plan is None):
                raise StateError(
                    "Live Windows session winlogon and process-tree root must be staged together"
                )
            if winlogon_plan is not None and process_tree_root_plan is not winlogon_plan:
                raise StateError(
                    "Live Windows session process-tree root must be its exact staged winlogon"
                )

            before = self._action_cohort_live_session_process_roles(normalized)
            explorer_pid = explorer_plan.identity.pid
            new_winlogon_pid = (
                winlogon_plan.identity.pid
                if winlogon_plan is not None
                else before.session_winlogon_pid
            )
            new_root_pid = (
                process_tree_root_plan.identity.pid
                if process_tree_root_plan is not None
                else before.process_tree_root
            )
            after = replace(
                before,
                session_winlogon_pid=new_winlogon_pid,
                explorer_pid=explorer_pid,
                initial_explorer_pid=(
                    explorer_pid
                    if before.initial_explorer_pid is None
                    else before.initial_explorer_pid
                ),
                process_tree_root=new_root_pid,
                windows_shell_bootstrapped=True,
            )
            patch = ActionCohortLiveSessionProcessRolesPatch(
                target=normalized,
                before=before,
                after=after,
                winlogon_plan=winlogon_plan,
                explorer_plan=explorer_plan,
                process_tree_root_plan=process_tree_root_plan,
                _capability=_ActionCohortCapability(),
            )
            processes = {process.identity.object_id: process for process in builder._processes}
            processes_by_pid = {
                (process.identity.hostname, process.identity.pid): process
                for process in builder._processes
            }
            process_indexes = {
                id(process): index for index, process in enumerate(builder._processes)
            }
            process_pid_namespaces = self._action_cohort_process_pid_namespaces(builder._processes)
            self._validate_action_cohort_live_session_process_roles_transition(
                patch,
                processes=processes,
                processes_by_pid=processes_by_pid,
                process_indexes=process_indexes,
                process_pid_namespaces=process_pid_namespaces,
            )
            return patch

    def _action_cohort_process_parent_target(
        self,
        builder: ActionCohortMaterializationBuilder,
        process: ProcessMaterializationPlan,
    ) -> ProcessMaterializationPlan | ProcessIdentity:
        """Resolve the exact staged or live parent of one staged process."""

        identity = process.identity
        if identity.parent_pid in {0, 4} or identity.parent_pid == identity.pid:
            raise StateError("Action cohort parent activity requires a distinct modeled parent")
        for candidate in reversed(builder._processes):
            if candidate is process:
                continue
            parent = candidate.identity
            if parent.hostname == identity.hostname and parent.pid == identity.parent_pid:
                return candidate
        live = self.state.running_processes.get((identity.hostname, identity.parent_pid))
        if live is None:
            raise StateError("Action cohort parent activity requires an exact live parent")
        return self._process_identity(live)

    def _action_cohort_staged_session_references(
        self,
        *,
        process_index: int,
        sessions: tuple[SessionMaterializationPlan, ...],
        links: tuple[_ActionCohortSessionProcessLinks, ...],
    ) -> tuple[_ProcessTerminationSessionReference, ...]:
        """Return exact staged-session role pointers cleared by one staged close."""

        role_fields = {
            "transport": "transport_pid",
            "shell": "session_shell_pid",
            "user_manager": "session_user_manager_pid",
            "winlogon": "session_winlogon_pid",
            "explorer": "explorer_pid",
            "process_tree_root": "process_tree_root",
        }
        references: list[_ProcessTerminationSessionReference] = []
        for session_links in links:
            fields_for_session = tuple(
                field_name
                for role, field_name in role_fields.items()
                if getattr(session_links.links, role) == process_index
            )
            if not fields_for_session:
                continue
            identity = sessions[session_links.session_index].identity
            references.append(
                _ProcessTerminationSessionReference(
                    logon_id=identity.logon_id,
                    object_id=identity.object_id,
                    fields=fields_for_session,
                )
            )
        return tuple(references)

    def _seal_action_cohort_materialization(
        self,
        builder: ActionCohortMaterializationBuilder,
    ) -> ActionCohortMaterializationPlan:
        """Freeze and authenticate one exact builder without retaining it."""

        with self._capability_minting_guard("ActionCohortMaterializationBuilder.seal"):
            if (
                builder._manager is not self
                or builder._admission_epoch != self._prepared_state_admission_epoch
            ):
                raise StateError("Action cohort builder belongs to another StateManager")
            if builder.expected_version != self._materialization_version:
                raise StateError("Action cohort builder became stale before sealing")
            if self.state.current_time != builder._expected_state_time:
                raise StateError("Action cohort State time changed before sealing")
            if builder._boot_times:
                raise StateError("Action cohort materialization cannot stage host boot times")
            sessions = tuple(builder._action_sessions)
            processes = tuple(builder._processes)
            if not any(
                (
                    sessions,
                    processes,
                    builder._live_session_process_roles_patches,
                    builder._session_metadata_patches,
                    builder._process_activity_patches,
                    builder._session_activity_patches,
                    builder._process_termination_drafts,
                    builder._session_terminalization_drafts,
                )
            ):
                raise StateError("Action cohort materialization cannot be empty")

            process_indexes = {id(process): index for index, process in enumerate(processes)}
            session_links: list[_ActionCohortSessionProcessLinks] = []
            for session_index, session in enumerate(sessions):
                role_plans = builder._action_session_process_plans.get(id(session), {})
                session_links.append(
                    _ActionCohortSessionProcessLinks(
                        session_index=session_index,
                        links=_SessionProcessMaterializationLinks(
                            **{
                                role: process_indexes[id(process)]
                                for role, process in role_plans.items()
                            }
                        ),
                    )
                )
            frozen_links = tuple(session_links)

            process_terminations: list[ActionCohortProcessTermination] = []
            for termination in builder._process_termination_drafts:
                if type(termination.target) is ProcessMaterializationPlan:
                    process_index = process_indexes.get(id(termination.target))
                    if process_index is None:
                        raise StateError(
                            "Action cohort staged close target is not a process member"
                        )
                    references = self._action_cohort_staged_session_references(
                        process_index=process_index,
                        sessions=sessions,
                        links=frozen_links,
                    )
                    termination = replace(
                        termination,
                        staged_session_references=references,
                    )
                process_terminations.append(termination)

            times: list[datetime] = []
            if builder._expected_state_time is not None:
                times.append(ensure_utc(builder._expected_state_time))
            times.extend(session.identity.started_at for session in sessions)
            times.extend(process.identity.started_at for process in processes)
            times.extend(
                process._payload.parent_activity_time
                for process in processes
                if process._payload.parent_activity_time is not None
            )
            for patch in builder._session_metadata_patches:
                for value in (
                    patch.after.source_ready_time,
                    patch.after.network_close_time,
                ):
                    if value is not None:
                        times.append(value)
            times.extend(patch.activity_time for patch in builder._process_activity_patches)
            times.extend(patch.activity_time for patch in builder._session_activity_patches)
            times.extend(termination.end_time for termination in process_terminations)
            times.extend(
                terminalization.end_time
                for terminalization in builder._session_terminalization_drafts
            )
            final_state_time = max(times)
            capability = _ActionCohortCapability()
            semantic_kwargs = {
                "expected_version": builder.expected_version,
                "expected_state_time": builder._expected_state_time,
                "final_state_time": final_state_time,
                "sessions": sessions,
                "processes": processes,
                "session_process_links": frozen_links,
                "live_session_process_roles": tuple(builder._live_session_process_roles_patches),
                "session_metadata": tuple(builder._session_metadata_patches),
                "process_activity": tuple(builder._process_activity_patches),
                "session_activity": tuple(builder._session_activity_patches),
                "process_terminations": tuple(process_terminations),
                "session_terminalizations": tuple(builder._session_terminalization_drafts),
            }
            semantic_id = _action_cohort_semantic_id(**semantic_kwargs)
            plan = ActionCohortMaterializationPlan(
                _expected_version=builder.expected_version,
                _expected_state_time=builder._expected_state_time,
                _final_state_time=final_state_time,
                _sessions=sessions,
                _processes=processes,
                _session_process_links=frozen_links,
                _live_session_process_roles=tuple(builder._live_session_process_roles_patches),
                _session_metadata=tuple(builder._session_metadata_patches),
                _process_activity=tuple(builder._process_activity_patches),
                _session_activity=tuple(builder._session_activity_patches),
                _process_terminations=tuple(process_terminations),
                _session_terminalizations=tuple(builder._session_terminalization_drafts),
                _semantic_id=semantic_id,
                _capability=capability,
                _integrity_token="",
            )
            plan = replace(
                plan,
                _integrity_token=_action_cohort_integrity_token(
                    self._materialization_secret,
                    semantic_id=semantic_id,
                    capability=capability,
                    sessions=sessions,
                    processes=processes,
                    live_session_process_roles=plan._live_session_process_roles,
                    session_metadata=plan._session_metadata,
                    process_activity=plan._process_activity,
                    session_activity=plan._session_activity,
                    process_terminations=plan._process_terminations,
                    session_terminalizations=plan._session_terminalizations,
                ),
            )
            self.validate_action_cohort_materialization(plan)
            return plan

    def _plan_batch_session(
        self,
        builder: MaterializationBatchBuilder,
        kwargs: dict[str, object],
    ) -> SessionMaterializationPlan:
        """Plan the one batch session while preserving the builder's state fence."""

        with self._capability_minting_guard("MaterializationBatchBuilder.plan_session"):
            if (
                builder._manager is not self
                or builder._admission_epoch != self._prepared_state_admission_epoch
            ):
                raise StateError("Materialization batch belongs to another StateManager")
            if builder.expected_version != self._materialization_version:
                raise StateError("Materialization batch became stale during session planning")
            if self.state.current_time != builder._expected_state_time:
                raise StateError("Materialization batch state-time fence changed during planning")
            plan = self.plan_session_materialization(**kwargs)  # type: ignore[arg-type]
            if plan.expected_version != builder.expected_version:
                raise StateError("Materialization batch session fence changed during planning")
            return plan

    def _enrich_batch_linux_logind_session(
        self,
        builder: MaterializationBatchBuilder,
        plan: SessionMaterializationPlan,
        *,
        rng: random.Random,
        event_time: datetime,
    ) -> SessionMaterializationPlan:
        """Enrich the one batch session without publishing either allocator."""

        with self._capability_minting_guard(
            "MaterializationBatchBuilder.enrich_linux_logind_session"
        ):
            if (
                builder._manager is not self
                or builder._admission_epoch != self._prepared_state_admission_epoch
                or builder.expected_version != self._materialization_version
            ):
                raise StateError("Materialization batch became stale during logind planning")
            if self.state.current_time != builder._expected_state_time:
                raise StateError("Materialization batch state-time fence changed during planning")
            return self.plan_linux_logind_session_materialization(
                plan,
                rng=rng,
                event_time=event_time,
            )

    def _seal_materialization_batch(
        self,
        builder: MaterializationBatchBuilder,
    ) -> MaterializationBatchPlan:
        """Authenticate the builder's exact session/process membership."""

        with self._capability_minting_guard("MaterializationBatchBuilder.seal"):
            if (
                builder._manager is not self
                or builder._admission_epoch != self._prepared_state_admission_epoch
            ):
                raise StateError("Materialization batch belongs to another StateManager")
            if builder.expected_version != self._materialization_version:
                raise StateError("Materialization batch became stale before sealing")
            if self.state.current_time != builder._expected_state_time:
                raise StateError("Materialization batch state-time fence changed before sealing")
            processes = tuple(builder._processes)
            boot_times = tuple(sorted(builder._boot_times.items()))
            state_times = [process._payload.state_time for process in processes]
            state_times.extend(boot_time for _hostname, boot_time in boot_times)
            state_times.extend(
                process._payload.parent_activity_time
                for process in processes
                if process._payload.parent_activity_time is not None
            )
            if builder._session is not None:
                state_times.append(builder._session._payload.state_time)
                linux_logind = builder._session._allocator_patch.linux_logind
                if linux_logind is not None:
                    state_times.append(linux_logind.event_time)
            if builder._expected_state_time is not None:
                state_times.append(ensure_utc(builder._expected_state_time))
            final_state_time = max(state_times)
            process_indexes = {id(process): index for index, process in enumerate(processes)}
            links = _SessionProcessMaterializationLinks(
                **{
                    role: process_indexes[id(process)]
                    for role, process in builder._session_process_plans.items()
                }
            )
            plan = MaterializationBatchPlan(
                _expected_version=builder.expected_version,
                _expected_state_time=builder._expected_state_time,
                _admission_epoch=builder._admission_epoch,
                _final_state_time=final_state_time,
                _session=builder._session,
                _processes=processes,
                _boot_times=boot_times,
                _session_process_links=links,
                _integrity_token=_materialization_batch_integrity_token(
                    self._materialization_secret,
                    expected_version=builder.expected_version,
                    expected_state_time=builder._expected_state_time,
                    admission_epoch=builder._admission_epoch,
                    final_state_time=final_state_time,
                    session=builder._session,
                    processes=processes,
                    boot_times=boot_times,
                    session_process_links=links,
                ),
            )
            self._validate_materialization_batch_plan(plan)
            return plan

    def _preview_host_logon_base(self, system: str) -> tuple[int, tuple[str, int] | None]:
        base = self._logon_id_host_bases.get(system)
        if base is not None:
            return base, None
        bucket = _stable_seed(f"logon_luid_host_{system}") % _HOST_LOGON_BUCKET_SPACE
        salt = 0
        while True:
            candidate = _MIN_GENERATED_LOGON_LUID + (
                (bucket + (salt * _HOST_LOGON_BUCKET_STEP)) % _HOST_LOGON_BUCKET_SPACE
            )
            if candidate not in self._logon_id_used_host_bases:
                return candidate, (system, candidate)
            salt += 1

    def _preview_host_logon_epoch(
        self,
        system: str,
        current_time: datetime,
    ) -> tuple[datetime, tuple[str, datetime] | None]:
        boot_time = self._system_boot_times.get(system)
        if boot_time is not None:
            return ensure_utc(boot_time), None
        epoch = self._logon_id_epochs.get(system)
        if epoch is not None:
            return epoch, None
        uptime_seconds = 3600 + (_stable_seed(f"logon_luid_uptime_{system}") % (3 * 86400))
        epoch = ensure_utc(current_time) - timedelta(seconds=uptime_seconds)
        return epoch, (system, epoch)

    def _preview_logon_luid(
        self,
        system: str,
        event_time: datetime,
    ) -> tuple[
        int, tuple[str, int] | None, tuple[str, datetime] | None, tuple[tuple[str, int, int], int]
    ]:
        current_time = ensure_utc(event_time)
        base, host_base_patch = self._preview_host_logon_base(system)
        epoch, host_epoch_patch = self._preview_host_logon_epoch(system, current_time)
        elapsed_seconds = max(0, int((current_time - epoch).total_seconds()))
        block = elapsed_seconds // 60
        second_in_block = elapsed_seconds % 60
        subsecond_bucket = min(15, current_time.microsecond // 62500)
        ordinal_key = (system, elapsed_seconds, subsecond_bucket)
        ordinal = self._logon_id_second_ordinals.get(ordinal_key, 0)
        stride = self._logon_luid_block_stride(system, block)
        candidate = base + self._logon_luid_block_offset(system, block)
        candidate += (second_in_block * stride) + (subsecond_bucket * 3) + ordinal
        candidate += (
            _stable_seed(f"logon_luid_low:{system}:{current_time.isoformat()}:{ordinal}") % 3
        )
        candidate = _normalize_generated_logon_luid(candidate)
        while candidate in self._used_logon_ids or candidate in self._reserved_logon_ids:
            candidate = _normalize_generated_logon_luid(candidate + 1)
        return candidate, host_base_patch, host_epoch_patch, (ordinal_key, ordinal + 1)

    def _preview_windows_session_id(
        self,
        *,
        system: str,
        username: str,
        logon_type: int,
        session_kind: str,
    ) -> tuple[int, tuple[str, int] | None]:
        if not windows_logon_can_own_desktop(logon_type) or session_kind in {
            "network",
            "new_credentials",
            "service",
            "ssh",
        }:
            return 0, None
        used_ids = {
            session.session_id
            for session in self._active_sessions.find("system", system)
            if session.session_id > 0
        }
        if logon_type in {2, 11} and session_kind in {"interactive", "logon"}:
            preferred = 1 + (_stable_seed(f"windows_console_session:{system}") % 2)
            if preferred not in used_ids:
                return preferred, None
        initial = self._windows_session_id_counters.get(
            system,
            3 + (_stable_seed(f"windows_session_initial:{system}") % 3),
        )
        candidate = initial
        while candidate in used_ids or candidate <= 0:
            candidate += 1 + (_stable_seed(f"windows_session_gap:{system}:{candidate}") % 2)
        return candidate, (system, candidate + 1)

    def plan_session_materialization(
        self,
        *,
        username: str,
        system: str,
        logon_type: int,
        source_ip: str,
        source_port: int = 0,
        session_kind: str = "logon",
        transport_pid: int | None = None,
        start_time: datetime | None = None,
        logon_id: str | None = None,
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
        network_close_time: datetime | None = None,
        source_ready_time: datetime | None = None,
        closure_owned_by_bundle: bool = False,
        end_plan: SessionEndPlan | None = None,
    ) -> SessionMaterializationPlan:
        """Plan one exact session identity without consuming LUID/session allocators."""

        with self._capability_minting_guard("plan_session_materialization"):
            if start_time is None and self.state.current_time is None:
                raise StateError("Cannot plan session: current_time not set")
            session_start = ensure_utc(start_time or self.state.current_time)
            ready_at = ensure_utc(source_ready_time) if source_ready_time is not None else None
            closes_at = ensure_utc(network_close_time) if network_close_time is not None else None
            if type(closure_owned_by_bundle) is not bool:
                raise TypeError("Session closure ownership requires an exact bool")
            if ready_at is not None and ready_at < session_start:
                raise StateError("Session readiness cannot precede session start")
            if closes_at is not None and closes_at < session_start:
                raise StateError("Session network close cannot precede session start")
            if ready_at is not None and closes_at is not None and ready_at >= closes_at:
                raise StateError("Session readiness must precede its network close")
            if end_plan is not None:
                if type(end_plan) is not SessionEndPlan:
                    raise TypeError("Session materialization requires an exact end plan")
                end_plan = replace(
                    end_plan,
                    canonical_end=ensure_utc(end_plan.canonical_end),
                )
                if end_plan.canonical_end < session_start:
                    raise StateError("Session end plan cannot precede session start")
            provided_logon_id = logon_id is not None
            host_base_patch: tuple[str, int] | None = None
            host_epoch_patch: tuple[str, datetime] | None = None
            ordinal_patch: tuple[tuple[str, int, int], int] | None = None
            used_logon_id: int | None = None
            if logon_id is None:
                (
                    used_logon_id,
                    host_base_patch,
                    host_epoch_patch,
                    ordinal_patch,
                ) = self._preview_logon_luid(system, session_start)
                logon_id = f"0x{used_logon_id:x}"
            else:
                resolved = self._resolve_logon_id(logon_id)
                if logon_id in self._ended_sessions or resolved in self._ended_sessions:
                    raise StateError(
                        "Cannot register a new session with ended LogonID "
                        f"{logon_id}; allocate a fresh canonical LogonID"
                    )
                if resolved in self.state.active_sessions:
                    raise StateError(
                        f"Cannot plan session: LogonID {logon_id} is already materialized"
                    )
                try:
                    used_logon_id = int(logon_id, 16)
                except (TypeError, ValueError):
                    used_logon_id = None
                if used_logon_id is not None and used_logon_id in self._used_logon_ids:
                    raise StateError(f"Cannot plan session: LogonID {logon_id} is already used")

            linux_logind_patch: _LinuxLogindAllocatorPatch | None = None
            if session_id is None:
                session_id, session_counter_patch = self._preview_windows_session_id(
                    system=system,
                    username=username,
                    logon_type=logon_type,
                    session_kind=session_kind,
                )
            else:
                session_counter_patch = None
            object_id = stable_uuid(
                "registered-session" if provided_logon_id else "session",
                system,
                username,
                logon_type,
                session_kind,
                source_ip,
                source_port,
                session_start.isoformat(),
                logon_id,
                session_id,
            )
            if logon_guid_required is not None:
                logon_guid = (
                    self._stable_logon_guid(system, logon_id)
                    if logon_guid_required
                    else _NULL_LOGON_GUID
                )
            lifecycle_id = lifecycle_group_id or stable_uuid("session-lifecycle", object_id)
            identity = SessionIdentity(
                hostname=system,
                object_id=object_id,
                logon_id=logon_id,
                session_id=session_id,
                principal=username,
                session_kind=session_kind,
                started_at=session_start,
                lifecycle_group_id=lifecycle_id,
                logon_guid=logon_guid,
                parent_lifecycle_group_id=parent_lifecycle_group_id,
            )
            payload = _SessionMaterializationPayload(
                logon_type=logon_type,
                source_ip=source_ip,
                source_port=source_port,
                transport_pid=transport_pid,
                auth_protocol=auth_protocol,
                smb_principal=smb_principal,
                account_scope=account_scope,
                auth_session_ref=auth_session_ref,
                effective_uid=effective_uid,
                effective_gid=effective_gid,
                state_time=session_start,
                network_close_time=closes_at,
                source_ready_time=ready_at,
                closure_owned_by_bundle=closure_owned_by_bundle,
                end_plan=end_plan,
            )
            allocator_patch = _SessionAllocatorPatch(
                host_base=host_base_patch,
                host_epoch=host_epoch_patch,
                ordinal=ordinal_patch,
                used_logon_id=used_logon_id,
                windows_session_counter=session_counter_patch,
                linux_logind=linux_logind_patch,
            )
            expected_version = self._materialization_version
            return SessionMaterializationPlan(
                _expected_version=expected_version,
                _identity=identity,
                _payload=payload,
                _allocator_patch=allocator_patch,
                _integrity_token=_materialization_integrity_token(
                    self._materialization_secret,
                    "session",
                    expected_version,
                    identity,
                    payload,
                    allocator_patch,
                ),
            )

    def materialize_session(self, plan: SessionMaterializationPlan) -> ActiveSession:
        """Commit one already-admitted session plan without sampling or domain validation."""

        admission_epoch = self._reject_mutation_during_action_cohort_claim("materialize_session")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "materialize_session",
                admitted_at=admission_epoch,
            )
            self.validate_session_materialization(plan)
            return self._commit_prevalidated_session_materialization(plan)

    def plan_linux_logind_session_materialization(
        self,
        plan: SessionMaterializationPlan,
        *,
        rng: random.Random,
        event_time: datetime,
    ) -> SessionMaterializationPlan:
        """Enrich an uncommitted session plan with one exact Linux logind ID.

        The input plan remains allocation-free and is commonly used to derive a
        LogonID-scoped deterministic RNG. The returned replacement carries the
        exact allocator patch and action RNG successor state; neither owner is
        mutated until authority commit.
        """

        with self._capability_minting_guard("plan_linux_logind_session_materialization"):
            self._validate_session_materialization_plan(plan)
            if plan.expected_version != self._materialization_version:
                raise StateError("Session materialization plan became stale before enrichment")
            if plan._allocator_patch.linux_logind is not None:
                raise StateError("Session materialization plan already owns a Linux logind ID")
            if plan.identity.session_id != 0:
                raise StateError("Linux logind enrichment requires an unresolved session_id=0 plan")
            session_id, logind_patch = self._preview_linux_logind_session_id(
                plan.identity.hostname,
                rng.getstate(),
                event_time,
            )
            identity = replace(plan.identity, session_id=session_id)
            allocator_patch = replace(
                plan._allocator_patch,
                windows_session_counter=None,
                linux_logind=logind_patch,
            )
            return SessionMaterializationPlan(
                _expected_version=plan.expected_version,
                _identity=identity,
                _payload=plan._payload,
                _allocator_patch=allocator_patch,
                _integrity_token=_materialization_integrity_token(
                    self._materialization_secret,
                    "session",
                    plan.expected_version,
                    identity,
                    plan._payload,
                    allocator_patch,
                ),
            )

    def validate_session_materialization(self, plan: SessionMaterializationPlan) -> None:
        """Validate every fallible session-start condition without publishing state."""

        with self._lock:
            self._validate_session_materialization_plan(plan)
            if plan.expected_version != self._materialization_version:
                raise StateError("Session materialization plan became stale before commit")
            identity = plan.identity
            if identity.logon_id in self.state.active_sessions:
                raise StateError(
                    f"Session materialization LogonID is already live: {identity.logon_id}"
                )
            if identity.logon_id in self._ended_sessions:
                raise StateError(
                    f"Session materialization LogonID is already ended: {identity.logon_id}"
                )

    def _commit_prevalidated_session_materialization(
        self,
        plan: SessionMaterializationPlan,
        *,
        advance_version: bool = True,
        update_state_time: bool = True,
        prepared: _PreparedActionCohortSessionStart | None = None,
        emit_log: bool = True,
    ) -> ActiveSession:
        """Perform primitive session writes after validation under materialization_guard."""

        patch = plan._allocator_patch
        if patch.host_base is not None:
            host, base = patch.host_base
            self._logon_id_host_bases[host] = base
            self._logon_id_used_host_bases.add(base)
        if patch.host_epoch is not None:
            host, epoch = patch.host_epoch
            self._logon_id_epochs[host] = epoch
        if patch.ordinal is not None:
            key, value = patch.ordinal
            self._logon_id_second_ordinals[key] = value
        if patch.used_logon_id is not None:
            self._used_logon_ids.add(patch.used_logon_id)
        if patch.windows_session_counter is not None:
            host, counter = patch.windows_session_counter
            self._windows_session_id_counters[host] = counter
        if patch.linux_logind is not None:
            self._commit_linux_logind_allocator_patch(
                patch.linux_logind,
                used_ids_default=(
                    prepared.linux_logind_used_ids_default if prepared is not None else None
                ),
                allocations_default=(
                    prepared.linux_logind_allocations_default if prepared is not None else None
                ),
            )
        payload = plan._payload
        if update_state_time:
            self.state.current_time = payload.state_time
        session = (
            prepared.session
            if prepared is not None
            else self._prepare_action_cohort_session_start(plan).session
        )
        self.state.active_sessions[session.logon_id] = session
        self._remove_logon_id_alias(session.logon_id)
        self._remove_ended_session(session.logon_id)
        if advance_version:
            self._materialization_version += 1
        if emit_log:
            logger.debug(
                "Materialized session %s for %s@%s",
                session.logon_id,
                session.username,
                session.system,
            )
        return session

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
        admission_epoch = self._reject_mutation_during_action_cohort_claim("allocate_logon_id")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "allocate_logon_id",
                admitted_at=admission_epoch,
            )
            if event_time is None:
                if self.state.current_time is None:
                    raise StateError("Cannot allocate LogonID: current_time not set")
                event_time = self.state.current_time
            logon_id = f"0x{self._allocate_logon_luid(system, event_time):x}"
            self._materialization_version += 1
            return logon_id

    def preview_logon_id(self, system: str, event_time: datetime) -> str:
        """Return the next canonical LogonID without mutating allocator state."""

        with self._lock:
            candidate, _host_base, _host_epoch, _ordinal = self._preview_logon_luid(
                system,
                ensure_utc(event_time),
            )
            return f"0x{candidate:x}"

    def next_semantic_peer_ordinal(self, family: str, stable_key: str) -> int:
        """Allocate an ordinal scoped only to otherwise identical semantic peers."""

        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "next_semantic_peer_ordinal"
        )
        if not family or not stable_key:
            raise ValueError("Semantic peer ordinals require a family and stable key")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "next_semantic_peer_ordinal",
                admitted_at=admission_epoch,
            )
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

    def _record_logon_id_alias(self, alias: str, target: str) -> None:
        """Install one alias and its bounded reverse ownership entry."""

        prior = self._logon_id_aliases.get(alias)
        if prior == target:
            return
        if prior is not None:
            prior_aliases = self._logon_id_aliases_by_target.get(prior)
            if prior_aliases is not None:
                prior_aliases.discard(alias)
                if not prior_aliases:
                    self._logon_id_aliases_by_target.pop(prior, None)
        self._logon_id_aliases[alias] = target
        self._logon_id_aliases_by_target.setdefault(target, set()).add(alias)

    def _remove_logon_id_alias(self, alias: str) -> None:
        """Remove one alias and its reverse ownership entry."""

        target = self._logon_id_aliases.pop(alias, None)
        if target is None:
            return
        aliases = self._logon_id_aliases_by_target.get(target)
        if aliases is None:
            return
        aliases.discard(alias)
        if not aliases:
            self._logon_id_aliases_by_target.pop(target, None)

    def _cleanup_ended_session_retention_entry(
        self,
        logon_id: str,
        ended: tuple[ActiveSession, datetime],
    ) -> None:
        """Remove every reverse/index entry owned by one retained-session key."""

        session, _end_time = ended
        if logon_id != session.logon_id:
            self._remove_logon_id_alias(logon_id)
            return
        self._ended_sessions_by_username_end.remove(logon_id)
        self._ended_sessions_by_system_end.remove(logon_id)
        self._authoritative_session_ends.remove(logon_id)
        aliases = tuple(self._logon_id_aliases_by_target.pop(logon_id, ()))
        for alias in aliases:
            self._logon_id_aliases.pop(alias, None)
            self._ended_sessions.pop(alias, None)

    def _remove_ended_session(self, logon_id: str) -> None:
        """Remove ended-session state and its canonical temporal indexes."""
        ended = self._ended_sessions.pop(logon_id, None)
        if ended is None:
            return
        self._cleanup_ended_session_retention_entry(logon_id, ended)

    def _index_ended_session(
        self,
        logon_id: str,
        session: ActiveSession,
        end_time: datetime,
    ) -> None:
        """Index one canonical ended session by owner and visible end time."""
        self._ended_sessions_by_username_end.add(logon_id, session.username, end_time)
        self._ended_sessions_by_system_end.add(logon_id, session.system, end_time)

    def _trim_retained_session_identities(self) -> None:
        """Enforce the hard cap while preserving newest ended session identities."""

        for logon_id, ended in self._ended_sessions.trim_earliest(_MAX_RETAINED_SESSION_IDENTITIES):
            self._cleanup_ended_session_retention_entry(logon_id, ended)

    def _index_authoritative_session_end(self, session: ActiveSession) -> None:
        """Index an authoritative end plan for constant-time rebootstrap checks."""
        plan = session.end_plan
        if plan is None or not plan.is_hard_deadline:
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
        admission_epoch = self._reject_mutation_during_action_cohort_claim("create_session")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "create_session", admitted_at=admission_epoch
            )
            plan = self.plan_session_materialization(
                username=username,
                system=system,
                logon_type=logon_type,
                source_ip=source_ip,
                source_port=source_port,
                session_kind=session_kind,
                transport_pid=transport_pid,
                start_time=start_time,
                logon_guid=logon_guid,
                logon_guid_required=logon_guid_required,
                session_id=session_id,
                lifecycle_group_id=lifecycle_group_id,
                parent_lifecycle_group_id=parent_lifecycle_group_id,
                auth_protocol=auth_protocol,
                smb_principal=smb_principal,
                account_scope=account_scope,
                auth_session_ref=auth_session_ref,
                effective_uid=effective_uid,
                effective_gid=effective_gid,
            )
            with self.materialization_guard(plan.expected_version):
                return self.materialize_session(plan).logon_id

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
        admission_epoch = self._reject_mutation_during_action_cohort_claim("register_session")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "register_session", admitted_at=admission_epoch
            )
            resolved_logon_id = self._resolve_logon_id(logon_id)
            existing = self.state.active_sessions.get(logon_id) or self.state.active_sessions.get(
                resolved_logon_id
            )
            if existing is not None:
                return existing
            plan = self.plan_session_materialization(
                logon_id=logon_id,
                username=username,
                system=system,
                logon_type=logon_type,
                source_ip=source_ip,
                start_time=start_time,
                source_port=source_port,
                session_kind=session_kind,
                transport_pid=transport_pid,
                logon_guid=logon_guid,
                logon_guid_required=logon_guid_required,
                session_id=session_id,
                lifecycle_group_id=lifecycle_group_id,
                parent_lifecycle_group_id=parent_lifecycle_group_id,
                auth_protocol=auth_protocol,
                smb_principal=smb_principal,
                account_scope=account_scope,
                auth_session_ref=auth_session_ref,
                effective_uid=effective_uid,
                effective_gid=effective_gid,
            )
            with self.materialization_guard(plan.expected_version):
                return self.materialize_session(plan)

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
        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "update_session_metadata"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "update_session_metadata",
                admitted_at=admission_epoch,
            )
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

        Explicit storyline ends and action-bundle hard deadlines cannot be
        silently replaced by another event. Re-applying the same plan is
        idempotent.
        """

        admission_epoch = self._reject_mutation_during_action_cohort_claim("plan_session_end")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "plan_session_end",
                admitted_at=admission_epoch,
            )
            session = self.state.active_sessions.get(self._resolve_logon_id(logon_id))
            if session is None:
                return False
            existing = session.end_plan
            if existing is not None and existing != plan:
                if existing.is_hard_deadline:
                    raise StateError(
                        "Cannot replace authoritative or action-bundle session end plan for "
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
        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "get_or_create_session_logon_guid"
        )
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
                self._reject_mutation_during_action_cohort_claim(
                    "get_or_create_session_logon_guid",
                    admitted_at=admission_epoch,
                )
                session.logon_guid = guid
            return guid

    def reassign_session_logon_id(self, logon_id: str, event_time: datetime) -> str | None:
        """Re-key an active session after its final source-native start time is known."""
        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "reassign_session_logon_id"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "reassign_session_logon_id",
                admitted_at=admission_epoch,
            )
            session = self._active_sessions.pop(logon_id, None)
            if session is None:
                return None
            new_logon_id = f"0x{self._allocate_logon_luid(session.system, event_time):x}"
            session.logon_id = new_logon_id
            session.start_time = ensure_utc(event_time)
            self._active_sessions[new_logon_id] = session
            self._authoritative_session_ends.remove(logon_id)
            self._index_authoritative_session_end(session)
            self._remove_ended_session(logon_id)
            self._remove_ended_session(new_logon_id)
            self._record_logon_id_alias(logon_id, new_logon_id)
            self._materialization_version += 1
            return new_logon_id

    def end_session(self, logon_id: str, end_time: datetime | None = None) -> bool:
        """End an active session.

        Args:
            logon_id: LogonID of session to end
            end_time: Timestamp of the visible logoff/logout event

        Returns:
            True if session was found and removed, False if not found
        """
        admission_epoch = self._reject_mutation_during_action_cohort_claim("end_session")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "end_session",
                admitted_at=admission_epoch,
            )
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
                    self._trim_retained_session_identities()
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

    def _preview_linux_logind_session_id(
        self,
        system: str,
        rng_state: object,
        event_time: datetime,
    ) -> tuple[int, _LinuxLogindAllocatorPatch]:
        """Preview one logind ID and its exact allocator patch without mutation."""

        preview_rng = random.Random()
        preview_rng.setstate(rng_state)
        sampled_initial = preview_rng.randint(20, 250)
        normalized_time = ensure_utc(event_time).replace(microsecond=0)
        current_initial = self._linux_logind_session_initials.get(system)
        initial = current_initial if current_initial is not None else sampled_initial
        initial_patch = initial if current_initial is None else None
        boot_epoch = self._system_boot_times.get(system)
        current_epoch = self._linux_logind_session_epochs.get(system)
        epoch = boot_epoch if boot_epoch is not None else current_epoch
        epoch_patch: datetime | None = None
        if epoch is None:
            epoch = normalized_time
            epoch_patch = normalized_time
        elapsed_seconds = max(
            0,
            int((normalized_time - ensure_utc(epoch)).total_seconds()),
        )
        elapsed_minutes = elapsed_seconds // 60
        second_slot = normalized_time.second // 10
        stride = 8 + (_stable_seed(f"logind_session_minute_stride:{system}") % 2)
        minute_jitter = _stable_seed(f"logind_session_minute_jitter:{system}:{elapsed_minutes}") % 2
        candidate = initial + (elapsed_minutes * stride) + second_slot + minute_jitter
        used = self._linux_logind_session_used_ids.get(system, set())
        allocations = self._linux_logind_session_allocations.get(system)
        earlier_max = (
            allocations.max_value_at_or_before(normalized_time) if allocations is not None else None
        )
        if earlier_max is not None and candidate <= earlier_max:
            bump = 1 + (
                _stable_seed(f"logind_session_lower_bound:{system}:{normalized_time}:{candidate}")
                % 3
            )
            candidate = earlier_max + bump
        salt = 0
        while candidate in used or (
            allocations is not None
            and allocations.matches_elapsed_delta(
                normalized_time,
                candidate,
                tolerance=0.0,
                integral_seconds=True,
            )
        ):
            candidate += 7 + (
                _stable_seed(f"logind_session_collision:{system}:{candidate}:{salt}") % 7
            )
            salt += 1
        return candidate, _LinuxLogindAllocatorPatch(
            system=system,
            event_time=normalized_time,
            session_id=candidate,
            initial=initial_patch,
            epoch=epoch_patch,
            rng_state_after=preview_rng.getstate(),
        )

    def _commit_linux_logind_allocator_patch(
        self,
        patch: _LinuxLogindAllocatorPatch,
        *,
        used_ids_default: set[int] | None = None,
        allocations_default: TemporalAllocationIndex | None = None,
    ) -> None:
        """Apply one validated logind allocator patch with primitive writes only."""

        if patch.initial is not None:
            self._linux_logind_session_initials[patch.system] = patch.initial
        if patch.epoch is not None:
            self._linux_logind_session_epochs[patch.system] = patch.epoch
        used_ids = self._linux_logind_session_used_ids.get(patch.system)
        if used_ids is None:
            used_ids = used_ids_default if used_ids_default is not None else set()
            self._linux_logind_session_used_ids[patch.system] = used_ids
        used_ids.add(patch.session_id)
        allocations = self._linux_logind_session_allocations.get(patch.system)
        if allocations is None:
            allocations = (
                allocations_default
                if allocations_default is not None
                else TemporalAllocationIndex()
            )
            self._linux_logind_session_allocations[patch.system] = allocations
        allocations.add(patch.event_time, patch.session_id)
        self._linux_logind_session_last_ids[patch.system] = max(
            patch.session_id,
            self._linux_logind_session_last_ids.get(patch.system, patch.session_id),
        )

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
        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "next_linux_logind_session_id"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "next_linux_logind_session_id",
                admitted_at=admission_epoch,
            )
            if event_time is not None:
                candidate, patch = self._preview_linux_logind_session_id(
                    system,
                    rng.getstate(),
                    event_time,
                )
                self._commit_linux_logind_allocator_patch(patch)
                rng.setstate(patch.rng_state_after)
                self._materialization_version += 1
                return candidate

            if system not in self._linux_logind_session_counters:
                self._linux_logind_session_counters[system] = rng.randint(20, 250)
            self._linux_logind_session_counters[system] += rng.randint(1, 4)
            self._materialization_version += 1
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

    @staticmethod
    def _build_linux_pid_weekly_churn_prefix(system: str) -> tuple[int, ...]:
        """Build one immutable hidden-churn prefix without mutating allocator caches."""

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
            base_churn = 76 if day >= 5 else 116 if 8 <= hour < 18 else 92
            hourly_target = round(base_churn * hourly_factor)
            lower = max(48, round(hourly_target * 0.45))
            upper = min(720, max(lower, round(hourly_target * 1.55)))
            churn = rng.randint(lower, upper)
            if rng.random() < 0.04:
                churn += rng.randint(90, 480)
            churn = max(churn, 2 * _LINUX_PID_REORDER_LANE_WIDTH)
            prefix.append(prefix[-1] + churn)
        return tuple(prefix)

    @staticmethod
    def _linux_pid_hidden_churn_from_prefix(
        prefix: tuple[int, ...],
        elapsed_seconds: int,
    ) -> int:
        if elapsed_seconds <= 0:
            return 0
        elapsed_minutes, second_in_minute = divmod(elapsed_seconds, 60)
        full_weeks, minute_of_week = divmod(elapsed_minutes, _MINUTES_PER_WEEK)
        weekly_churn = prefix[-1]
        minute_churn = prefix[minute_of_week + 1] - prefix[minute_of_week]
        partial_churn = (second_in_minute * minute_churn) // 60
        return (full_weeks * weekly_churn) + prefix[minute_of_week] + partial_churn

    def _preview_pid_allocator(
        self,
        system: str,
        os_category: str,
    ) -> tuple[int, random.Random, bool]:
        retained_os = self._pid_os.get(system)
        if retained_os is not None and retained_os != os_category:
            raise StateError(
                f"Cannot plan {os_category} process in {retained_os} PID namespace for {system}"
            )
        retained_rng = self._pid_rngs.get(system)
        if retained_rng is not None:
            rng = random.Random()
            rng.setstate(retained_rng.getstate())
            return self._pid_counters[system], rng, False
        rng = random.Random(_stable_seed(f"pid_alloc_{system}"))
        if system in self._pid_counters:
            return self._pid_counters[system], rng, False
        if os_category == "windows":
            start = rng.randint(2000, 6000)
            counter = start - (start % 4)
        else:
            counter = rng.randint(8000, 42000)
        return counter, rng, True

    def _preview_windows_pid(
        self,
        *,
        system: str,
        counter: int,
        rng: random.Random,
        current_time: datetime,
        extra_reserved_pids: set[int] | None = None,
    ) -> tuple[int, int, int, int]:
        logical_position = counter
        gap = max(1, int(rng.lognormvariate(1.2, 0.8)))
        next_logical = logical_position + (_WINDOWS_PID_STEP * gap)
        planned = extra_reserved_pids or set()
        occupied = self._reserved_pid_count(system) + len(planned)
        candidates = 0
        for _probe in range(occupied + 1):
            candidates += 1
            pid = (
                logical_position
                if logical_position <= _WINDOWS_PID_MAX
                else self._normalize_windows_pid(logical_position)
            )
            if pid not in planned and not self._pid_is_reserved(
                system,
                pid,
                current_time,
                None,
            ):
                return (
                    pid,
                    logical_position,
                    max(next_logical, logical_position + _WINDOWS_PID_STEP),
                    candidates,
                )
            logical_position += _WINDOWS_PID_STEP
        raise StateError("Windows PID namespace is fully occupied by active reservations")

    def _preview_linux_pid(
        self,
        *,
        system: str,
        counter: int,
        rng: random.Random,
        current_time: datetime,
        minimum_logical_exclusive: int | None,
        prefix: tuple[int, ...],
        epoch: datetime,
        bucket_ordinal: int | None = None,
        extra_allocations: tuple[tuple[datetime, int], ...] = (),
        extra_reserved_pids: set[int] | None = None,
    ) -> tuple[int, int, tuple[tuple[str, datetime], int], int]:
        if (
            self._pid_allocation_watermark is not None
            and current_time < self._pid_allocation_watermark
        ):
            raise StateError(
                "Cannot plan PID before the sealed allocation watermark: "
                f"{current_time.isoformat()} < {self._pid_allocation_watermark.isoformat()}"
            )
        elapsed_seconds = max(0, int((current_time - epoch).total_seconds()))
        time_offset = self._linux_pid_hidden_churn_from_prefix(prefix, elapsed_seconds)
        lane_start_seconds = (
            elapsed_seconds // _LINUX_PID_REORDER_LANE_SECONDS
        ) * _LINUX_PID_REORDER_LANE_SECONDS
        lane_end_seconds = lane_start_seconds + _LINUX_PID_REORDER_LANE_SECONDS
        lane_start = epoch + timedelta(seconds=lane_start_seconds)
        lane_end = epoch + timedelta(seconds=lane_end_seconds)
        lane_start_offset = self._linux_pid_hidden_churn_from_prefix(prefix, lane_start_seconds)
        lane_end_offset = self._linux_pid_hidden_churn_from_prefix(prefix, lane_end_seconds)
        if lane_end_offset - lane_start_offset < _LINUX_PID_REORDER_LANE_WIDTH:
            raise StateError(
                "Linux PID reorder lane is narrower than its configured capacity "
                f"(host={system}, start={lane_start.isoformat()})"
            )
        lane_lower_bound = counter + lane_start_offset
        lane_upper_bound = counter + lane_end_offset
        ordinal_key = (system, current_time)
        ordinal = (
            self._pid_bucket_offsets.get(ordinal_key, 0)
            if bucket_ordinal is None
            else bucket_ordinal
        )
        gap = max(1, min(5, int(rng.lognormvariate(0.3, 0.8))))
        lane_width = lane_upper_bound - lane_lower_bound
        natural_offset = min(
            max(0, time_offset - lane_start_offset),
            lane_width - _LINUX_PID_REORDER_LANE_HEADROOM - 1,
        )
        natural_lane_position = lane_lower_bound + natural_offset
        logical_position = natural_lane_position + ordinal
        natural_logical_position = logical_position
        allocations = self._linux_pid_allocations.get(system)
        extra_before = [
            logical for allocated_at, logical in extra_allocations if allocated_at <= current_time
        ]
        extra_after = sorted(
            (allocated_at, logical)
            for allocated_at, logical in extra_allocations
            if allocated_at > current_time
        )
        prior_logical = (
            allocations.max_value_at_or_before(current_time) if allocations is not None else None
        )
        if extra_before:
            prior_logical = max(
                max(extra_before),
                prior_logical if prior_logical is not None else max(extra_before),
            )
        sealed_logical = self._pid_sealed_logical_positions.get(system)
        lower_bound = max(
            value
            for value in (minimum_logical_exclusive, prior_logical, sealed_logical, 0)
            if value is not None
        )
        future_logical = allocations.min_value_after(current_time) if allocations else None
        future_record = allocations.first_record_after(current_time) if allocations else None
        if extra_after and (future_record is None or extra_after[0][0] < future_record[0]):
            future_record = extra_after[0]
            future_logical = extra_after[0][1]
        future_lane_record = (
            allocations.first_record_after(lane_end - timedelta(microseconds=1))
            if allocations
            else None
        )
        extra_lane_record = next(
            (
                (allocated_at, logical)
                for allocated_at, logical in extra_after
                if allocated_at >= lane_end
            ),
            None,
        )
        if extra_lane_record is not None and (
            future_lane_record is None or extra_lane_record[0] < future_lane_record[0]
        ):
            future_lane_record = extra_lane_record
        logical_position = max(logical_position, lower_bound + 1, lane_lower_bound)
        if future_logical is not None and logical_position >= future_logical:
            logical_position = max(lower_bound + 1, lane_lower_bound)
        if future_logical is not None and logical_position >= future_logical:
            future_time = future_record[0] if future_record is not None else None
            if future_time is not None and future_time < lane_end:
                logical_position = max(natural_logical_position, lower_bound, future_logical) + 1
                future_logical = None
            else:
                raise StateError(
                    "Cannot plan Linux PID inside its bounded 30-second reorder lane; "
                    f"host={system} time={current_time.isoformat()}"
                )
        if logical_position >= lane_upper_bound and future_lane_record is not None:
            raise StateError(
                "Linux PID 30-second reorder lane capacity exhausted "
                f"(host={system}, time={current_time.isoformat()})"
            )
        planned_pids = extra_reserved_pids or set()
        occupied = (
            self._reserved_pid_count(system)
            + (len(allocations) if allocations else 0)
            + len(extra_allocations)
            + len(planned_pids)
        )
        available_positions = max(0, lane_upper_bound - logical_position)
        probe_budget = (
            min(occupied + 1, available_positions)
            if future_lane_record is not None
            else occupied + 1
        )
        candidates = 0
        for _probe in range(probe_budget):
            candidates += 1
            pid = self._normalize_linux_pid(logical_position)
            if (
                (allocations is None or not allocations.contains_value(logical_position))
                and all(
                    planned_logical != logical_position
                    for _planned_at, planned_logical in extra_allocations
                )
                and pid not in planned_pids
                and not self._pid_is_reserved(system, pid, current_time, None)
            ):
                consumed = logical_position - natural_lane_position
                return (
                    pid,
                    logical_position,
                    (ordinal_key, max(ordinal + gap, consumed + gap)),
                    candidates,
                )
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
                    "Cannot plan Linux PID before a future lane; current lane is reserved"
                )
        raise StateError(
            "Linux PID 30-second reorder lane contains only reserved candidates "
            f"(host={system}, time={current_time.isoformat()})"
        )

    def _preview_primary_thread(
        self,
        *,
        system: str,
        os_category: str,
        object_id: str,
        pid: int,
        counter_override: int | None = None,
        rng_state_override: object | None = None,
        extra_used_tids: set[int] | None = None,
    ) -> tuple[int, tuple[str, int] | None, tuple[str, object] | None]:
        if os_category == "linux":
            return pid, None, None
        counter = (
            self._thread_id_counters.get(
                system,
                2000 + (4 * (_stable_seed(f"windows_tid_initial:{system}") % 5000)),
            )
            if counter_override is None
            else counter_override
        )
        retained_rng = self._thread_id_rngs.get(system)
        rng = random.Random()
        rng.setstate(
            rng_state_override
            if rng_state_override is not None
            else retained_rng.getstate()
            if retained_rng is not None
            else random.Random(_stable_seed(f"windows_tid_alloc:{system}")).getstate()
        )
        used = {thread.tid for thread in self._running_threads.find("system", system)}
        used.update(extra_used_tids or ())
        candidate = counter - (counter % 4)
        while candidate in used or candidate <= 0:
            candidate += 4
        next_counter = candidate + (4 * rng.randint(1, 17))
        return candidate, (system, next_counter), (system, rng.getstate())

    def plan_process_materialization(
        self,
        *,
        system: str,
        parent_pid: int,
        image: str,
        command_line: str,
        username: str,
        integrity_level: str,
        os_category: str,
        logon_id: str = "",
        lifecycle_group_id: str = "",
        parent_lifecycle_group_id: str = "",
        concurrency_group_id: str = "",
        start_time: datetime | None = None,
        fixed_pid: int | None = None,
        require_session: bool = False,
        parent_activity_time: datetime | None = None,
        auth_session_id: int | None = None,
        auth_logon_type: int | None = None,
    ) -> ProcessMaterializationPlan:
        """Plan one exact process identity without consuming PID/thread allocators."""

        with self._capability_minting_guard("plan_process_materialization"):
            raw_start = start_time or self.state.current_time
            if raw_start is None:
                raise StateError("Cannot plan process: current_time not set")
            effective_start = ensure_utc(raw_start)
            if parent_pid not in {0, 4} and not self.is_process_active_at(
                system, parent_pid, effective_start
            ):
                raise StateError(
                    f"Cannot plan process: parent PID {parent_pid} does not exist on {system}"
                )
            if require_session and not logon_id:
                raise StateError("Session-owned process materialization requires a LogonID")
            owning_session = self.get_session_at(logon_id, effective_start) if logon_id else None
            if require_session and logon_id and owning_session is None:
                raise StateError(
                    f"Cannot plan process outside session {logon_id} at "
                    f"{effective_start.isoformat()}"
                )
            if owning_session is not None:
                if auth_session_id is not None and auth_session_id != owning_session.session_id:
                    raise StateError("Process auth session ID disagrees with its owning session")
                if auth_logon_type is not None and auth_logon_type != owning_session.logon_type:
                    raise StateError("Process auth logon type disagrees with its owning session")
                auth_session_id = owning_session.session_id
                auth_logon_type = owning_session.logon_type
            counter, pid_rng, allocator_new = self._preview_pid_allocator(system, os_category)
            pid_epoch_patch: tuple[str, datetime] | None = None
            prefix_patch: tuple[str, tuple[int, ...]] | None = None
            linux_allocation: tuple[str, datetime, int] | None = None
            bucket_patch: tuple[tuple[str, datetime], int] | None = None
            fixed_patch: tuple[str, int] | None = None
            candidate_delta = 0
            allocation_delta = 0
            if fixed_pid is not None:
                if fixed_pid < 0 or self._pid_is_reserved(system, fixed_pid, effective_start, None):
                    raise StateError(
                        f"Cannot plan fixed process: PID {fixed_pid} is reserved on {system}"
                    )
                pid = fixed_pid
                logical_position = fixed_pid
                fixed_patch = (system, fixed_pid)
                if os_category == "linux":
                    linux_allocation = (system, effective_start, fixed_pid)
            elif os_category == "windows":
                pid, logical_position, counter, candidate_delta = self._preview_windows_pid(
                    system=system,
                    counter=counter,
                    rng=pid_rng,
                    current_time=effective_start,
                )
                allocation_delta = 1
            else:
                epoch = self._system_boot_times.get(system) or self._pid_time_epochs.get(system)
                if epoch is None:
                    epoch = effective_start
                    pid_epoch_patch = (system, epoch)
                prefix = self._linux_pid_weekly_churn_prefixes.get(system)
                if prefix is None:
                    prefix = self._build_linux_pid_weekly_churn_prefix(system)
                    prefix_patch = (system, prefix)
                minimum_parent = None
                parent = self.state.running_processes.get((system, parent_pid))
                if parent is not None and parent.start_time <= effective_start and parent.pid > 1:
                    minimum_parent = parent.pid_logical_position
                pid, logical_position, bucket_patch, candidate_delta = self._preview_linux_pid(
                    system=system,
                    counter=counter,
                    rng=pid_rng,
                    current_time=effective_start,
                    minimum_logical_exclusive=minimum_parent,
                    prefix=prefix,
                    epoch=ensure_utc(epoch),
                )
                linux_allocation = (system, effective_start, logical_position)
                allocation_delta = 1
            object_id = stable_uuid(
                "registered-process" if fixed_pid is not None else "process",
                system,
                pid,
                parent_pid,
                image,
                command_line,
                username,
                effective_start.isoformat(),
                logon_id,
            )
            process_lifecycle_id = lifecycle_group_id or stable_uuid("process-lifecycle", object_id)
            process_parent_group = self._process_parent_lifecycle_group(
                process_lifecycle_id,
                parent_lifecycle_group_id,
                owning_session,
            )
            thread_os_category = (
                os_category if allocator_new else self._pid_os.get(system, "windows")
            )
            primary_tid, thread_counter, thread_rng_state = self._preview_primary_thread(
                system=system,
                os_category=thread_os_category,
                object_id=object_id,
                pid=pid,
            )
            thread_object_id = stable_uuid(
                "thread",
                system,
                object_id,
                pid,
                primary_tid,
                effective_start.isoformat(),
                "primary",
            )
            identity = ProcessIdentity(
                hostname=system,
                object_id=object_id,
                pid=pid,
                parent_pid=parent_pid,
                image=image,
                command_line=command_line,
                principal=username,
                logon_id=logon_id,
                started_at=effective_start,
                lifecycle_group_id=process_lifecycle_id,
                parent_lifecycle_group_id=process_parent_group,
                primary_thread=ThreadIdentity(
                    hostname=system,
                    process_object_id=object_id,
                    pid=pid,
                    tid=primary_tid,
                    object_id=thread_object_id,
                    started_at=effective_start,
                ),
            )
            payload = _ProcessMaterializationPayload(
                integrity_level=integrity_level,
                concurrency_group_id=concurrency_group_id,
                pid_logical_position=logical_position,
                state_time=effective_start,
                parent_activity_time=(
                    ensure_utc(parent_activity_time) if parent_activity_time is not None else None
                ),
                auth_session_id=auth_session_id,
                auth_logon_type=auth_logon_type,
                require_session=require_session,
            )
            allocator_patch = _ProcessAllocatorPatch(
                pid_counter=(system, counter),
                pid_os=(system, os_category) if allocator_new else None,
                pid_rng_state=(system, pid_rng.getstate()),
                pid_epoch=pid_epoch_patch,
                pid_weekly_prefix=prefix_patch,
                linux_allocation=linux_allocation,
                pid_bucket_offset=bucket_patch,
                fixed_pid=fixed_patch,
                pid_allocation_count_delta=allocation_delta,
                pid_candidate_probe_delta=candidate_delta,
                thread_counter=thread_counter,
                thread_rng_state=thread_rng_state,
            )
            expected_version = self._materialization_version
            return ProcessMaterializationPlan(
                _expected_version=expected_version,
                _identity=identity,
                _payload=payload,
                _allocator_patch=allocator_patch,
                _integrity_token=_materialization_integrity_token(
                    self._materialization_secret,
                    "process",
                    expected_version,
                    identity,
                    payload,
                    allocator_patch,
                ),
            )

    def _process_termination_threads(
        self,
        process_object_id: str,
    ) -> tuple[ThreadIdentity, ...]:
        """Return the exact ordered live-thread set for one process object."""

        return tuple(
            sorted(
                (
                    self._thread_identity(thread)
                    for thread in self._running_threads.find(
                        "process_object_id",
                        process_object_id,
                    )
                ),
                key=lambda thread: (
                    thread.hostname,
                    thread.process_object_id,
                    thread.tid,
                    thread.object_id,
                ),
            )
        )

    def _process_termination_session_references(
        self,
        system: str,
        pid: int,
    ) -> tuple[_ProcessTerminationSessionReference, ...]:
        """Return the exact active-session pointers cleared by a termination."""

        references = []
        for session in self._active_sessions.find("system", system):
            referenced_fields = tuple(
                name for name in _SESSION_PROCESS_REFERENCE_FIELDS if getattr(session, name) == pid
            )
            if referenced_fields:
                references.append(
                    _ProcessTerminationSessionReference(
                        logon_id=session.logon_id,
                        object_id=session.ecar_object_id,
                        fields=referenced_fields,
                    )
                )
        return tuple(
            sorted(
                references,
                key=lambda reference: (
                    reference.logon_id,
                    reference.object_id,
                    reference.fields,
                ),
            )
        )

    def plan_process_termination_materialization(
        self,
        *,
        system: str,
        pid: int,
        end_time: datetime | None = None,
        parent_activity_time: datetime | None = None,
    ) -> ProcessTerminationMaterializationPlan:
        """Freeze one exact live process termination without publishing state."""

        with self._capability_minting_guard("plan_process_termination_materialization"):
            process = self.state.running_processes.get((system, pid))
            if process is None:
                raise StateError(
                    f"Cannot plan process termination: PID {pid} is not live on {system}"
                )
            identity = self._process_identity(process)
            effective_end = ensure_utc(end_time or self.state.current_time or process.start_time)
            normalized_parent_activity = (
                ensure_utc(parent_activity_time) if parent_activity_time is not None else None
            )
            parent_identity: ProcessIdentity | None = None
            if normalized_parent_activity is not None:
                if identity.parent_pid <= 0 or identity.parent_pid == identity.pid:
                    raise StateError(
                        "Process termination parent activity requires a distinct live parent"
                    )
                parent = self.state.running_processes.get((identity.hostname, identity.parent_pid))
                if parent is None:
                    raise StateError(
                        "Process termination parent activity requires an exact live parent: "
                        f"{identity.hostname} PID={identity.parent_pid}"
                    )
                parent_identity = self._process_identity(parent)
                if normalized_parent_activity < parent_identity.started_at:
                    raise StateError("Process termination parent activity precedes parent start")

            payload = _ProcessTerminationMaterializationPayload(
                end_time=effective_end,
                threads=self._process_termination_threads(identity.object_id),
                parent_identity=parent_identity,
                parent_activity_time=normalized_parent_activity,
                session_references=self._process_termination_session_references(system, pid),
            )
            expected_version = self._materialization_version
            plan = ProcessTerminationMaterializationPlan(
                _expected_version=expected_version,
                _identity=identity,
                _payload=payload,
                _integrity_token=_process_termination_materialization_integrity_token(
                    self._materialization_secret,
                    expected_version=expected_version,
                    identity=identity,
                    payload=payload,
                ),
            )
            self.validate_process_termination_materialization(plan)
            return plan

    def _plan_batch_process(
        self,
        builder: MaterializationBatchBuilder,
        *,
        system: str,
        parent_pid: int,
        image: str,
        command_line: str,
        username: str,
        integrity_level: str,
        os_category: str,
        logon_id: str,
        lifecycle_group_id: str,
        parent_lifecycle_group_id: str,
        concurrency_group_id: str,
        start_time: datetime | None,
        fixed_pid: int | None,
        require_session: bool,
        parent_activity_time: datetime | None,
        auth_session_id: int | None,
        auth_logon_type: int | None,
        parent_plan: ProcessMaterializationPlan | None,
        session_plan: SessionMaterializationPlan | None,
    ) -> ProcessMaterializationPlan:
        """Plan one batch process against exact canonical and prior staged owners."""

        with self._capability_minting_guard("MaterializationBatchBuilder.plan_process"):
            if (
                builder._manager is not self
                or builder._admission_epoch != self._prepared_state_admission_epoch
                or builder.expected_version != self._materialization_version
            ):
                raise StateError("Materialization batch became stale during process planning")
            if self.state.current_time != builder._expected_state_time:
                raise StateError("Materialization batch state-time fence changed during planning")
            raw_start = start_time or self.state.current_time
            if raw_start is None:
                raise StateError("Cannot plan process: current_time not set")
            effective_start = ensure_utc(raw_start)

            planned_parent: ProcessIdentity | None = None
            if parent_plan is not None:
                if parent_plan not in builder._processes:
                    raise StateError("Batch process parent must be an earlier planned member")
                planned_parent = parent_plan.identity
                if (
                    planned_parent.hostname != system
                    or planned_parent.pid != parent_pid
                    or planned_parent.started_at > effective_start
                ):
                    raise StateError("Batch process parent identity is not active for child start")
            elif parent_pid not in {0, 4} and not self.is_process_active_at(
                system,
                parent_pid,
                effective_start,
            ):
                raise StateError(
                    f"Cannot plan process: parent PID {parent_pid} does not exist on {system}"
                )

            if require_session and not logon_id:
                raise StateError("Session-owned process materialization requires a LogonID")
            if session_plan is None and builder._session is not None:
                if builder._session.identity.logon_id == logon_id:
                    session_plan = builder._session
            if session_plan is not None:
                if session_plan is not builder._session:
                    raise StateError("Batch process session must be the batch session member")
                planned_session = session_plan.identity
                if (
                    planned_session.hostname != system
                    or planned_session.logon_id != logon_id
                    or planned_session.started_at > effective_start
                ):
                    raise StateError("Batch process session identity is not active for start")
                owning_session = None
            else:
                planned_session = None
                owning_session = (
                    self.get_session_at(logon_id, effective_start) if logon_id else None
                )
            if require_session and logon_id and owning_session is None and planned_session is None:
                raise StateError(
                    f"Cannot plan process outside session {logon_id} at "
                    f"{effective_start.isoformat()}"
                )
            expected_session_id = (
                planned_session.session_id
                if planned_session is not None
                else owning_session.session_id
                if owning_session is not None
                else None
            )
            expected_logon_type = (
                session_plan.logon_type
                if planned_session is not None and session_plan is not None
                else owning_session.logon_type
                if owning_session is not None
                else None
            )
            if planned_session is not None or owning_session is not None:
                if auth_session_id is not None and auth_session_id != expected_session_id:
                    raise StateError("Process auth session ID disagrees with its owning session")
                if auth_logon_type is not None and auth_logon_type != expected_logon_type:
                    raise StateError("Process auth logon type disagrees with its owning session")
                auth_session_id = expected_session_id
                auth_logon_type = expected_logon_type

            allocator_new = False
            if system not in builder._pid_counters:
                counter, pid_rng, allocator_new = self._preview_pid_allocator(
                    system,
                    os_category,
                )
                builder._pid_counters[system] = counter
                builder._pid_rng_states[system] = pid_rng.getstate()
                builder._pid_os[system] = os_category
                if allocator_new:
                    builder._new_pid_namespaces.add(system)
            elif builder._pid_os[system] != os_category:
                raise StateError(
                    f"Cannot plan {os_category} process in {builder._pid_os[system]} "
                    f"PID namespace for {system}"
                )
            counter = builder._pid_counters[system]
            pid_rng = random.Random()
            pid_rng.setstate(builder._pid_rng_states[system])
            planned_pids = builder._planned_pids.setdefault(system, set())

            pid_epoch_patch: tuple[str, datetime] | None = None
            prefix_patch: tuple[str, tuple[int, ...]] | None = None
            linux_allocation: tuple[str, datetime, int] | None = None
            bucket_patch: tuple[tuple[str, datetime], int] | None = None
            fixed_patch: tuple[str, int] | None = None
            candidate_delta = 0
            allocation_delta = 0
            if fixed_pid is not None:
                if (
                    fixed_pid < 0
                    or fixed_pid in planned_pids
                    or self._pid_is_reserved(system, fixed_pid, effective_start, None)
                ):
                    raise StateError(
                        f"Cannot plan fixed process: PID {fixed_pid} is reserved on {system}"
                    )
                pid = fixed_pid
                logical_position = fixed_pid
                fixed_patch = (system, fixed_pid)
                if os_category == "linux":
                    linux_allocation = (system, effective_start, fixed_pid)
            elif os_category == "windows":
                pid, logical_position, counter, candidate_delta = self._preview_windows_pid(
                    system=system,
                    counter=counter,
                    rng=pid_rng,
                    current_time=effective_start,
                    extra_reserved_pids=planned_pids,
                )
                allocation_delta = 1
            else:
                epoch = builder._pid_epochs.get(system)
                if epoch is None:
                    epoch = self._system_boot_times.get(system) or self._pid_time_epochs.get(system)
                    if epoch is None:
                        epoch = effective_start
                        pid_epoch_patch = (system, epoch)
                    builder._pid_epochs[system] = ensure_utc(epoch)
                prefix = builder._pid_prefixes.get(system)
                if prefix is None:
                    prefix = self._linux_pid_weekly_churn_prefixes.get(system)
                    if prefix is None:
                        prefix = self._build_linux_pid_weekly_churn_prefix(system)
                        prefix_patch = (system, prefix)
                    builder._pid_prefixes[system] = prefix
                minimum_parent = None
                if planned_parent is not None:
                    minimum_parent = parent_plan._payload.pid_logical_position
                else:
                    parent = self.state.running_processes.get((system, parent_pid))
                    if (
                        parent is not None
                        and parent.start_time <= effective_start
                        and parent.pid > 1
                    ):
                        minimum_parent = parent.pid_logical_position
                ordinal_key = (system, effective_start)
                bucket_ordinal = builder._pid_bucket_offsets.get(
                    ordinal_key,
                    self._pid_bucket_offsets.get(ordinal_key, 0),
                )
                planned_allocations = tuple(builder._linux_allocations.get(system, ()))
                pid, logical_position, bucket_patch, candidate_delta = self._preview_linux_pid(
                    system=system,
                    counter=counter,
                    rng=pid_rng,
                    current_time=effective_start,
                    minimum_logical_exclusive=minimum_parent,
                    prefix=prefix,
                    epoch=ensure_utc(epoch),
                    bucket_ordinal=bucket_ordinal,
                    extra_allocations=planned_allocations,
                    extra_reserved_pids=planned_pids,
                )
                linux_allocation = (system, effective_start, logical_position)
                builder._linux_allocations.setdefault(system, []).append(
                    (effective_start, logical_position)
                )
                builder._pid_bucket_offsets[bucket_patch[0]] = bucket_patch[1]
                allocation_delta = 1

            object_id = stable_uuid(
                "registered-process" if fixed_pid is not None else "process",
                system,
                pid,
                parent_pid,
                image,
                command_line,
                username,
                effective_start.isoformat(),
                logon_id,
            )
            process_lifecycle_id = lifecycle_group_id or stable_uuid(
                "process-lifecycle",
                object_id,
            )
            if parent_lifecycle_group_id and parent_lifecycle_group_id != process_lifecycle_id:
                process_parent_group = parent_lifecycle_group_id
            elif planned_session is not None:
                process_parent_group = (
                    planned_session.parent_lifecycle_group_id
                    if planned_session.lifecycle_group_id == process_lifecycle_id
                    else planned_session.lifecycle_group_id
                )
            else:
                process_parent_group = self._process_parent_lifecycle_group(
                    process_lifecycle_id,
                    parent_lifecycle_group_id,
                    owning_session,
                )

            thread_os_category = builder._pid_os[system]
            primary_tid, thread_counter, thread_rng_state = self._preview_primary_thread(
                system=system,
                os_category=thread_os_category,
                object_id=object_id,
                pid=pid,
                counter_override=builder._thread_counters.get(system),
                rng_state_override=builder._thread_rng_states.get(system),
                extra_used_tids=builder._planned_tids.setdefault(system, set()),
            )
            thread_object_id = stable_uuid(
                "thread",
                system,
                object_id,
                pid,
                primary_tid,
                effective_start.isoformat(),
                "primary",
            )
            identity = ProcessIdentity(
                hostname=system,
                object_id=object_id,
                pid=pid,
                parent_pid=parent_pid,
                image=image,
                command_line=command_line,
                principal=username,
                logon_id=logon_id,
                started_at=effective_start,
                lifecycle_group_id=process_lifecycle_id,
                parent_lifecycle_group_id=process_parent_group,
                primary_thread=ThreadIdentity(
                    hostname=system,
                    process_object_id=object_id,
                    pid=pid,
                    tid=primary_tid,
                    object_id=thread_object_id,
                    started_at=effective_start,
                ),
            )
            payload = _ProcessMaterializationPayload(
                integrity_level=integrity_level,
                concurrency_group_id=concurrency_group_id,
                pid_logical_position=logical_position,
                state_time=effective_start,
                parent_activity_time=(
                    ensure_utc(parent_activity_time) if parent_activity_time is not None else None
                ),
                auth_session_id=auth_session_id,
                auth_logon_type=auth_logon_type,
                require_session=require_session,
            )
            allocator_patch = _ProcessAllocatorPatch(
                pid_counter=(system, counter),
                pid_os=(system, os_category)
                if system in builder._new_pid_namespaces
                and system not in builder._pid_namespace_patch_emitted
                else None,
                pid_rng_state=(system, pid_rng.getstate()),
                pid_epoch=pid_epoch_patch,
                pid_weekly_prefix=prefix_patch,
                linux_allocation=linux_allocation,
                pid_bucket_offset=bucket_patch,
                fixed_pid=fixed_patch,
                pid_allocation_count_delta=allocation_delta,
                pid_candidate_probe_delta=candidate_delta,
                thread_counter=thread_counter,
                thread_rng_state=thread_rng_state,
            )
            plan = ProcessMaterializationPlan(
                _expected_version=builder.expected_version,
                _identity=identity,
                _payload=payload,
                _allocator_patch=allocator_patch,
                _integrity_token=_materialization_integrity_token(
                    self._materialization_secret,
                    "process",
                    builder.expected_version,
                    identity,
                    payload,
                    allocator_patch,
                ),
            )
            builder._pid_counters[system] = counter
            builder._pid_rng_states[system] = pid_rng.getstate()
            if allocator_patch.pid_os is not None:
                builder._pid_namespace_patch_emitted.add(system)
            planned_pids.add(pid)
            builder._planned_tids.setdefault(system, set()).add(primary_tid)
            if thread_counter is not None:
                builder._thread_counters[system] = thread_counter[1]
            if thread_rng_state is not None:
                builder._thread_rng_states[system] = thread_rng_state[1]
            return plan

    def materialize_process(self, plan: ProcessMaterializationPlan) -> RunningProcess:
        """Commit one already-admitted process plan without sampling or domain validation."""

        admission_epoch = self._reject_mutation_during_action_cohort_claim("materialize_process")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "materialize_process",
                admitted_at=admission_epoch,
            )
            self.validate_process_materialization(plan)
            return self._commit_prevalidated_process_materialization(plan)

    def validate_process_termination_materialization(
        self,
        plan: ProcessTerminationMaterializationPlan,
    ) -> None:
        """Validate every fallible process-termination condition without mutation."""

        with self._lock:
            self._validate_process_termination_materialization_plan(plan)
            if plan.expected_version != self._materialization_version:
                raise StateError("Process termination materialization plan became stale")

            identity = plan.identity
            key = (identity.hostname, identity.pid)
            process = self.state.running_processes.get(key)
            if process is None:
                raise StateError(
                    "Process termination materialization target is no longer live: "
                    f"{identity.hostname} PID={identity.pid}"
                )
            if self._process_identity(process) != identity:
                raise StateError("Process termination materialization target identity drifted")
            if (
                process.last_activity_time is not None
                and process.last_activity_time > plan.end_time
            ):
                raise StateError("Process termination materialization precedes retained activity")
            if (
                self._process_object_ids.get(key) != identity.object_id
                or self._processes_by_object_id.get(identity.object_id) is not process
            ):
                raise StateError("Process termination materialization live indexes drifted")
            if self._active_pid_reservation_counts.get(identity.hostname, 0) <= 0:
                raise StateError("Process termination materialization PID reservation is absent")

            live_threads = self._process_termination_threads(identity.object_id)
            if live_threads != plan._payload.threads:
                raise StateError("Process termination materialization live threads drifted")

            parent_identity = plan._payload.parent_identity
            parent_activity_time = plan._payload.parent_activity_time
            if (parent_identity is None) != (parent_activity_time is None):
                raise StateError("Process termination parent activity patch is incomplete")
            if parent_identity is not None and parent_activity_time is not None:
                parent_key = (parent_identity.hostname, parent_identity.pid)
                parent = self.state.running_processes.get(parent_key)
                if (
                    parent is None
                    or parent_identity.hostname != identity.hostname
                    or parent_identity.pid != identity.parent_pid
                    or parent_identity.pid == identity.pid
                    or self._process_identity(parent) != parent_identity
                    or self._process_object_ids.get(parent_key) != parent_identity.object_id
                    or self._processes_by_object_id.get(parent_identity.object_id) is not parent
                ):
                    raise StateError(
                        "Process termination parent activity does not name the exact live parent"
                    )
                if parent_activity_time < parent_identity.started_at:
                    raise StateError("Process termination parent activity precedes parent start")

            if (
                self._process_termination_session_references(
                    identity.hostname,
                    identity.pid,
                )
                != plan._payload.session_references
            ):
                raise StateError("Process termination active-session references drifted")

    def _commit_prevalidated_process_termination_materialization(
        self,
        plan: ProcessTerminationMaterializationPlan,
        *,
        advance_version: bool = True,
        prepared: _PreparedActionCohortProcessTermination | None = None,
        emit_log: bool = True,
        enforce_retention: bool = True,
    ) -> ProcessIdentity:
        """Perform primitive process-termination writes after guarded validation."""

        identity = plan.identity
        payload = plan._payload
        key = prepared.process_key if prepared is not None else (identity.hostname, identity.pid)
        process = self.state.running_processes[key]

        parent_identity = payload.parent_identity
        parent_activity_time = payload.parent_activity_time
        if parent_identity is not None and parent_activity_time is not None:
            parent = self._processes_by_object_id[parent_identity.object_id]
            if (
                parent.last_activity_time is None
                or parent.last_activity_time < parent_activity_time
            ):
                parent.last_activity_time = parent_activity_time

        thread_deadline = (
            prepared.thread_deadline
            if prepared is not None
            else (payload.end_time + _ENDED_IDENTITY_RETENTION).timestamp()
        )
        thread_keys = (
            prepared.thread_keys
            if prepared is not None
            else tuple(
                (thread.hostname, thread.process_object_id, thread.tid)
                for thread in payload.threads
            )
        )
        for thread_key in thread_keys:
            thread = self.state.running_threads.pop(thread_key)
            thread.end_time = payload.end_time
            self._ended_threads.set(thread_key, thread, thread_deadline)

        del self.state.running_processes[key]
        remaining = self._active_pid_reservation_counts[identity.hostname] - 1
        if remaining > 0:
            self._active_pid_reservation_counts[identity.hostname] = remaining
        else:
            self._active_pid_reservation_counts.pop(identity.hostname)
        process.end_time = payload.end_time
        self._process_object_ids.pop(key)
        self._processes_by_object_id.pop(identity.object_id)
        process_deadline = (
            prepared.process_deadline
            if prepared is not None
            else (payload.end_time + _ENDED_IDENTITY_RETENTION).timestamp()
        )
        self._ended_processes_by_key.set(key, process, process_deadline)
        self._ended_processes_by_object_id.set(
            identity.object_id,
            process,
            process_deadline,
        )

        for reference in payload.session_references:
            session = self.state.active_sessions[reference.logon_id]
            for name in reference.fields:
                setattr(session, name, None)

        if enforce_retention:
            self._trim_retained_thread_identities()
            self._trim_retained_process_identities()
        if advance_version:
            self._materialization_version += 1
        if emit_log:
            logger.debug("Ended process %s on %s", identity.pid, identity.hostname)
        return identity

    def materialize_process_termination(
        self,
        plan: ProcessTerminationMaterializationPlan,
    ) -> ProcessIdentity:
        """Commit one exact process termination and return its receipt-ready identity."""

        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "materialize_process_termination"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "materialize_process_termination",
                admitted_at=admission_epoch,
            )
            with self.process_termination_materialization_guard(plan):
                return self._commit_prevalidated_process_termination_materialization(plan)

    @staticmethod
    def _action_session_identity(
        target: SessionMaterializationPlan | SessionIdentity,
    ) -> SessionIdentity:
        return target.identity if type(target) is SessionMaterializationPlan else target

    @staticmethod
    def _action_process_identity(
        target: ProcessMaterializationPlan
        | ProcessTerminationMaterializationPlan
        | ProcessIdentity,
    ) -> ProcessIdentity:
        return (
            target.identity
            if type(target) in {ProcessMaterializationPlan, ProcessTerminationMaterializationPlan}
            else target
        )

    def _validate_action_live_session_identity(self, identity: SessionIdentity) -> ActiveSession:
        session = self._active_sessions.get(self._resolve_logon_id(identity.logon_id))
        if session is None or self.get_session_identity(session.logon_id) != identity:
            raise StateError("Action cohort live session identity is absent or drifted")
        return session

    def _validate_action_live_process_identity(self, identity: ProcessIdentity) -> RunningProcess:
        process = self._processes_by_object_id.get(identity.object_id)
        if (
            process is None
            or self.state.running_processes.get((identity.hostname, identity.pid)) is not process
            or self._process_identity(process) != identity
        ):
            raise StateError("Action cohort live process identity is absent or drifted")
        return process

    def _validate_action_cohort_session_metadata_transition(
        self,
        patch: ActionCohortSessionMetadataPatch,
        *,
        sessions: dict[str, SessionMaterializationPlan],
    ) -> SessionIdentity:
        identity = self._action_session_identity(patch.target)
        if type(patch.target) is SessionMaterializationPlan:
            if sessions.get(identity.object_id) is not patch.target:
                raise StateError("Action cohort metadata replaced its staged session capability")
            current = ActionCohortSessionMetadataState()
        else:
            self._validate_action_live_session_identity(identity)
            current = self._action_cohort_session_metadata(identity)
        if patch.before != current:
            raise StateError("Action cohort session metadata before-state drifted")
        after = patch.after
        if after.source_ready_time is not None and after.source_ready_time < identity.started_at:
            raise StateError("Action cohort session readiness precedes session start")
        if after.network_close_time is not None and after.network_close_time < identity.started_at:
            raise StateError("Action cohort session network close precedes session start")
        if (
            after.source_ready_time is not None
            and after.network_close_time is not None
            and after.source_ready_time > after.network_close_time
        ):
            raise StateError("Action cohort session readiness follows network close")
        end_plan = after.end_plan
        if end_plan is not None and ensure_utc(end_plan.canonical_end) < identity.started_at:
            raise StateError("Action cohort session end plan precedes session start")
        if (
            current.end_plan is not None
            and current.end_plan.is_hard_deadline
            and current.end_plan != end_plan
        ):
            raise StateError("Action cohort cannot replace a hard session end plan")
        return identity

    def _validate_action_cohort_live_session_process_roles_transition(
        self,
        patch: ActionCohortLiveSessionProcessRolesPatch,
        *,
        processes: dict[str, ProcessMaterializationPlan],
        processes_by_pid: dict[tuple[str, int], ProcessMaterializationPlan],
        process_indexes: dict[int, int],
        process_pid_namespaces: dict[int, str],
    ) -> SessionIdentity:
        """Validate one closed live Windows desktop role transition."""

        target = patch.target
        session = self._validate_action_live_session_identity(target)
        if not windows_logon_can_own_desktop(session.logon_type) or session.session_kind in {
            "network",
            "new_credentials",
            "service",
        }:
            raise StateError("Action cohort live Windows shell requires a desktop-owning session")
        current = self._action_cohort_live_session_process_roles(target)
        if patch.before != current:
            raise StateError("Action cohort live-session process-role before-state drifted")
        if patch.before.explorer_pid is not None:
            raise StateError("Action cohort cannot overwrite a live session Explorer role")

        def _require_staged(
            plan: ProcessMaterializationPlan | None,
            role: str,
        ) -> ProcessMaterializationPlan:
            if plan is None or processes.get(plan.identity.object_id) is not plan:
                raise StateError(
                    f"Action cohort live-session {role} replaced its staged process capability"
                )
            return plan

        def _require_staged_windows_pid(
            plan: ProcessMaterializationPlan,
            role: str,
        ) -> None:
            identity = plan.identity
            if (
                process_pid_namespaces.get(id(plan)) != "windows"
                or not self._action_cohort_is_valid_windows_pid(identity.pid)
                or identity.pid == identity.parent_pid
            ):
                raise StateError(f"Action cohort live-session {role} requires an exact Windows PID")

        def _require_target_valid_at(start_time: datetime, role: str) -> None:
            if self.get_session_at(target.logon_id, start_time) is not session:
                raise StateError(f"Action cohort live-session target is not valid at {role} start")

        explorer = _require_staged(patch.explorer_plan, "Explorer")
        explorer_identity = explorer.identity
        if (
            explorer_identity.hostname != target.hostname
            or explorer_identity.logon_id != target.logon_id
            or explorer_identity.principal != target.principal
            or self._action_cohort_windows_process_basename(explorer) != "explorer.exe"
            or explorer.integrity_level != "Medium"
        ):
            raise StateError("Action cohort live-session Explorer identity is incompatible")
        _require_staged_windows_pid(explorer, "Explorer")
        initial_explorer_pid = patch.before.initial_explorer_pid
        if initial_explorer_pid is not None and self.is_process_active_at(
            target.hostname,
            initial_explorer_pid,
            explorer_identity.started_at,
        ):
            raise StateError(
                "Action cohort cannot replace an initial Explorer active at replacement start"
            )

        userinit = processes_by_pid.get((explorer_identity.hostname, explorer_identity.parent_pid))
        if (
            userinit is None
            or process_indexes[id(userinit)] >= process_indexes[id(explorer)]
            or userinit.identity.logon_id != target.logon_id
            or userinit.identity.principal != target.principal
            or self._action_cohort_windows_process_basename(userinit) != "userinit.exe"
            or userinit.integrity_level != "Medium"
        ):
            raise StateError(
                "Action cohort live-session Explorer requires an earlier staged userinit"
            )
        _require_staged_windows_pid(userinit, "userinit")

        winlogon = patch.winlogon_plan
        process_tree_root = patch.process_tree_root_plan
        if (winlogon is None) != (process_tree_root is None):
            raise StateError("Action cohort live-session winlogon and process-tree root drifted")
        if winlogon is not None:
            staged_winlogon = _require_staged(winlogon, "winlogon")
            staged_root = _require_staged(process_tree_root, "process-tree root")
            if staged_root is not staged_winlogon:
                raise StateError(
                    "Action cohort live-session process-tree root is not its staged winlogon"
                )
            winlogon_identity = staged_winlogon.identity
            if (
                patch.before.session_winlogon_pid is not None
                or patch.before.process_tree_root is not None
            ):
                raise StateError("Action cohort cannot overwrite a live session winlogon role")
            _require_staged_windows_pid(staged_winlogon, "winlogon")
            if (
                winlogon_identity.hostname != target.hostname
                or winlogon_identity.logon_id.casefold() != "0x3e7"
                or winlogon_identity.principal.casefold() != "system"
                or self._action_cohort_windows_process_basename(staged_winlogon) != "winlogon.exe"
                or staged_winlogon.integrity_level != "System"
                or userinit.identity.parent_pid != winlogon_identity.pid
                or process_indexes[id(staged_winlogon)] >= process_indexes[id(userinit)]
            ):
                raise StateError("Action cohort live-session winlogon identity is incompatible")
            expected_winlogon_pid = winlogon_identity.pid
            expected_root_pid = winlogon_identity.pid
            winlogon_start_time = winlogon_identity.started_at
        else:
            existing_winlogon_pid = patch.before.session_winlogon_pid
            if existing_winlogon_pid is None:
                raise StateError(
                    "Action cohort live-session shell requires a live or staged winlogon"
                )
            live_winlogon = self.state.running_processes.get(
                (target.hostname, existing_winlogon_pid)
            )
            if (
                live_winlogon is None
                or self._pid_os.get(target.hostname) != "windows"
                or not self._action_cohort_is_valid_windows_pid(existing_winlogon_pid)
                or live_winlogon.pid == live_winlogon.parent_pid
                or live_winlogon.logon_id.casefold() != "0x3e7"
                or live_winlogon.username.casefold() != "system"
                or live_winlogon.image.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
                != "winlogon.exe"
                or userinit.identity.parent_pid != existing_winlogon_pid
                or ensure_utc(live_winlogon.start_time) > userinit.identity.started_at
            ):
                raise StateError("Action cohort live-session retained winlogon is incompatible")
            expected_winlogon_pid = existing_winlogon_pid
            expected_root_pid = patch.before.process_tree_root
            winlogon_start_time = ensure_utc(live_winlogon.start_time)

        _require_target_valid_at(winlogon_start_time, "winlogon")
        _require_target_valid_at(userinit.identity.started_at, "userinit")
        _require_target_valid_at(explorer_identity.started_at, "Explorer")
        if (
            userinit.auth_session_id != target.session_id
            or userinit.auth_logon_type != session.logon_type
        ):
            raise StateError("Action cohort live-session userinit auth owner is incompatible")
        if (
            explorer.auth_session_id != target.session_id
            or explorer.auth_logon_type != session.logon_type
        ):
            raise StateError("Action cohort live-session Explorer auth owner is incompatible")

        expected_after = replace(
            patch.before,
            session_winlogon_pid=expected_winlogon_pid,
            explorer_pid=explorer_identity.pid,
            initial_explorer_pid=(
                explorer_identity.pid
                if patch.before.initial_explorer_pid is None
                else patch.before.initial_explorer_pid
            ),
            process_tree_root=expected_root_pid,
            windows_shell_bootstrapped=True,
        )
        if patch.after != expected_after:
            raise StateError("Action cohort live-session process-role after-state drifted")
        return target

    def validate_action_cohort_materialization(
        self,
        plan: ActionCohortMaterializationPlan,
    ) -> None:
        """Validate every fallible action-cohort condition without mutation."""

        with self._lock:
            self._validate_action_cohort_plan_integrity(plan)
            if plan.expected_version != self._materialization_version:
                raise StateError("Action cohort materialization plan is stale")
            if self.state.current_time != plan._expected_state_time:
                raise StateError("Action cohort materialization State time changed")

            sessions: dict[str, SessionMaterializationPlan] = {}
            session_logons: set[str] = set()
            host_session_ids: set[tuple[str, int]] = set()
            for session in plan.sessions:
                identity = session.identity
                if identity.object_id in sessions or identity.logon_id in session_logons:
                    raise StateError("Action cohort repeats a session start identity")
                if (
                    identity.logon_id in self._active_sessions
                    or identity.logon_id in self._ended_sessions
                ):
                    raise StateError(
                        f"Action cohort session LogonID is already retained: {identity.logon_id}"
                    )
                if identity.session_id > 0:
                    session_id_key = (identity.hostname, identity.session_id)
                    if session_id_key in host_session_ids or any(
                        existing.session_id == identity.session_id
                        for existing in self._active_sessions.find("system", identity.hostname)
                    ):
                        raise StateError("Action cohort repeats a live host session ID")
                    host_session_ids.add(session_id_key)
                sessions[identity.object_id] = session
                session_logons.add(identity.logon_id)

            process_indexes = {id(process): index for index, process in enumerate(plan.processes)}
            processes: dict[str, ProcessMaterializationPlan] = {}
            processes_by_pid: dict[tuple[str, int], ProcessMaterializationPlan] = {}
            thread_keys: set[tuple[str, str, int]] = set()
            sessions_by_host_logon = {
                (session.identity.hostname, session.identity.logon_id): session
                for session in plan.sessions
            }
            for index, process in enumerate(plan.processes):
                identity = process.identity
                primary_thread = identity.primary_thread
                if primary_thread is None:
                    raise StateError("Action cohort process start has no primary thread")
                key = (identity.hostname, identity.pid)
                thread_key = (
                    primary_thread.hostname,
                    primary_thread.process_object_id,
                    primary_thread.tid,
                )
                if (
                    identity.object_id in processes
                    or key in processes_by_pid
                    or key in self.state.running_processes
                    or identity.object_id in self._processes_by_object_id
                    or thread_key in thread_keys
                    or thread_key in self.state.running_threads
                ):
                    raise StateError("Action cohort repeats a live process or thread identity")
                if (
                    primary_thread.hostname != identity.hostname
                    or primary_thread.process_object_id != identity.object_id
                    or primary_thread.pid != identity.pid
                    or primary_thread.started_at != identity.started_at
                ):
                    raise StateError("Action cohort primary thread disagrees with its process")
                if identity.parent_pid not in {0, 4}:
                    parent = processes_by_pid.get((identity.hostname, identity.parent_pid))
                    if parent is not None and process_indexes[id(parent)] >= index:
                        raise StateError("Action cohort process parent is not ordered first")
                    if parent is None and not self.is_process_active_at(
                        identity.hostname,
                        identity.parent_pid,
                        identity.started_at,
                    ):
                        raise StateError("Action cohort process parent is not active at start")
                    if parent is not None and parent.identity.started_at > identity.started_at:
                        raise StateError("Action cohort process parent starts after its child")
                staged_session = sessions_by_host_logon.get((identity.hostname, identity.logon_id))
                live_session = (
                    self.get_session_at(identity.logon_id, identity.started_at)
                    if identity.logon_id and staged_session is None
                    else None
                )
                if (
                    process._payload.require_session
                    and staged_session is None
                    and live_session is None
                ):
                    raise StateError("Action cohort process has no exact owning session")
                expected_session_id = (
                    staged_session.identity.session_id
                    if staged_session is not None
                    else live_session.session_id
                    if live_session is not None
                    else None
                )
                expected_logon_type = (
                    staged_session.logon_type
                    if staged_session is not None
                    else live_session.logon_type
                    if live_session is not None
                    else None
                )
                if (staged_session is not None or live_session is not None) and (
                    process.auth_session_id != expected_session_id
                    or process.auth_logon_type != expected_logon_type
                ):
                    raise StateError("Action cohort process auth identity drifted")
                if process._payload.parent_activity_time is not None:
                    if identity.parent_pid in {0, 4}:
                        raise StateError("Action cohort process start has no activity parent")
                    parent_identity = (
                        processes_by_pid[(identity.hostname, identity.parent_pid)].identity
                        if (identity.hostname, identity.parent_pid) in processes_by_pid
                        else self.get_process_identity(identity.hostname, identity.parent_pid)
                    )
                    if (
                        parent_identity is None
                        or process._payload.parent_activity_time < parent_identity.started_at
                    ):
                        raise StateError("Action cohort process parent activity is invalid")
                processes[identity.object_id] = process
                processes_by_pid[key] = process
                thread_keys.add(thread_key)

            process_pid_namespaces = self._action_cohort_process_pid_namespaces(plan.processes)
            if len(plan._session_process_links) != len(plan.sessions):
                raise StateError("Action cohort session process links are incomplete")
            role_plan_owners: dict[int, str] = {}
            role_pid_owners: dict[tuple[str, int], str] = {}

            def _claim_staged_role_owner(
                process: ProcessMaterializationPlan,
                owner_object_id: str,
            ) -> None:
                plan_owner = role_plan_owners.get(id(process))
                pid_key = (process.identity.hostname, process.identity.pid)
                pid_owner = role_pid_owners.get(pid_key)
                if (
                    plan_owner is not None
                    and plan_owner != owner_object_id
                    or pid_owner is not None
                    and pid_owner != owner_object_id
                ):
                    raise StateError(
                        "Action cohort staged process role is bound to multiple sessions"
                    )
                role_plan_owners[id(process)] = owner_object_id
                role_pid_owners[pid_key] = owner_object_id

            for expected_index, session_links in enumerate(plan._session_process_links):
                if session_links.session_index != expected_index:
                    raise StateError("Action cohort session process link order drifted")
                session = plan.sessions[expected_index]
                for role in (
                    "transport",
                    "shell",
                    "user_manager",
                    "winlogon",
                    "explorer",
                    "process_tree_root",
                ):
                    process_index = getattr(session_links.links, role)
                    if process_index < 0:
                        continue
                    if process_index >= len(plan.processes):
                        raise StateError("Action cohort session role points outside the cohort")
                    process_identity = plan.processes[process_index].identity
                    if (
                        role != "transport"
                        and process_identity.hostname != session.identity.hostname
                    ):
                        raise StateError("Action cohort session role crosses host boundaries")
                    if role in {"shell", "user_manager", "explorer"} and (
                        process_identity.logon_id != session.identity.logon_id
                    ):
                        raise StateError("Action cohort session role crosses session boundaries")
                    _claim_staged_role_owner(
                        plan.processes[process_index],
                        session.identity.object_id,
                    )

            live_role_by_session: dict[str, ActionCohortLiveSessionProcessRolesPatch] = {}
            live_role_process_owners: dict[str, str] = {}
            live_role_process_references: set[tuple[str, int]] = set()
            for patch in plan._live_session_process_roles:
                identity = self._validate_action_cohort_live_session_process_roles_transition(
                    patch,
                    processes=processes,
                    processes_by_pid=processes_by_pid,
                    process_indexes=process_indexes,
                    process_pid_namespaces=process_pid_namespaces,
                )
                if identity.object_id in live_role_by_session:
                    raise StateError("Action cohort repeats a live-session process-role target")
                live_role_by_session[identity.object_id] = patch
                role_plans = {
                    role.identity.object_id: role
                    for role in (
                        patch.winlogon_plan,
                        patch.explorer_plan,
                        patch.process_tree_root_plan,
                    )
                    if role is not None
                }
                for object_id, role_plan in role_plans.items():
                    _claim_staged_role_owner(role_plan, identity.object_id)
                    live_role_process_owners[object_id] = identity.object_id
                for field_name in _SESSION_PROCESS_REFERENCE_FIELDS:
                    pid = getattr(patch.after, field_name)
                    if pid is not None:
                        pid_key = (identity.hostname, pid)
                        pid_owner = role_pid_owners.get(pid_key)
                        if pid_owner is not None and pid_owner != identity.object_id:
                            raise StateError(
                                "Action cohort process-role PID is bound to multiple sessions"
                            )
                        role_pid_owners[pid_key] = identity.object_id
                        live_role_process_references.add(pid_key)

            metadata_by_session: dict[str, ActionCohortSessionMetadataPatch] = {}
            for patch in plan._session_metadata:
                identity = self._validate_action_cohort_session_metadata_transition(
                    patch,
                    sessions=sessions,
                )
                if identity.object_id in metadata_by_session:
                    raise StateError("Action cohort repeats a session metadata target")
                metadata_by_session[identity.object_id] = patch

            process_activity: dict[str, ActionCohortProcessActivityPatch] = {}
            for patch in plan._process_activity:
                identity = self._action_process_identity(patch.target)
                if type(patch.target) is ProcessMaterializationPlan:
                    if processes.get(identity.object_id) is not patch.target:
                        raise StateError("Action cohort process activity replaced its staged plan")
                else:
                    self._validate_action_live_process_identity(identity)
                if identity.object_id in process_activity:
                    raise StateError("Action cohort repeats a process activity target")
                if patch.activity_time < identity.started_at:
                    raise StateError("Action cohort process activity precedes process start")
                process_activity[identity.object_id] = patch

            session_activity: dict[str, ActionCohortSessionActivityPatch] = {}
            for patch in plan._session_activity:
                identity = self._action_session_identity(patch.target)
                if type(patch.target) is SessionMaterializationPlan:
                    if sessions.get(identity.object_id) is not patch.target:
                        raise StateError("Action cohort session activity replaced its staged plan")
                else:
                    self._validate_action_live_session_identity(identity)
                if identity.object_id in session_activity:
                    raise StateError("Action cohort repeats a session activity target")
                if patch.activity_time < identity.started_at:
                    raise StateError("Action cohort session activity precedes session start")
                session_activity[identity.object_id] = patch

            termination_by_process: dict[str, tuple[int, ActionCohortProcessTermination]] = {}
            for index, termination in enumerate(plan.process_terminations):
                identity = termination.identity
                if identity.object_id in termination_by_process:
                    raise StateError("Action cohort repeats a process terminalization")
                if termination.end_time < identity.started_at:
                    raise StateError("Action cohort process close precedes process start")
                if type(termination.target) is ProcessTerminationMaterializationPlan:
                    self.validate_process_termination_materialization(termination.target)
                else:
                    if processes.get(identity.object_id) is not termination.target:
                        raise StateError("Action cohort staged close replaced its process start")
                    expected_references = self._action_cohort_staged_session_references(
                        process_index=process_indexes[id(termination.target)],
                        sessions=plan.sessions,
                        links=plan._session_process_links,
                    )
                    if termination.staged_session_references != expected_references:
                        raise StateError("Action cohort staged process session references drifted")
                if termination.parent_activity is not None:
                    parent_identity = self._action_process_identity(
                        termination.parent_activity.target
                    )
                    if (
                        parent_identity.hostname != identity.hostname
                        or parent_identity.pid != identity.parent_pid
                        or termination.parent_activity.activity_time < parent_identity.started_at
                        or termination.parent_activity.activity_time > termination.end_time
                    ):
                        raise StateError("Action cohort process-close parent activity is invalid")
                termination_by_process[identity.object_id] = (index, termination)

            for object_id, (index, termination) in termination_by_process.items():
                identity = termination.identity
                parent = processes_by_pid.get((identity.hostname, identity.parent_pid))
                if parent is None:
                    live_parent = self.state.running_processes.get(
                        (identity.hostname, identity.parent_pid)
                    )
                    parent_object_id = live_parent.ecar_object_id if live_parent is not None else ""
                else:
                    parent_object_id = parent.identity.object_id
                parent_close = termination_by_process.get(parent_object_id)
                if parent_close is not None:
                    parent_index, parent_termination = parent_close
                    if index >= parent_index:
                        raise StateError("Action cohort process closes are not child-before-parent")
                    if termination.end_time > parent_termination.end_time:
                        raise StateError("Action cohort child process outlives its closing parent")
                activity = process_activity.get(object_id)
                if activity is not None and activity.activity_time > termination.end_time:
                    raise StateError("Action cohort process activity follows process close")
                if object_id in live_role_process_owners:
                    raise StateError("Action cohort cannot close a staged live-session shell role")
                if (identity.hostname, identity.pid) in live_role_process_references:
                    raise StateError("Action cohort cannot close a live-session process role")

            for process in plan.processes:
                identity = process.identity
                parent = processes_by_pid.get((identity.hostname, identity.parent_pid))
                if parent is not None:
                    parent_close = termination_by_process.get(parent.identity.object_id)
                    if parent_close is not None and parent_close[1].end_time < identity.started_at:
                        raise StateError(
                            "Action cohort staged parent closes before its child starts"
                        )
                parent_activity_time = process._payload.parent_activity_time
                if parent_activity_time is None or identity.parent_pid in {0, 4}:
                    continue
                parent_identity = (
                    parent.identity
                    if parent is not None
                    else self.get_process_identity(identity.hostname, identity.parent_pid)
                )
                if parent_identity is None:
                    raise StateError("Action cohort process activity parent disappeared")
                parent_close = termination_by_process.get(parent_identity.object_id)
                if parent_close is not None and parent_activity_time > parent_close[1].end_time:
                    raise StateError("Action cohort parent activity follows parent close")

            terminalization_by_session: dict[str, ActionCohortSessionTerminalization] = {}
            for terminalization in plan.session_terminalizations:
                identity = terminalization.identity
                if identity.object_id in terminalization_by_session:
                    raise StateError("Action cohort repeats a session terminalization")
                if identity.object_id in live_role_by_session:
                    raise StateError(
                        "Action cohort cannot terminalize a live session receiving shell roles"
                    )
                if type(terminalization.target) is SessionMaterializationPlan:
                    if sessions.get(identity.object_id) is not terminalization.target:
                        raise StateError("Action cohort staged session close replaced its start")
                    current_session = None
                else:
                    current_session = self._validate_action_live_session_identity(identity)
                if terminalization.end_time < identity.started_at:
                    raise StateError("Action cohort session close precedes session start")
                metadata = metadata_by_session.get(identity.object_id)
                metadata_state = (
                    metadata.after
                    if metadata is not None
                    else self._action_cohort_session_metadata(terminalization.target)
                )
                end_plan = metadata_state.end_plan
                if end_plan is not None:
                    canonical_end = ensure_utc(end_plan.canonical_end)
                    if end_plan.is_authoritative and terminalization.end_time != canonical_end:
                        raise StateError("Action cohort violates an authoritative session end")
                    if end_plan.is_hard_deadline and terminalization.end_time > canonical_end:
                        raise StateError("Action cohort session close exceeds its hard deadline")
                if any(
                    timestamp is not None and timestamp > terminalization.end_time
                    for timestamp in (
                        metadata_state.source_ready_time,
                        metadata_state.network_close_time,
                    )
                ):
                    raise StateError("Action cohort session metadata follows session close")
                activity = session_activity.get(identity.object_id)
                if activity is not None and activity.activity_time > terminalization.end_time:
                    raise StateError("Action cohort session activity follows session close")
                if (
                    current_session is not None
                    and current_session.last_activity_time is not None
                    and current_session.last_activity_time > terminalization.end_time
                ):
                    raise StateError("Action cohort session close precedes retained activity")
                terminalization_by_session[identity.object_id] = terminalization

                owned_processes = [
                    self._process_identity(process)
                    for process in self._running_processes.find("logon_id", identity.logon_id)
                    if process.system == identity.hostname
                ]
                owned_processes.extend(
                    process.identity
                    for process in plan.processes
                    if process.identity.hostname == identity.hostname
                    and process.identity.logon_id == identity.logon_id
                )
                for owned in owned_processes:
                    close = termination_by_process.get(owned.object_id)
                    if close is None or close[1].end_time > terminalization.end_time:
                        raise StateError(
                            "Action cohort terminalized session retains a live owned process"
                        )

            member_frontiers = [
                value
                for value in (
                    plan._expected_state_time,
                    *(session.identity.started_at for session in plan.sessions),
                    *(process.identity.started_at for process in plan.processes),
                    *(process._payload.parent_activity_time for process in plan.processes),
                    *(patch.after.source_ready_time for patch in plan._session_metadata),
                    *(patch.after.network_close_time for patch in plan._session_metadata),
                    *(patch.activity_time for patch in plan._process_activity),
                    *(patch.activity_time for patch in plan._session_activity),
                    *(termination.end_time for termination in plan.process_terminations),
                    *(
                        terminalization.end_time
                        for terminalization in plan.session_terminalizations
                    ),
                )
                if value is not None
            ]
            if not member_frontiers or plan.final_state_time != max(member_frontiers):
                raise StateError("Action cohort final State time drifted from its member frontier")

    @staticmethod
    def _prepare_action_cohort_session_start(
        plan: SessionMaterializationPlan,
    ) -> _PreparedActionCohortSessionStart:
        """Construct one runtime session row and allocator defaults before claim."""

        identity = plan.identity
        payload = plan._payload
        session = ActiveSession(
            logon_id=identity.logon_id,
            username=identity.principal,
            system=identity.hostname,
            logon_type=payload.logon_type,
            start_time=identity.started_at,
            source_ip=payload.source_ip,
            session_id=identity.session_id,
            source_port=payload.source_port,
            session_kind=identity.session_kind,
            transport_pid=payload.transport_pid,
            ecar_object_id=identity.object_id,
            logon_guid=identity.logon_guid,
            lifecycle_group_id=identity.lifecycle_group_id,
            parent_lifecycle_group_id=identity.parent_lifecycle_group_id,
            auth_protocol=payload.auth_protocol,
            smb_principal=payload.smb_principal,
            account_scope=payload.account_scope,
            auth_session_ref=payload.auth_session_ref,
            effective_uid=payload.effective_uid,
            effective_gid=payload.effective_gid,
            network_close_time=payload.network_close_time,
            source_ready_time=payload.source_ready_time,
            closure_owned_by_bundle=payload.closure_owned_by_bundle,
            end_plan=payload.end_plan,
        )
        linux_logind = plan._allocator_patch.linux_logind
        return _PreparedActionCohortSessionStart(
            plan=plan,
            session=session,
            linux_logind_used_ids_default=set() if linux_logind is not None else None,
            linux_logind_allocations_default=(
                TemporalAllocationIndex() if linux_logind is not None else None
            ),
        )

    @staticmethod
    def _prepare_action_cohort_process_start(
        plan: ProcessMaterializationPlan,
    ) -> _PreparedActionCohortProcessStart:
        """Construct one runtime process/thread row and allocator defaults before claim."""

        identity = plan.identity
        payload = plan._payload
        primary_thread = identity.primary_thread
        assert primary_thread is not None
        process = RunningProcess(
            pid=identity.pid,
            parent_pid=identity.parent_pid,
            image=identity.image,
            command_line=identity.command_line,
            username=identity.principal,
            system=identity.hostname,
            start_time=identity.started_at,
            integrity_level=payload.integrity_level,
            logon_id=identity.logon_id,
            token_logon_id=identity.logon_id,
            auth_session_id=payload.auth_session_id,
            auth_logon_type=payload.auth_logon_type,
            ecar_object_id=identity.object_id,
            primary_tid=primary_thread.tid,
            lifecycle_group_id=identity.lifecycle_group_id,
            parent_lifecycle_group_id=identity.parent_lifecycle_group_id,
            concurrency_group_id=payload.concurrency_group_id,
            pid_logical_position=payload.pid_logical_position,
        )
        thread = RunningThread(
            hostname=primary_thread.hostname,
            process_object_id=primary_thread.process_object_id,
            pid=primary_thread.pid,
            tid=primary_thread.tid,
            object_id=primary_thread.object_id,
            start_time=primary_thread.started_at,
            kind=primary_thread.kind,
        )
        patch = plan._allocator_patch
        pid_rng: random.Random | None = None
        if patch.pid_rng_state is not None:
            pid_rng = random.Random()
            pid_rng.setstate(patch.pid_rng_state[1])
        thread_rng: random.Random | None = None
        if patch.thread_rng_state is not None:
            thread_rng = random.Random()
            thread_rng.setstate(patch.thread_rng_state[1])
        return _PreparedActionCohortProcessStart(
            plan=plan,
            process=process,
            thread=thread,
            pid_rng_replacement=pid_rng,
            linux_pid_allocations_default=(
                TemporalAllocationIndex() if patch.linux_allocation is not None else None
            ),
            fixed_pid_reservations_default=(set() if patch.fixed_pid is not None else None),
            thread_rng_replacement=thread_rng,
        )

    @staticmethod
    def _prepare_action_cohort_process_termination(
        termination: ActionCohortProcessTermination,
    ) -> _PreparedActionCohortProcessTermination:
        """Construct exact process-close primitives and deadlines before claim."""

        target = termination.target
        if type(target) is ProcessTerminationMaterializationPlan:
            primitive = target
        else:
            assert type(target) is ProcessMaterializationPlan
            identity = target.identity
            parent_activity = termination.parent_activity
            parent_identity = (
                StateManager._action_process_identity(parent_activity.target)
                if parent_activity is not None
                else None
            )
            primary_thread = identity.primary_thread
            assert primary_thread is not None
            payload = _ProcessTerminationMaterializationPayload(
                end_time=termination.end_time,
                threads=(primary_thread,),
                parent_identity=parent_identity,
                parent_activity_time=(
                    parent_activity.activity_time if parent_activity is not None else None
                ),
                session_references=termination.staged_session_references,
            )
            primitive = ProcessTerminationMaterializationPlan(
                _expected_version=target.expected_version,
                _identity=identity,
                _payload=payload,
                _integrity_token="",
            )
        identity = primitive.identity
        deadline = (primitive.end_time + _ENDED_IDENTITY_RETENTION).timestamp()
        return _PreparedActionCohortProcessTermination(
            plan=primitive,
            process_key=(identity.hostname, identity.pid),
            thread_keys=tuple(
                (thread.hostname, thread.process_object_id, thread.tid)
                for thread in primitive._payload.threads
            ),
            thread_deadline=deadline,
            process_deadline=deadline,
        )

    def _prepare_action_cohort_rollback_journal(
        self,
        plan: ActionCohortMaterializationPlan | _MaterializationBatchRollbackProjection,
        *,
        sessions: tuple[_PreparedActionCohortSessionStart, ...],
        processes: tuple[_PreparedActionCohortProcessStart, ...],
        process_terminations: tuple[_PreparedActionCohortProcessTermination, ...],
        session_terminalizations: tuple[_PreparedActionCohortSessionTerminalization, ...],
        boot_times: tuple[tuple[str, datetime], ...] = (),
    ) -> _ActionCohortRollbackJournal:
        """Capture only cohort-addressable keys, members, and runtime rows."""

        mapping_entries: dict[tuple[int, object], _ActionCohortMappingSavepoint] = {}
        set_entries: dict[tuple[int, object], _ActionCohortSetSavepoint] = {}
        mapped_set_entries: dict[tuple[int, object, object], _ActionCohortMappedSetSavepoint] = {}
        indexed_store_entries: dict[tuple[int, object], _ActionCohortIndexedStoreSavepoint] = {}
        grouped_entries: dict[tuple[int, object], _ActionCohortGroupedTemporalSavepoint] = {}
        temporal_entries: list[_ActionCohortTemporalAllocationSavepoint] = []
        object_entries: dict[int, _ActionCohortObjectSavepoint] = {}
        temporal_offsets: dict[tuple[int, str], int] = {}

        def capture_mapping(mapping: dict[object, object], key: object) -> None:
            journal_key = (id(mapping), key)
            if journal_key in mapping_entries:
                return
            mapping_entries[journal_key] = _ActionCohortMappingSavepoint(
                mapping=mapping,
                key=key,
                present=key in mapping,
                value=mapping.get(key),
            )

        def capture_set(values: set[object], value: object) -> None:
            journal_key = (id(values), value)
            if journal_key in set_entries:
                return
            set_entries[journal_key] = _ActionCohortSetSavepoint(
                values=values,
                value=value,
                present=value in values,
            )

        def capture_mapped_set(
            mapping: dict[object, object],
            key: object,
            value: object,
        ) -> None:
            journal_key = (id(mapping), key, value)
            if journal_key in mapped_set_entries:
                return
            current = mapping.get(key)
            values = current if isinstance(current, set) else None
            mapped_set_entries[journal_key] = _ActionCohortMappedSetSavepoint(
                mapping=mapping,
                key=key,
                mapping_present=key in mapping,
                values=values,
                value=value,
                value_present=values is not None and value in values,
            )

        def capture_indexed(store: IndexedEntityStore[object, object], key: object) -> None:
            journal_key = (id(store), key)
            if journal_key in indexed_store_entries:
                return
            present = key in store._items
            indexed_values = store._indexed_values.get(key)
            buckets: tuple[tuple[str, object, dict[object, None]], ...] = ()
            if indexed_values is not None:
                buckets = tuple(
                    (name, indexed_value, store._indexes[name][indexed_value])
                    for name, indexed_value in indexed_values.items()
                )
            indexed_store_entries[journal_key] = _ActionCohortIndexedStoreSavepoint(
                store=store,
                key=key,
                present=present,
                value=store._items.get(key),
                indexed_values=indexed_values,
                buckets=buckets,
            )

        def capture_object(target: ActiveSession | RunningProcess | RunningThread) -> None:
            if id(target) in object_entries:
                return
            object_entries[id(target)] = _ActionCohortObjectSavepoint(
                target=target,
                fields=tuple(target.__dict__.items()),
            )

        def capture_grouped(
            index: GroupedTemporalIndex[object, object],
            key: object,
            *,
            added_group: object | None,
            added_time: datetime | None,
            adds_record: bool,
        ) -> None:
            journal_key = (id(index), key)
            existing = grouped_entries.get(journal_key)
            if existing is not None:
                if not adds_record or existing.added_record is not None:
                    return
                assert added_group is not None
                assert added_time is not None
                prior = existing.prior_current
                grouped_entries[journal_key] = _ActionCohortGroupedTemporalSavepoint(
                    index=index,
                    key=key,
                    prior_current=prior,
                    prior_next_sequence=existing.prior_next_sequence,
                    prior_stale_counts=existing.prior_stale_counts,
                    added_record=(
                        added_group,
                        added_time,
                        prior[2] if prior is not None else existing.prior_next_sequence,
                        prior[3] + 1 if prior is not None else 1,
                    ),
                )
                return
            prior_current = index._current.get(key)
            groups: list[object] = []
            if prior_current is not None:
                groups.append(prior_current[0])
            if added_group is not None and added_group not in groups:
                groups.append(added_group)
            added_record = None
            if adds_record:
                assert added_group is not None
                assert added_time is not None
                added_record = (
                    added_group,
                    added_time,
                    prior_current[2] if prior_current is not None else index._next_sequence,
                    prior_current[3] + 1 if prior_current is not None else 1,
                )
            grouped_entries[journal_key] = _ActionCohortGroupedTemporalSavepoint(
                index=index,
                key=key,
                prior_current=prior_current,
                prior_next_sequence=index._next_sequence,
                prior_stale_counts=tuple(
                    (group, index._stale_counts.get(group)) for group in groups
                ),
                added_record=added_record,
            )

        def capture_temporal_addition(
            mapping: dict[str, TemporalAllocationIndex],
            host: str,
            event_time: datetime,
            value: int,
        ) -> None:
            capture_mapping(mapping, host)  # type: ignore[arg-type]
            index = mapping.get(host)
            offset_key = (id(mapping), host)
            offset = temporal_offsets.get(offset_key, 0)
            temporal_offsets[offset_key] = offset + 1
            temporal_entries.append(
                _ActionCohortTemporalAllocationSavepoint(
                    mapping=mapping,
                    host=host,
                    index_was_present=index is not None,
                    index=index,
                    event_time=event_time,
                    value=value,
                    sequence=(index._sequence if index is not None else 0) + offset,
                )
            )

        session_rows = {item.plan.identity.object_id: item.session for item in sessions}
        process_rows = {item.plan.identity.object_id: item.process for item in processes}
        thread_rows = {
            item.plan.identity.primary_thread.object_id: item.thread
            for item in processes
            if item.plan.identity.primary_thread is not None
        }
        for hostname, _boot_time in boot_times:
            capture_mapping(self._system_boot_times, hostname)  # type: ignore[arg-type]
        for item in sessions:
            capture_object(item.session)
            capture_indexed(self._active_sessions, item.session.logon_id)  # type: ignore[arg-type]
            patch = item.plan._allocator_patch
            if patch.host_base is not None:
                host, base = patch.host_base
                capture_mapping(self._logon_id_host_bases, host)  # type: ignore[arg-type]
                capture_set(self._logon_id_used_host_bases, base)  # type: ignore[arg-type]
            if patch.host_epoch is not None:
                capture_mapping(self._logon_id_epochs, patch.host_epoch[0])  # type: ignore[arg-type]
            if patch.ordinal is not None:
                capture_mapping(self._logon_id_second_ordinals, patch.ordinal[0])  # type: ignore[arg-type]
            if patch.used_logon_id is not None:
                capture_set(self._used_logon_ids, patch.used_logon_id)  # type: ignore[arg-type]
            if patch.windows_session_counter is not None:
                capture_mapping(
                    self._windows_session_id_counters,
                    patch.windows_session_counter[0],
                )  # type: ignore[arg-type]
            if patch.linux_logind is not None:
                logind = patch.linux_logind
                capture_mapping(self._linux_logind_session_initials, logind.system)  # type: ignore[arg-type]
                capture_mapping(self._linux_logind_session_epochs, logind.system)  # type: ignore[arg-type]
                capture_mapping(self._linux_logind_session_last_ids, logind.system)  # type: ignore[arg-type]
                capture_mapped_set(
                    self._linux_logind_session_used_ids,  # type: ignore[arg-type]
                    logind.system,
                    logind.session_id,
                )
                capture_temporal_addition(
                    self._linux_logind_session_allocations,
                    logind.system,
                    logind.event_time,
                    logind.session_id,
                )
            capture_mapping(self._logon_id_aliases, item.session.logon_id)  # type: ignore[arg-type]
            alias_target = self._logon_id_aliases.get(item.session.logon_id)
            if alias_target is not None:
                capture_mapped_set(
                    self._logon_id_aliases_by_target,  # type: ignore[arg-type]
                    alias_target,
                    item.session.logon_id,
                )

        for item in processes:
            process = item.process
            thread = item.thread
            capture_object(process)
            capture_object(thread)
            process_key = (process.system, process.pid)
            thread_key = (thread.hostname, thread.process_object_id, thread.tid)
            capture_indexed(self._running_processes, process_key)  # type: ignore[arg-type]
            capture_indexed(self._running_threads, thread_key)  # type: ignore[arg-type]
            capture_mapping(self._active_pid_reservation_counts, process.system)  # type: ignore[arg-type]
            capture_mapping(self._process_object_ids, process_key)  # type: ignore[arg-type]
            capture_mapping(self._processes_by_object_id, process.ecar_object_id)  # type: ignore[arg-type]
            patch = item.plan._allocator_patch
            for mapping, entry in (
                (self._pid_counters, patch.pid_counter),
                (self._pid_os, patch.pid_os),
                (self._pid_rngs, patch.pid_rng_state),
                (self._pid_time_epochs, patch.pid_epoch),
                (self._linux_pid_weekly_churn_prefixes, patch.pid_weekly_prefix),
                (self._pid_bucket_offsets, patch.pid_bucket_offset),
                (self._thread_id_counters, patch.thread_counter),
                (self._thread_id_rngs, patch.thread_rng_state),
            ):
                if entry is not None:
                    capture_mapping(mapping, entry[0])  # type: ignore[arg-type]
            if patch.linux_allocation is not None:
                host, event_time, logical_position = patch.linux_allocation
                capture_temporal_addition(
                    self._linux_pid_allocations,
                    host,
                    event_time,
                    logical_position,
                )
            if patch.fixed_pid is not None:
                capture_mapped_set(
                    self._fixed_pid_reservations,  # type: ignore[arg-type]
                    patch.fixed_pid[0],
                    patch.fixed_pid[1],
                )
            if item.plan.identity.parent_pid:
                parent = self._running_processes.get(
                    (item.plan.identity.hostname, item.plan.identity.parent_pid)
                )
                if parent is not None:
                    capture_object(parent)

        ended_process_keys: set[object] = {
            (item.process.system, item.process.pid) for item in processes
        }
        ended_process_object_ids: set[object] = set()
        ended_thread_keys: set[object] = set()
        for item in process_terminations:
            identity = item.plan.identity
            process = process_rows.get(identity.object_id) or self._processes_by_object_id.get(
                identity.object_id
            )
            if process is not None:
                capture_object(process)
            capture_indexed(self._running_processes, item.process_key)  # type: ignore[arg-type]
            capture_mapping(self._active_pid_reservation_counts, identity.hostname)  # type: ignore[arg-type]
            capture_mapping(self._process_object_ids, item.process_key)  # type: ignore[arg-type]
            capture_mapping(self._processes_by_object_id, identity.object_id)  # type: ignore[arg-type]
            ended_process_keys.add(item.process_key)
            ended_process_object_ids.add(identity.object_id)
            for thread_identity, thread_key in zip(
                item.plan._payload.threads,
                item.thread_keys,
                strict=True,
            ):
                thread = thread_rows.get(thread_identity.object_id) or self._running_threads.get(
                    thread_key
                )
                if thread is not None:
                    capture_object(thread)
                capture_indexed(self._running_threads, thread_key)  # type: ignore[arg-type]
                ended_thread_keys.add(thread_key)
            parent_identity = item.plan._payload.parent_identity
            if parent_identity is not None:
                parent = process_rows.get(
                    parent_identity.object_id
                ) or self._processes_by_object_id.get(parent_identity.object_id)
                if parent is not None:
                    capture_object(parent)
            for reference in item.plan._payload.session_references:
                referenced = session_rows.get(reference.object_id) or self._active_sessions.get(
                    reference.logon_id
                )
                if referenced is not None:
                    capture_object(referenced)

        ended_session_keys: set[object] = set()
        for item in session_terminalizations:
            terminalization = item.terminalization
            identity = terminalization.identity
            session = item.ended[0]
            capture_object(session)
            capture_indexed(self._active_sessions, item.resolved_logon_id)  # type: ignore[arg-type]
            ended_session_keys.add(item.resolved_logon_id)
            if item.resolved_logon_id != identity.logon_id:
                ended_session_keys.add(identity.logon_id)
            capture_grouped(
                self._ended_sessions_by_username_end,  # type: ignore[arg-type]
                item.resolved_logon_id,
                added_group=session.username,
                added_time=terminalization.end_time,
                adds_record=True,
            )
            capture_grouped(
                self._ended_sessions_by_system_end,  # type: ignore[arg-type]
                item.resolved_logon_id,
                added_group=session.system,
                added_time=terminalization.end_time,
                adds_record=True,
            )

        for patch in plan._live_session_process_roles:
            session = self._active_sessions[self._resolve_logon_id(patch.target.logon_id)]
            capture_object(session)
        for patch in plan._session_metadata:
            identity = self._action_session_identity(patch.target)
            session = (
                session_rows.get(identity.object_id)
                or self._active_sessions[self._resolve_logon_id(identity.logon_id)]
            )
            capture_object(session)
            if patch.before.end_plan != patch.after.end_plan:
                after_plan = patch.after.end_plan
                adds_record = after_plan is not None and after_plan.is_hard_deadline
                capture_grouped(
                    self._authoritative_session_ends,  # type: ignore[arg-type]
                    session.logon_id,
                    added_group=((session.username, session.system) if adds_record else None),
                    added_time=(ensure_utc(after_plan.canonical_end) if adds_record else None),
                    adds_record=adds_record,
                )
        for patch in plan._process_activity:
            identity = self._action_process_identity(patch.target)
            process = (
                process_rows.get(identity.object_id)
                or self._processes_by_object_id[identity.object_id]
            )
            capture_object(process)
        for patch in plan._session_activity:
            identity = self._action_session_identity(patch.target)
            session = (
                session_rows.get(identity.object_id)
                or self._active_sessions[self._resolve_logon_id(identity.logon_id)]
            )
            capture_object(session)

        def capture_expiring(
            index: ExpiringIndex[object, object],
            keys: set[object],
        ) -> _ActionCohortExpiringIndexSavepoint:
            return _ActionCohortExpiringIndexSavepoint(
                index=index,
                keys=tuple(
                    _ActionCohortExpiringKeySavepoint(
                        key=key,
                        present=key in index._items,
                        value=index._items.get(key),
                        deadline=index._deadlines.get(key),
                        order=index._orders.get(key),
                        version=index._versions.get(key),
                    )
                    for key in keys
                ),
                next_order=index._next_order,
                high_water_mark=index._high_water_mark,
            )

        return _ActionCohortRollbackJournal(
            mapping_entries=tuple(mapping_entries.values()),
            set_entries=tuple(set_entries.values()),
            mapped_set_entries=tuple(mapped_set_entries.values()),
            indexed_store_entries=tuple(indexed_store_entries.values()),
            expiring_indexes=(
                capture_expiring(self._ended_sessions, ended_session_keys),  # type: ignore[arg-type]
                capture_expiring(self._ended_processes_by_key, ended_process_keys),  # type: ignore[arg-type]
                capture_expiring(
                    self._ended_processes_by_object_id,  # type: ignore[arg-type]
                    ended_process_object_ids,
                ),
                capture_expiring(self._ended_threads, ended_thread_keys),  # type: ignore[arg-type]
            ),
            grouped_temporal_entries=tuple(grouped_entries.values()),
            temporal_allocations=tuple(temporal_entries),
            object_entries=tuple(object_entries.values()),
            scalar_entries=(
                ("_pid_allocation_count", self._pid_allocation_count),
                ("_pid_candidate_probe_count", self._pid_candidate_probe_count),
            ),
            retention_mapping_entries=[],
            retention_mapped_set_entries=[],
            retention_expiring_indexes=[],
            retention_grouped_temporal_entries=[],
            state_time=self.state.current_time,
            materialization_version=self._materialization_version,
        )

    @staticmethod
    def _action_cohort_observation_value(value: object) -> object:
        """Project one touched scalar or owner reference without traversing global state."""

        if value is None or isinstance(value, (bool, int, float, str, bytes, datetime, Enum)):
            return _freeze_materialization_digest_value(value, set())
        return ("owner", type(value).__module__, type(value).__qualname__, id(value))

    @staticmethod
    def _action_cohort_temporal_record_present(
        index: TemporalAllocationIndex,
        record: tuple[datetime, int, int],
    ) -> bool:
        """Return whether one exact allocation record remains in its bounded index lane."""

        event_time = record[0]
        block_index = bisect_left(index._block_last_times, event_time)
        if block_index == len(index._blocks):
            return False
        while block_index > 0 and index._blocks[block_index - 1][-1][0] >= event_time:
            block_index -= 1
        while block_index < len(index._blocks):
            block = index._blocks[block_index]
            if block[0][0] > event_time:
                return False
            position = bisect_left(block, record)
            if position < len(block) and block[position] == record:
                return True
            block_index += 1
        return False

    def _action_cohort_rollback_observation(
        self,
        journal: _ActionCohortRollbackJournal,
    ) -> object:
        """Capture the current O(cohort delta) projection that rollback may overwrite."""

        mapping_entries = (*journal.mapping_entries, *journal.retention_mapping_entries)
        mapped_set_entries = (
            *journal.mapped_set_entries,
            *journal.retention_mapped_set_entries,
        )
        expiring_indexes = (*journal.expiring_indexes, *journal.retention_expiring_indexes)
        grouped_entries = (
            *journal.grouped_temporal_entries,
            *journal.retention_grouped_temporal_entries,
        )

        mapping_observation = tuple(
            (
                id(entry.mapping),
                self._action_cohort_observation_value(entry.key),
                entry.key in entry.mapping,
                self._action_cohort_observation_value(entry.mapping.get(entry.key)),
            )
            for entry in mapping_entries
        )
        set_observation = tuple(
            (
                id(entry.values),
                self._action_cohort_observation_value(entry.value),
                entry.value in entry.values,
            )
            for entry in journal.set_entries
        )
        mapped_set_observation = tuple(
            (
                id(entry.mapping),
                self._action_cohort_observation_value(entry.key),
                entry.key in entry.mapping,
                id(entry.mapping.get(entry.key)),
                isinstance(entry.mapping.get(entry.key), set)
                and entry.value in entry.mapping[entry.key],
            )
            for entry in mapped_set_entries
        )

        indexed_observation: list[object] = []
        for entry in journal.indexed_store_entries:
            store = entry.store
            indexed_values = store._indexed_values.get(entry.key)
            buckets: list[object] = []
            if indexed_values is not None:
                for name, indexed_value in indexed_values.items():
                    index = store._indexes.get(name)
                    bucket = index.get(indexed_value) if index is not None else None
                    buckets.append(
                        (
                            name,
                            self._action_cohort_observation_value(indexed_value),
                            id(bucket),
                            bucket is not None and entry.key in bucket,
                        )
                    )
            indexed_observation.append(
                (
                    id(store),
                    self._action_cohort_observation_value(entry.key),
                    entry.key in store._items,
                    id(store._items.get(entry.key)),
                    _freeze_materialization_digest_value(indexed_values, set()),
                    tuple(buckets),
                )
            )

        expiring_observation = tuple(
            (
                id(entry.index),
                entry.index._next_order,
                entry.index._high_water_mark,
                tuple(
                    (
                        self._action_cohort_observation_value(key.key),
                        key.key in entry.index._items,
                        self._action_cohort_observation_value(entry.index._items.get(key.key)),
                        entry.index._deadlines.get(key.key),
                        entry.index._orders.get(key.key),
                        entry.index._versions.get(key.key),
                    )
                    for key in entry.keys
                ),
            )
            for entry in expiring_indexes
        )

        grouped_observation: list[object] = []
        for entry in grouped_entries:
            current = entry.index._current.get(entry.key)
            groups = {group for group, _count in entry.prior_stale_counts}
            record_present = False
            if current is not None:
                group, event_time, sequence, version = current
                groups.add(group)
                records = entry.index._records.get(group, [])
                record = (event_time, sequence, version, entry.key)
                position = bisect_left(records, record)
                record_present = position < len(records) and records[position] == record
            grouped_observation.append(
                (
                    id(entry.index),
                    self._action_cohort_observation_value(entry.key),
                    self._action_cohort_observation_value(current),
                    entry.index._next_sequence,
                    tuple(
                        sorted(
                            (
                                self._action_cohort_observation_value(group),
                                entry.index._stale_counts.get(group),
                            )
                            for group in groups
                        )
                    ),
                    record_present,
                )
            )

        temporal_observation = tuple(
            (
                id(entry.mapping),
                entry.host,
                id(entry.mapping.get(entry.host)),
                (
                    entry.mapping[entry.host]._sequence,
                    entry.mapping[entry.host]._value_counts.get(entry.value),
                    self._action_cohort_temporal_record_present(
                        entry.mapping[entry.host],
                        (entry.event_time, entry.sequence, entry.value),
                    ),
                )
                if entry.host in entry.mapping
                else None,
            )
            for entry in journal.temporal_allocations
        )

        object_observation = tuple(
            (
                id(entry.target),
                tuple(
                    sorted(
                        (
                            name,
                            _freeze_materialization_digest_value(value, set()),
                        )
                        for name, value in entry.target.__dict__.items()
                    )
                ),
            )
            for entry in journal.object_entries
        )
        scalar_observation = tuple(
            (name, self._action_cohort_observation_value(getattr(self, name)))
            for name, _value in journal.scalar_entries
        )
        return (
            mapping_observation,
            set_observation,
            mapped_set_observation,
            tuple(indexed_observation),
            expiring_observation,
            tuple(grouped_observation),
            temporal_observation,
            object_observation,
            scalar_observation,
            self.state.current_time,
            self._materialization_version,
        )

    def _restore_claimed_action_cohort_rollback(
        self,
        record: _ActionCohortPreparationRecord,
    ) -> None:
        """Restore one exact claim only while its touched postimage is unchanged."""

        preparation = record.preparation
        if (
            self._active_action_cohort_claim is not record
            or self._active_prepared_state_claim is not record
            or self._active_action_cohort_preparations.get(id(preparation)) is not record
            or record.claim_thread_id != get_ident()
            or record.claim_epoch != self._prepared_state_admission_epoch
            or record.terminal
        ):
            raise StateError("Prepared action cohort no longer owns the rollback lane")
        expected_postimage = record.provisional_postimage
        if expected_postimage is None:
            raise StateError("Prepared action cohort has no rollback postimage")
        if (
            self._action_cohort_rollback_observation(record.commit_plan.rollback_journal)
            != expected_postimage
        ):
            raise StateError(
                "Prepared action cohort touched State drifted after provisional apply; "
                "refusing rollback"
            )
        self._restore_action_cohort_rollback_journal(record.commit_plan.rollback_journal)

    @staticmethod
    def _rollback_action_cohort_temporal_allocation(
        savepoint: _ActionCohortTemporalAllocationSavepoint,
    ) -> None:
        """Remove one exact appended temporal-allocation record in bounded work."""

        if not savepoint.index_was_present:
            return
        index = savepoint.index
        assert index is not None
        record = (savepoint.event_time, savepoint.sequence, savepoint.value)
        block_index = bisect_left(index._block_last_times, savepoint.event_time)
        if block_index == len(index._blocks):
            block_index -= 1
        while block_index > 0 and index._blocks[block_index - 1][-1][0] >= savepoint.event_time:
            block_index -= 1
        removed = False
        while block_index < len(index._blocks):
            block = index._blocks[block_index]
            if block[0][0] > savepoint.event_time:
                break
            position = bisect_left(block, record)
            if position < len(block) and block[position] == record:
                block.pop(position)
                removed = True
                if block:
                    index._refresh_block_summary(block_index)
                    index._update_summary_tree(block_index)
                else:
                    index._blocks.pop(block_index)
                    index._block_last_times.pop(block_index)
                    index._block_max_values.pop(block_index)
                    index._block_min_values.pop(block_index)
                    index._rebuild_summary_tree()
                break
            block_index += 1
        if not removed:
            return

        epoch = savepoint.event_time.timestamp()
        for buckets, invariant in (
            (index._minus_invariants, savepoint.value - epoch),
            (index._plus_invariants, savepoint.value + epoch),
        ):
            bucket_key = math.floor(invariant)
            bucket = buckets.get(bucket_key)
            entry = (invariant, savepoint.event_time, savepoint.value)
            if bucket is not None:
                if bucket and bucket[-1] == entry:
                    bucket.pop()
                else:
                    position = len(bucket) - 1
                    while position >= 0 and bucket[position] != entry:
                        position -= 1
                    if position >= 0:
                        bucket.pop(position)
                if not bucket:
                    buckets.pop(bucket_key, None)
        count = index._value_counts.get(savepoint.value, 0)
        if count > 1:
            index._value_counts[savepoint.value] = count - 1
        else:
            index._value_counts.pop(savepoint.value, None)
        index._sequence = savepoint.sequence

    @staticmethod
    def _restore_action_cohort_indexed_store_key(
        savepoint: _ActionCohortIndexedStoreSavepoint,
    ) -> None:
        """Restore one IndexedEntityStore key without invoking indexer callbacks."""

        store = savepoint.store
        current = store._indexed_values.pop(savepoint.key, None)
        if current is not None:
            for name, indexed_value in current.items():
                bucket = store._indexes[name].get(indexed_value)
                if bucket is None:
                    continue
                bucket.pop(savepoint.key, None)
                if not bucket:
                    store._indexes[name].pop(indexed_value, None)
        store._items.pop(savepoint.key, None)
        if not savepoint.present:
            return
        assert savepoint.indexed_values is not None
        store._items[savepoint.key] = savepoint.value
        store._indexed_values[savepoint.key] = savepoint.indexed_values
        for name, indexed_value, bucket in savepoint.buckets:
            store._indexes[name][indexed_value] = bucket
            bucket[savepoint.key] = None

    @staticmethod
    def _restore_action_cohort_expiring_index(
        savepoint: _ActionCohortExpiringIndexSavepoint,
    ) -> None:
        """Restore touched expiry keys and compact bounded stale entries."""

        index = savepoint.index
        for entry in savepoint.keys:
            index._items.pop(entry.key, None)
            index._deadlines.pop(entry.key, None)
            index._orders.pop(entry.key, None)
            index._versions.pop(entry.key, None)
        for entry in savepoint.keys:
            if not entry.present:
                continue
            assert entry.deadline is not None
            assert entry.order is not None
            assert entry.version is not None
            index._items[entry.key] = entry.value
            index._deadlines[entry.key] = entry.deadline
            index._orders[entry.key] = entry.order
            index._versions[entry.key] = entry.version
            heapq.heappush(
                index._heap,
                (entry.deadline, entry.order, entry.version, entry.key),
            )
        index._next_order = savepoint.next_order
        index._high_water_mark = savepoint.high_water_mark
        if not index._items:
            index._items = {}
            index._deadlines = {}
            index._orders = {}
            index._versions = {}
            index._heap = []
            index._retired_heap = None
            index._next_order = 0
        else:
            index.compact(max_entries=4_096)

    @staticmethod
    def _restore_action_cohort_grouped_temporal(
        savepoint: _ActionCohortGroupedTemporalSavepoint,
    ) -> None:
        """Remove one new record and reactivate its exact prior locator."""

        index = savepoint.index
        added_record = savepoint.added_record
        if added_record is not None:
            group, event_time, sequence, version = added_record
            record = (event_time, sequence, version, savepoint.key)
            records = index._records.get(group)
            if records is not None:
                position = bisect_left(records, record)
                if position < len(records) and records[position] == record:
                    records.pop(position)
                if not records:
                    index._records.pop(group, None)
        if savepoint.prior_current is None:
            index._current.pop(savepoint.key, None)
        else:
            group, event_time, sequence, version = savepoint.prior_current
            prior_record = (event_time, sequence, version, savepoint.key)
            records = index._records.setdefault(group, [])
            position = bisect_left(records, prior_record)
            if position == len(records) or records[position] != prior_record:
                records.insert(position, prior_record)
            index._current[savepoint.key] = savepoint.prior_current
        index._next_sequence = savepoint.prior_next_sequence
        for group, stale_count in savepoint.prior_stale_counts:
            if stale_count is None:
                index._stale_counts.pop(group, None)
            else:
                index._stale_counts[group] = stale_count

    def _restore_action_cohort_rollback_journal(
        self,
        journal: _ActionCohortRollbackJournal,
    ) -> None:
        """Undo every cohort-owned mutation without scanning retained State."""

        for savepoint in reversed(journal.temporal_allocations):
            self._rollback_action_cohort_temporal_allocation(savepoint)
        for savepoint in journal.object_entries:
            savepoint.target.__dict__.clear()
            savepoint.target.__dict__.update(savepoint.fields)
        for savepoint in reversed(journal.indexed_store_entries):
            self._restore_action_cohort_indexed_store_key(savepoint)
        for savepoint in reversed(journal.retention_mapping_entries):
            if savepoint.present:
                savepoint.mapping[savepoint.key] = savepoint.value
            else:
                savepoint.mapping.pop(savepoint.key, None)
        for savepoint in reversed(journal.mapping_entries):
            if savepoint.present:
                savepoint.mapping[savepoint.key] = savepoint.value
            else:
                savepoint.mapping.pop(savepoint.key, None)
        for savepoint in reversed(journal.set_entries):
            if savepoint.present:
                savepoint.values.add(savepoint.value)
            else:
                savepoint.values.discard(savepoint.value)
        for savepoint in reversed(journal.retention_mapped_set_entries):
            if not savepoint.mapping_present:
                savepoint.mapping.pop(savepoint.key, None)
                continue
            assert savepoint.values is not None
            savepoint.mapping[savepoint.key] = savepoint.values
            if savepoint.value_present:
                savepoint.values.add(savepoint.value)
            else:
                savepoint.values.discard(savepoint.value)
        for savepoint in reversed(journal.mapped_set_entries):
            if not savepoint.mapping_present:
                savepoint.mapping.pop(savepoint.key, None)
                continue
            assert savepoint.values is not None
            savepoint.mapping[savepoint.key] = savepoint.values
            if savepoint.value_present:
                savepoint.values.add(savepoint.value)
            else:
                savepoint.values.discard(savepoint.value)
        for savepoint in reversed(journal.retention_expiring_indexes):
            self._restore_action_cohort_expiring_index(savepoint)
        for savepoint in journal.expiring_indexes:
            self._restore_action_cohort_expiring_index(savepoint)
        for savepoint in reversed(journal.retention_grouped_temporal_entries):
            self._restore_action_cohort_grouped_temporal(savepoint)
        for savepoint in reversed(journal.grouped_temporal_entries):
            self._restore_action_cohort_grouped_temporal(savepoint)
        for name, value in journal.scalar_entries:
            setattr(self, name, value)
        self.state.current_time = journal.state_time
        self._materialization_version = journal.materialization_version

    def _prepare_action_cohort_commit_plan(
        self,
        plan: ActionCohortMaterializationPlan,
    ) -> _PreparedActionCohortCommitPlan:
        """Build every runtime and rollback object while the validated guard is held."""

        sessions = tuple(self._prepare_action_cohort_session_start(item) for item in plan.sessions)
        processes = tuple(
            self._prepare_action_cohort_process_start(item) for item in plan.processes
        )
        sessions_by_object_id = {item.plan.identity.object_id: item.session for item in sessions}
        terminalizations: list[_PreparedActionCohortSessionTerminalization] = []
        for terminalization in plan.session_terminalizations:
            identity = terminalization.identity
            session = sessions_by_object_id.get(identity.object_id)
            resolved = identity.logon_id
            if session is None:
                resolved = self._resolve_logon_id(identity.logon_id)
                session = self._active_sessions[resolved]
            terminalizations.append(
                _PreparedActionCohortSessionTerminalization(
                    terminalization=terminalization,
                    resolved_logon_id=resolved,
                    ended=(session, terminalization.end_time),
                    retention_deadline=(
                        terminalization.end_time + _ENDED_IDENTITY_RETENTION
                    ).timestamp(),
                )
            )
        process_terminations = tuple(
            self._prepare_action_cohort_process_termination(item)
            for item in plan.process_terminations
        )
        session_terminalizations = tuple(terminalizations)
        rollback_journal = self._prepare_action_cohort_rollback_journal(
            plan,
            sessions=sessions,
            processes=processes,
            process_terminations=process_terminations,
            session_terminalizations=session_terminalizations,
        )
        return _PreparedActionCohortCommitPlan(
            plan=plan,
            committed_version=plan.expected_version + 1,
            sessions=sessions,
            processes=processes,
            process_terminations=process_terminations,
            session_terminalizations=session_terminalizations,
            rollback_journal=rollback_journal,
            claim_version=self._materialization_version,
            claim_state_time=self.state.current_time,
            claim_preimage=self._action_cohort_rollback_observation(rollback_journal),
        )

    @contextmanager
    def prepared_action_cohort_materialization(
        self,
        plan: ActionCohortMaterializationPlan,
    ) -> Iterator[PreparedActionCohortMaterialization]:
        """Retain the State guard after all cohort validation succeeds."""

        claim_admission_epoch = self._prepared_state_admission_epoch
        if self._active_prepared_state_claim is not None:
            if self._active_action_cohort_claim is not None:
                raise StateError("StateManager already has an active action-cohort claim")
            raise StateError("StateManager already has an active prepared-State claim")
        with self._lock:
            if self._active_prepared_state_claim is not None:
                if self._active_action_cohort_claim is not None:
                    raise StateError("StateManager already has an active action-cohort claim")
                raise StateError("StateManager already has an active prepared-State claim")
            if claim_admission_epoch != self._prepared_state_admission_epoch:
                raise StateError("Action-cohort claim overlapped another prepared-State claim")
            self.validate_action_cohort_materialization(plan)
            commit_plan = self._prepare_action_cohort_commit_plan(plan)
            expected_result = ActionCohortMaterializationResult(
                semantic_id=plan.semantic_id,
                prior_version=plan.expected_version,
                committed_version=plan.expected_version + 1,
                started_sessions=tuple(item.identity for item in plan.sessions),
                started_processes=tuple(item.identity for item in plan.processes),
                terminated_processes=tuple(item.identity for item in plan.process_terminations),
                terminalized_sessions=tuple(
                    item.identity for item in plan.session_terminalizations
                ),
            )
            prepared = PreparedActionCohortMaterialization(
                _manager=self,
                _plan=plan,
                _expected_result=expected_result,
                _claim_thread_id=get_ident(),
            )
            token = _action_cohort_result_publication_token(
                self._materialization_secret,
                plan=plan,
                result=expected_result,
                commit_plan=commit_plan,
            )
            claim_epoch = self._prepared_state_admission_epoch + 1
            record = _ActionCohortPreparationRecord(
                preparation=prepared,
                expected_result=expected_result,
                expected_result_publication_token=token,
                commit_plan=commit_plan,
                claim_thread_id=prepared._claim_thread_id,
                claim_epoch=claim_epoch,
            )
            locator = id(prepared)
            self._active_action_cohort_preparations[locator] = record
            self._prepared_state_admission_epoch = claim_epoch
            self._active_action_cohort_claim = record
            self._active_prepared_state_claim = record
            primary_error: BaseException | None = None
            try:
                yield prepared
            except BaseException as error:
                primary_error = error
                raise
            finally:
                cleanup_error: BaseException | None = None
                if (
                    self._active_action_cohort_claim is record
                    and self._active_prepared_state_claim is record
                    and self._active_action_cohort_preparations.get(locator) is record
                    and record.provisional
                    and not record.committed
                ):
                    try:
                        self._restore_claimed_action_cohort_rollback(record)
                        record.provisional = False
                        record.provisional_postimage = None
                    except BaseException as error:
                        if primary_error is not None:
                            primary_error.add_note(
                                "State provisional action-cohort rollback also raised "
                                f"{type(error).__name__}: {error}"
                            )
                        else:
                            cleanup_error = error
                if (
                    self._active_action_cohort_preparations.get(locator) is not record
                    or self._active_action_cohort_claim is not record
                    or self._active_prepared_state_claim is not record
                ) and cleanup_error is None:
                    cleanup_error = StateError(
                        "Prepared action cohort no longer owns its prepared-State lane"
                    )
                if self._active_action_cohort_preparations.get(locator) is record:
                    self._active_action_cohort_preparations.pop(locator)
                if self._active_action_cohort_claim is record:
                    self._active_action_cohort_claim = None
                if self._active_prepared_state_claim is record:
                    self._active_prepared_state_claim = None
                    self._prepared_state_admission_epoch += 1
                record.terminal = True
                prepared._active = False
                prepared._committed = record.committed
                if not record.committed:
                    prepared._result = None
                if cleanup_error is not None:
                    raise cleanup_error

    def materialize_action_cohort(
        self,
        plan: ActionCohortMaterializationPlan,
    ) -> ActionCohortMaterializationResult:
        """Compatibility commit for one fully prepared action cohort."""

        claim_admission_epoch = self._prepared_state_admission_epoch
        if self._active_prepared_state_claim is not None:
            if self._active_action_cohort_claim is not None:
                raise StateError("StateManager already has an active action-cohort claim")
            raise StateError("StateManager already has an active prepared-State claim")
        with self._lock:
            if self._active_prepared_state_claim is not None:
                if self._active_action_cohort_claim is not None:
                    raise StateError("StateManager already has an active action-cohort claim")
                raise StateError("StateManager already has an active prepared-State claim")
            if claim_admission_epoch != self._prepared_state_admission_epoch:
                raise StateError("Action-cohort claim overlapped another prepared-State claim")
            with self.prepared_action_cohort_materialization(plan) as prepared:
                return prepared.commit_no_fail()

    def _commit_action_cohort_session_metadata(
        self,
        patch: ActionCohortSessionMetadataPatch,
    ) -> None:
        identity = self._action_session_identity(patch.target)
        session = self._active_sessions[self._resolve_logon_id(identity.logon_id)]
        after = patch.after
        session.source_ready_time = after.source_ready_time
        session.network_close_time = after.network_close_time
        session.closure_owned_by_bundle = after.closure_owned_by_bundle
        session.login_occurrence_emitted = after.login_occurrence_emitted
        session.storyline_protected = after.storyline_protected
        if session.end_plan != after.end_plan:
            self._authoritative_session_ends.remove(session.logon_id)
            session.end_plan = after.end_plan
            self._index_authoritative_session_end(session)

    def _commit_action_cohort_live_session_process_roles(
        self,
        patch: ActionCohortLiveSessionProcessRolesPatch,
    ) -> None:
        """Install one fully validated live-session process-role projection."""

        session = self._active_sessions[self._resolve_logon_id(patch.target.logon_id)]
        after = patch.after
        session.transport_pid = after.transport_pid
        session.session_shell_pid = after.session_shell_pid
        session.session_user_manager_pid = after.session_user_manager_pid
        session.session_winlogon_pid = after.session_winlogon_pid
        session.explorer_pid = after.explorer_pid
        session.initial_explorer_pid = after.initial_explorer_pid
        session.process_tree_root = after.process_tree_root
        session.windows_shell_bootstrapped = after.windows_shell_bootstrapped

    def _commit_action_cohort_session_terminalization(
        self,
        prepared: _PreparedActionCohortSessionTerminalization,
    ) -> SessionIdentity:
        terminalization = prepared.terminalization
        identity = terminalization.identity
        resolved = prepared.resolved_logon_id
        session = self._active_sessions.pop(resolved)
        ended = prepared.ended
        assert ended[0] is session
        self._ended_sessions.set(resolved, ended, prepared.retention_deadline)
        self._index_ended_session(resolved, session, terminalization.end_time)
        if resolved != identity.logon_id:
            self._ended_sessions.set(
                identity.logon_id,
                ended,
                prepared.retention_deadline,
            )
        return identity

    @staticmethod
    def _capture_action_cohort_expiring_key(
        index: ExpiringIndex[object, object],
        key: object,
    ) -> _ActionCohortExpiringIndexSavepoint:
        """Capture one exact live expiry key before bounded retention removal."""

        return _ActionCohortExpiringIndexSavepoint(
            index=index,
            keys=(
                _ActionCohortExpiringKeySavepoint(
                    key=key,
                    present=key in index._items,
                    value=index._items.get(key),
                    deadline=index._deadlines.get(key),
                    order=index._orders.get(key),
                    version=index._versions.get(key),
                ),
            ),
            next_order=index._next_order,
            high_water_mark=index._high_water_mark,
        )

    @staticmethod
    def _capture_action_cohort_grouped_key(
        index: GroupedTemporalIndex[object, object],
        key: object,
    ) -> _ActionCohortGroupedTemporalSavepoint:
        """Capture one exact grouped locator before retention cleanup removes it."""

        prior = index._current.get(key)
        return _ActionCohortGroupedTemporalSavepoint(
            index=index,
            key=key,
            prior_current=prior,
            prior_next_sequence=index._next_sequence,
            prior_stale_counts=(
                ((prior[0], index._stale_counts.get(prior[0])),) if prior is not None else ()
            ),
            added_record=None,
        )

    @staticmethod
    def _next_action_cohort_retention_victim(
        index: ExpiringIndex[object, object],
    ) -> tuple[list[tuple[float, int, int, object]], object, object] | None:
        """Resolve one live earliest victim with bounded stale-heap repair."""

        while heap := index._earliest_heap():
            deadline, order, version, key = heap[0]
            if (
                index._versions.get(key) == version
                and index._deadlines.get(key) == deadline
                and index._orders.get(key) == order
            ):
                return heap, key, index._items[key]
            heapq.heappop(heap)
        return None

    def _capture_action_cohort_session_retention_victim(
        self,
        journal: _ActionCohortRollbackJournal,
        logon_id: str,
        ended: tuple[ActiveSession, datetime],
    ) -> None:
        """Append the complete bounded undo projection for one session victim."""

        session = ended[0]
        expiring = [
            self._capture_action_cohort_expiring_key(
                self._ended_sessions,  # type: ignore[arg-type]
                logon_id,
            )
        ]
        mappings: list[_ActionCohortMappingSavepoint] = []
        mapped_sets: list[_ActionCohortMappedSetSavepoint] = []
        grouped: list[_ActionCohortGroupedTemporalSavepoint] = []
        if logon_id == session.logon_id:
            aliases = tuple(self._logon_id_aliases_by_target.get(logon_id, ()))
            mappings.append(
                _ActionCohortMappingSavepoint(
                    mapping=self._logon_id_aliases_by_target,  # type: ignore[arg-type]
                    key=logon_id,
                    present=logon_id in self._logon_id_aliases_by_target,
                    value=self._logon_id_aliases_by_target.get(logon_id),
                )
            )
            for alias in aliases:
                mappings.append(
                    _ActionCohortMappingSavepoint(
                        mapping=self._logon_id_aliases,  # type: ignore[arg-type]
                        key=alias,
                        present=alias in self._logon_id_aliases,
                        value=self._logon_id_aliases.get(alias),
                    )
                )
                if alias in self._ended_sessions:
                    expiring.append(
                        self._capture_action_cohort_expiring_key(
                            self._ended_sessions,  # type: ignore[arg-type]
                            alias,
                        )
                    )
            grouped.extend(
                (
                    self._capture_action_cohort_grouped_key(
                        self._ended_sessions_by_username_end,  # type: ignore[arg-type]
                        logon_id,
                    ),
                    self._capture_action_cohort_grouped_key(
                        self._ended_sessions_by_system_end,  # type: ignore[arg-type]
                        logon_id,
                    ),
                    self._capture_action_cohort_grouped_key(
                        self._authoritative_session_ends,  # type: ignore[arg-type]
                        logon_id,
                    ),
                )
            )
        else:
            target = self._logon_id_aliases.get(logon_id)
            mappings.append(
                _ActionCohortMappingSavepoint(
                    mapping=self._logon_id_aliases,  # type: ignore[arg-type]
                    key=logon_id,
                    present=logon_id in self._logon_id_aliases,
                    value=target,
                )
            )
            if target is not None:
                aliases = self._logon_id_aliases_by_target.get(target)
                mapped_sets.append(
                    _ActionCohortMappedSetSavepoint(
                        mapping=self._logon_id_aliases_by_target,  # type: ignore[arg-type]
                        key=target,
                        mapping_present=target in self._logon_id_aliases_by_target,
                        values=aliases,
                        value=logon_id,
                        value_present=aliases is not None and logon_id in aliases,
                    )
                )
        journal.retention_expiring_indexes.extend(expiring)
        journal.retention_mapping_entries.extend(mappings)
        journal.retention_mapped_set_entries.extend(mapped_sets)
        journal.retention_grouped_temporal_entries.extend(grouped)

    def _capture_action_cohort_process_retention_victim(
        self,
        journal: _ActionCohortRollbackJournal,
        object_id: str,
        process: RunningProcess,
    ) -> None:
        """Append both exact process retention keys before coupled removal."""

        entries = [
            self._capture_action_cohort_expiring_key(
                self._ended_processes_by_object_id,  # type: ignore[arg-type]
                object_id,
            )
        ]
        key = (process.system, process.pid)
        if self._ended_processes_by_key.get(key) is process:
            entries.append(
                self._capture_action_cohort_expiring_key(
                    self._ended_processes_by_key,  # type: ignore[arg-type]
                    key,
                )
            )
        journal.retention_expiring_indexes.extend(entries)

    def _commit_action_cohort_retention_evictions(
        self,
        prepared: _PreparedActionCohortCommitPlan,
    ) -> None:
        """Capture and apply exact bounded retention victims under the State lane."""

        journal = prepared.rollback_journal
        while len(self._ended_sessions) > _MAX_RETAINED_SESSION_IDENTITIES:
            victim = self._next_action_cohort_retention_victim(
                self._ended_sessions  # type: ignore[arg-type]
            )
            if victim is None:
                break
            heap, key, ended = victim
            assert isinstance(key, str)
            assert isinstance(ended, tuple)
            self._capture_action_cohort_session_retention_victim(journal, key, ended)
            heapq.heappop(heap)
            removed = self._ended_sessions.pop(key, None)
            if removed is not None:
                self._cleanup_ended_session_retention_entry(key, removed)

        while len(self._ended_processes_by_object_id) > _MAX_RETAINED_PROCESS_IDENTITIES:
            victim = self._next_action_cohort_retention_victim(
                self._ended_processes_by_object_id  # type: ignore[arg-type]
            )
            if victim is None:
                break
            heap, key, process = victim
            assert isinstance(key, str)
            assert isinstance(process, RunningProcess)
            self._capture_action_cohort_process_retention_victim(journal, key, process)
            heapq.heappop(heap)
            removed = self._ended_processes_by_object_id.pop(key, None)
            if removed is not None:
                process_key = (removed.system, removed.pid)
                if self._ended_processes_by_key.get(process_key) is removed:
                    self._ended_processes_by_key.pop(process_key, None)

        while len(self._ended_threads) > _MAX_RETAINED_THREAD_IDENTITIES:
            victim = self._next_action_cohort_retention_victim(
                self._ended_threads  # type: ignore[arg-type]
            )
            if victim is None:
                break
            heap, key, _thread = victim
            assert isinstance(key, tuple)
            journal.retention_expiring_indexes.append(
                self._capture_action_cohort_expiring_key(
                    self._ended_threads,  # type: ignore[arg-type]
                    key,
                )
            )
            heapq.heappop(heap)
            self._ended_threads.pop(key, None)

    def _commit_prevalidated_action_cohort(
        self,
        prepared: _PreparedActionCohortCommitPlan,
    ) -> None:
        """Apply one prevalidated cohort using only primitive no-fail writes."""

        plan = prepared.plan
        sessions = prepared.sessions
        processes = prepared.processes
        for session in sessions:
            self._commit_prevalidated_session_materialization(
                session.plan,
                advance_version=False,
                update_state_time=False,
                prepared=session,
                emit_log=False,
            )
        for process in processes:
            self._commit_prevalidated_process_materialization(
                process.plan,
                advance_version=False,
                update_state_time=False,
                prepared=process,
                emit_log=False,
            )
        for session_links in plan._session_process_links:
            session = sessions[session_links.session_index].session
            links = session_links.links
            transport_pid = processes[links.transport].process.pid if links.transport >= 0 else None
            session.transport_pid = transport_pid or session.transport_pid
            session.session_shell_pid = (
                processes[links.shell].process.pid if links.shell >= 0 else None
            )
            session.session_user_manager_pid = (
                processes[links.user_manager].process.pid if links.user_manager >= 0 else None
            )
            session.session_winlogon_pid = (
                processes[links.winlogon].process.pid if links.winlogon >= 0 else None
            )
            session.process_tree_root = (
                processes[links.process_tree_root].process.pid
                if links.process_tree_root >= 0
                else None
            )
            explorer_pid = processes[links.explorer].process.pid if links.explorer >= 0 else None
            if explorer_pid is not None:
                session.explorer_pid = explorer_pid
                session.initial_explorer_pid = explorer_pid
                session.windows_shell_bootstrapped = True

        for patch in plan._live_session_process_roles:
            self._commit_action_cohort_live_session_process_roles(patch)
        for patch in plan._session_metadata:
            self._commit_action_cohort_session_metadata(patch)
        for patch in plan._process_activity:
            identity = self._action_process_identity(patch.target)
            process = self._processes_by_object_id[identity.object_id]
            if (
                process.last_activity_time is None
                or process.last_activity_time < patch.activity_time
            ):
                process.last_activity_time = patch.activity_time
        for patch in plan._session_activity:
            identity = self._action_session_identity(patch.target)
            session = self._active_sessions[self._resolve_logon_id(identity.logon_id)]
            if (
                session.last_activity_time is None
                or session.last_activity_time < patch.activity_time
            ):
                session.last_activity_time = patch.activity_time

        for termination in prepared.process_terminations:
            self._commit_prevalidated_process_termination_materialization(
                termination.plan,
                advance_version=False,
                prepared=termination,
                emit_log=False,
                enforce_retention=False,
            )
        for terminalization in prepared.session_terminalizations:
            self._commit_action_cohort_session_terminalization(terminalization)
        self._commit_action_cohort_retention_evictions(prepared)
        self.state.current_time = plan.final_state_time
        self._materialization_version = prepared.committed_version

    def validate_materialization_batch(self, plan: MaterializationBatchPlan) -> None:
        """Validate every batch member and dependency without publishing state."""

        with self._lock:
            self._validate_materialization_batch_plan(plan)
            if plan.expected_version != self._materialization_version:
                raise StateError("Materialization batch became stale before commit")
            if self.state.current_time != plan._expected_state_time:
                raise StateError("Materialization batch state-time fence changed before commit")
            if not self._materialization_batch_admission_epoch_matches(plan):
                raise StateError("Materialization batch crossed its State admission fence")
            session = plan.session
            if session is not None:
                identity = session.identity
                if identity.logon_id in self.state.active_sessions:
                    raise StateError(
                        f"Session materialization LogonID is already live: {identity.logon_id}"
                    )
                if identity.logon_id in self._ended_sessions:
                    raise StateError(
                        f"Session materialization LogonID is already ended: {identity.logon_id}"
                    )
            link_values = {
                "transport": plan._session_process_links.transport,
                "shell": plan._session_process_links.shell,
                "user_manager": plan._session_process_links.user_manager,
                "winlogon": plan._session_process_links.winlogon,
                "explorer": plan._session_process_links.explorer,
                "process_tree_root": plan._session_process_links.process_tree_root,
            }
            if any(index >= 0 for index in link_values.values()) and session is None:
                raise StateError("Session process links require a batch session")
            for role, index in link_values.items():
                if index < 0:
                    continue
                if index >= len(plan.processes):
                    raise StateError(f"Session {role} link index is outside the batch")
                process_identity = plan.processes[index].identity
                assert session is not None
                if role != "transport" and process_identity.hostname != session.identity.hostname:
                    raise StateError(f"Session {role} process cannot use another host")
                if role in {"shell", "user_manager", "explorer"} and (
                    process_identity.logon_id != session.identity.logon_id
                ):
                    raise StateError(f"Session {role} process must belong to the session")

            staged_processes: dict[str, ProcessIdentity] = {}
            staged_processes_by_pid: dict[tuple[str, int], ProcessIdentity] = {}
            staged_pids: set[tuple[str, int]] = set()
            staged_threads: set[tuple[str, str, int]] = set()
            for process in plan.processes:
                identity = process.identity
                primary_thread = identity.primary_thread
                if primary_thread is None:
                    raise StateError("Process materialization plan has no primary thread")
                process_key = (identity.hostname, identity.pid)
                if process_key in self.state.running_processes or process_key in staged_pids:
                    raise StateError(
                        f"Process materialization PID is already live: {identity.hostname} "
                        f"PID={identity.pid}"
                    )
                if (
                    identity.object_id in self._processes_by_object_id
                    or identity.object_id in staged_processes
                ):
                    raise StateError(
                        f"Process materialization object is already live: {identity.object_id}"
                    )
                thread_key = (
                    primary_thread.hostname,
                    primary_thread.process_object_id,
                    primary_thread.tid,
                )
                if thread_key in self.state.running_threads or thread_key in staged_threads:
                    raise StateError(
                        f"Process materialization primary thread is already live: {thread_key!r}"
                    )
                if identity.parent_pid not in {0, 4}:
                    planned_parent = staged_processes_by_pid.get(
                        (identity.hostname, identity.parent_pid)
                    )
                    if planned_parent is None and not self.is_process_active_at(
                        identity.hostname,
                        identity.parent_pid,
                        identity.started_at,
                    ):
                        raise StateError(
                            f"Process materialization parent PID {identity.parent_pid} "
                            "is not active"
                        )
                    if (
                        planned_parent is not None
                        and planned_parent.started_at > identity.started_at
                    ):
                        raise StateError("Batch process parent starts after its child")
                if process._payload.require_session and not identity.logon_id:
                    raise StateError("Session-owned process materialization requires a LogonID")
                if process._payload.require_session and identity.logon_id:
                    planned_session = (
                        session is not None
                        and session.identity.logon_id == identity.logon_id
                        and session.identity.hostname == identity.hostname
                        and session.identity.started_at <= identity.started_at
                    )
                    if (
                        not planned_session
                        and self.get_session_at(
                            identity.logon_id,
                            identity.started_at,
                        )
                        is None
                    ):
                        raise StateError(
                            f"Cannot materialize batch process outside session {identity.logon_id}"
                        )
                token_session = (
                    session
                    if session is not None and session.identity.logon_id == identity.logon_id
                    else None
                )
                live_session = (
                    self.get_session_at(identity.logon_id, identity.started_at)
                    if identity.logon_id and token_session is None
                    else None
                )
                expected_session_id = (
                    token_session.identity.session_id
                    if token_session is not None
                    else live_session.session_id
                    if live_session is not None
                    else None
                )
                expected_logon_type = (
                    token_session.logon_type
                    if token_session is not None
                    else live_session.logon_type
                    if live_session is not None
                    else None
                )
                if (token_session is not None or live_session is not None) and (
                    process.auth_session_id != expected_session_id
                    or process.auth_logon_type != expected_logon_type
                ):
                    raise StateError("Process auth token disagrees with its owning session")
                staged_processes[identity.object_id] = identity
                staged_processes_by_pid[process_key] = identity
                staged_pids.add(process_key)
                staged_threads.add(thread_key)

    def _commit_prevalidated_materialization_batch(
        self,
        plan: MaterializationBatchPlan,
        *,
        advance_version: bool = True,
        update_state_time: bool = True,
    ) -> tuple[ActiveSession | None, tuple[RunningProcess, ...]]:
        """Publish all prevalidated members with primitive writes and one version step."""

        for hostname, boot_time in plan.boot_times:
            self._system_boot_times[hostname] = boot_time
        session = (
            self._commit_prevalidated_session_materialization(
                plan.session,
                advance_version=False,
                update_state_time=False,
            )
            if plan.session is not None
            else None
        )
        processes = tuple(
            self._commit_prevalidated_process_materialization(
                process,
                advance_version=False,
                update_state_time=False,
            )
            for process in plan.processes
        )
        if session is not None:
            links = plan._session_process_links

            def _linked_pid(index: int) -> int | None:
                return processes[index].pid if index >= 0 else None

            session.transport_pid = _linked_pid(links.transport) or session.transport_pid
            session.session_shell_pid = _linked_pid(links.shell)
            session.session_user_manager_pid = _linked_pid(links.user_manager)
            session.session_winlogon_pid = _linked_pid(links.winlogon)
            session.process_tree_root = _linked_pid(links.process_tree_root)
            explorer_pid = _linked_pid(links.explorer)
            if explorer_pid is not None:
                session.explorer_pid = explorer_pid
                session.initial_explorer_pid = explorer_pid
                session.windows_shell_bootstrapped = True
        if update_state_time:
            self.state.current_time = plan.final_state_time
        if advance_version:
            self._materialization_version += 1
        return session, processes

    def validate_process_materialization(self, plan: ProcessMaterializationPlan) -> None:
        """Validate every fallible process-start condition without publishing state."""

        with self._lock:
            self._validate_process_materialization_plan(plan)
            if plan.expected_version != self._materialization_version:
                raise StateError("Process materialization plan became stale before commit")
            identity = plan.identity
            primary_thread = identity.primary_thread
            if primary_thread is None:
                raise StateError("Process materialization plan has no primary thread")
            process_key = (identity.hostname, identity.pid)
            if process_key in self.state.running_processes:
                raise StateError(
                    f"Process materialization PID is already live: {identity.hostname} "
                    f"PID={identity.pid}"
                )
            if identity.object_id in self._processes_by_object_id:
                raise StateError(
                    f"Process materialization object is already live: {identity.object_id}"
                )
            thread_key = (
                primary_thread.hostname,
                primary_thread.process_object_id,
                primary_thread.tid,
            )
            if thread_key in self.state.running_threads:
                raise StateError(
                    f"Process materialization primary thread is already live: {thread_key!r}"
                )
            if identity.parent_pid not in {0, 4} and not self.is_process_active_at(
                identity.hostname,
                identity.parent_pid,
                identity.started_at,
            ):
                raise StateError(
                    f"Process materialization parent PID {identity.parent_pid} is not active"
                )
            if plan._payload.require_session and not identity.logon_id:
                raise StateError("Session-owned process materialization requires a LogonID")
            owning_session = (
                self.get_session_at(identity.logon_id, identity.started_at)
                if identity.logon_id
                else None
            )
            if plan._payload.require_session and owning_session is None:
                raise StateError(f"Cannot materialize process outside session {identity.logon_id}")
            if owning_session is not None and (
                plan.auth_session_id != owning_session.session_id
                or plan.auth_logon_type != owning_session.logon_type
            ):
                raise StateError("Process auth token disagrees with its owning session")

    def _commit_prevalidated_process_materialization(
        self,
        plan: ProcessMaterializationPlan,
        *,
        advance_version: bool = True,
        update_state_time: bool = True,
        prepared: _PreparedActionCohortProcessStart | None = None,
        emit_log: bool = True,
    ) -> RunningProcess:
        """Perform primitive process writes after validation under materialization_guard."""

        patch = plan._allocator_patch
        if patch.pid_counter is not None:
            host, counter = patch.pid_counter
            self._pid_counters[host] = counter
        if patch.pid_os is not None:
            host, category = patch.pid_os
            self._pid_os[host] = category
        if patch.pid_rng_state is not None:
            host, rng_state = patch.pid_rng_state
            if prepared is not None and prepared.pid_rng_replacement is not None:
                self._pid_rngs[host] = prepared.pid_rng_replacement
            else:
                rng = self._pid_rngs.setdefault(host, random.Random())
                rng.setstate(rng_state)
        if patch.pid_epoch is not None:
            host, epoch = patch.pid_epoch
            self._pid_time_epochs[host] = epoch
        if patch.pid_weekly_prefix is not None:
            host, prefix = patch.pid_weekly_prefix
            self._linux_pid_weekly_churn_prefixes[host] = prefix
        if patch.linux_allocation is not None:
            host, at, logical_position = patch.linux_allocation
            allocations = self._linux_pid_allocations.get(host)
            if allocations is None:
                allocations = (
                    prepared.linux_pid_allocations_default
                    if prepared is not None and prepared.linux_pid_allocations_default is not None
                    else TemporalAllocationIndex()
                )
                self._linux_pid_allocations[host] = allocations
            allocations.add(at, logical_position)
        if patch.pid_bucket_offset is not None:
            key, offset = patch.pid_bucket_offset
            self._pid_bucket_offsets[key] = offset
        if patch.fixed_pid is not None:
            host, pid = patch.fixed_pid
            reservations = self._fixed_pid_reservations.get(host)
            if reservations is None:
                reservations = (
                    prepared.fixed_pid_reservations_default
                    if prepared is not None and prepared.fixed_pid_reservations_default is not None
                    else set()
                )
                self._fixed_pid_reservations[host] = reservations
            reservations.add(pid)
        self._pid_allocation_count += patch.pid_allocation_count_delta
        self._pid_candidate_probe_count += patch.pid_candidate_probe_delta
        if patch.thread_counter is not None:
            host, counter = patch.thread_counter
            self._thread_id_counters[host] = counter
        if patch.thread_rng_state is not None:
            host, rng_state = patch.thread_rng_state
            if prepared is not None and prepared.thread_rng_replacement is not None:
                self._thread_id_rngs[host] = prepared.thread_rng_replacement
            else:
                rng = self._thread_id_rngs.setdefault(host, random.Random())
                rng.setstate(rng_state)

        payload = plan._payload
        if update_state_time:
            self.state.current_time = payload.state_time
        identity = plan.identity
        if payload.parent_activity_time is not None and identity.parent_pid:
            parent = self.state.running_processes.get((identity.hostname, identity.parent_pid))
            if parent is not None and (
                parent.last_activity_time is None
                or parent.last_activity_time < payload.parent_activity_time
            ):
                parent.last_activity_time = payload.parent_activity_time
        prepared_start = prepared or self._prepare_action_cohort_process_start(plan)
        process = prepared_start.process
        key = (process.system, process.pid)
        self.state.running_processes[key] = process
        self._active_pid_reservation_counts[process.system] = (
            self._active_pid_reservation_counts.get(process.system, 0) + 1
        )
        self._process_object_ids[key] = process.ecar_object_id
        self._processes_by_object_id[process.ecar_object_id] = process
        self._ended_processes_by_key.pop(key, None)
        thread = prepared_start.thread
        self.state.running_threads[(thread.hostname, thread.process_object_id, thread.tid)] = thread
        self._ended_threads.pop((thread.hostname, thread.process_object_id, thread.tid), None)
        if advance_version:
            self._materialization_version += 1
        if emit_log:
            logger.debug(
                "Materialized process %s on %s: %s",
                process.pid,
                process.system,
                process.image,
            )
        return process

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
        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "advance_pid_allocation_watermark"
        )
        normalized_cutoff = ensure_utc(cutoff)
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "advance_pid_allocation_watermark",
                admitted_at=admission_epoch,
            )
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
            self._materialization_version += 1

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
        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "allocate_transient_linux_pid"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "allocate_transient_linux_pid",
                admitted_at=admission_epoch,
            )
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
            self._materialization_version += 1
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

        admission_epoch = self._reject_mutation_during_action_cohort_claim("register_process")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "register_process", admitted_at=admission_epoch
            )
            plan = self.plan_process_materialization(
                system=system,
                fixed_pid=pid,
                parent_pid=parent_pid,
                image=image,
                command_line=command_line,
                username=username,
                integrity_level=integrity_level,
                os_category=os_category,
                start_time=start_time,
                logon_id=logon_id,
                lifecycle_group_id=lifecycle_group_id,
                parent_lifecycle_group_id=parent_lifecycle_group_id,
            )
            with self.materialization_guard(plan.expected_version):
                return self.materialize_process(plan)

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
        concurrency_group_id: str = "",
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
        admission_epoch = self._reject_mutation_during_action_cohort_claim("create_process")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "create_process", admitted_at=admission_epoch
            )
            if self.state.current_time is None:
                raise StateError("Cannot create process: current_time not set")
            os_category = self._pid_os.get(system) or (
                "windows" if "\\" in image or image.casefold().endswith(".exe") else "linux"
            )
            plan = self.plan_process_materialization(
                system=system,
                parent_pid=parent_pid,
                image=image,
                command_line=command_line,
                username=username,
                integrity_level=integrity_level,
                os_category=os_category,
                logon_id=logon_id,
                lifecycle_group_id=lifecycle_group_id,
                parent_lifecycle_group_id=parent_lifecycle_group_id,
                concurrency_group_id=concurrency_group_id,
            )
            with self.materialization_guard(plan.expected_version):
                return self.materialize_process(plan).pid

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

        admission_epoch = self._reject_mutation_during_action_cohort_claim("create_thread")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "create_thread",
                admitted_at=admission_epoch,
            )
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
            thread_key = (system, process_object_id, thread_id)
            was_live = thread_key in self.state.running_threads
            thread = self._register_thread(
                process,
                tid=thread_id,
                kind=kind,
                start_time=effective_start,
            )
            if not was_live:
                self._materialization_version += 1
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

        admission_epoch = self._reject_mutation_during_action_cohort_claim("end_thread")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "end_thread",
                admitted_at=admission_epoch,
            )
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
            if process.logon_id:
                session = self.state.active_sessions.get(self._resolve_logon_id(process.logon_id))
                if session is not None and not _session_valid_at(session, effective_time):
                    return False
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
        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "update_process_activity_time"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "update_process_activity_time",
                admitted_at=admission_epoch,
            )
            proc = self.state.running_processes.get((system, pid))
            if proc is None:
                return False
            activity_time = ensure_utc(activity_time)
            if proc.logon_id:
                session = self.state.active_sessions.get(self._resolve_logon_id(proc.logon_id))
                if session is not None and not _session_valid_at(session, activity_time):
                    return False
            if proc.last_activity_time is None or activity_time > proc.last_activity_time:
                proc.last_activity_time = activity_time
            return True

    def assign_process_to_session(self, system: str, pid: int, logon_id: str) -> bool:
        """Attach a running process to its owning active session.

        This is used when a tuple-scoped responder must be materialized before
        authentication has finished allocating the session identity. Secondary
        indexes are refreshed so later session closure can find the process.
        The process token LogonID remains the immutable identity recorded when
        the process was created; session membership is a lifecycle relationship,
        not a token replacement.
        """
        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "assign_process_to_session"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "assign_process_to_session",
                admitted_at=admission_epoch,
            )
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

    def publish_process_auth_identity(
        self,
        system: str,
        pid: int,
        *,
        logon_id: str,
        session_id: int,
        logon_type: int,
    ) -> bool:
        """Freeze the authentication identity rendered for a process lifecycle."""
        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "publish_process_auth_identity"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "publish_process_auth_identity",
                admitted_at=admission_epoch,
            )
            process = self.state.running_processes.get((system, pid))
            if process is None:
                return False
            published = (
                process.token_logon_id,
                process.auth_session_id,
                process.auth_logon_type,
            )
            candidate = (logon_id, session_id, logon_type)
            if process.auth_session_id is not None and published != candidate:
                raise StateError(
                    "Cannot replace published process authentication identity for "
                    f"{system} pid={pid}: {published} -> {candidate}"
                )
            if process.token_logon_id and process.token_logon_id != logon_id:
                raise StateError(
                    "Process token LogonID disagrees with its create occurrence for "
                    f"{system} pid={pid}: {process.token_logon_id} -> {logon_id}"
                )
            process.token_logon_id = logon_id
            process.auth_session_id = session_id
            process.auth_logon_type = logon_type
            return True

    def update_session_activity_time(self, logon_id: str, activity_time: datetime) -> bool:
        """Record the latest dependent activity timestamp for an active session."""
        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "update_session_activity_time"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "update_session_activity_time",
                admitted_at=admission_epoch,
            )
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
        admission_epoch = self._reject_mutation_during_action_cohort_claim("mark_story_process")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "mark_story_process",
                admitted_at=admission_epoch,
            )
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
        admission_epoch = self._reject_mutation_during_action_cohort_claim("end_process")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "end_process",
                admitted_at=admission_epoch,
            )
            if self.state.running_processes.get((system, pid)) is None:
                return False
            plan = self.plan_process_termination_materialization(
                system=system,
                pid=pid,
                end_time=end_time,
            )
            self.materialize_process_termination(plan)
            return True

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
        for logon_id, ended in self._ended_sessions.expire_before(cutoff, inclusive=True):
            self._cleanup_ended_session_retention_entry(logon_id, ended)
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

    @staticmethod
    def _connection_parent_snapshot(connection: OpenConnection) -> _ConnectionParentSnapshot:
        """Freeze every retained physical field relevant to child accounting."""

        return _ConnectionParentSnapshot(
            conn_id=connection.conn_id,
            zeek_uid=connection.zeek_uid,
            src_ip=connection.src_ip,
            src_port=connection.src_port,
            dst_ip=connection.dst_ip,
            dst_port=connection.dst_port,
            protocol=connection.protocol,
            state=connection.state,
            start_time=connection.start_time,
            source_system=connection.source_system,
            source_hostname=connection.source_hostname,
            hostname=connection.hostname,
            initiating_pid=connection.initiating_pid,
            close_time=connection.close_time,
            bytes_sent=connection.bytes_sent,
            bytes_received=connection.bytes_received,
            traffic_ledger=connection.traffic_ledger,
            transaction_id=connection.transaction_id,
            conn_state=connection.conn_state,
            history=connection.history,
            duration=connection.duration,
        )

    def _connection_existing_session_state(
        self,
        identity: SessionIdentity,
    ) -> ConnectionExistingSessionState:
        """Snapshot one exact active session for an RDP transport transition."""

        session = self._active_sessions.get(self._resolve_logon_id(identity.logon_id))
        if (
            session is None
            or session.ecar_object_id != identity.object_id
            or self.get_session_identity(session.logon_id) != identity
        ):
            raise StateError("RDP connection session identity is absent or drifted")
        return ConnectionExistingSessionState(
            identity=identity,
            logon_type=session.logon_type,
            source_ip=session.source_ip,
            source_port=session.source_port,
            transport_pid=session.transport_pid,
            network_close_time=session.network_close_time,
            source_ready_time=session.source_ready_time,
            closure_owned_by_bundle=session.closure_owned_by_bundle,
            end_plan=session.end_plan,
        )

    def _connection_existing_session_process_roles_state(
        self,
        identity: SessionIdentity,
    ) -> ConnectionExistingSessionProcessRolesState:
        """Snapshot every mutable process role for one exact live session."""

        session = self._active_sessions.get(self._resolve_logon_id(identity.logon_id))
        if (
            session is None
            or session.ecar_object_id != identity.object_id
            or self.get_session_identity(session.logon_id) != identity
        ):
            raise StateError("Connection session process-role identity is absent or drifted")
        return ConnectionExistingSessionProcessRolesState(
            transport_pid=session.transport_pid,
            session_shell_pid=session.session_shell_pid,
            session_user_manager_pid=session.session_user_manager_pid,
            session_winlogon_pid=session.session_winlogon_pid,
            explorer_pid=session.explorer_pid,
            initial_explorer_pid=session.initial_explorer_pid,
            process_tree_root=session.process_tree_root,
            windows_shell_bootstrapped=session.windows_shell_bootstrapped,
        )

    def prepare_connection_existing_session_start_patch(
        self,
        identity: SessionIdentity,
        *,
        username: str,
        target_system: str,
        start_time: datetime,
        source_ready_time: datetime,
        source_ip: str,
        source_port: int,
        transport_pid: int | None,
        lifecycle_group_id: str,
        network_close_time: datetime,
        session_kind: str,
        closure_owned_by_bundle: bool = False,
        end_plan: SessionEndPlan | None = None,
    ) -> ConnectionExistingSessionPatch:
        """Prepare an exact unpublished RDP/SSH session transition."""

        with self._capability_minting_guard("prepare_connection_existing_session_start_patch"):
            if type(identity) is not SessionIdentity:
                raise TypeError("Connection session start patch requires an exact identity")
            if identity.hostname != target_system:
                raise StateError("Connection session start patch targets another session host")
            if session_kind not in {"rdp", "ssh"}:
                raise StateError("Connection session start patch requires RDP or SSH ownership")
            if not username.strip() or not lifecycle_group_id.strip():
                raise StateError(
                    "Connection session start patch requires a principal and lifecycle group"
                )
            if type(closure_owned_by_bundle) is not bool:
                raise TypeError("Connection session closure ownership requires an exact bool")
            before = self._connection_existing_session_state(identity)
            if before.logon_type != 10 or identity.session_kind != session_kind:
                raise StateError(
                    "Connection session start patch requires a live Type-10 protocol session"
                )
            if before.network_close_time is not None or before.source_ready_time is not None:
                raise StateError(
                    "Connection session start patch cannot repurpose a transport-bound session"
                )
            started_at = ensure_utc(start_time)
            ready_at = ensure_utc(source_ready_time)
            closed_at = ensure_utc(network_close_time)
            if ready_at < started_at or closed_at <= ready_at:
                raise StateError(
                    "Connection session start patch requires ordered start/readiness/close"
                )
            normalized_end = end_plan
            if normalized_end is not None:
                if type(normalized_end) is not SessionEndPlan:
                    raise TypeError("Connection session start requires an exact end plan")
                normalized_end = replace(
                    normalized_end,
                    canonical_end=ensure_utc(normalized_end.canonical_end),
                )
                if normalized_end.canonical_end < closed_at:
                    raise StateError("Connection session end plan precedes its network close")
            after_identity = replace(
                identity,
                principal=username,
                session_kind=session_kind,
                started_at=started_at,
                lifecycle_group_id=lifecycle_group_id,
                logon_guid=(
                    identity.logon_guid
                    or self._stable_logon_guid(identity.hostname, identity.logon_id)
                ),
            )
            after = ConnectionExistingSessionState(
                identity=after_identity,
                logon_type=10,
                source_ip=source_ip,
                source_port=source_port,
                transport_pid=transport_pid,
                network_close_time=closed_at,
                source_ready_time=ready_at,
                closure_owned_by_bundle=closure_owned_by_bundle,
                end_plan=normalized_end,
            )
            expected_version = self._materialization_version
            expected_state_time = self.state.current_time
            admission_epoch = self._prepared_state_admission_epoch
            disposition = ConnectionExistingSessionLifecycleDisposition.START
            return ConnectionExistingSessionPatch(
                before=before,
                after=after,
                lifecycle_disposition=disposition,
                _expected_version=expected_version,
                _expected_state_time=expected_state_time,
                _admission_epoch=admission_epoch,
                _integrity_token=_connection_existing_session_patch_integrity_token(
                    self._materialization_secret,
                    before,
                    after,
                    lifecycle_disposition=disposition,
                    expected_version=expected_version,
                    expected_state_time=expected_state_time,
                    admission_epoch=admission_epoch,
                ),
            )

    def prepare_rdp_connection_existing_session_patch(
        self,
        identity: SessionIdentity,
        *,
        username: str,
        target_system: str,
        start_time: datetime,
        source_ip: str,
        source_port: int,
        transport_pid: int | None,
        lifecycle_group_id: str,
        network_close_time: datetime,
    ) -> ConnectionExistingSessionPatch:
        """Prepare an allocation-free exact preallocated-session RDP transition."""

        return self.prepare_connection_existing_session_start_patch(
            identity,
            username=username,
            target_system=target_system,
            start_time=start_time,
            source_ready_time=start_time,
            source_ip=source_ip,
            source_port=source_port,
            transport_pid=transport_pid,
            lifecycle_group_id=lifecycle_group_id,
            network_close_time=network_close_time,
            session_kind="rdp",
        )

    def prepare_connection_live_session_patch(
        self,
        identity: SessionIdentity,
        *,
        source_ip: str,
        source_port: int,
        transport_pid: int | None,
        source_ready_time: datetime | None,
        network_close_time: datetime,
        end_plan: SessionEndPlan | None = None,
    ) -> ConnectionExistingSessionPatch:
        """Prepare an exact metadata transition for an already-published session."""

        with self._capability_minting_guard("prepare_connection_live_session_patch"):
            if type(identity) is not SessionIdentity:
                raise TypeError("Live connection patch requires an exact session identity")
            before = self._connection_existing_session_state(identity)
            if identity.session_kind not in {"rdp", "ssh"}:
                raise StateError("Live connection patch requires an RDP or SSH session")
            closed_at = ensure_utc(network_close_time)
            ready_at = ensure_utc(source_ready_time) if source_ready_time is not None else None
            if ready_at is not None and closed_at <= ready_at:
                raise StateError("Live connection patch requires close after readiness")
            selected_end = before.end_plan
            if end_plan is not None:
                if type(end_plan) is not SessionEndPlan:
                    raise TypeError("Live connection patch requires an exact end plan")
                normalized_end = replace(
                    end_plan,
                    canonical_end=ensure_utc(end_plan.canonical_end),
                )
                if normalized_end.canonical_end < closed_at:
                    raise StateError("Live connection session end plan precedes network close")
                if (
                    selected_end is not None
                    and selected_end.is_hard_deadline
                    and selected_end != normalized_end
                ):
                    raise StateError("Live connection cannot replace a hard session end plan")
                selected_end = normalized_end
            after = ConnectionExistingSessionState(
                identity=identity,
                logon_type=before.logon_type,
                source_ip=source_ip,
                source_port=source_port,
                transport_pid=transport_pid,
                network_close_time=closed_at,
                source_ready_time=ready_at,
                closure_owned_by_bundle=before.closure_owned_by_bundle,
                end_plan=selected_end,
            )
            expected_version = self._materialization_version
            expected_state_time = self.state.current_time
            admission_epoch = self._prepared_state_admission_epoch
            disposition = ConnectionExistingSessionLifecycleDisposition.EXISTING
            return ConnectionExistingSessionPatch(
                before=before,
                after=after,
                lifecycle_disposition=disposition,
                _expected_version=expected_version,
                _expected_state_time=expected_state_time,
                _admission_epoch=admission_epoch,
                _integrity_token=_connection_existing_session_patch_integrity_token(
                    self._materialization_secret,
                    before,
                    after,
                    lifecycle_disposition=disposition,
                    expected_version=expected_version,
                    expected_state_time=expected_state_time,
                    admission_epoch=admission_epoch,
                ),
            )

    def _validate_connection_existing_session_patch_preimage(
        self,
        patch: ConnectionExistingSessionPatch,
    ) -> None:
        """Authenticate one exact live-session transition and its State fence."""

        if type(patch) is not ConnectionExistingSessionPatch:
            raise StateError("Connection composite has an unsupported session patch")
        expected_integrity = _connection_existing_session_patch_integrity_token(
            self._materialization_secret,
            patch.before,
            patch.after,
            lifecycle_disposition=patch.lifecycle_disposition,
            expected_version=patch._expected_version,
            expected_state_time=patch._expected_state_time,
            admission_epoch=patch._admission_epoch,
        )
        if not hmac.compare_digest(patch._integrity_token, expected_integrity):
            raise StateError("Connection session patch integrity validation failed")
        admission_epoch_matches = patch._admission_epoch == self._prepared_state_admission_epoch
        active_claim = self._active_prepared_state_claim
        if (
            not admission_epoch_matches
            and type(active_claim) is _PreparedConnectionCompositeMaterializationRecord
            and active_claim.plan.existing_session_patch is patch
            and active_claim.claim_epoch == self._prepared_state_admission_epoch
            and patch._admission_epoch + 1 == active_claim.claim_epoch
        ):
            admission_epoch_matches = True
        if (
            patch._expected_version != self._materialization_version
            or patch._expected_state_time != self.state.current_time
            or not admission_epoch_matches
        ):
            raise StateError("Connection session patch crossed its State admission fence")
        if self._connection_existing_session_state(patch.before.identity) != patch.before:
            raise StateError("Connection session before-state drifted")

    def _validate_rdp_connection_existing_session_patch(
        self,
        patch: ConnectionExistingSessionPatch,
        transaction: NetworkTransactionPlan,
        *,
        initiating_pid: int,
    ) -> None:
        """Recheck an exact preallocated-session transition at the State fence."""

        self._validate_connection_existing_session_patch_preimage(patch)
        after = patch.after
        identity = after.identity
        disposition = patch.lifecycle_disposition
        expected_port = 3389 if identity.session_kind == "rdp" else 22
        if (
            transaction.protocol.casefold() != "tcp"
            or transaction.dst_port != expected_port
            or transaction.outcome != "success"
            or transaction.conn_state.upper() != "SF"
            or transaction.closed_at is None
        ):
            raise StateError("Connection session patch requires a successful protocol root")
        if (
            after.source_ip != transaction.src_ip
            or after.source_port != transaction.src_port
            or after.network_close_time != transaction.closed_at
        ):
            raise StateError("Connection session source/timing disagrees with its transport")
        if disposition is ConnectionExistingSessionLifecycleDisposition.START:
            if after.logon_type != 10 or identity.session_kind not in {"rdp", "ssh"}:
                raise StateError("Connection session start patch lost its Type-10 identity")
            if not transaction.started_at <= identity.started_at < transaction.closed_at:
                raise StateError("Connection session start falls outside its transport")
            if after.source_ready_time is None or not (
                identity.started_at <= after.source_ready_time < transaction.closed_at
            ):
                raise StateError("Connection session readiness disagrees with authentication")
            if identity.session_kind == "rdp" and after.source_ready_time != identity.started_at:
                raise StateError("RDP session readiness must equal its authentication start")
            expected_transport_pid = (
                initiating_pid
                if identity.session_kind == "rdp" and initiating_pid > 0
                else transaction.responding_pid
                if identity.session_kind == "ssh" and transaction.responding_pid > 0
                else None
            )
            if after.transport_pid != expected_transport_pid:
                raise StateError("Connection session process disagrees with its transport owner")
        else:
            if identity.session_kind not in {"rdp", "ssh"}:
                raise StateError("Existing connection session has an unsupported kind")
            if after.source_ready_time is not None and not (
                transaction.started_at <= after.source_ready_time < transaction.closed_at
            ):
                raise StateError("Existing connection session readiness falls outside transport")

    def _validate_connection_existing_session_process_batch(
        self,
        patch: ConnectionExistingSessionPatch,
        batch: MaterializationBatchPlan,
    ) -> None:
        """Bind a process-only start batch to one exact patched session preimage."""

        if type(patch) is not ConnectionExistingSessionPatch:
            raise StateError("Existing-session process batch requires an exact session patch")
        if type(batch) is not MaterializationBatchPlan or batch.session is not None:
            raise StateError("Existing-session process batch cannot contain a State session")
        if (
            batch.expected_version != patch._expected_version
            or batch._expected_state_time != patch._expected_state_time
            or batch.admission_epoch != patch._admission_epoch
        ):
            raise StateError("Existing-session process batch crossed its session patch State fence")
        target = patch.after
        target_identity = target.identity
        target_logon_id = self._resolve_logon_id(target_identity.logon_id)
        seen_objects: set[str] = set()
        seen_instances: set[tuple[str, int]] = set()
        for process in batch.processes:
            identity = process.identity
            instance = (identity.hostname, identity.pid)
            if identity.object_id in seen_objects or instance in seen_instances:
                raise StateError("Existing-session process batch repeats a process member")
            seen_objects.add(identity.object_id)
            seen_instances.add(instance)
            if not identity.logon_id:
                continue
            process_logon_id = self._resolve_logon_id(identity.logon_id)
            if process_logon_id != target_logon_id:
                continue
            if identity.hostname != target_identity.hostname:
                raise StateError(
                    "Existing-session process cannot bind the target LogonID across hosts"
                )
            if identity.started_at < target_identity.started_at:
                raise StateError(
                    "Existing-session process cannot predate its patched target session"
                )
            if (
                process.auth_session_id != target_identity.session_id
                or process.auth_logon_type != target.logon_type
            ):
                raise StateError(
                    "Existing-session process authentication disagrees with its target session"
                )

    @staticmethod
    def _connection_existing_session_role_plans(
        patch: ConnectionExistingSessionProcessRolesPatch,
    ) -> tuple[tuple[str, ProcessMaterializationPlan | None], ...]:
        """Return one stable ordered view of every target-session role plan."""

        return (
            ("transport", patch.transport_plan),
            ("shell", patch.shell_plan),
            ("user_manager", patch.user_manager_plan),
            ("winlogon", patch.winlogon_plan),
            ("explorer", patch.explorer_plan),
            ("process_tree_root", patch.process_tree_root_plan),
        )

    @staticmethod
    def _connection_existing_session_expected_role_state(
        patch: ConnectionExistingSessionProcessRolesPatch,
    ) -> ConnectionExistingSessionProcessRolesState:
        """Derive the only valid role postimage from exact member plans."""

        before = patch.before
        explorer_pid = (
            patch.explorer_plan.identity.pid
            if patch.explorer_plan is not None
            else before.explorer_pid
        )
        return replace(
            before,
            transport_pid=(
                patch.transport_plan.identity.pid
                if patch.transport_plan is not None
                else before.transport_pid
            ),
            session_shell_pid=(
                patch.shell_plan.identity.pid
                if patch.shell_plan is not None
                else before.session_shell_pid
            ),
            session_user_manager_pid=(
                patch.user_manager_plan.identity.pid
                if patch.user_manager_plan is not None
                else before.session_user_manager_pid
            ),
            session_winlogon_pid=(
                patch.winlogon_plan.identity.pid
                if patch.winlogon_plan is not None
                else before.session_winlogon_pid
            ),
            explorer_pid=explorer_pid,
            initial_explorer_pid=(
                explorer_pid
                if patch.explorer_plan is not None and before.initial_explorer_pid is None
                else before.initial_explorer_pid
            ),
            process_tree_root=(
                patch.process_tree_root_plan.identity.pid
                if patch.process_tree_root_plan is not None
                else before.process_tree_root
            ),
            windows_shell_bootstrapped=(
                True if patch.explorer_plan is not None else before.windows_shell_bootstrapped
            ),
        )

    def prepare_connection_existing_session_process_roles_patch(
        self,
        existing_session_patch: ConnectionExistingSessionPatch,
        batch: MaterializationBatchPlan,
        *,
        transport_plan: ProcessMaterializationPlan | None = None,
        shell_plan: ProcessMaterializationPlan | None = None,
        user_manager_plan: ProcessMaterializationPlan | None = None,
        winlogon_plan: ProcessMaterializationPlan | None = None,
        explorer_plan: ProcessMaterializationPlan | None = None,
        process_tree_root_plan: ProcessMaterializationPlan | None = None,
    ) -> ConnectionExistingSessionProcessRolesPatch:
        """Prepare target-session roles backed by exact process-only batch members."""

        with self._capability_minting_guard(
            "prepare_connection_existing_session_process_roles_patch"
        ):
            self._validate_connection_existing_session_patch_preimage(existing_session_patch)
            self.validate_materialization_batch(batch)
            self._validate_connection_existing_session_process_batch(
                existing_session_patch,
                batch,
            )
            plans = (
                transport_plan,
                shell_plan,
                user_manager_plan,
                winlogon_plan,
                explorer_plan,
                process_tree_root_plan,
            )
            if not any(plan is not None for plan in plans):
                raise StateError("Connection session process-role patch cannot be empty")
            current = self._connection_existing_session_process_roles_state(
                existing_session_patch.before.identity
            )
            before = replace(
                current,
                transport_pid=existing_session_patch.after.transport_pid,
            )
            capability = _ConnectionExistingSessionProcessRolesCapability()
            patch = ConnectionExistingSessionProcessRolesPatch(
                target=existing_session_patch.after.identity,
                before=before,
                after=before,
                transport_plan=transport_plan,
                shell_plan=shell_plan,
                user_manager_plan=user_manager_plan,
                winlogon_plan=winlogon_plan,
                explorer_plan=explorer_plan,
                process_tree_root_plan=process_tree_root_plan,
                _expected_version=existing_session_patch._expected_version,
                _expected_state_time=existing_session_patch._expected_state_time,
                _admission_epoch=existing_session_patch._admission_epoch,
                _capability=capability,
                _integrity_token="",
            )
            object.__setattr__(
                patch,
                "after",
                self._connection_existing_session_expected_role_state(patch),
            )
            object.__setattr__(
                patch,
                "_integrity_token",
                _connection_existing_session_process_roles_integrity_token(
                    self._materialization_secret,
                    patch,
                ),
            )
            capability.bind(patch)
            self._validate_connection_existing_session_process_roles_patch(
                patch,
                existing_session_patch=existing_session_patch,
                batch=batch,
            )
            return patch

    def prepare_deferred_session_state_authority(
        self,
        *,
        protocol: DeferredSessionProtocol,
        binding_disposition: DeferredSessionBindingDisposition,
        bound_at: datetime,
        batch: MaterializationBatchPlan,
        existing_session_patch: ConnectionExistingSessionPatch | None = None,
        existing_session_process_roles_patch: (
            ConnectionExistingSessionProcessRolesPatch | None
        ) = None,
    ) -> DeferredSessionStateAuthority:
        """Issue one exact strict deferred-session State handoff."""

        with self._capability_minting_guard("prepare_deferred_session_state_authority"):
            capability = _DeferredSessionStateAuthorityCapability()
            owner_identity = id(self)
            admission_epoch = batch.admission_epoch
            integrity = _deferred_session_state_authority_integrity_token(
                self._materialization_secret,
                protocol=protocol,
                binding_disposition=binding_disposition,
                bound_at=bound_at,
                batch=batch,
                existing_session_patch=existing_session_patch,
                existing_session_process_roles_patch=(existing_session_process_roles_patch),
                owner_identity=owner_identity,
                admission_epoch=admission_epoch,
                capability=capability,
            )
            payload = DeferredSessionStateAuthority(
                protocol=protocol,
                binding_disposition=binding_disposition,
                bound_at=bound_at,
                batch=batch,
                existing_session_patch=existing_session_patch,
                existing_session_process_roles_patch=(existing_session_process_roles_patch),
                _owner=self,
                _owner_identity=owner_identity,
                _admission_epoch=admission_epoch,
                _capability=capability,
                _integrity_token=integrity,
            )
            capability.bind_payload(payload)
            self._validate_deferred_session_state_authority(payload)
            return payload

    def authenticates_deferred_session_state_authority(
        self,
        payload: object,
        *,
        outer_authority: object | None = None,
    ) -> bool:
        """Return whether this owner issued the intact exact payload and outer binding."""

        try:
            with self._capability_minting_guard("authenticates_deferred_session_state_authority"):
                self._validate_deferred_session_state_authority(
                    payload,
                    outer_authority=outer_authority,
                )
        except (AttributeError, StateError, TypeError, ValueError):
            return False
        return True

    def authenticates_deferred_session_state_payload(self, payload: object) -> bool:
        """Authenticate payload contents before or after its exact outer binding."""

        try:
            with self._capability_minting_guard("authenticates_deferred_session_state_payload"):
                self._validate_deferred_session_state_authority(
                    payload,
                    allow_bound_without_outer=True,
                )
        except (AttributeError, StateError, TypeError, ValueError):
            return False
        return True

    def bind_deferred_session_state_authority(
        self,
        payload: DeferredSessionStateAuthority,
        outer_authority: object,
    ) -> None:
        """Bind a strict State handoff to its final resolved network authority once."""

        from evidenceforge.generation.actions.network_connection import (
            DeferredSessionNetworkAuthority,
        )

        with self._capability_minting_guard("bind_deferred_session_state_authority"):
            self._validate_deferred_session_state_authority(payload)
            if type(outer_authority) is not DeferredSessionNetworkAuthority:
                raise StateError(
                    "Deferred session State authority requires the exact network wrapper"
                )
            if outer_authority.strict_state_authority is not payload:
                raise StateError("Deferred session State authority was replaced in transit")
            if outer_authority.strict_state_authority_bound:
                raise StateError("Deferred session State authority network handoff was replayed")
            if outer_authority.kind.value != payload.protocol.value:
                raise StateError("Deferred session State authority crossed protocol owners")
            if outer_authority.binding_disposition is not payload.binding_disposition:
                raise StateError("Deferred session State disposition changed in transit")
            integrity = _deferred_session_outer_authority_integrity_token(
                self._materialization_secret,
                payload,
                outer_authority,
            )
            payload._capability.bind_outer(outer_authority, integrity)

    def _validate_deferred_session_state_authority(
        self,
        payload: object,
        *,
        outer_authority: object | None = None,
        allow_bound_without_outer: bool = False,
    ) -> None:
        """Authenticate one strict payload without changing State or its capability."""

        if type(payload) is not DeferredSessionStateAuthority:
            raise StateError("Deferred session State authority has an unsupported exact type")
        assert isinstance(payload, DeferredSessionStateAuthority)
        if payload._owner is not self or payload._owner_identity != id(self):
            raise StateError("Deferred session State authority belongs to another owner")
        if payload._capability.payload is not payload:
            raise StateError("Deferred session State authority is not its exact capability")
        if payload._admission_epoch != payload.batch.admission_epoch:
            raise StateError("Deferred session State authority changed its admission epoch")
        expected = _deferred_session_state_authority_integrity_token(
            self._materialization_secret,
            protocol=payload.protocol,
            binding_disposition=payload.binding_disposition,
            bound_at=payload.bound_at,
            batch=payload.batch,
            existing_session_patch=payload.existing_session_patch,
            existing_session_process_roles_patch=(payload.existing_session_process_roles_patch),
            owner_identity=payload._owner_identity,
            admission_epoch=payload._admission_epoch,
            capability=payload._capability,
        )
        if not hmac.compare_digest(payload.publication_token, expected):
            raise StateError("Deferred session State authority integrity validation failed")
        self.validate_materialization_batch(payload.batch)
        if not payload.batch.processes:
            raise StateError("Deferred session State authority requires process members")
        self._validate_deferred_session_state_authority_semantics(payload)
        if outer_authority is None:
            if payload._capability.outer_authority is not None and not allow_bound_without_outer:
                raise StateError("Deferred session State authority already owns a network handoff")
            return
        if payload._capability.outer_authority is not outer_authority:
            raise StateError("Deferred session State authority owns another network wrapper")
        outer_integrity = _deferred_session_outer_authority_integrity_token(
            self._materialization_secret,
            payload,
            outer_authority,
        )
        if not hmac.compare_digest(payload._capability.outer_integrity, outer_integrity):
            raise StateError("Deferred session outer network authority integrity failed")

    def _validate_deferred_session_state_authority_semantics(
        self,
        payload: DeferredSessionStateAuthority,
    ) -> None:
        """Require the exact NEW/PREALLOCATED/ACTIVE State member shape."""

        disposition = payload.binding_disposition
        batch = payload.batch
        patch = payload.existing_session_patch
        roles = payload.existing_session_process_roles_patch
        if disposition is DeferredSessionBindingDisposition.NEW_SESSION:
            if patch is not None or roles is not None or batch.session is None:
                raise StateError(
                    "NEW deferred session authority requires only a session+process batch"
                )
            if batch.session.identity.session_kind != payload.protocol.value:
                raise StateError("NEW deferred session authority changed protocol identity")
            expected_bound = (
                batch.session._payload.source_ready_time or batch.session.identity.started_at
            )
            if payload.bound_at != expected_bound:
                raise StateError("NEW deferred session authority changed its binding time")
            self._validate_new_deferred_session_process_shape(payload)
            return

        if batch.session is not None or patch is None:
            raise StateError(
                "Existing deferred session authority requires a process-only batch and patch"
            )
        expected_lifecycle_disposition = (
            ConnectionExistingSessionLifecycleDisposition.START
            if disposition is DeferredSessionBindingDisposition.PREALLOCATED_SESSION_START
            else ConnectionExistingSessionLifecycleDisposition.EXISTING
        )
        if patch.lifecycle_disposition is not expected_lifecycle_disposition:
            raise StateError("Deferred session binding disposition disagrees with its patch")
        if patch.after.identity.session_kind != payload.protocol.value:
            raise StateError("Deferred existing session authority changed protocol identity")
        expected_bound = patch.after.source_ready_time or patch.after.identity.started_at
        if payload.bound_at != expected_bound:
            raise StateError("Deferred existing session authority changed its binding time")
        self._validate_connection_existing_session_patch_preimage(patch)
        self._validate_connection_existing_session_process_batch(patch, batch)
        target_plans = tuple(
            plan
            for plan in batch.processes
            if plan.identity.hostname == patch.after.identity.hostname
        )
        self._validate_deferred_cross_host_processes(payload, target_plans)
        if (
            disposition is DeferredSessionBindingDisposition.ACTIVE_SESSION
            and payload.protocol is DeferredSessionProtocol.RDP
            and target_plans
        ):
            raise StateError("ACTIVE RDP reconnect cannot start target-session processes")
        if (
            disposition is DeferredSessionBindingDisposition.PREALLOCATED_SESSION_START
            and not target_plans
        ):
            raise StateError("PREALLOCATED deferred session requires target process members")
        if target_plans:
            if roles is None:
                raise StateError(
                    "Deferred target process members require an exact session role patch"
                )
            self._validate_connection_existing_session_process_roles_patch(
                roles,
                existing_session_patch=patch,
                batch=batch,
            )
            role_plans = {
                id(plan)
                for _role, plan in self._connection_existing_session_role_plans(roles)
                if plan is not None
            }
            if role_plans != {id(plan) for plan in target_plans}:
                raise StateError("Deferred target process members and role patch disagree exactly")
        elif roles is not None:
            raise StateError("Source-only deferred session cannot carry target role bindings")

    def _validate_new_deferred_session_process_shape(
        self,
        payload: DeferredSessionStateAuthority,
    ) -> None:
        """Require new target members to be exact session-linked process roles."""

        batch = payload.batch
        session = batch.session
        assert session is not None
        target_plans = tuple(
            plan for plan in batch.processes if plan.identity.hostname == session.identity.hostname
        )
        if not target_plans:
            raise StateError("NEW deferred session requires target process members")
        self._validate_deferred_cross_host_processes(payload, target_plans)
        links = batch._session_process_links
        ordered_indexes = (
            links.transport,
            links.shell,
            links.user_manager,
            links.winlogon,
            links.explorer,
            links.process_tree_root,
        )
        linked_plans = {id(batch.processes[index]) for index in ordered_indexes if index >= 0}
        if linked_plans != {id(plan) for plan in target_plans}:
            raise StateError("NEW deferred target processes lack exact session role bindings")
        if payload.protocol is DeferredSessionProtocol.SSH:
            if (
                links.transport < 0
                or links.process_tree_root != links.transport
                or any(index >= 0 for index in (links.user_manager, links.winlogon, links.explorer))
            ):
                raise StateError("NEW SSH session has invalid receiver process roles")
        elif (
            links.transport >= 0
            or links.shell >= 0
            or min(
                links.user_manager,
                links.winlogon,
                links.explorer,
                links.process_tree_root,
            )
            < 0
            or links.process_tree_root != links.winlogon
        ):
            raise StateError("NEW RDP session has invalid target process roles")

    def _validate_deferred_cross_host_processes(
        self,
        payload: DeferredSessionStateAuthority,
        target_plans: tuple[ProcessMaterializationPlan, ...],
    ) -> None:
        """Reject disguised same-host sources and foreign cross-host sessions."""

        target_ids = {id(plan) for plan in target_plans}
        target_identity = (
            payload.batch.session.identity
            if payload.batch.session is not None
            else payload.existing_session_patch.after.identity
            if payload.existing_session_patch is not None
            else None
        )
        assert target_identity is not None
        for plan in payload.batch.processes:
            identity = plan.identity
            if id(plan) in target_ids:
                continue
            if identity.hostname == target_identity.hostname:
                raise StateError(
                    "Deferred source process cannot disguise itself on the target host"
                )
            if not identity.logon_id:
                continue
            source_session = self.get_session_identity(identity.logon_id)
            if (
                source_session is None
                or source_session.hostname != identity.hostname
                or plan.auth_session_id != source_session.session_id
            ):
                raise StateError(
                    "Deferred cross-host process requires its exact live State session"
                )

    def _validate_connection_existing_session_process_roles_patch(
        self,
        patch: ConnectionExistingSessionProcessRolesPatch,
        *,
        existing_session_patch: ConnectionExistingSessionPatch,
        batch: MaterializationBatchPlan,
    ) -> None:
        """Authenticate exact role membership and before/after projections."""

        if type(patch) is not ConnectionExistingSessionProcessRolesPatch:
            raise StateError("Connection session process-role patch has an unsupported type")
        if patch._capability.patch is not patch:
            raise StateError("Connection session process-role patch is not its exact capability")
        expected_integrity = _connection_existing_session_process_roles_integrity_token(
            self._materialization_secret,
            patch,
        )
        if not hmac.compare_digest(patch._integrity_token, expected_integrity):
            raise StateError("Connection session process-role patch integrity validation failed")
        if (
            patch.target != existing_session_patch.after.identity
            or patch._expected_version != existing_session_patch._expected_version
            or patch._expected_state_time != existing_session_patch._expected_state_time
            or patch._admission_epoch != existing_session_patch._admission_epoch
            or batch.expected_version != patch._expected_version
            or batch._expected_state_time != patch._expected_state_time
            or batch.admission_epoch != patch._admission_epoch
        ):
            raise StateError("Connection session process-role patch crossed its exact State fence")
        current = self._connection_existing_session_process_roles_state(
            existing_session_patch.before.identity
        )
        expected_before = replace(
            current,
            transport_pid=existing_session_patch.after.transport_pid,
        )
        if patch.before != expected_before:
            raise StateError("Connection session process-role before-state drifted")

        role_plans = self._connection_existing_session_role_plans(patch)
        if not any(plan is not None for _role, plan in role_plans):
            raise StateError("Connection session process-role patch cannot be empty")
        target = patch.target
        target_logon_id = self._resolve_logon_id(target.logon_id)
        for role, plan in role_plans:
            if plan is None:
                continue
            if not any(plan is member for member in batch.processes):
                raise StateError(f"Connection session {role} role replaced its exact batch member")
            identity = plan.identity
            if identity.hostname != target.hostname:
                raise StateError(f"Connection session {role} role belongs to another host")
            if identity.started_at < target.started_at:
                raise StateError(f"Connection session {role} role predates its target session")
            is_rdp_system_root = (
                target.session_kind == "rdp"
                and role in {"winlogon", "process_tree_root"}
                and plan is patch.winlogon_plan
            )
            if is_rdp_system_root:
                basename = identity.image.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
                if (
                    identity.logon_id.casefold() != "0x3e7"
                    or identity.principal.casefold() != "system"
                    or basename != "winlogon.exe"
                ):
                    raise StateError("Connection session winlogon role is incompatible")
            else:
                process_logon_id = self._resolve_logon_id(identity.logon_id)
                if process_logon_id != target_logon_id:
                    raise StateError(f"Connection session {role} role belongs to another session")
                if (
                    plan.auth_session_id != target.session_id
                    or plan.auth_logon_type != existing_session_patch.after.logon_type
                ):
                    raise StateError(
                        f"Connection session {role} role has incompatible authentication"
                    )
                if role in {"shell", "user_manager", "explorer"} and (
                    identity.principal.casefold() != target.principal.casefold()
                ):
                    raise StateError(f"Connection session {role} principal is incompatible")
            if role == "transport":
                if (
                    target.session_kind != "ssh"
                    or identity.pid != existing_session_patch.after.transport_pid
                ):
                    raise StateError("Connection session transport role is incompatible")
            if role == "explorer" and target.session_kind != "rdp":
                raise StateError("Connection session Explorer role requires RDP")

            before_pid = (
                existing_session_patch.before.transport_pid
                if role == "transport"
                else getattr(patch.before, f"session_{role}_pid", None)
                if role in {"shell", "user_manager", "winlogon"}
                else patch.before.explorer_pid
                if role == "explorer"
                else patch.before.process_tree_root
            )
            if (
                before_pid is not None
                and before_pid != identity.pid
                and self.is_process_active_at(target.hostname, before_pid, identity.started_at)
            ):
                raise StateError(f"Connection session {role} role cannot overwrite a live process")

        if target.session_kind == "rdp":
            if (patch.winlogon_plan is None) != (patch.process_tree_root_plan is None):
                raise StateError("RDP winlogon and process-tree root must be staged together")
            if (
                patch.winlogon_plan is not None
                and patch.process_tree_root_plan is not patch.winlogon_plan
            ):
                raise StateError("RDP process-tree root must be its exact staged winlogon")
            if patch.transport_plan is not None or patch.shell_plan is not None:
                raise StateError("RDP source transport cannot enter target-session roles")
        else:
            if patch.winlogon_plan is not None or patch.explorer_plan is not None:
                raise StateError("SSH target-session roles cannot contain Windows desktop plans")
            if (
                patch.process_tree_root_plan is not None
                and patch.process_tree_root_plan is not patch.transport_plan
            ):
                raise StateError("SSH process-tree root must be its exact receiver process")

        expected_after = self._connection_existing_session_expected_role_state(patch)
        if patch.after != expected_after:
            raise StateError("Connection session process-role after-state drifted")

    def _materialization_batch_admission_epoch_matches(
        self,
        plan: MaterializationBatchPlan,
    ) -> bool:
        """Return whether a batch still owns its exact prepared-State lane epoch."""

        if plan.admission_epoch == self._prepared_state_admission_epoch:
            return True
        active = self._active_prepared_state_claim
        current_epoch = self._prepared_state_admission_epoch
        if plan.admission_epoch + 1 != current_epoch:
            return False
        if type(active) is _PreparedConnectionCompositeMaterializationRecord:
            return active.plan.batch is plan and active.claim_epoch == current_epoch
        if type(active) is _PreparedMaterializationBatchRecord:
            return active.plan is plan and active.claim_epoch == current_epoch
        return False

    @staticmethod
    def _normalize_process_activity_patches(
        patches: tuple[ProcessActivityPatch, ...],
    ) -> tuple[ProcessActivityPatch, ...]:
        """Coalesce exact process objects to one stable maximum frontier."""

        normalized: dict[str, ProcessActivityPatch] = {}
        for patch in patches:
            object_id = patch.identity.object_id
            if not object_id:
                raise StateError("Process activity patch requires an exact object identity")
            activity_time = ensure_utc(patch.activity_time)
            existing = normalized.get(object_id)
            if existing is not None and existing.identity != patch.identity:
                raise StateError("Process activity patches disagree on exact object identity")
            if existing is None or activity_time > existing.activity_time:
                normalized[object_id] = ProcessActivityPatch(patch.identity, activity_time)
        return tuple(
            normalized[object_id]
            for object_id in sorted(
                normalized,
                key=lambda candidate: (
                    normalized[candidate].identity.hostname,
                    candidate,
                ),
            )
        )

    @staticmethod
    def _normalize_session_activity_patches(
        patches: tuple[SessionActivityPatch, ...],
    ) -> tuple[SessionActivityPatch, ...]:
        """Coalesce exact session objects to one stable maximum frontier."""

        normalized: dict[str, SessionActivityPatch] = {}
        for patch in patches:
            object_id = patch.identity.object_id
            if not object_id:
                raise StateError("Session activity patch requires an exact object identity")
            activity_time = ensure_utc(patch.activity_time)
            existing = normalized.get(object_id)
            if existing is not None and existing.identity != patch.identity:
                raise StateError("Session activity patches disagree on exact object identity")
            if existing is None or activity_time > existing.activity_time:
                normalized[object_id] = SessionActivityPatch(patch.identity, activity_time)
        return tuple(
            normalized[object_id]
            for object_id in sorted(
                normalized,
                key=lambda candidate: (
                    normalized[candidate].identity.hostname,
                    candidate,
                ),
            )
        )

    def begin_connection_planning(self, owner_rng: random.Random) -> ConnectionPlanningCursor:
        """Start an isolated, allocation-free connection-planning transaction."""

        with self._capability_minting_guard("begin_connection_planning"):
            entry_state = owner_rng.getstate()
            token = _connection_cursor_integrity_token(
                self._materialization_secret,
                expected_version=self._materialization_version,
                expected_state_time=self.state.current_time,
                expected_connection_counter=self._connection_id_counter,
                owner_identity=id(owner_rng),
                rng_state_entry=entry_state,
            )
            return ConnectionPlanningCursor(
                self,
                expected_version=self._materialization_version,
                expected_state_time=self.state.current_time,
                expected_connection_counter=self._connection_id_counter,
                admission_epoch=self._prepared_state_admission_epoch,
                owner_rng=owner_rng,
                rng_state_entry=entry_state,
                cursor_token=token,
            )

    def _validate_connection_cursor(self, cursor: ConnectionPlanningCursor) -> None:
        """Validate a live cursor without sealing or sampling it."""

        if cursor._manager is not self:
            raise StateError("Connection planning cursor belongs to another StateManager")
        cursor._require_active()
        if cursor._admission_epoch != self._prepared_state_admission_epoch:
            raise StateError("Connection planning cursor crossed a prepared-State claim")
        expected = _connection_cursor_integrity_token(
            self._materialization_secret,
            expected_version=cursor._expected_version,
            expected_state_time=cursor._expected_state_time,
            expected_connection_counter=cursor._expected_connection_counter,
            owner_identity=cursor._owner_identity,
            rng_state_entry=cursor._rng_state_entry,
        )
        if not hmac.compare_digest(cursor._cursor_token, expected):
            raise StateError("Connection planning cursor integrity validation failed")
        if cursor._expected_version != self._materialization_version:
            raise StateError("Connection planning cursor became stale")
        if cursor._expected_state_time != self.state.current_time:
            raise StateError("Connection planning cursor state-time fence changed")
        if cursor._expected_connection_counter != self._connection_id_counter:
            raise StateError("Connection allocator changed during isolated planning")
        if cursor._owner_rng.getstate() != cursor._rng_state_entry:
            raise StateError("Connection planning RNG owner changed during isolated planning")

    def _reserve_connection_cursor_identity(
        self,
        cursor: ConnectionPlanningCursor,
    ) -> ConnectionIdentityPlan:
        """Perform the exact historical UID draw on a live isolated cursor."""

        with self._capability_minting_guard("ConnectionPlanningCursor.reserve_identity"):
            self._validate_connection_cursor(cursor)
            if cursor._identity is not None:
                raise StateError("Connection planning cursor already reserved an identity")
            if self._connection_id_counter > 999_999_999:
                raise StateError("Connection ID counter exhausted")
            preview_rng = cursor._preview_rng
            if preview_rng is None:
                raise StateError("Connection planning cursor has no active RNG")
            rng_state_before = preview_rng.getstate()
            zeek_uid = generate_zeek_uid_from_rng(preview_rng, "C")
            rng_state_after_identity = preview_rng.getstate()
            counter_after = self._connection_id_counter + 1
            conn_id = f"conn-{self._connection_id_counter}"
            identity = ConnectionIdentityPlan(
                _expected_version=cursor.expected_version,
                _conn_id=conn_id,
                _zeek_uid=zeek_uid,
                _counter_after=counter_after,
                _rng_state_before=rng_state_before,
                _rng_state_after_identity=rng_state_after_identity,
                _integrity_token=_connection_identity_integrity_token(
                    self._materialization_secret,
                    expected_version=cursor.expected_version,
                    conn_id=conn_id,
                    zeek_uid=zeek_uid,
                    counter_after=counter_after,
                    rng_state_before=rng_state_before,
                    rng_state_after_identity=rng_state_after_identity,
                ),
            )
            cursor._identity = identity
            cursor._identity_binding_token = _connection_cursor_identity_binding_token(
                self._materialization_secret,
                cursor_token=cursor._cursor_token,
                identity_token=identity.publication_token,
            )
            return identity

    def _validate_application_child_transaction(
        self,
        transaction: NetworkTransactionPlan,
        parent: OpenConnection,
    ) -> None:
        """Validate exact reuse and immutable interval containment."""

        if not transaction.application_layer_only:
            raise StateError("Application-child composite requires application_layer_only")
        if transaction.conn_id != parent.conn_id or transaction.zeek_uid != parent.zeek_uid:
            raise StateError("Application-child transaction changed parent connection identity")
        if (
            transaction.src_ip != parent.src_ip
            or transaction.src_port != parent.src_port
            or transaction.dst_ip != parent.dst_ip
            or transaction.dst_port != parent.dst_port
            or transaction.protocol != parent.protocol
        ):
            raise StateError("Application-child transaction changed parent network tuple")
        if parent.close_time is None or transaction.closed_at is None:
            raise StateError("Application-child transaction requires a closed parent interval")
        if ensure_utc(transaction.started_at) < ensure_utc(parent.start_time) or ensure_utc(
            transaction.closed_at
        ) > ensure_utc(parent.close_time):
            raise StateError("Application-child transaction is outside its parent interval")

    def _validate_connection_activity_patches(
        self,
        process_activity: tuple[ProcessActivityPatch, ...],
        session_activity: tuple[SessionActivityPatch, ...],
        batch: MaterializationBatchPlan | None,
        existing_session_patch: ConnectionExistingSessionPatch | None = None,
    ) -> None:
        """Validate exact live or staged owners for all activity frontiers."""

        staged_processes = (
            {process.identity.object_id: process.identity for process in batch.processes}
            if batch is not None
            else {}
        )
        staged_session = batch.session.identity if batch is not None and batch.session else None
        if staged_session is None and existing_session_patch is not None:
            staged_session = existing_session_patch.after.identity
        for patch in process_activity:
            expected = staged_processes.get(patch.identity.object_id)
            if expected is None:
                live = self._processes_by_object_id.get(patch.identity.object_id)
                expected = self._process_identity(live) if live is not None else None
            if expected != patch.identity:
                raise StateError("Process activity patch does not name an exact live owner")
            if ensure_utc(patch.activity_time) < ensure_utc(patch.identity.started_at):
                raise StateError("Process activity patch precedes process start")
        for patch in session_activity:
            expected = (
                staged_session
                if staged_session is not None
                and staged_session.object_id == patch.identity.object_id
                else None
            )
            if expected is None:
                live = self.state.active_sessions.get(
                    self._resolve_logon_id(patch.identity.logon_id)
                )
                if live is not None and live.ecar_object_id == patch.identity.object_id:
                    expected = self.get_session_identity(live.logon_id)
            if expected != patch.identity:
                raise StateError("Session activity patch does not name an exact live owner")
            if ensure_utc(patch.activity_time) < ensure_utc(patch.identity.started_at):
                raise StateError("Session activity patch precedes session start")

    def finalize_connection_composite_materialization(
        self,
        cursor: ConnectionPlanningCursor,
        transaction: NetworkTransactionPlan,
        *,
        source_system: str = "",
        source_hostname: str = "",
        hostname: str = "",
        initiating_pid: int = -1,
        mode: ConnectionMaterializationMode = ConnectionMaterializationMode.PHYSICAL,
        batch: MaterializationBatchPlan | None = None,
        rdp_existing_session_patch: ConnectionExistingSessionPatch | None = None,
        existing_session_process_roles_patch: (
            ConnectionExistingSessionProcessRolesPatch | None
        ) = None,
        process_activity: tuple[ProcessActivityPatch, ...] = (),
        session_activity: tuple[SessionActivityPatch, ...] = (),
    ) -> ConnectionCompositeMaterializationPlan:
        """Seal one physical/child transaction and optional start batch without mutation."""

        with self._capability_minting_guard("finalize_connection_composite_materialization"):
            self._validate_connection_cursor(cursor)
            if not isinstance(mode, ConnectionMaterializationMode):
                raise StateError("Connection composite requires an explicit typed mode")
            normalized_process_activity = self._normalize_process_activity_patches(process_activity)
            normalized_session_activity = self._normalize_session_activity_patches(session_activity)
            if batch is not None:
                self.validate_materialization_batch(batch)
                if batch.expected_version != cursor.expected_version:
                    raise StateError("Connection composite batch uses another State version")
                if batch._expected_state_time != cursor._expected_state_time:
                    raise StateError("Connection composite batch uses another state-time fence")
            if rdp_existing_session_patch is not None:
                if batch is not None and batch.session is not None:
                    raise StateError(
                        "Existing-session patch cannot also materialize a new State session"
                    )
                if mode is not ConnectionMaterializationMode.PHYSICAL:
                    raise StateError("RDP existing-session patch requires a physical transport")
                self._validate_rdp_connection_existing_session_patch(
                    rdp_existing_session_patch,
                    transaction,
                    initiating_pid=initiating_pid,
                )
                if batch is not None:
                    self._validate_connection_existing_session_process_batch(
                        rdp_existing_session_patch,
                        batch,
                    )
            if existing_session_process_roles_patch is not None:
                if rdp_existing_session_patch is None or batch is None:
                    raise StateError(
                        "Connection session process roles require one session patch and batch"
                    )
                self._validate_connection_existing_session_process_roles_patch(
                    existing_session_process_roles_patch,
                    existing_session_patch=rdp_existing_session_patch,
                    batch=batch,
                )
            self._validate_connection_activity_patches(
                normalized_process_activity,
                normalized_session_activity,
                batch,
                rdp_existing_session_patch,
            )

            identity = cursor._identity
            parent_patch: _ConnectionParentAccountingPatch | None = None
            if mode is ConnectionMaterializationMode.PHYSICAL:
                if identity is None:
                    raise StateError("Physical connection composite requires reserved identity")
                self._validate_connection_identity_plan(identity)
                expected_binding = _connection_cursor_identity_binding_token(
                    self._materialization_secret,
                    cursor_token=cursor._cursor_token,
                    identity_token=identity.publication_token,
                )
                if not hmac.compare_digest(
                    cursor._identity_binding_token,
                    expected_binding,
                ):
                    raise StateError("Physical identity belongs to another planning cursor")
                if transaction.application_layer_only:
                    raise StateError("Physical connection cannot be application-layer-only")
                if transaction.conn_id != identity.conn_id:
                    raise StateError("Physical connection transaction ID changed after planning")
                if transaction.zeek_uid != identity.zeek_uid:
                    raise StateError("Physical connection Zeek UID changed after planning")
                if transaction.conn_id in self.state.open_connections:
                    raise StateError(
                        f"Connection materialization ID is already live: {transaction.conn_id}"
                    )
                if self._open_connections.find("zeek_uid", transaction.zeek_uid):
                    raise StateError(
                        f"Connection materialization UID is already live: {transaction.zeek_uid}"
                    )
            else:
                if identity is not None or cursor._identity_binding_token:
                    raise StateError("Application-child composite cannot reserve a new identity")
                parent = self.state.open_connections.get(transaction.conn_id)
                if parent is None:
                    raise StateError(
                        f"Application-child composite references unknown {transaction.conn_id}"
                    )
                self._validate_application_child_transaction(transaction, parent)
                before = self._connection_parent_snapshot(parent)
                parent_patch = _ConnectionParentAccountingPatch(
                    before=before,
                    after_traffic=before.traffic_ledger.accumulate(transaction.traffic),
                )

            times = [ensure_utc(transaction.started_at)]
            if transaction.closed_at is not None:
                times.append(ensure_utc(transaction.closed_at))
            if cursor._expected_state_time is not None:
                times.append(ensure_utc(cursor._expected_state_time))
            if batch is not None:
                times.append(ensure_utc(batch.final_state_time))
            times.extend(patch.activity_time for patch in normalized_process_activity)
            times.extend(patch.activity_time for patch in normalized_session_activity)
            final_state_time = max(times)
            rng_state_final = cursor._seal()
            validated_rng = random.Random()
            validated_rng.setstate(rng_state_final)
            plan = ConnectionCompositeMaterializationPlan(
                _expected_version=cursor._expected_version,
                _expected_state_time=cursor._expected_state_time,
                _expected_connection_counter=cursor._expected_connection_counter,
                _owner_rng=cursor._owner_rng,
                _owner_identity=cursor._owner_identity,
                _rng_state_entry=cursor._rng_state_entry,
                _rng_state_final=rng_state_final,
                _cursor_token=cursor._cursor_token,
                _identity=identity,
                _transaction=transaction,
                _source_system=source_system,
                _source_hostname=source_hostname,
                _hostname=hostname,
                _initiating_pid=initiating_pid,
                _mode=mode,
                _parent_patch=parent_patch,
                _batch=batch,
                _existing_session_patch=rdp_existing_session_patch,
                _existing_session_process_roles_patch=(existing_session_process_roles_patch),
                _process_activity=normalized_process_activity,
                _session_activity=normalized_session_activity,
                _final_state_time=final_state_time,
                _integrity_token="",
            )
            token = _connection_composite_integrity_token(
                self._materialization_secret,
                expected_version=plan._expected_version,
                expected_state_time=plan._expected_state_time,
                expected_connection_counter=plan._expected_connection_counter,
                owner_identity=plan._owner_identity,
                rng_state_entry=plan._rng_state_entry,
                rng_state_final=plan._rng_state_final,
                cursor_token=plan._cursor_token,
                identity=plan._identity,
                transaction=plan._transaction,
                source_system=plan._source_system,
                source_hostname=plan._source_hostname,
                hostname=plan._hostname,
                initiating_pid=plan._initiating_pid,
                mode=plan._mode,
                parent_patch=plan._parent_patch,
                batch=plan._batch,
                existing_session_patch=plan._existing_session_patch,
                existing_session_process_roles_patch=(plan._existing_session_process_roles_patch),
                process_activity=plan._process_activity,
                session_activity=plan._session_activity,
                final_state_time=plan._final_state_time,
            )
            return replace(plan, _integrity_token=token)

    def _validate_connection_composite_semantics(
        self,
        plan: ConnectionCompositeMaterializationPlan,
        owner_rng: random.Random,
    ) -> None:
        """Validate every fallible composite condition under the State guard."""

        self._validate_connection_composite_plan_integrity(plan)
        if plan.expected_version != self._materialization_version:
            raise StateError("Connection composite became stale before commit")
        if self.state.current_time != plan._expected_state_time:
            raise StateError("Connection composite state-time fence changed before commit")
        if self._connection_id_counter != plan._expected_connection_counter:
            raise StateError("Connection allocator changed before composite commit")
        if owner_rng is not plan._owner_rng or id(owner_rng) != plan._owner_identity:
            raise StateError("Connection composite belongs to another RNG owner")
        if owner_rng.getstate() != plan._rng_state_entry:
            raise StateError("Connection composite RNG owner changed before commit")
        validated_rng = random.Random()
        validated_rng.setstate(plan._rng_state_final)

        if plan.materializes_connection:
            identity = plan._identity
            if identity is None:
                raise StateError("Physical connection composite has no reserved identity")
            if identity.expected_version != plan.expected_version:
                raise StateError("Physical connection identity uses another State version")
            if identity._counter_after != self._connection_id_counter + 1:
                raise StateError("Physical connection allocator changed after planning")
            transaction = plan.transaction
            if transaction.application_layer_only:
                raise StateError("Physical connection cannot be application-layer-only")
            if transaction.conn_id != identity.conn_id or transaction.zeek_uid != identity.zeek_uid:
                raise StateError("Physical connection identity changed after planning")
            if transaction.conn_id in self.state.open_connections:
                raise StateError(
                    f"Connection materialization ID is already live: {transaction.conn_id}"
                )
            if self._open_connections.find("zeek_uid", transaction.zeek_uid):
                raise StateError(
                    f"Connection materialization UID is already live: {transaction.zeek_uid}"
                )
            if plan._parent_patch is not None:
                raise StateError("Physical connection composite carries child accounting")
        else:
            if plan._identity is not None:
                raise StateError("Application-child composite reserved a physical identity")
            patch = plan._parent_patch
            if patch is None:
                raise StateError("Application-child composite has no parent accounting patch")
            parent = self.state.open_connections.get(plan.transaction.conn_id)
            if parent is None:
                raise StateError(
                    f"Application-child composite references unknown {plan.transaction.conn_id}"
                )
            if self._connection_parent_snapshot(parent) != patch.before:
                raise StateError("Application-child parent changed after planning")
            self._validate_application_child_transaction(plan.transaction, parent)
            if patch.after_traffic != parent.traffic_ledger.accumulate(plan.transaction.traffic):
                raise StateError("Application-child accounting changed after planning")

        if plan.batch is not None:
            self.validate_materialization_batch(plan.batch)
        if plan.existing_session_patch is not None:
            if not plan.materializes_connection:
                raise StateError("Session patch lost its physical connection ownership")
            if plan.batch is not None and plan.batch.session is not None:
                raise StateError("Session patch cannot carry a second State session")
            self._validate_rdp_connection_existing_session_patch(
                plan.existing_session_patch,
                plan.transaction,
                initiating_pid=plan._initiating_pid,
            )
            if plan.batch is not None:
                self._validate_connection_existing_session_process_batch(
                    plan.existing_session_patch,
                    plan.batch,
                )
        roles_patch = plan.existing_session_process_roles_patch
        if roles_patch is not None:
            if plan.existing_session_patch is None or plan.batch is None:
                raise StateError(
                    "Connection session process roles lost their session patch or batch"
                )
            self._validate_connection_existing_session_process_roles_patch(
                roles_patch,
                existing_session_patch=plan.existing_session_patch,
                batch=plan.batch,
            )
        self._validate_connection_activity_patches(
            plan.process_activity,
            plan.session_activity,
            plan.batch,
            plan.existing_session_patch,
        )
        times = [ensure_utc(plan.transaction.started_at)]
        if plan.transaction.closed_at is not None:
            times.append(ensure_utc(plan.transaction.closed_at))
        if plan._expected_state_time is not None:
            times.append(ensure_utc(plan._expected_state_time))
        if plan.batch is not None:
            times.append(ensure_utc(plan.batch.final_state_time))
        times.extend(patch.activity_time for patch in plan.process_activity)
        times.extend(patch.activity_time for patch in plan.session_activity)
        if plan.final_state_time != max(times):
            raise StateError("Connection composite final State frontier changed")

    def validate_connection_composite_materialization(
        self,
        plan: ConnectionCompositeMaterializationPlan,
        owner_rng: random.Random,
    ) -> None:
        """Validate an exact connection composite without publishing any state."""

        with self._lock:
            self._validate_connection_composite_semantics(plan, owner_rng)

    @contextmanager
    def prepared_connection_composite_materialization(
        self,
        plan: ConnectionCompositeMaterializationPlan,
        owner_rng: random.Random,
    ) -> Iterator[PreparedConnectionCompositeMaterialization]:
        """Claim the State guard after all composite validation has succeeded."""

        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "prepared_connection_composite_materialization"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "prepared_connection_composite_materialization",
                admitted_at=admission_epoch,
            )
            self._validate_connection_composite_semantics(plan, owner_rng)
            prepared = PreparedConnectionCompositeMaterialization(
                _manager=self,
                _plan=plan,
                _owner_rng=owner_rng,
            )
            claim_epoch = self._prepared_state_admission_epoch + 1
            record = _PreparedConnectionCompositeMaterializationRecord(
                preparation=prepared,
                plan=plan,
                owner_rng=owner_rng,
                claim_thread_id=get_ident(),
                claim_epoch=claim_epoch,
                claim_version=self._materialization_version,
                claim_state_time=self.state.current_time,
                rng_state=owner_rng.getstate(),
            )
            locator = id(prepared)
            self._active_connection_composite_preparations[locator] = record
            self._prepared_state_admission_epoch = claim_epoch
            self._active_prepared_state_claim = record
            primary_error: BaseException | None = None
            try:
                yield prepared
            except BaseException as error:
                primary_error = error
                raise
            finally:
                cleanup_error: StateError | None = None
                if (
                    self._active_connection_composite_preparations.get(locator) is not record
                    or self._active_prepared_state_claim is not record
                ):
                    cleanup_error = StateError(
                        "Prepared connection composite no longer owns its State lane"
                    )
                if self._active_connection_composite_preparations.get(locator) is record:
                    self._active_connection_composite_preparations.pop(locator)
                if self._active_prepared_state_claim is record:
                    self._active_prepared_state_claim = None
                    self._prepared_state_admission_epoch += 1
                record.terminal = True
                prepared._active = False
                prepared._committed = record.committed
                prepared._result = record.result
                if cleanup_error is not None:
                    if primary_error is not None:
                        primary_error.add_note(str(cleanup_error))
                    else:
                        raise cleanup_error

    def materialize_connection_composite(
        self,
        plan: ConnectionCompositeMaterializationPlan,
        owner_rng: random.Random,
    ) -> ConnectionCompositeMaterializationResult:
        """Commit one fully finalized State-only connection transaction."""

        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "materialize_connection_composite"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "materialize_connection_composite",
                admitted_at=admission_epoch,
            )
            with self.prepared_connection_composite_materialization(plan, owner_rng) as prepared:
                return prepared.commit()

    def _commit_prevalidated_connection_composite(
        self,
        plan: ConnectionCompositeMaterializationPlan,
        owner_rng: random.Random,
    ) -> ConnectionCompositeMaterializationResult:
        """Apply primitive composite writes after the retained guard validates all inputs."""

        connection: OpenConnection | None
        if plan.materializes_connection:
            identity = plan._identity
            assert identity is not None
            transaction = plan.transaction
            connection = OpenConnection(
                conn_id=transaction.conn_id,
                zeek_uid=transaction.zeek_uid,
                src_ip=transaction.src_ip,
                src_port=transaction.src_port,
                dst_ip=transaction.dst_ip,
                dst_port=transaction.dst_port,
                protocol=transaction.protocol,
                state=("closed" if transaction.closed_at is not None else transaction.conn_state),
                start_time=ensure_utc(transaction.started_at),
                source_system=plan._source_system,
                source_hostname=plan._source_hostname,
                hostname=plan._hostname,
                initiating_pid=plan._initiating_pid,
                close_time=(
                    ensure_utc(transaction.closed_at) if transaction.closed_at is not None else None
                ),
                bytes_sent=transaction.traffic.orig.payload_bytes,
                bytes_received=transaction.traffic.resp.payload_bytes,
                traffic_ledger=transaction.traffic,
                transaction_id=transaction.stable_id,
                conn_state=transaction.conn_state,
                history=transaction.history,
                duration=transaction.duration,
            )
            self.state.open_connections[connection.conn_id] = connection
            self._index_connection(connection)
            self._connection_id_counter = identity._counter_after
        else:
            connection = self.state.open_connections[plan.transaction.conn_id]
            patch = plan._parent_patch
            assert patch is not None
            connection.traffic_ledger = patch.after_traffic
            connection.bytes_sent = patch.after_traffic.orig.payload_bytes
            connection.bytes_received = patch.after_traffic.resp.payload_bytes

        session: ActiveSession | None = None
        processes: tuple[RunningProcess, ...] = ()
        if plan.batch is not None:
            session, processes = self._commit_prevalidated_materialization_batch(
                plan.batch,
                advance_version=False,
                update_state_time=False,
            )
        existing_session_patch = plan.existing_session_patch
        if existing_session_patch is not None:
            before_identity = existing_session_patch.before.identity
            session = self._active_sessions[self._resolve_logon_id(before_identity.logon_id)]
            after = existing_session_patch.after
            self._authoritative_session_ends.remove(session.logon_id)
            session.username = after.identity.principal
            session.start_time = after.identity.started_at
            session.source_ip = after.source_ip
            session.source_port = after.source_port
            session.session_kind = after.identity.session_kind
            session.transport_pid = after.transport_pid
            session.network_close_time = after.network_close_time
            session.source_ready_time = after.source_ready_time
            session.closure_owned_by_bundle = after.closure_owned_by_bundle
            session.lifecycle_group_id = after.identity.lifecycle_group_id
            session.logon_guid = after.identity.logon_guid
            session.end_plan = after.end_plan
            self._active_sessions.refresh(session.logon_id)
            self._index_authoritative_session_end(session)
        roles_patch = plan.existing_session_process_roles_patch
        if roles_patch is not None:
            session = self._active_sessions[self._resolve_logon_id(roles_patch.target.logon_id)]
            roles_after = roles_patch.after
            session.transport_pid = roles_after.transport_pid
            session.session_shell_pid = roles_after.session_shell_pid
            session.session_user_manager_pid = roles_after.session_user_manager_pid
            session.session_winlogon_pid = roles_after.session_winlogon_pid
            session.explorer_pid = roles_after.explorer_pid
            session.initial_explorer_pid = roles_after.initial_explorer_pid
            session.process_tree_root = roles_after.process_tree_root
            session.windows_shell_bootstrapped = roles_after.windows_shell_bootstrapped
        for patch in plan.process_activity:
            process = self._processes_by_object_id[patch.identity.object_id]
            if (
                process.last_activity_time is None
                or process.last_activity_time < patch.activity_time
            ):
                process.last_activity_time = patch.activity_time
        for patch in plan.session_activity:
            active_session = self.state.active_sessions[
                self._resolve_logon_id(patch.identity.logon_id)
            ]
            if (
                active_session.last_activity_time is None
                or active_session.last_activity_time < patch.activity_time
            ):
                active_session.last_activity_time = patch.activity_time
        self.state.current_time = plan.final_state_time
        owner_rng.setstate(plan._rng_state_final)
        self._materialization_version += 1
        return ConnectionCompositeMaterializationResult(
            connection=connection,
            session=session,
            processes=processes,
        )

    def plan_connection_identity(self, rng: random.Random) -> ConnectionIdentityPlan:
        """Reserve deterministic connection/UID identity without advancing either owner."""

        with self._capability_minting_guard("plan_connection_identity"):
            if self._connection_id_counter > 999_999_999:
                raise StateError("Connection ID counter exhausted")
            expected_version = self._materialization_version
            counter_after = self._connection_id_counter + 1
            conn_id = f"conn-{self._connection_id_counter}"
            rng_state_before = rng.getstate()
            preview_rng = random.Random()
            preview_rng.setstate(rng_state_before)
            zeek_uid = generate_zeek_uid_from_rng(preview_rng, "C")
            rng_state_after_identity = preview_rng.getstate()
            return ConnectionIdentityPlan(
                _expected_version=expected_version,
                _conn_id=conn_id,
                _zeek_uid=zeek_uid,
                _counter_after=counter_after,
                _rng_state_before=rng_state_before,
                _rng_state_after_identity=rng_state_after_identity,
                _integrity_token=_connection_identity_integrity_token(
                    self._materialization_secret,
                    expected_version=expected_version,
                    conn_id=conn_id,
                    zeek_uid=zeek_uid,
                    counter_after=counter_after,
                    rng_state_before=rng_state_before,
                    rng_state_after_identity=rng_state_after_identity,
                ),
            )

    def finalize_connection_materialization(
        self,
        identity: ConnectionIdentityPlan,
        transaction: NetworkTransactionPlan,
        *,
        continuation_rng: random.Random,
        source_system: str = "",
        source_hostname: str = "",
        hostname: str = "",
        initiating_pid: int = -1,
        materialize_connection: bool = True,
    ) -> ConnectionMaterializationPlan:
        """Freeze final connection/accounting truth without publishing allocator or state."""

        with self._capability_minting_guard("finalize_connection_materialization"):
            self._validate_connection_identity_plan(identity)
            if identity.expected_version != self._materialization_version:
                raise StateError("Connection identity plan became stale before finalization")
            if materialize_connection and (
                transaction.conn_id != identity.conn_id or transaction.zeek_uid != identity.zeek_uid
            ):
                raise StateError(
                    "New connection transaction must use its reserved connection and UID"
                )
            final_rng_state = continuation_rng.getstate()
            validated_rng = random.Random()
            validated_rng.setstate(final_rng_state)
            payload = _ConnectionMaterializationPayload(
                transaction=transaction,
                source_system=source_system,
                source_hostname=source_hostname,
                hostname=hostname,
                initiating_pid=initiating_pid,
                materialize_connection=materialize_connection,
                final_rng_state=final_rng_state,
            )
            return ConnectionMaterializationPlan(
                _expected_version=identity.expected_version,
                _identity=identity,
                _payload=payload,
                _integrity_token=_connection_materialization_integrity_token(
                    self._materialization_secret,
                    expected_version=identity.expected_version,
                    identity=identity,
                    payload=payload,
                ),
            )

    def validate_connection_materialization(
        self,
        plan: ConnectionMaterializationPlan,
        rng: random.Random,
    ) -> None:
        """Validate every fallible allocator and final-row condition without mutation."""

        with self._lock:
            self._validate_connection_materialization_plan(plan)
            if plan.expected_version != self._materialization_version:
                raise StateError("Connection materialization plan became stale before commit")
            identity = plan.identity
            if identity._counter_after != self._connection_id_counter + 1:
                raise StateError("Connection allocator changed after identity planning")
            if rng.getstate() != identity._rng_state_before:
                raise StateError("Connection identity RNG stream changed before commit")
            transaction = plan.transaction
            if plan.materializes_connection:
                if transaction.conn_id != identity.conn_id:
                    raise StateError("Connection transaction ID changed after planning")
                if transaction.zeek_uid != identity.zeek_uid:
                    raise StateError("Connection Zeek UID changed after planning")
                if transaction.conn_id in self.state.open_connections:
                    raise StateError(
                        f"Connection materialization ID is already live: {transaction.conn_id}"
                    )
                if self._open_connections.find("zeek_uid", transaction.zeek_uid):
                    raise StateError(
                        f"Connection materialization UID is already live: {transaction.zeek_uid}"
                    )
            else:
                existing = self.state.open_connections.get(transaction.conn_id)
                if existing is None:
                    raise StateError(
                        f"Reused connection materialization references unknown {transaction.conn_id}"
                    )
                if existing.zeek_uid != transaction.zeek_uid:
                    raise StateError("Reused connection materialization UID changed")

    @contextmanager
    def prepared_connection_materialization(
        self,
        plan: ConnectionMaterializationPlan,
        rng: random.Random,
    ) -> Iterator[PreparedConnectionMaterialization]:
        """Validate one connection and retain the state guard until commit or cancel."""

        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "prepared_connection_materialization"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "prepared_connection_materialization",
                admitted_at=admission_epoch,
            )
            self.validate_connection_materialization(plan, rng)
            prepared = PreparedConnectionMaterialization(
                _manager=self,
                _plan=plan,
                _rng=rng,
            )
            claim_epoch = self._prepared_state_admission_epoch + 1
            record = _PreparedConnectionMaterializationRecord(
                preparation=prepared,
                plan=plan,
                rng=rng,
                claim_thread_id=get_ident(),
                claim_epoch=claim_epoch,
                claim_version=self._materialization_version,
                claim_state_time=self.state.current_time,
                rng_state=rng.getstate(),
            )
            locator = id(prepared)
            self._active_connection_preparations[locator] = record
            self._prepared_state_admission_epoch = claim_epoch
            self._active_prepared_state_claim = record
            primary_error: BaseException | None = None
            try:
                yield prepared
            except BaseException as error:
                primary_error = error
                raise
            finally:
                cleanup_error: StateError | None = None
                if (
                    self._active_connection_preparations.get(locator) is not record
                    or self._active_prepared_state_claim is not record
                ):
                    cleanup_error = StateError(
                        "Prepared connection materialization no longer owns its State lane"
                    )
                if self._active_connection_preparations.get(locator) is record:
                    self._active_connection_preparations.pop(locator)
                if self._active_prepared_state_claim is record:
                    self._active_prepared_state_claim = None
                    self._prepared_state_admission_epoch += 1
                record.terminal = True
                prepared._active = False
                prepared._committed = record.committed
                prepared._result = record.result
                if cleanup_error is not None:
                    if primary_error is not None:
                        primary_error.add_note(str(cleanup_error))
                    else:
                        raise cleanup_error

    def materialize_connection(
        self,
        plan: ConnectionMaterializationPlan,
        rng: random.Random,
    ) -> OpenConnection | None:
        """Compatibility commit for one already-finalized connection plan."""

        admission_epoch = self._reject_mutation_during_action_cohort_claim("materialize_connection")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "materialize_connection", admitted_at=admission_epoch
            )
            with self.prepared_connection_materialization(plan, rng) as prepared:
                return prepared.commit()

    def _commit_prevalidated_connection_materialization(
        self,
        plan: ConnectionMaterializationPlan,
        rng: random.Random,
    ) -> OpenConnection | None:
        """Apply primitive allocator/final-row writes under a prepared state guard."""

        identity = plan.identity
        payload = plan._payload
        transaction = payload.transaction
        self._connection_id_counter = identity._counter_after
        connection: OpenConnection | None = None
        if payload.materialize_connection:
            connection = OpenConnection(
                conn_id=transaction.conn_id,
                zeek_uid=transaction.zeek_uid,
                src_ip=transaction.src_ip,
                src_port=transaction.src_port,
                dst_ip=transaction.dst_ip,
                dst_port=transaction.dst_port,
                protocol=transaction.protocol,
                state=("closed" if transaction.closed_at is not None else transaction.conn_state),
                start_time=transaction.started_at,
                source_system=payload.source_system,
                source_hostname=payload.source_hostname,
                hostname=payload.hostname,
                initiating_pid=payload.initiating_pid,
                close_time=transaction.closed_at,
                bytes_sent=transaction.traffic.orig.payload_bytes,
                bytes_received=transaction.traffic.resp.payload_bytes,
                traffic_ledger=transaction.traffic,
                transaction_id=transaction.stable_id,
                conn_state=transaction.conn_state,
                history=transaction.history,
                duration=transaction.duration,
            )
            self.state.open_connections[connection.conn_id] = connection
            self._index_connection(connection)
        rng.setstate(payload.final_rng_state)
        self._materialization_version += 1
        return connection

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
        admission_epoch = self._reject_mutation_during_action_cohort_claim("open_connection")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "open_connection", admitted_at=admission_epoch
            )
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

        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "reserve_connection_identity"
        )
        rng = _get_rng()
        plan = self.plan_connection_identity(rng)
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "reserve_connection_identity",
                admitted_at=admission_epoch,
            )
            self._validate_connection_identity_plan(plan)
            if plan.expected_version != self._materialization_version:
                raise StateError("Connection identity plan became stale before commit")
            if rng.getstate() != plan._rng_state_before:
                raise StateError("Connection identity RNG stream changed before commit")
            if plan._counter_after != self._connection_id_counter + 1:
                raise StateError("Connection allocator changed after identity planning")
            self._connection_id_counter = plan._counter_after
            rng.setstate(plan._rng_state_after_identity)
            self._materialization_version += 1
            return plan.conn_id, plan.zeek_uid

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
        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "update_connection_interval"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "update_connection_interval",
                admitted_at=admission_epoch,
            )
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
        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "update_connection_bytes"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "update_connection_bytes",
                admitted_at=admission_epoch,
            )
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

        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "update_connection_transaction"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "update_connection_transaction",
                admitted_at=admission_epoch,
            )
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
        admission_epoch = self._reject_mutation_during_action_cohort_claim("close_connection")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "close_connection", admitted_at=admission_epoch
            )
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
        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "sweep_closed_connections"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "sweep_closed_connections",
                admitted_at=admission_epoch,
            )
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
        admission_epoch = self._reject_mutation_during_action_cohort_claim("register_hostname")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "register_hostname", admitted_at=admission_epoch
            )
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
        admission_epoch = self._reject_mutation_during_action_cohort_claim("set_current_time")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "set_current_time", admitted_at=admission_epoch
            )
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
        admission_epoch = self._reject_mutation_during_action_cohort_claim("advance_time")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "advance_time", admitted_at=admission_epoch
            )
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

    def _smb_file_mutation_journal_integrity_token(
        self,
        journal_id: str,
        operation_id: str,
    ) -> str:
        """Authenticate one bounded file-mutation journal."""

        canonical = ("smb-file-mutation-journal-v1", journal_id, operation_id)
        return hmac.new(
            self._materialization_secret,
            repr(canonical).encode(),
            hashlib.sha256,
        ).hexdigest()

    def _smb_file_mutation_journal_id(self, operation_id: str) -> str:
        """Derive an opaque, non-retained identity without burning allocator state."""

        canonical = ("smb-file-mutation-journal-id-v1", operation_id)
        return hmac.new(
            self._materialization_secret,
            repr(canonical).encode(),
            hashlib.sha256,
        ).hexdigest()

    def _active_smb_file_mutation_journal(
        self,
        journal: SmbFileMutationJournal,
    ) -> _SmbFileMutationJournalCapability:
        if type(journal) is not SmbFileMutationJournal:
            raise StateError("SMB file mutation journal has invalid authority type")
        expected = self._smb_file_mutation_journal_integrity_token(
            journal._journal_id,
            journal._operation_id,
        )
        if not hmac.compare_digest(journal._integrity_token, expected):
            raise StateError("SMB file mutation journal failed integrity validation")
        capability = self._smb_file_mutation_journals.get(journal._journal_id)
        if capability is None or capability.journal is not journal:
            raise StateError("SMB file mutation journal is stale, copied, or foreign")
        return capability

    def _record_smb_file_mutation_preimages(
        self,
        capability: _SmbFileMutationJournalCapability,
        *,
        file_ids: tuple[str, ...] = (),
        path_keys: tuple[tuple[str, str], ...] = (),
    ) -> None:
        """Reserve and snapshot each exact file/path identity before mutation."""

        journal_id = capability.journal._journal_id
        unique_file_ids = tuple(dict.fromkeys(file_ids))
        unique_path_keys = tuple(dict.fromkeys(path_keys))
        for file_id in unique_file_ids:
            owner = self._smb_file_mutation_owner_by_file_id.get(file_id)
            if owner is not None and owner != journal_id:
                raise StateError(f"SMB file {file_id} is already owned by another mutation")
        for path_key in unique_path_keys:
            owner = self._smb_file_mutation_owner_by_path.get(path_key)
            if owner is not None and owner != journal_id:
                raise StateError(
                    f"SMB path {path_key[0]}:{path_key[1]} is already owned by another mutation"
                )
        new_entry_count = sum(
            file_id not in capability.file_preimages for file_id in unique_file_ids
        ) + sum(path_key not in capability.path_preimages for path_key in unique_path_keys)
        retained_entry_count = len(capability.file_preimages) + len(capability.path_preimages)
        if retained_entry_count + new_entry_count > _MAX_SMB_FILE_MUTATION_JOURNAL_ENTRIES:
            raise StateError(
                "SMB file mutation journal exceeds "
                f"{_MAX_SMB_FILE_MUTATION_JOURNAL_ENTRIES} retained entries"
            )
        for file_id in unique_file_ids:
            if file_id in capability.file_preimages:
                continue
            original = self._smb_file_overlay.get(file_id)
            capability.file_preimages[file_id] = _SmbFileStatePreimage(
                original=original,
                snapshot=replace(original) if original is not None else None,
            )
            self._smb_file_mutation_owner_by_file_id[file_id] = journal_id
        for path_key in unique_path_keys:
            if path_key in capability.path_preimages:
                continue
            capability.path_preimages[path_key] = self._smb_file_by_share_path.get(path_key)
            self._smb_file_mutation_owner_by_path[path_key] = journal_id

    def _require_unowned_smb_file_mutation(
        self,
        *,
        file_ids: tuple[str, ...] = (),
        path_keys: tuple[tuple[str, str], ...] = (),
    ) -> None:
        """Fence nontransactional callers from identities owned by an active journal."""

        if any(file_id in self._smb_file_mutation_owner_by_file_id for file_id in file_ids):
            raise StateError("SMB file is owned by an active mutation journal")
        if any(path_key in self._smb_file_mutation_owner_by_path for path_key in path_keys):
            raise StateError("SMB path is owned by an active mutation journal")

    def _release_smb_file_mutation_ownership(
        self,
        capability: _SmbFileMutationJournalCapability,
    ) -> None:
        journal_id = capability.journal._journal_id
        for file_id in capability.file_preimages:
            if self._smb_file_mutation_owner_by_file_id.get(file_id) == journal_id:
                self._smb_file_mutation_owner_by_file_id.pop(file_id)
        for path_key in capability.path_preimages:
            if self._smb_file_mutation_owner_by_path.get(path_key) == journal_id:
                self._smb_file_mutation_owner_by_path.pop(path_key)

    def begin_smb_file_mutation_journal(self, operation_id: str) -> SmbFileMutationJournal:
        """Reserve one bounded rollback journal for an SMB operation."""

        if type(operation_id) is not str or not operation_id.strip() or len(operation_id) > 512:
            raise StateError("SMB file mutation operation_id must be a nonempty bounded string")
        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "begin_smb_file_mutation_journal"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "begin_smb_file_mutation_journal",
                admitted_at=admission_epoch,
            )
            existing_id = self._smb_file_mutation_journal_by_operation.get(operation_id)
            if existing_id is not None:
                existing = self._smb_file_mutation_journals[existing_id]
                if existing.file_preimages or existing.path_preimages:
                    raise StateError("SMB operation already owns an active mutation in progress")
                return existing.journal
            if len(self._smb_file_mutation_journals) >= _MAX_ACTIVE_SMB_FILE_MUTATION_JOURNALS:
                raise StateError(
                    "active SMB file mutation journals exceed "
                    f"{_MAX_ACTIVE_SMB_FILE_MUTATION_JOURNALS}"
                )
            journal_id = self._smb_file_mutation_journal_id(operation_id)
            if journal_id in self._smb_file_mutation_journals:
                raise StateError("SMB file mutation journal identity collision")
            journal = SmbFileMutationJournal(
                _journal_id=journal_id,
                _operation_id=operation_id,
                _integrity_token=self._smb_file_mutation_journal_integrity_token(
                    journal_id,
                    operation_id,
                ),
            )
            self._smb_file_mutation_journals[journal_id] = _SmbFileMutationJournalCapability(
                journal=journal
            )
            self._smb_file_mutation_journal_by_operation[operation_id] = journal_id
            return journal

    def authenticates_smb_file_mutation_journal(
        self,
        journal: SmbFileMutationJournal,
    ) -> bool:
        """Return whether this manager retains the exact active journal."""

        with self._lock:
            try:
                self._active_smb_file_mutation_journal(journal)
            except (StateError, TypeError, ValueError):
                return False
            return True

    def commit_smb_file_mutation_journal(self, journal: SmbFileMutationJournal) -> None:
        """Accept journaled file mutations and release their transient preimages."""

        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "commit_smb_file_mutation_journal"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "commit_smb_file_mutation_journal",
                admitted_at=admission_epoch,
            )
            capability = self._active_smb_file_mutation_journal(journal)
            self._release_smb_file_mutation_ownership(capability)
            self._smb_file_mutation_journals.pop(journal._journal_id)
            self._smb_file_mutation_journal_by_operation.pop(journal._operation_id, None)

    def cancel_smb_file_mutation_journal(self, journal: SmbFileMutationJournal) -> None:
        """Restore every exact file/path preimage retained by a live journal."""

        admission_epoch = self._reject_mutation_during_action_cohort_claim(
            "cancel_smb_file_mutation_journal"
        )
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "cancel_smb_file_mutation_journal",
                admitted_at=admission_epoch,
            )
            capability = self._active_smb_file_mutation_journal(journal)
            for file_id, preimage in capability.file_preimages.items():
                if preimage.snapshot is None:
                    self._smb_file_overlay.pop(file_id, None)
                    continue
                original = preimage.original
                if original is None:
                    raise StateError("SMB mutation journal lost its original file object")
                snapshot = preimage.snapshot
                original.share = snapshot.share
                original.path = snapshot.path
                original.version = snapshot.version
                original.size_bytes = snapshot.size_bytes
                original.mime_type = snapshot.mime_type
                original.tags = snapshot.tags
                original.deleted = snapshot.deleted
                original.prior_paths = snapshot.prior_paths
                self._smb_file_overlay[file_id] = original
            for path_key, prior_file_id in capability.path_preimages.items():
                if prior_file_id is None:
                    self._smb_file_by_share_path.pop(path_key, None)
                else:
                    self._smb_file_by_share_path[path_key] = prior_file_id
            self._release_smb_file_mutation_ownership(capability)
            self._smb_file_mutation_journals.pop(journal._journal_id)
            self._smb_file_mutation_journal_by_operation.pop(journal._operation_id, None)

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

    def touch_smb_file(
        self,
        file: object,
        *,
        journal: SmbFileMutationJournal | None = None,
    ) -> SmbFileState:
        """Return a mutable overlay view for one compiled storage file."""

        admission_epoch = self._reject_mutation_during_action_cohort_claim("touch_smb_file")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "touch_smb_file", admitted_at=admission_epoch
            )
            capability = (
                self._active_smb_file_mutation_journal(journal) if journal is not None else None
            )
            file_id = file.file_id
            path_key = (file.share.casefold(), file.path.casefold())
            if capability is not None:
                self._record_smb_file_mutation_preimages(
                    capability,
                    file_ids=(file_id,),
                    path_keys=(path_key,),
                )
            else:
                self._require_unowned_smb_file_mutation(
                    file_ids=(file_id,),
                    path_keys=(path_key,),
                )
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
        journal: SmbFileMutationJournal | None = None,
    ) -> SmbFileState:
        """Create a new file identity in the mutation overlay."""

        admission_epoch = self._reject_mutation_during_action_cohort_claim("create_smb_file")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "create_smb_file", admitted_at=admission_epoch
            )
            capability = (
                self._active_smb_file_mutation_journal(journal) if journal is not None else None
            )
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
            if capability is not None:
                self._record_smb_file_mutation_preimages(
                    capability,
                    file_ids=(file_id,),
                    path_keys=(key,),
                )
            else:
                self._require_unowned_smb_file_mutation(
                    file_ids=(file_id,),
                    path_keys=(key,),
                )
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

    def update_smb_file(
        self,
        file_id: str,
        *,
        size_bytes: int,
        journal: SmbFileMutationJournal | None = None,
    ) -> SmbFileState:
        """Advance a file content version and size."""

        admission_epoch = self._reject_mutation_during_action_cohort_claim("update_smb_file")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "update_smb_file", admitted_at=admission_epoch
            )
            if journal is not None:
                capability = self._active_smb_file_mutation_journal(journal)
                self._record_smb_file_mutation_preimages(
                    capability,
                    file_ids=(file_id,),
                )
            else:
                self._require_unowned_smb_file_mutation(file_ids=(file_id,))
            state = self._smb_file_overlay[file_id]
            if state.deleted:
                raise StateError(f"cannot update deleted SMB file {file_id}")
            state.version += 1
            state.size_bytes = max(0, size_bytes)
            return state

    def move_smb_file(
        self,
        file_id: str,
        *,
        share: str,
        path: str,
        journal: SmbFileMutationJournal | None = None,
    ) -> SmbFileState:
        """Move a file while preserving its durable identity."""

        admission_epoch = self._reject_mutation_during_action_cohort_claim("move_smb_file")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "move_smb_file", admitted_at=admission_epoch
            )
            capability = (
                self._active_smb_file_mutation_journal(journal) if journal is not None else None
            )
            state = self._smb_file_overlay[file_id]
            destination_key = (share.casefold(), path.casefold())
            destination_id = self._smb_file_by_share_path.get(destination_key)
            destination = self._smb_file_overlay.get(destination_id or "")
            if destination is not None and not destination.deleted and destination_id != file_id:
                raise StateError(f"SMB path already exists: {share}:{path}")
            old_key = (state.share.casefold(), state.path.casefold())
            if capability is not None:
                self._record_smb_file_mutation_preimages(
                    capability,
                    file_ids=(file_id,),
                    path_keys=(old_key, destination_key),
                )
            else:
                self._require_unowned_smb_file_mutation(
                    file_ids=(file_id,),
                    path_keys=(old_key, destination_key),
                )
            self._smb_file_by_share_path.pop(old_key, None)
            state.prior_paths = (*state.prior_paths, state.path)
            state.share = share
            state.path = path
            self._smb_file_by_share_path[destination_key] = file_id
            return state

    def delete_smb_file(
        self,
        file_id: str,
        *,
        journal: SmbFileMutationJournal | None = None,
    ) -> SmbFileState:
        """Tombstone a file identity."""

        admission_epoch = self._reject_mutation_during_action_cohort_claim("delete_smb_file")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim(
                "delete_smb_file", admitted_at=admission_epoch
            )
            capability = (
                self._active_smb_file_mutation_journal(journal) if journal is not None else None
            )
            state = self._smb_file_overlay[file_id]
            path_key = (state.share.casefold(), state.path.casefold())
            if capability is not None:
                self._record_smb_file_mutation_preimages(
                    capability,
                    file_ids=(file_id,),
                    path_keys=(path_key,),
                )
            else:
                self._require_unowned_smb_file_mutation(
                    file_ids=(file_id,),
                    path_keys=(path_key,),
                )
            state.deleted = True
            self._smb_file_by_share_path.pop(
                path_key,
                None,
            )
            return state

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
                "smb_mutations": len(self._smb_file_overlay),
                "smb_file_mutation_journals": len(self._smb_file_mutation_journals),
                "smb_file_mutation_journal_entries": sum(
                    len(capability.file_preimages) + len(capability.path_preimages)
                    for capability in self._smb_file_mutation_journals.values()
                ),
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
        admission_epoch = self._reject_mutation_during_action_cohort_claim("register_boot_time")
        with self._lock:
            normalized = ensure_utc(boot_time)
            if self._system_boot_times.get(system) == normalized:
                return
            self._reject_mutation_during_action_cohort_claim(
                "register_boot_time", admitted_at=admission_epoch
            )
            self._system_boot_times[system] = normalized
            self._materialization_version += 1

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
        admission_epoch = self._reject_mutation_during_action_cohort_claim("apply")
        with self._lock:
            self._reject_mutation_during_action_cohort_claim("apply", admitted_at=admission_epoch)
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
                    owning_session = (
                        self.state.active_sessions.get(self._resolve_logon_id(proc.logon_id))
                        if proc.logon_id
                        else None
                    )
                    if (
                        owning_session is None or _session_valid_at(owning_session, activity_time)
                    ) and (
                        proc.last_activity_time is None or activity_time > proc.last_activity_time
                    ):
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
