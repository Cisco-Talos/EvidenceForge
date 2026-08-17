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
import hmac
import logging
import random
import secrets
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, fields, is_dataclass, replace
from datetime import datetime, timedelta
from enum import Enum, StrEnum
from threading import RLock, get_ident

from evidenceforge.events.authentication import windows_logon_can_own_desktop
from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.events.identity import ProcessIdentity, SessionIdentity, ThreadIdentity
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.events.network import NetworkTrafficLedger, NetworkTransactionPlan
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
_SESSION_PROCESS_REFERENCE_FIELDS = (
    "explorer_pid",
    "session_user_manager_pid",
    "session_winlogon_pid",
    "session_shell_pid",
    "process_tree_root",
    "transport_pid",
)


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
        owner_rng: random.Random,
        rng_state_entry: object,
        cursor_token: str,
    ) -> None:
        self._manager = manager
        self._expected_version = expected_version
        self._expected_state_time = expected_state_time
        self._expected_connection_counter = expected_connection_counter
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
    tree.  Every member is planned against the same StateManager version and the
    primitive commit advances that version exactly once.
    """

    _expected_version: int
    _expected_state_time: datetime | None
    _final_state_time: datetime
    _session: SessionMaterializationPlan | None
    _processes: tuple[ProcessMaterializationPlan, ...]
    _session_process_links: _SessionProcessMaterializationLinks
    _integrity_token: str = field(repr=False)

    @property
    def expected_version(self) -> int:
        """Return the single StateManager fence consumed by this batch."""

        return self._expected_version

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
    def publication_token(self) -> str:
        """Return the authenticated token bound to the complete batch."""

        return self._integrity_token


class MaterializationBatchBuilder:
    """Allocation-free builder for one session and its bootstrap process tree."""

    def __init__(self, manager: "StateManager", expected_version: int) -> None:
        self._manager = manager
        self._expected_version = expected_version
        self._expected_state_time = manager.state.current_time
        self._session: SessionMaterializationPlan | None = None
        self._processes: list[ProcessMaterializationPlan] = []
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

    def plan_session(self, **kwargs: object) -> SessionMaterializationPlan:
        """Plan the batch's optional session without changing canonical state."""

        if self._sealed:
            raise StateError("Materialization batch builder is already sealed")
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

        if self._sealed:
            raise StateError("Materialization batch builder is already sealed")
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

        if self._sealed:
            raise StateError("Materialization batch builder is already sealed")
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

        if self._sealed:
            raise StateError("Materialization batch builder is already sealed")
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

        if self._sealed:
            raise StateError("Materialization batch builder is already sealed")
        if self._session is None and not self._processes:
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


class ActionCohortMaterializationBuilder(MaterializationBatchBuilder):
    """Allocation-free builder for one ordered multi-session action cohort."""

    def __init__(self, manager: "StateManager", expected_version: int) -> None:
        super().__init__(manager, expected_version)
        self._action_sessions: list[SessionMaterializationPlan] = []
        self._action_session_process_plans: dict[int, dict[str, ProcessMaterializationPlan]] = {}
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
        if self._sealed:
            raise StateError("Action cohort materialization builder is already sealed")

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
    final_state_time: datetime,
    session: SessionMaterializationPlan | None,
    processes: tuple[ProcessMaterializationPlan, ...],
    session_process_links: _SessionProcessMaterializationLinks,
) -> str:
    """Authenticate the exact ordered membership of one start batch."""

    canonical = repr(
        (
            "materialization-batch",
            expected_version,
            expected_state_time,
            final_state_time,
            session.publication_token if session is not None else "",
            tuple(plan.publication_token for plan in processes),
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
    session_metadata: tuple[ActionCohortSessionMetadataPatch, ...],
    process_activity: tuple[ActionCohortProcessActivityPatch, ...],
    session_activity: tuple[ActionCohortSessionActivityPatch, ...],
    process_terminations: tuple[ActionCohortProcessTermination, ...],
    session_terminalizations: tuple[ActionCohortSessionTerminalization, ...],
) -> tuple[object, ...]:
    """Return deterministic semantics without secrets or object addresses."""

    return (
        "action-cohort-materialization-v1",
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
    session_metadata: tuple[ActionCohortSessionMetadataPatch, ...],
    process_activity: tuple[ActionCohortProcessActivityPatch, ...],
    session_activity: tuple[ActionCohortSessionActivityPatch, ...],
    process_terminations: tuple[ActionCohortProcessTermination, ...],
    session_terminalizations: tuple[ActionCohortSessionTerminalization, ...],
) -> str:
    """Authenticate the exact ephemeral capabilities and their tuple order."""

    canonical = (
        "action-cohort-capability-v1",
        semantic_id,
        id(capability),
        tuple((id(plan), plan.publication_token) for plan in sessions),
        tuple((id(plan), plan.publication_token) for plan in processes),
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

        return self._committed

    def commit(self) -> OpenConnection | None:
        """Publish the fully validated plan using primitive writes only."""

        if not self._active:
            raise StateError("Prepared connection materialization is no longer active")
        if not self._committed:
            self._result = self._manager._commit_prevalidated_connection_materialization(
                self._plan,
                self._rng,
            )
            self._committed = True
        return self._result


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

        return self._committed

    def commit(self) -> ConnectionCompositeMaterializationResult:
        """Publish the fully prevalidated composite exactly once."""

        if not self._active:
            raise StateError("Prepared connection composite is no longer active")
        if self._committed:
            raise StateError("Prepared connection composite is already committed")
        self._result = self._manager._commit_prevalidated_connection_composite(
            self._plan,
            self._owner_rng,
        )
        self._committed = True
        return self._result


@dataclass(slots=True)
class PreparedActionCohortMaterialization:
    """State-guard-scoped one-shot action-cohort commit capability."""

    _manager: "StateManager"
    _plan: ActionCohortMaterializationPlan
    _claim_thread_id: int
    _active: bool = True
    _committed: bool = False
    _result: ActionCohortMaterializationResult | None = None

    @property
    def committed(self) -> bool:
        """Return whether the complete State cohort was published."""

        return self._committed

    def commit_no_fail(self) -> ActionCohortMaterializationResult:
        """Publish the fully prevalidated primitive transaction exactly once."""

        if not self._active:
            raise StateError("Prepared action cohort materialization is no longer active")
        if self._committed:
            raise StateError("Prepared action cohort materialization is already committed")
        if get_ident() != self._claim_thread_id:
            raise StateError(
                "Prepared action cohort materialization must commit on its claiming thread"
            )
        self._result = self._manager._commit_prevalidated_action_cohort(self._plan)
        self._committed = True
        return self._result

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
                    if name not in {"_lock", "_materialization_secret", "state"}
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
    def materialization_guard(self, plan: _MaterializationPlan | int) -> Iterator[None]:
        """Hold the state-start lane after authenticating one opaque plan.

        Global prepared-publication lock order is artifact publication (when an
        occurrence owns one), then this StateManager guard, then the LifecycleRegistry
        prepared-start ticket. No registry path may acquire this guard while retaining
        a registry lock, and StateManager never acquires artifact-registry ownership.

        The integer form remains a private compatibility seam for callers that have
        not yet adopted an opaque plan; production start publication passes the plan.
        """

        with self._lock:
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

        with self._lock:
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
            process_activity=plan._process_activity,
            session_activity=plan._session_activity,
            final_state_time=plan._final_state_time,
        )
        if not hmac.compare_digest(plan._integrity_token, expected):
            raise StateError("Connection composite plan integrity validation failed")

    def _validate_materialization_batch_plan(self, plan: MaterializationBatchPlan) -> None:
        session = plan._session
        if session is not None:
            self._validate_session_materialization_plan(session)
            if session.expected_version != plan.expected_version:
                raise StateError("Materialization batch session uses another state version")
        for process in plan._processes:
            self._validate_process_materialization_plan(process)
            if process.expected_version != plan.expected_version:
                raise StateError("Materialization batch process uses another state version")
        expected = _materialization_batch_integrity_token(
            self._materialization_secret,
            expected_version=plan._expected_version,
            expected_state_time=plan._expected_state_time,
            final_state_time=plan._final_state_time,
            session=session,
            processes=plan._processes,
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
            plan._session_metadata,
            plan._process_activity,
            plan._session_activity,
            plan._process_terminations,
            plan._session_terminalizations,
        )
        if any(type(value) is not tuple for value in tuple_fields):
            raise StateError("Action cohort materialization members must be exact tuples")
        expected_types = (
            (plan._sessions, SessionMaterializationPlan),
            (plan._processes, ProcessMaterializationPlan),
            (plan._session_process_links, _ActionCohortSessionProcessLinks),
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
        for patch in (
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

        with self._lock:
            return MaterializationBatchBuilder(self, self._materialization_version)

    def begin_action_cohort_materialization(self) -> ActionCohortMaterializationBuilder:
        """Return an allocation-free multi-session action-cohort builder."""

        with self._lock:
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

        with self._lock:
            if builder._manager is not self:
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

        with self._lock:
            if (
                builder._manager is not self
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

        with self._lock:
            if (
                builder._manager is not self
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

        with self._lock:
            if builder._manager is not self:
                raise StateError("Action cohort builder belongs to another StateManager")
            if builder.expected_version != self._materialization_version:
                raise StateError("Action cohort builder became stale before sealing")
            if self.state.current_time != builder._expected_state_time:
                raise StateError("Action cohort State time changed before sealing")
            sessions = tuple(builder._action_sessions)
            processes = tuple(builder._processes)
            if not any(
                (
                    sessions,
                    processes,
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

        with self._lock:
            if builder._manager is not self:
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

        with self._lock:
            if (
                builder._manager is not self
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

        with self._lock:
            if builder._manager is not self:
                raise StateError("Materialization batch belongs to another StateManager")
            if builder.expected_version != self._materialization_version:
                raise StateError("Materialization batch became stale before sealing")
            if self.state.current_time != builder._expected_state_time:
                raise StateError("Materialization batch state-time fence changed before sealing")
            processes = tuple(builder._processes)
            state_times = [process._payload.state_time for process in processes]
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
                _final_state_time=final_state_time,
                _session=builder._session,
                _processes=processes,
                _session_process_links=links,
                _integrity_token=_materialization_batch_integrity_token(
                    self._materialization_secret,
                    expected_version=builder.expected_version,
                    expected_state_time=builder._expected_state_time,
                    final_state_time=final_state_time,
                    session=builder._session,
                    processes=processes,
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
    ) -> SessionMaterializationPlan:
        """Plan one exact session identity without consuming LUID/session allocators."""

        with self._lock:
            if start_time is None and self.state.current_time is None:
                raise StateError("Cannot plan session: current_time not set")
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

        with self._lock:
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

        with self._lock:
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
            self._commit_linux_logind_allocator_patch(patch.linux_logind)
        identity = plan.identity
        payload = plan._payload
        if update_state_time:
            self.state.current_time = payload.state_time
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
        )
        self.state.active_sessions[session.logon_id] = session
        self._remove_logon_id_alias(session.logon_id)
        self._remove_ended_session(session.logon_id)
        if advance_version:
            self._materialization_version += 1
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
        with self._lock:
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
        with self._lock:
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

        Explicit storyline ends and action-bundle hard deadlines cannot be
        silently replaced by another event. Re-applying the same plan is
        idempotent.
        """

        with self._lock:
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
    ) -> None:
        """Apply one validated logind allocator patch with primitive writes only."""

        if patch.initial is not None:
            self._linux_logind_session_initials[patch.system] = patch.initial
        if patch.epoch is not None:
            self._linux_logind_session_epochs[patch.system] = patch.epoch
        self._linux_logind_session_used_ids.setdefault(patch.system, set()).add(patch.session_id)
        self._linux_logind_session_allocations.setdefault(
            patch.system,
            TemporalAllocationIndex(),
        ).add(patch.event_time, patch.session_id)
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
        with self._lock:
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

        with self._lock:
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

        with self._lock:
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

        with self._lock:
            if (
                builder._manager is not self
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

        with self._lock:
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
    ) -> ProcessIdentity:
        """Perform primitive process-termination writes after guarded validation."""

        identity = plan.identity
        payload = plan._payload
        key = (identity.hostname, identity.pid)
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

        thread_deadline = (payload.end_time + _ENDED_IDENTITY_RETENTION).timestamp()
        for thread_identity in payload.threads:
            thread_key = (
                thread_identity.hostname,
                thread_identity.process_object_id,
                thread_identity.tid,
            )
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
        process_deadline = (payload.end_time + _ENDED_IDENTITY_RETENTION).timestamp()
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

        self._trim_retained_thread_identities()
        self._trim_retained_process_identities()
        if advance_version:
            self._materialization_version += 1
        logger.debug("Ended process %s on %s", identity.pid, identity.hostname)
        return identity

    def materialize_process_termination(
        self,
        plan: ProcessTerminationMaterializationPlan,
    ) -> ProcessIdentity:
        """Commit one exact process termination and return its receipt-ready identity."""

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

            if len(plan._session_process_links) != len(plan.sessions):
                raise StateError("Action cohort session process links are incomplete")
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

            for process in plan.processes:
                parent_activity_time = process._payload.parent_activity_time
                identity = process.identity
                if parent_activity_time is None or identity.parent_pid in {0, 4}:
                    continue
                parent = processes_by_pid.get((identity.hostname, identity.parent_pid))
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

    @contextmanager
    def prepared_action_cohort_materialization(
        self,
        plan: ActionCohortMaterializationPlan,
    ) -> Iterator[PreparedActionCohortMaterialization]:
        """Retain the State guard after all cohort validation succeeds."""

        with self._lock:
            self.validate_action_cohort_materialization(plan)
            prepared = PreparedActionCohortMaterialization(
                _manager=self,
                _plan=plan,
                _claim_thread_id=get_ident(),
            )
            try:
                yield prepared
            finally:
                prepared._active = False

    def materialize_action_cohort(
        self,
        plan: ActionCohortMaterializationPlan,
    ) -> ActionCohortMaterializationResult:
        """Compatibility commit for one fully prepared action cohort."""

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

    def _commit_action_cohort_staged_process_termination(
        self,
        termination: ActionCohortProcessTermination,
    ) -> ProcessIdentity:
        target = termination.target
        assert type(target) is ProcessMaterializationPlan
        identity = target.identity
        parent_activity = termination.parent_activity
        parent_identity = (
            self._action_process_identity(parent_activity.target)
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
        return self._commit_prevalidated_process_termination_materialization(
            primitive,
            advance_version=False,
        )

    def _commit_action_cohort_session_terminalization(
        self,
        terminalization: ActionCohortSessionTerminalization,
    ) -> SessionIdentity:
        identity = terminalization.identity
        resolved = self._resolve_logon_id(identity.logon_id)
        session = self._active_sessions.pop(resolved)
        ended = (session, terminalization.end_time)
        self._ended_sessions[resolved] = ended
        self._index_ended_session(resolved, session, terminalization.end_time)
        if resolved != identity.logon_id:
            self._ended_sessions[identity.logon_id] = ended
        self._trim_retained_session_identities()
        return identity

    def _commit_prevalidated_action_cohort(
        self,
        plan: ActionCohortMaterializationPlan,
    ) -> ActionCohortMaterializationResult:
        """Apply one prevalidated cohort using only primitive no-fail writes."""

        prior_version = self._materialization_version
        sessions = tuple(
            self._commit_prevalidated_session_materialization(
                session,
                advance_version=False,
                update_state_time=False,
            )
            for session in plan.sessions
        )
        processes = tuple(
            self._commit_prevalidated_process_materialization(
                process,
                advance_version=False,
                update_state_time=False,
            )
            for process in plan.processes
        )
        for session_links in plan._session_process_links:
            session = sessions[session_links.session_index]
            links = session_links.links

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

        terminated: list[ProcessIdentity] = []
        for termination in plan.process_terminations:
            if type(termination.target) is ProcessTerminationMaterializationPlan:
                terminated.append(
                    self._commit_prevalidated_process_termination_materialization(
                        termination.target,
                        advance_version=False,
                    )
                )
            else:
                terminated.append(
                    self._commit_action_cohort_staged_process_termination(termination)
                )
        terminalized = tuple(
            self._commit_action_cohort_session_terminalization(terminalization)
            for terminalization in plan.session_terminalizations
        )
        self.state.current_time = plan.final_state_time
        self._materialization_version = prior_version + 1
        return ActionCohortMaterializationResult(
            semantic_id=plan.semantic_id,
            prior_version=prior_version,
            committed_version=self._materialization_version,
            started_sessions=tuple(session.identity for session in plan.sessions),
            started_processes=tuple(process.identity for process in plan.processes),
            terminated_processes=tuple(terminated),
            terminalized_sessions=terminalized,
        )

    def validate_materialization_batch(self, plan: MaterializationBatchPlan) -> None:
        """Validate every batch member and dependency without publishing state."""

        with self._lock:
            self._validate_materialization_batch_plan(plan)
            if plan.expected_version != self._materialization_version:
                raise StateError("Materialization batch became stale before commit")
            if self.state.current_time != plan._expected_state_time:
                raise StateError("Materialization batch state-time fence changed before commit")
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
            self._linux_pid_allocations.setdefault(host, TemporalAllocationIndex()).add(
                at, logical_position
            )
        if patch.pid_bucket_offset is not None:
            key, offset = patch.pid_bucket_offset
            self._pid_bucket_offsets[key] = offset
        if patch.fixed_pid is not None:
            host, pid = patch.fixed_pid
            self._fixed_pid_reservations.setdefault(host, set()).add(pid)
        self._pid_allocation_count += patch.pid_allocation_count_delta
        self._pid_candidate_probe_count += patch.pid_candidate_probe_delta
        if patch.thread_counter is not None:
            host, counter = patch.thread_counter
            self._thread_id_counters[host] = counter
        if patch.thread_rng_state is not None:
            host, rng_state = patch.thread_rng_state
            rng = self._thread_id_rngs.setdefault(host, random.Random())
            rng.setstate(rng_state)

        identity = plan.identity
        payload = plan._payload
        if update_state_time:
            self.state.current_time = payload.state_time
        if payload.parent_activity_time is not None and identity.parent_pid:
            parent = self.state.running_processes.get((identity.hostname, identity.parent_pid))
            if parent is not None and (
                parent.last_activity_time is None
                or parent.last_activity_time < payload.parent_activity_time
            ):
                parent.last_activity_time = payload.parent_activity_time
        primary_thread_identity = identity.primary_thread
        assert primary_thread_identity is not None
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
            primary_tid=primary_thread_identity.tid,
            lifecycle_group_id=identity.lifecycle_group_id,
            parent_lifecycle_group_id=identity.parent_lifecycle_group_id,
            concurrency_group_id=payload.concurrency_group_id,
            pid_logical_position=payload.pid_logical_position,
        )
        key = (process.system, process.pid)
        self.state.running_processes[key] = process
        self._active_pid_reservation_counts[process.system] = (
            self._active_pid_reservation_counts.get(process.system, 0) + 1
        )
        self._process_object_ids[key] = process.ecar_object_id
        self._processes_by_object_id[process.ecar_object_id] = process
        self._ended_processes_by_key.pop(key, None)
        thread = RunningThread(
            hostname=primary_thread_identity.hostname,
            process_object_id=primary_thread_identity.process_object_id,
            pid=primary_thread_identity.pid,
            tid=primary_thread_identity.tid,
            object_id=primary_thread_identity.object_id,
            start_time=primary_thread_identity.started_at,
            kind=primary_thread_identity.kind,
        )
        self.state.running_threads[(thread.hostname, thread.process_object_id, thread.tid)] = thread
        self._ended_threads.pop((thread.hostname, thread.process_object_id, thread.tid), None)
        if advance_version:
            self._materialization_version += 1
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
        with self._lock:
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
        with self._lock:
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
        with self._lock:
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

        with self._lock:
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
                owner_rng=owner_rng,
                rng_state_entry=entry_state,
                cursor_token=token,
            )

    def _validate_connection_cursor(self, cursor: ConnectionPlanningCursor) -> None:
        """Validate a live cursor without sealing or sampling it."""

        if cursor._manager is not self:
            raise StateError("Connection planning cursor belongs to another StateManager")
        cursor._require_active()
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

        with self._lock:
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
    ) -> None:
        """Validate exact live or staged owners for all activity frontiers."""

        staged_processes = (
            {process.identity.object_id: process.identity for process in batch.processes}
            if batch is not None
            else {}
        )
        staged_session = batch.session.identity if batch is not None and batch.session else None
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
        process_activity: tuple[ProcessActivityPatch, ...] = (),
        session_activity: tuple[SessionActivityPatch, ...] = (),
    ) -> ConnectionCompositeMaterializationPlan:
        """Seal one physical/child transaction and optional start batch without mutation."""

        with self._lock:
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
            self._validate_connection_activity_patches(
                normalized_process_activity,
                normalized_session_activity,
                batch,
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
        self._validate_connection_activity_patches(
            plan.process_activity,
            plan.session_activity,
            plan.batch,
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

        with self._lock:
            self._validate_connection_composite_semantics(plan, owner_rng)
            prepared = PreparedConnectionCompositeMaterialization(
                _manager=self,
                _plan=plan,
                _owner_rng=owner_rng,
            )
            try:
                yield prepared
            finally:
                prepared._active = False

    def materialize_connection_composite(
        self,
        plan: ConnectionCompositeMaterializationPlan,
        owner_rng: random.Random,
    ) -> ConnectionCompositeMaterializationResult:
        """Commit one fully finalized State-only connection transaction."""

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

        with self._lock:
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

        with self._lock:
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

        with self._lock:
            self.validate_connection_materialization(plan, rng)
            prepared = PreparedConnectionMaterialization(
                _manager=self,
                _plan=plan,
                _rng=rng,
            )
            try:
                yield prepared
            finally:
                prepared._active = False

    def materialize_connection(
        self,
        plan: ConnectionMaterializationPlan,
        rng: random.Random,
    ) -> OpenConnection | None:
        """Compatibility commit for one already-finalized connection plan."""

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

        rng = _get_rng()
        plan = self.plan_connection_identity(rng)
        with self._lock:
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
            normalized = ensure_utc(boot_time)
            if self._system_boot_times.get(system) == normalized:
                return
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
