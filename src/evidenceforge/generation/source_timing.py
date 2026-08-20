# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Source-aware timestamp planning for canonical canonical occurrences.

``OccurrenceBuilder.timestamp`` remains canonical world time. This module plans the
timestamps individual sources render from that event, using shared timing
profiles and explicit constraints instead of independent emitter-local jitter.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import sys
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from threading import RLock, get_ident
from typing import Any, TypeAlias, cast
from weakref import ReferenceType, ref

from evidenceforge.events.base import CanonicalOccurrence, OccurrenceBuilder
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.generation.activity.timing_profiles import (
    endpoint_clock_timing,
    get_timing_window,
    network_sensor_observation_timing,
    startup_module_observation_timing,
    sysmon_envelope_timing,
)
from evidenceforge.generation.process_runtime_cache import BoundedRuntimeCache, deadline_seconds
from evidenceforge.generation.timing import (
    ConstantDistribution,
    MixtureDistribution,
    SourceClockKey,
    SourceClockSpec,
    TemporalConstraintGraph,
    TimingDistributionError,
    TimingRuntime,
    TimingRuntimeCensus,
    TimingRuntimePreparation,
    TimingScope,
    TriangularDistribution,
    TruncatedLognormalDistribution,
    WeightedDistribution,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.time import ensure_utc

TimingOccurrence: TypeAlias = OccurrenceBuilder | CanonicalOccurrence

_SOURCE_EPSILON = timedelta(milliseconds=1)
_PROCESS_CREATE_SOURCE_KEYS = {
    "source.windows_security_process_create",
    "source.sysmon_process_create",
    "source.ecar_process_create",
}
_PROCESS_START_EVENT_TYPES = {"process_create", "system_process_create"}
_PROCESS_END_EVENT_TYPES = {"process_terminate"}
_SESSION_CLOSURE_SOURCE_KEYS = {
    "ecar": "source.ecar_session_logout",
    "windows_security": "source.windows_security_session_logout",
    "windows_event_security": "source.windows_security_session_logout",
    "syslog": "source.syslog_session_logout",
}
_SESSION_CLOSURE_TAILS = {
    "ecar": timedelta(seconds=15),
    "windows_security": timedelta(seconds=15),
    "windows_event_security": timedelta(seconds=15),
    "syslog": timedelta(seconds=4),
}
_SOURCE_TIMING_LIFECYCLE_RETENTION = timedelta(hours=48)
_SOURCE_TIMING_TRANSPORT_RETENTION = timedelta(minutes=10)
_SOURCE_TIMING_TICKET_RETENTION = timedelta(seconds=10)
_DEFAULT_SOURCE_TIMING_PREPARATION_AUTHORITY_CAPACITY = 4_096
_DEFAULT_SOURCE_TIMING_DETACHED_BINDING_CAPACITY = 4_096
_MAX_UTC_DATETIME = datetime.max.replace(tzinfo=UTC)
_CACHE_TOMBSTONE = object()


def _exact_sha256_hex(value: object, field_name: str) -> str:
    """Return one exact lowercase SHA-256 digest or reject the value."""

    if type(value) is not str or len(value) != 64:
        raise StateError(f"{field_name} must be one exact SHA-256 digest")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise StateError(f"{field_name} must be one exact SHA-256 digest") from error
    if any(byte not in b"0123456789abcdef" for byte in encoded):
        raise StateError(f"{field_name} must be one exact SHA-256 digest")
    return value


def _source_timing_detached_frame(*values: bytes) -> bytes:
    """Frame trusted bounded byte fields without repr or delimiter ambiguity."""

    return b"".join(len(value).to_bytes(8, "big") + value for value in values)


class SourceTimingPlanningRuntime:
    """Read-only capability for sampling against one open timing preparation.

    The source-timing preparation retains all lifecycle authority. Consumers may
    use this view to share its sampler, clocks, and audit overlay while planning,
    but cannot seal, claim, commit, or cancel the underlying runtime transaction.
    """

    __slots__ = ("_preparation",)

    def __init__(self, preparation: SourceTimingPreparation) -> None:
        self._preparation = preparation

    def _open_runtime(self) -> TimingRuntimePreparation:
        runtime = self._preparation._runtime_preparation
        if not self._preparation._owner.is_active_preparation(self._preparation) or runtime is None:
            raise StateError("Source timing planning runtime is no longer open")
        return runtime

    @property
    def sampler(self) -> Any:
        """Return the staged sampler while planning remains open."""

        return self._open_runtime().sampler

    @property
    def clocks(self) -> Any:
        """Return the staged clock registry while planning remains open."""

        return self._open_runtime().clocks

    @property
    def source_clock_registry(self) -> Any:
        """Return the staged source-clock registry while planning remains open."""

        return self._open_runtime().source_clock_registry

    @property
    def audit(self) -> Any:
        """Return the staged timing audit while planning remains open."""

        return self._open_runtime().audit

    def census(self, *, estimate_bytes: bool = False) -> TimingRuntimeCensus:
        """Return staged timing diagnostics while planning remains open."""

        return self._open_runtime().census(estimate_bytes=estimate_bytes)


_ACTIVE_SOURCE_TIMING_PREPARATION: ContextVar[Any] = ContextVar(
    "active_source_timing_preparation",
    default=None,
)


def active_source_timing_planning_runtime(
    owner_runtime: TimingRuntime,
) -> SourceTimingPlanningRuntime | None:
    """Return the exact owner's active non-owning planning view, if any.

    The lookup is total and read-only: foreign owners, inactive contexts, and
    preparations that have already sealed all return ``None``.
    """

    preparation = _ACTIVE_SOURCE_TIMING_PREPARATION.get()
    if (
        type(preparation) is not SourceTimingPreparation
        or preparation.owner.timing_runtime is not owner_runtime
    ):
        return None
    try:
        return preparation.planning_runtime
    except StateError:
        return None


@dataclass(slots=True)
class SourceTimingPlan:
    """Planned source-native timestamps for one canonical event."""

    canonical_timestamp: datetime
    clock_profile_name: str = "complete"
    compatibility_mode: bool = False
    observation_delays: dict[str, timedelta] = field(default_factory=dict)
    source_times: dict[str, datetime] = field(default_factory=dict)
    finalized_times: dict[str, datetime] = field(default_factory=dict)
    finalized_flags: dict[str, bool] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SourceTimingIndexCensus:
    """Constant-time structural census for one cross-event timing index."""

    name: str
    live_entries: int
    backing_entries: int
    stale_entries: int
    high_water_mark: int
    estimated_bytes: int
    lookup_candidates_inspected: int
    expiry_work: int


@dataclass(frozen=True, slots=True)
class SourceTimingIndexFamilySpec:
    """Public production shape for one bounded source-timing index family."""

    name: str
    key_shape: str
    value_shape: str
    deadline_shape: str


@dataclass(frozen=True, slots=True)
class SourceTimingProbeLoadResult:
    """Describe one representative production-shaped probe insertion."""

    inserted: bool
    replaced: bool
    key: Any
    deadline: datetime


@dataclass(frozen=True, slots=True)
class SourceTimingPlannerCensus:
    """Constant-time census for bounded planner indexes and the shared runtime."""

    index_count: int
    live_entries: int
    backing_entries: int
    stale_entries: int
    high_water_entries: int
    estimated_index_bytes: int
    estimated_total_bytes: int
    lookup_candidates_inspected: int
    expiry_work: int
    watermark: datetime | None
    indexes: tuple[SourceTimingIndexCensus, ...]
    runtime: TimingRuntimeCensus


PRODUCTION_SOURCE_TIMING_INDEX_FAMILIES: tuple[SourceTimingIndexFamilySpec, ...] = (
    SourceTimingIndexFamilySpec(
        "ecar_process_create", "process_object_id", "datetime", "lifecycle+48h"
    ),
    SourceTimingIndexFamilySpec(
        "runtime_process_create",
        "family/source_instance/process_object_id",
        "datetime",
        "lifecycle+48h",
    ),
    SourceTimingIndexFamilySpec(
        "runtime_cross_source_sysmon_create",
        "hostname/process_object_id",
        "native/render datetime pair",
        "lifecycle+48h",
    ),
    SourceTimingIndexFamilySpec(
        "sysmon_process_render_create",
        "hostname/process_object_id",
        "datetime",
        "lifecycle+48h",
    ),
    SourceTimingIndexFamilySpec(
        "process_dependent_create",
        "family/source_instance/process_object_id",
        "datetime",
        "lifecycle+48h",
    ),
    SourceTimingIndexFamilySpec(
        "kerberos_service",
        "format/principal/source_ip/dc_hostname",
        "latest datetime",
        "ticket+10s",
    ),
    SourceTimingIndexFamilySpec(
        "latest_session_start", "family/lifecycle_group_id", "datetime", "lifecycle+48h"
    ),
    SourceTimingIndexFamilySpec(
        "latest_session_dependent",
        "family/lifecycle_group_id",
        "datetime",
        "lifecycle+48h",
    ),
    SourceTimingIndexFamilySpec(
        "latest_session_dependent_description",
        "family/lifecycle_group_id",
        "description",
        "lifecycle+48h",
    ),
    SourceTimingIndexFamilySpec(
        "admitted_ecar_remote_transport",
        "action/transaction/host/network tuple",
        "datetime",
        "transport+10m",
    ),
    SourceTimingIndexFamilySpec(
        "admitted_windows_remote_transport",
        "action/transaction/host/network tuple",
        "datetime",
        "transport+10m",
    ),
    SourceTimingIndexFamilySpec(
        "admitted_ecar_transport_transaction",
        "transaction/host/network tuple",
        "datetime",
        "transport+10m",
    ),
    SourceTimingIndexFamilySpec(
        "ecar_transport_close_deadline",
        "transaction/host/network tuple",
        "datetime",
        "transport+10m",
    ),
    SourceTimingIndexFamilySpec(
        "admitted_windows_transport_transaction",
        "transaction/host/network tuple",
        "datetime",
        "transport+10m",
    ),
    SourceTimingIndexFamilySpec(
        "admitted_ecar_ssh_transport",
        "host/network tuple",
        "datetime",
        "transport+10m",
    ),
    SourceTimingIndexFamilySpec(
        "admitted_ecar_smb_transport",
        "host/network tuple",
        "datetime",
        "transport+10m",
    ),
)


def ecar_flow_render_key(direction: str, hostname: str) -> str:
    """Return the finalized-plan key for one host-local eCAR FLOW row."""

    return f"ecar.flow.{direction.lower()}.{hostname}"


def ecar_session_render_key(lifecycle: str) -> str:
    """Return the finalized-plan key for one eCAR USER_SESSION row."""

    return f"ecar.session.{lifecycle}"


def ecar_process_render_key(lifecycle: str, hostname: str) -> str:
    """Return the finalized-plan key for one eCAR PROCESS lifecycle row."""

    return f"ecar.process.{lifecycle.lower()}.{hostname}"


def ecar_process_create_source_key(hostname: str, pid: int, started_at: datetime) -> str:
    """Return the compatibility-plan key for one eCAR process-create anchor."""

    return SourceTimingPlanner._cache_key(
        "source.ecar_process_create",
        (hostname, pid, started_at),
    )


def sysmon_process_native_key(lifecycle: str, hostname: str) -> str:
    """Return the finalized-plan key for a Sysmon PROCESS payload timestamp."""

    return f"sysmon.process.{lifecycle.lower()}.native.{hostname}"


def sysmon_process_render_key(lifecycle: str, hostname: str) -> str:
    """Return the finalized-plan key for a Sysmon PROCESS envelope timestamp."""

    return f"sysmon.process.{lifecycle.lower()}.render.{hostname}"


def sysmon_parent_process_render_key(hostname: str) -> str:
    """Return the finalized-plan key for a Sysmon Event 1 parent identity."""

    return f"sysmon.process.parent.render.{hostname}"


def sysmon_process_identity_render_key(
    hostname: str,
    pid: int,
    started_at: datetime,
) -> str:
    """Return the frozen Sysmon Event 1 envelope key for one exact process."""

    return (
        f"sysmon.process.identity.render.{hostname.casefold()}:"
        f"{pid}:{ensure_utc(started_at).isoformat()}"
    )


def sysmon_process_pid_render_key(hostname: str, pid: int) -> str:
    """Return an occurrence-local Sysmon Event 1 envelope alias by PID."""

    return f"sysmon.process.pid.render.{hostname.casefold()}:{pid}"


def endpoint_event_native_key(
    format_name: str,
    hostname: str,
    phase: str = "base",
) -> str:
    """Return the frozen source-native payload key for one endpoint row."""

    family = _endpoint_format_family(format_name)
    return f"{family}.event.{phase}.native.{hostname}"


def endpoint_event_render_key(
    format_name: str,
    hostname: str,
    phase: str = "base",
) -> str:
    """Return the frozen rendered-envelope key for one endpoint row."""

    family = _endpoint_format_family(format_name)
    return f"{family}.event.{phase}.render.{hostname}"


def _endpoint_format_family(format_name: str) -> str:
    """Normalize endpoint format aliases to one timing family."""

    if format_name in {"windows_security", "windows_event_security"}:
        return "windows_security"
    if format_name in {"windows_event_sysmon", "sysmon"}:
        return "sysmon"
    if format_name == "ecar":
        return "ecar"
    raise ValueError(f"unsupported endpoint timing format: {format_name!r}")


def ecar_flow_identity_key(direction: str, hostname: str) -> str:
    """Return the finalized-plan key for FLOW process-attribution safety."""

    return f"ecar.flow_identity_safe.{direction.lower()}.{hostname}"


_WINDOWS_WFP_RENDER_KEY = "windows.wfp_connection"
_REMOTE_TRANSPORT_KEY = tuple[str, str, str, str, int, str, int, str]
_TRANSACTION_TRANSPORT_KEY = tuple[str, str, str, int, str, int, str]
_SSH_TRANSPORT_KEY = tuple[str, str, int, str, int, str]
_SMB_TRANSPORT_KEY = tuple[str, str, int, str, int, str]


def _retained_until(timestamp: datetime, retention: timedelta) -> datetime:
    """Return an overflow-safe UTC retention deadline."""

    canonical = ensure_utc(timestamp)
    if canonical > _MAX_UTC_DATETIME - retention:
        return _MAX_UTC_DATETIME
    return canonical + retention


def _latest_retained_until(
    timestamps: tuple[datetime, ...],
    retention: timedelta,
) -> datetime:
    """Return the retention deadline after the latest timestamp in a fixed tuple."""

    return _retained_until(max(timestamps), retention)


def _lifecycle_retention_deadline(timestamp: datetime) -> datetime:
    return _retained_until(timestamp, _SOURCE_TIMING_LIFECYCLE_RETENTION)


def _tuple_lifecycle_retention_deadline(
    timestamps: tuple[datetime, datetime],
) -> datetime:
    return _latest_retained_until(timestamps, _SOURCE_TIMING_LIFECYCLE_RETENTION)


def _transport_retention_deadline(timestamp: datetime) -> datetime:
    return _retained_until(timestamp, _SOURCE_TIMING_TRANSPORT_RETENTION)


def _ticket_retention_deadline(timestamp: datetime) -> datetime:
    return _retained_until(timestamp, _SOURCE_TIMING_TICKET_RETENTION)


@dataclass(frozen=True, slots=True)
class SourceTimingPreparationToken:
    """Stable owner-authenticated identity shared by related prepared dispatches."""

    preparation_id: int
    base_state_digest: str
    _integrity: str = field(repr=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class SourceTimingPreparationReceipt:
    """Authenticated proof that one sealed timing overlay committed exactly once."""

    binding_token: SourceTimingPreparationToken
    overlay_digest: str
    committed_state_digest: str
    _integrity: str = field(repr=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class SourceTimingDetachedPreparationBinding:
    """Exact detached proof of one sealed timing overlay and caller context.

    The planner retains only a weak exact-object locator and bounded scalar
    metadata.  It never retains the source timing preparation through this
    proof.  A later owner can therefore authenticate the exact committed
    receipt without retaining the mutable copy-on-write overlay.
    """

    binding_id: str
    preparation_id: int
    base_state_digest: str
    overlay_digest: str
    context_digest: str
    _integrity: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class SourceTimingDetachedBindingCensus:
    """Constant-time detached timing-binding authority counts and bytes."""

    retained_bindings: int
    capacity: int
    high_water_bindings: int
    binding_semantic_bytes: int
    generation_semantic_bytes: int
    claim_semantic_bytes: int
    receipt_semantic_bytes: int
    entry_semantic_bytes: int
    table_backing_bytes: int
    estimated_bytes: int


@dataclass(frozen=True, slots=True)
class _SourceTimingDetachedBindingRecord:
    """Planner-private exact locator with no preparation reference."""

    owner_ref: ReferenceType[SourceTimingPlanner]
    owner_marker: object
    binding_ref: ReferenceType[SourceTimingDetachedPreparationBinding]
    binding_id: str
    preparation_id: int
    base_state_digest: str
    overlay_digest: str
    context_digest: str
    integrity: str
    generation_marker: object
    lane_epoch: int
    binding_token: SourceTimingPreparationToken


@dataclass(frozen=True, slots=True)
class _SourceTimingDetachedBindingFacts:
    """Callback-free public detached-binding snapshot."""

    binding: SourceTimingDetachedPreparationBinding
    binding_id: str
    preparation_id: int
    base_state_digest: str
    overlay_digest: str
    context_digest: str
    integrity: str


@dataclass(frozen=True, slots=True)
class SourceTimingPreparationCensus:
    """Constant-time structural census for one bounded batch overlay."""

    state: str
    cache_family_count: int
    staged_cache_keys: int
    staged_cache_operations: int
    staged_audit_operations: int
    clock_live_entries: int
    clock_capacity: int


@dataclass(frozen=True, slots=True)
class SourceTimingPreparationAuthorityCensus:
    """Constant-time counts for bounded preparation and receipt authorities."""

    retained_preparations: int
    active_claims: int
    terminal_preparations: int
    retained_receipts: int
    retained_plan_operations: int
    high_water_preparations: int
    high_water_receipts: int
    capacity: int


@dataclass(frozen=True, slots=True)
class _PreparedCacheRecord:
    value: Any
    deadline_seconds: float


@dataclass(frozen=True, slots=True)
class _PreparedCacheOperation:
    kind: str
    key: Any
    value: Any = None
    deadline_seconds: float = 0.0


@dataclass(frozen=True, slots=True)
class _SourceTimingCacheCommitPlan:
    """Owner-private bounded operation-native cache commit plan."""

    target: _SourceTimingCache
    operations: tuple[_PreparedCacheOperation, ...]
    lookup_candidate_delta: int
    version_delta: int


@dataclass(frozen=True, slots=True)
class _SourceTimingRuntimeCommitPlan:
    """Owner-private delta audit and prebuilt clock state for the primitive tail."""

    preparation: TimingRuntimePreparation
    audit_target: Any
    audit_operations: tuple[tuple[str, str, str], ...]
    clocks_target: Any
    clock_states: Any
    discarded_clock_states: Any
    clock_high_water_mark: int
    clock_cache_entry_estimated_bytes: int
    clock_lookup_count: int
    clock_cache_hit_count: int
    clock_cache_miss_count: int
    clock_eviction_count: int
    clock_mutation_version: int


@dataclass(slots=True)
class _SourceTimingReceiptAuthority:
    """Owner-side exact-object receipt publication truth."""

    receipt_ref: ReferenceType[SourceTimingPreparationReceipt]
    facts: _SourceTimingReceiptFacts
    generation_marker: object
    committed: bool = False


@dataclass(frozen=True, slots=True)
class _SourceTimingTokenFacts:
    """Callback-free exact primitive snapshot of one public binding token."""

    token: SourceTimingPreparationToken
    preparation_id: int
    base_state_digest: str
    integrity: str


@dataclass(frozen=True, slots=True)
class _SourceTimingReceiptFacts:
    """Callback-free exact primitive snapshot retained by receipt authority."""

    token: SourceTimingPreparationToken
    preparation_id: int
    base_state_digest: str
    token_integrity: str
    overlay_digest: str
    committed_state_digest: str
    integrity: str


@dataclass(frozen=True, slots=True)
class _SourceTimingLaneGenerationRecord:
    """Private identity for one exact preparation carrier and owner-lane epoch."""

    carrier_ref: ReferenceType[SourceTimingPreparation]
    lane_marker: object
    lane_epoch: int
    generation_marker: object
    token_facts: _SourceTimingTokenFacts
    sealed: bool
    overlay_digest: str
    seal_integrity: str


@dataclass(frozen=True, slots=True)
class _SourceTimingSealedCarrierFacts:
    """One callback-free public carrier snapshot used only for private revalidation."""

    preparation: SourceTimingPreparation
    token_facts: _SourceTimingTokenFacts
    overlay_digest: str
    seal_integrity: str
    lane_marker: object


@dataclass(slots=True)
class _SourceTimingClaimRecord:
    """Planner-owned exact claim, commit plan, certification, and terminal truth."""

    preparation_id: int
    preparation_ref: ReferenceType[SourceTimingPreparation]
    owner: SourceTimingPlanner
    claim_thread_id: int
    lane_marker: object
    lane_epoch: int
    generation_marker: object
    base_watermark: datetime | None
    binding_token: SourceTimingPreparationToken
    sealed_overlay_digest: str
    seal_integrity: str
    commit_state_digest: str
    expected_receipt: SourceTimingPreparationReceipt
    receipt_authority: _SourceTimingReceiptAuthority
    admitted_cache_overlays: tuple[
        tuple[str, _SourceTimingCache, _PreparedSourceTimingCache],
        ...,
    ]
    admitted_runtime_preparation: TimingRuntimePreparation | None
    cache_plans: tuple[_SourceTimingCacheCommitPlan, ...]
    runtime_plan: _SourceTimingRuntimeCommitPlan | None
    retained_plan_operations: int
    state: str = "claimed"
    certified_receipt: SourceTimingPreparationReceipt | None = None


def _source_timing_generation_semantic_bytes(
    record: _SourceTimingLaneGenerationRecord,
) -> int:
    """Estimate one private generation record from exact bounded fields."""

    token = record.token_facts
    return (
        sys.getsizeof(record)
        + sys.getsizeof(record.carrier_ref)
        + sys.getsizeof(record.lane_marker)
        + sys.getsizeof(record.generation_marker)
        + sys.getsizeof(record.lane_epoch)
        + sys.getsizeof(token)
        + sys.getsizeof(token.preparation_id)
        + len(token.base_state_digest)
        + len(token.integrity)
        + len(record.overlay_digest)
        + len(record.seal_integrity)
    )


def _source_timing_claim_semantic_bytes(record: _SourceTimingClaimRecord) -> int:
    """Estimate one claim locator without traversing its prepared payload graph."""

    return (
        sys.getsizeof(record)
        + sys.getsizeof(record.preparation_ref)
        + sys.getsizeof(record.preparation_id)
    )


def _source_timing_receipt_semantic_bytes(
    receipt_identity: int,
    authority: _SourceTimingReceiptAuthority,
) -> int:
    """Estimate one retained receipt authority from its trusted scalar snapshot."""

    facts = authority.facts
    return (
        sys.getsizeof(receipt_identity)
        + sys.getsizeof(authority)
        + sys.getsizeof(authority.receipt_ref)
        + sys.getsizeof(facts)
        + sys.getsizeof(facts.preparation_id)
        + len(facts.base_state_digest)
        + len(facts.token_integrity)
        + len(facts.overlay_digest)
        + len(facts.committed_state_digest)
        + len(facts.integrity)
    )


def _source_timing_detached_binding_semantic_bytes(
    binding_identity: int,
    record: _SourceTimingDetachedBindingRecord,
) -> int:
    """Estimate one detached locator and its exact semantic-key storage."""

    semantic_key = (record.lane_epoch, record.preparation_id, record.context_digest)
    return (
        sys.getsizeof(binding_identity)
        + sys.getsizeof(record)
        + sys.getsizeof(record.binding_ref)
        + sys.getsizeof(semantic_key)
        + sys.getsizeof(record.preparation_id)
        + sys.getsizeof(record.lane_epoch)
        + len(record.binding_id)
        + len(record.base_state_digest)
        + len(record.overlay_digest)
        + len(record.context_digest)
        + len(record.integrity)
    )


class _SourceTimingCache:
    """Versioned lock-owning facade for one bounded planner cache."""

    __slots__ = ("_cache", "_default_deadline", "_lock", "_mutation_version", "_owner")

    def __init__(self, *, default_deadline: Any) -> None:
        self._cache: BoundedRuntimeCache[Any, Any] = BoundedRuntimeCache(
            default_deadline=default_deadline
        )
        self._default_deadline = default_deadline
        self._lock = RLock()
        self._mutation_version = 0
        self._owner: SourceTimingPlanner | None = None

    def _enter_public_mutation(self) -> SourceTimingPlanner | None:
        """Enter the planner lane before one canonical cache mutation."""

        owner = self._owner
        if owner is not None:
            owner._enter_public_mutation_lane()
        return owner

    @staticmethod
    def _leave_public_mutation(owner: SourceTimingPlanner | None) -> None:
        if owner is not None:
            owner._leave_public_mutation_lane()

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)

    def __bool__(self) -> bool:
        with self._lock:
            return bool(self._cache)

    def __contains__(self, key: object) -> bool:
        return self.get(key) is not None

    def __getitem__(self, key: Any) -> Any:
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value

    def __setitem__(self, key: Any, value: Any) -> None:
        self.set(key, value, deadline=self._default_deadline(value))

    @property
    def mutation_version(self) -> int:
        with self._lock:
            return self._mutation_version

    def get(self, key: Any, default: Any = None) -> Any:
        owner = self._enter_public_mutation()
        try:
            with self._lock:
                prior_candidates = self._cache.lookup_candidates_inspected
                value = self._cache.get(key, default)
                if self._cache.lookup_candidates_inspected != prior_candidates:
                    self._mutation_version += 1
                return value
        finally:
            self._leave_public_mutation(owner)

    def raw_get(self, key: Any, default: Any = None) -> Any:
        with self._lock:
            return self._cache.raw_get(key, default)

    def set(self, key: Any, value: Any, *, deadline: datetime | float | int) -> None:
        owner = self._enter_public_mutation()
        try:
            with self._lock:
                self._cache.set(key, value, deadline=deadline)
                self._mutation_version += 1
        finally:
            self._leave_public_mutation(owner)

    def redeadline(self, key: Any, *, deadline: datetime | float | int) -> bool:
        owner = self._enter_public_mutation()
        try:
            with self._lock:
                moved = self._cache.redeadline(key, deadline=deadline)
                if moved:
                    self._mutation_version += 1
                return moved
        finally:
            self._leave_public_mutation(owner)

    def pop(self, key: Any, default: Any = None) -> Any:
        owner = self._enter_public_mutation()
        try:
            with self._lock:
                present = self._cache.raw_get(key, _CACHE_TOMBSTONE) is not _CACHE_TOMBSTONE
                value = self._cache.pop(key, default)
                if present:
                    self._mutation_version += 1
                return value
        finally:
            self._leave_public_mutation(owner)

    def advance_watermark(self, cutoff: datetime, *, limit: int) -> tuple[tuple[Any, Any], ...]:
        owner = self._enter_public_mutation()
        try:
            with self._lock:
                expired = self._cache.advance_watermark(cutoff, limit=limit)
                self._mutation_version += 1
                return expired
        finally:
            self._leave_public_mutation(owner)

    def metrics(self, *, estimate_bytes: bool = False) -> Any:
        with self._lock:
            return self._cache.metrics(estimate_bytes=estimate_bytes)

    @property
    def lookup_candidates_inspected(self) -> int:
        with self._lock:
            return self._cache.lookup_candidates_inspected

    @property
    def expiry_work(self) -> int:
        with self._lock:
            return self._cache.expiry_work

    def _peek(self, key: Any) -> tuple[_PreparedCacheRecord | None, bool]:
        """Return one exact record and visibility without counter mutation."""

        with self._lock:
            record = self._cache._record(key)
            if record is None:
                return None, False
            return (
                _PreparedCacheRecord(record.value, record.deadline_seconds),
                self._cache._visible(record),
            )

    def _apply_prepared_locked(self, prepared: _PreparedSourceTimingCache) -> None:
        """Apply a prevalidated ordered overlay while ``_lock`` is held."""

        self._apply_operations_locked(
            prepared.operations,
            lookup_candidate_delta=prepared.lookup_candidate_delta,
            version_delta=prepared.version_delta,
        )

    def _apply_operations_locked(
        self,
        operations: tuple[_PreparedCacheOperation, ...],
        *,
        lookup_candidate_delta: int,
        version_delta: int,
    ) -> None:
        """Apply one prevalidated bounded delta while the claim owns ``_lock``."""

        for operation in operations:
            if operation.kind == "set":
                self._cache.set(
                    operation.key,
                    operation.value,
                    deadline=operation.deadline_seconds,
                )
            else:
                self._cache.pop(operation.key)
        self._cache._lookup_candidates_inspected += lookup_candidate_delta
        self._mutation_version += version_delta


class _PreparedSourceTimingCache:
    """Copy-on-write exact-key view over one source-timing cache."""

    __slots__ = (
        "_base",
        "_base_watermark_seconds",
        "_base_version",
        "_lookup_candidate_delta",
        "_operations",
        "_overlay",
        "_version_delta",
    )

    def __init__(self, base: _SourceTimingCache) -> None:
        self._base = base
        with base._lock:
            self._base_version = base._mutation_version
            self._base_watermark_seconds = base._cache._watermark_seconds
        self._lookup_candidate_delta = 0
        self._version_delta = 0
        self._operations: list[_PreparedCacheOperation] = []
        self._overlay: dict[Any, _PreparedCacheRecord | object] = {}

    @property
    def base_version(self) -> int:
        return self._base_version

    @property
    def operations(self) -> tuple[_PreparedCacheOperation, ...]:
        return tuple(self._operations)

    @property
    def lookup_candidate_delta(self) -> int:
        return self._lookup_candidate_delta

    @property
    def version_delta(self) -> int:
        return self._version_delta

    @property
    def staged_keys(self) -> int:
        return len(self._overlay)

    def __contains__(self, key: object) -> bool:
        return self.get(key) is not None

    def __getitem__(self, key: Any) -> Any:
        value = self.get(key, _CACHE_TOMBSTONE)
        if value is _CACHE_TOMBSTONE:
            raise KeyError(key)
        return value

    def __setitem__(self, key: Any, value: Any) -> None:
        self.set(key, value, deadline=self._base._default_deadline(value))

    def _current(self, key: Any) -> tuple[_PreparedCacheRecord | None, bool]:
        staged = self._overlay.get(key, _CACHE_TOMBSTONE)
        if staged is _CACHE_TOMBSTONE:
            return self._base._peek(key)
        if staged is None:
            return None, False
        record = staged
        return (
            record,
            self._base_watermark_seconds is None
            or record.deadline_seconds >= self._base_watermark_seconds,
        )

    def get(self, key: Any, default: Any = None) -> Any:
        record, visible = self._current(key)
        if record is None:
            return default
        self._lookup_candidate_delta += 1
        self._version_delta += 1
        return record.value if visible else default

    def raw_get(self, key: Any, default: Any = None) -> Any:
        record, _visible = self._current(key)
        return default if record is None else record.value

    def set(self, key: Any, value: Any, *, deadline: datetime | float | int) -> None:
        deadline_value = deadline_seconds(deadline)
        record = _PreparedCacheRecord(value, deadline_value)
        self._overlay[key] = record
        self._operations.append(_PreparedCacheOperation("set", key, value, deadline_value))
        self._version_delta += 1

    def redeadline(self, key: Any, *, deadline: datetime | float | int) -> bool:
        record, _visible = self._current(key)
        if record is None:
            return False
        self.set(key, record.value, deadline=deadline)
        return True

    def pop(self, key: Any, default: Any = None) -> Any:
        record, _visible = self._current(key)
        if record is None:
            return default
        self._overlay[key] = None
        self._operations.append(_PreparedCacheOperation("pop", key))
        self._version_delta += 1
        return record.value

    def overlay_digest(self) -> str:
        payload = tuple(
            (operation.kind, repr(operation.key), repr(operation.value), operation.deadline_seconds)
            for operation in self._operations
        )
        payload += (("lookup", self._lookup_candidate_delta, self._version_delta, 0.0),)
        return hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()


class SourceTimingPlanner:
    """Plan source-native observation times with deterministic constraints."""

    def __init__(
        self,
        clock_profile_name: str = "complete",
        *,
        timing_runtime: TimingRuntime | None = None,
        preparation_authority_capacity: int = (
            _DEFAULT_SOURCE_TIMING_PREPARATION_AUTHORITY_CAPACITY
        ),
        detached_binding_capacity: int = _DEFAULT_SOURCE_TIMING_DETACHED_BINDING_CAPACITY,
    ) -> None:
        if type(preparation_authority_capacity) is not int or preparation_authority_capacity < 1:
            raise ValueError("preparation_authority_capacity must be a positive integer")
        if type(detached_binding_capacity) is not int or detached_binding_capacity < 1:
            raise ValueError("detached_binding_capacity must be a positive integer")
        self.clock_profile_name = clock_profile_name or "complete"
        self.timing_runtime = timing_runtime or TimingRuntime.compatibility_default()
        self._ecar_process_create_times = _SourceTimingCache(
            default_deadline=_lifecycle_retention_deadline
        )
        self._runtime_process_create_times = _SourceTimingCache(
            default_deadline=_lifecycle_retention_deadline
        )
        self._runtime_cross_source_sysmon_create_times = _SourceTimingCache(
            default_deadline=_tuple_lifecycle_retention_deadline
        )
        self._sysmon_process_render_create_times = _SourceTimingCache(
            default_deadline=_lifecycle_retention_deadline
        )
        self._process_dependent_create_times = _SourceTimingCache(
            default_deadline=_lifecycle_retention_deadline
        )
        self._kerberos_service_times = _SourceTimingCache(
            default_deadline=_ticket_retention_deadline
        )
        self._latest_session_start_times = _SourceTimingCache(
            default_deadline=_lifecycle_retention_deadline
        )
        self._latest_session_dependent_times = _SourceTimingCache(
            default_deadline=_lifecycle_retention_deadline
        )
        self._latest_session_dependent_descriptions = _SourceTimingCache(
            default_deadline=lambda _description: _MAX_UTC_DATETIME
        )
        self._admitted_ecar_remote_transports = _SourceTimingCache(
            default_deadline=_transport_retention_deadline
        )
        self._admitted_windows_remote_transports = _SourceTimingCache(
            default_deadline=_transport_retention_deadline
        )
        self._admitted_ecar_transport_transactions = _SourceTimingCache(
            default_deadline=_transport_retention_deadline
        )
        self._ecar_transport_close_deadlines = _SourceTimingCache(
            default_deadline=_transport_retention_deadline
        )
        self._admitted_windows_transport_transactions = _SourceTimingCache(
            default_deadline=_transport_retention_deadline
        )
        self._admitted_ecar_ssh_transports = _SourceTimingCache(
            default_deadline=_transport_retention_deadline
        )
        self._admitted_ecar_smb_transports = _SourceTimingCache(
            default_deadline=_transport_retention_deadline
        )
        self._watermark: datetime | None = None
        self._preparation_lock = RLock()
        self._preparation_admission_lock = RLock()
        self._preparation_lane_epoch = 0
        self._preparation_lane: SourceTimingPreparation | None = None
        self._preparation_lane_marker: object | None = None
        self._preparation_lane_generation: _SourceTimingLaneGenerationRecord | None = None
        self._preparation_authority_lock = RLock()
        self._preparation_secret = secrets.token_bytes(32)
        self._next_preparation_id = 1
        self._preparation_authority_capacity = preparation_authority_capacity
        self._preparation_claim_records: dict[int, _SourceTimingClaimRecord] = {}
        self._committed_preparation_receipts: dict[
            int,
            _SourceTimingReceiptAuthority,
        ] = {}
        self._preparation_authority_high_water = 0
        self._preparation_receipt_high_water = 0
        self._active_preparation_claims = 0
        self._terminal_preparations = 0
        self._retained_preparation_plan_operations = 0
        self._detached_binding_capacity = detached_binding_capacity
        self._detached_binding_owner_marker = object()
        self._detached_binding_semantic_bytes = 0
        self._preparation_generation_semantic_bytes = 0
        self._preparation_claim_semantic_bytes = 0
        self._preparation_receipt_semantic_bytes = 0
        self._detached_bindings: dict[int, _SourceTimingDetachedBindingRecord] = {}
        self._detached_binding_by_context: dict[tuple[int, int, str], int] = {}
        self._detached_binding_high_water = 0
        for _name, cache in self._bounded_indexes():
            cache._owner = self

    def __copy__(self) -> SourceTimingPlanner:
        """Reject shallow copies that could alias private timing authority."""

        raise StateError("Source timing planners cannot be copied")

    def __deepcopy__(self, _memo: dict[int, Any]) -> SourceTimingPlanner:
        """Reject deep copies that cannot preserve exact timing authority."""

        raise StateError("Source timing planners cannot be copied")

    def _isolate_preparation_authority_for_overlay(self) -> None:
        """Install empty, non-owning authority state on one planner overlay clone."""

        self._preparation_lock = RLock()
        self._preparation_admission_lock = RLock()
        self._preparation_lane_epoch = 0
        self._preparation_lane = None
        self._preparation_lane_marker = None
        self._preparation_lane_generation = None
        self._preparation_authority_lock = RLock()
        self._preparation_secret = secrets.token_bytes(32)
        self._next_preparation_id = 1
        self._preparation_claim_records = {}
        self._committed_preparation_receipts = {}
        self._preparation_authority_high_water = 0
        self._preparation_receipt_high_water = 0
        self._active_preparation_claims = 0
        self._terminal_preparations = 0
        self._retained_preparation_plan_operations = 0
        self._detached_binding_owner_marker = object()
        self._detached_binding_semantic_bytes = 0
        self._preparation_generation_semantic_bytes = 0
        self._preparation_claim_semantic_bytes = 0
        self._preparation_receipt_semantic_bytes = 0
        self._detached_bindings = {}
        self._detached_binding_by_context = {}
        self._detached_binding_high_water = 0

    def _require_public_mutation_lane(self) -> None:
        """Reject canonical planner mutation while one preparation owns the lane."""

        if self._preparation_lane_marker is not None:
            raise StateError("Source timing canonical mutation is blocked by an active owner claim")

    def _enter_public_mutation_lane(self) -> None:
        """Admit one mutation or reject if it overlaps any owner claim epoch."""

        observed_epoch = self._preparation_lane_epoch
        if self._preparation_lane_marker is not None:
            self._require_public_mutation_lane()
        with self._preparation_admission_lock:
            if (
                self._preparation_lane_marker is not None
                or self._preparation_lane_epoch != observed_epoch
            ):
                self._require_public_mutation_lane()
                raise StateError("Source timing canonical mutation overlapped an owner claim")
            admitted_epoch = self._preparation_lane_epoch
        self._preparation_lock.acquire()
        try:
            with self._preparation_admission_lock:
                if (
                    self._preparation_lane_marker is not None
                    or self._preparation_lane_epoch != admitted_epoch
                ):
                    self._require_public_mutation_lane()
                    raise StateError("Source timing canonical mutation overlapped an owner claim")
        except BaseException:
            self._preparation_lock.release()
            raise

    def _leave_public_mutation_lane(self) -> None:
        """Release one admitted canonical planner mutation."""

        self._preparation_lock.release()

    def _require_public_planning_entry(self) -> None:
        """Reject canonical planning while allowing the isolated overlay clone."""

        if self._preparation_lane is not None:
            self._require_public_mutation_lane()

    def _install_preparation_lane(self, marker: object) -> None:
        """Install one planner/runtime lane before constructing its snapshot."""

        with self._preparation_admission_lock:
            if self._preparation_lane_marker is not None:
                raise StateError("Source timing planner already has an active owner claim")
            try:
                self.timing_runtime._install_owner_lane(marker)
            except TimingDistributionError as error:
                raise StateError(str(error)) from error
            self._preparation_lane_epoch += 1
            self._preparation_lane_marker = marker

    def _set_preparation_lane_generation_locked(
        self,
        generation: _SourceTimingLaneGenerationRecord | None,
    ) -> None:
        """Replace one lane generation and its constant-time semantic byte count."""

        semantic_bytes = (
            0 if generation is None else _source_timing_generation_semantic_bytes(generation)
        )
        self._preparation_lane_generation = generation
        self._preparation_generation_semantic_bytes = semantic_bytes

    def _bind_preparation_lane(
        self,
        preparation: SourceTimingPreparation,
        marker: object,
    ) -> None:
        """Bind the installed marker and private generation to one exact carrier."""

        with self._preparation_admission_lock:
            if (
                self._preparation_lane_marker is not marker
                or self._preparation_lane is not None
                or self._preparation_lane_generation is not None
            ):
                raise StateError("Source timing preparation owner lane changed before binding")
            token = object.__getattribute__(preparation, "_binding_token")
            token_facts = self._snapshot_preparation_token(token)
            if token_facts is None:
                raise StateError("Source timing preparation token failed private generation issue")
            generation = _SourceTimingLaneGenerationRecord(
                carrier_ref=ref(preparation),
                lane_marker=marker,
                lane_epoch=self._preparation_lane_epoch,
                generation_marker=object(),
                token_facts=token_facts,
                sealed=False,
                overlay_digest="",
                seal_integrity="",
            )
            self._preparation_lane = preparation
            self._set_preparation_lane_generation_locked(generation)

    def _seal_preparation_lane_generation(
        self,
        preparation: SourceTimingPreparation,
        overlay_digest: str,
    ) -> tuple[SourceTimingPreparationToken, str]:
        """Seal the exact private lane generation without trusting carrier token slots."""

        overlay = _exact_sha256_hex(overlay_digest, "source timing sealed overlay digest")
        with self._preparation_admission_lock:
            record = self._preparation_lane_generation
            if (
                record is None
                or record.sealed
                or record.carrier_ref() is not preparation
                or self._preparation_lane is not preparation
                or self._preparation_lane_marker is not record.lane_marker
                or self._preparation_lane_epoch != record.lane_epoch
            ):
                raise StateError("Source timing preparation private generation cannot seal")
            seal_integrity = self._preparation_seal_integrity_from_fields(
                preparation_id=record.token_facts.preparation_id,
                token_integrity=record.token_facts.integrity,
                overlay_digest=overlay,
            )
            sealed_generation = _SourceTimingLaneGenerationRecord(
                carrier_ref=record.carrier_ref,
                lane_marker=record.lane_marker,
                lane_epoch=record.lane_epoch,
                generation_marker=record.generation_marker,
                token_facts=record.token_facts,
                sealed=True,
                overlay_digest=overlay,
                seal_integrity=seal_integrity,
            )
            self._set_preparation_lane_generation_locked(sealed_generation)
            return record.token_facts.token, seal_integrity

    def _release_preparation_lane(
        self,
        preparation: SourceTimingPreparation,
        marker: object,
    ) -> None:
        """Release only the exact preparation/runtime owner lane."""

        with self._preparation_lock:
            with self._preparation_admission_lock:
                if (
                    self._preparation_lane is not preparation
                    or self._preparation_lane_marker is not marker
                ):
                    raise StateError("Source timing preparation owner lane is not active")
                generation = self._preparation_lane_generation
                if (
                    generation is None
                    or generation.carrier_ref() is not preparation
                    or generation.lane_marker is not marker
                    or generation.lane_epoch != self._preparation_lane_epoch
                ):
                    raise StateError("Source timing preparation private generation is not active")
                self._preparation_lane = None
                self._preparation_lane_marker = None
                self._set_preparation_lane_generation_locked(None)
                try:
                    self.timing_runtime._release_owner_lane(marker)
                except TimingDistributionError as error:
                    self._preparation_lane = preparation
                    self._preparation_lane_marker = marker
                    self._set_preparation_lane_generation_locked(generation)
                    raise StateError(str(error)) from error
                self._preparation_lane_epoch += 1

    def _install_preparation_claim_record(
        self,
        preparation: SourceTimingPreparation,
        record: _SourceTimingClaimRecord,
    ) -> None:
        """Install one exact weak carrier locator while the preparation lock is held."""

        preparation_id = id(preparation)
        semantic_bytes = _source_timing_claim_semantic_bytes(record)
        with self._preparation_authority_lock:
            if len(self._preparation_claim_records) >= self._preparation_authority_capacity:
                raise StateError("Source timing preparation authority capacity is exhausted")
            if preparation_id in self._preparation_claim_records:
                raise StateError("Source timing preparation already owns an active claim record")
            self._preparation_claim_records[preparation_id] = record
            self._preparation_claim_semantic_bytes += semantic_bytes
            self._active_preparation_claims += 1
            self._retained_preparation_plan_operations += record.retained_plan_operations
            self._preparation_authority_high_water = max(
                self._preparation_authority_high_water,
                len(self._preparation_claim_records),
            )

    def _active_preparation_claim_record(
        self,
        preparation: object,
    ) -> _SourceTimingClaimRecord | None:
        """Resolve one exact planner-owned carrier record without trusting carrier fields."""

        if type(preparation) is not SourceTimingPreparation:
            return None
        with self._preparation_authority_lock:
            record = self._preparation_claim_records.get(id(preparation))
            if record is None or record.preparation_ref() is not preparation:
                return None
            return record

    def _claim_record_matches_current_state(
        self,
        record: _SourceTimingClaimRecord,
    ) -> bool:
        """Match one claim to the exact canonical primitives it will replace."""

        generation = self._preparation_lane_generation
        if (
            record.owner is not self
            or record.claim_thread_id != get_ident()
            or self._preparation_lane_marker is not record.lane_marker
            or self._preparation_lane is not record.preparation_ref()
            or generation is None
            or generation.generation_marker is not record.generation_marker
            or generation.lane_epoch != record.lane_epoch
            or generation.lane_marker is not record.lane_marker
            or generation.token_facts.token is not record.binding_token
            or self._watermark != record.base_watermark
        ):
            return False
        if any(
            cache._mutation_version != prepared.base_version
            for _name, cache, prepared in record.admitted_cache_overlays
        ):
            return False
        runtime_preparation = record.admitted_runtime_preparation
        if runtime_preparation is None:
            return False
        runtime_base = runtime_preparation._base
        return bool(
            runtime_base.audit._mutation_version == runtime_preparation.audit.base_version
            and runtime_base.clocks._mutation_version == runtime_preparation.clocks.base_version
        )

    def _discard_preparation_claim_record(
        self,
        preparation: SourceTimingPreparation,
    ) -> None:
        """Discard only the exact active record for ``preparation``."""

        preparation_id = id(preparation)
        with self._preparation_authority_lock:
            record = self._preparation_claim_records.get(preparation_id)
            if record is not None and record.preparation_ref() is preparation:
                self._preparation_claim_records.pop(preparation_id, None)
                self._remove_preparation_record_counts_locked(record)

    def _remove_preparation_record_counts_locked(
        self,
        record: _SourceTimingClaimRecord,
    ) -> None:
        """Remove one exact active or terminal record from constant-time counts."""

        if record.state in {"claimed", "certified"}:
            self._active_preparation_claims -= 1
        elif record.state == "committed":
            self._terminal_preparations -= 1
        self._retained_preparation_plan_operations -= record.retained_plan_operations
        self._preparation_claim_semantic_bytes -= _source_timing_claim_semantic_bytes(record)
        if not self._preparation_claim_records:
            self._preparation_claim_records.clear()

    def _terminalize_preparation_record_no_fail(
        self,
        record: _SourceTimingClaimRecord,
    ) -> None:
        """Publish one already-certified terminal record with scalar-only writes."""

        with self._preparation_authority_lock:
            self._active_preparation_claims -= 1
            self._terminal_preparations += 1
            self._retained_preparation_plan_operations -= record.retained_plan_operations
            record.receipt_authority.committed = True
            record.state = "committed"
            record.retained_plan_operations = 0

    def _preparation_carrier_collected(
        self,
        preparation_id: int,
        carrier_ref: ReferenceType[SourceTimingPreparation],
    ) -> None:
        """Prune one dead preparation locator without an untrusted carrier callback."""

        with self._preparation_authority_lock:
            record = self._preparation_claim_records.get(preparation_id)
            if record is not None and record.preparation_ref is carrier_ref:
                self._preparation_claim_records.pop(preparation_id, None)
                self._remove_preparation_record_counts_locked(record)

    def _remove_preparation_receipt_authority_locked(
        self,
        receipt_identity: int,
        authority: _SourceTimingReceiptAuthority,
    ) -> bool:
        """Remove one exact receipt authority and its semantic byte charge."""

        if self._committed_preparation_receipts.get(receipt_identity) is not authority:
            return False
        self._committed_preparation_receipts.pop(receipt_identity, None)
        self._preparation_receipt_semantic_bytes -= _source_timing_receipt_semantic_bytes(
            receipt_identity,
            authority,
        )
        if not self._committed_preparation_receipts:
            self._committed_preparation_receipts.clear()
        return True

    def _retain_expected_preparation_receipt(
        self,
        receipt: SourceTimingPreparationReceipt,
        *,
        generation_marker: object,
    ) -> _SourceTimingReceiptAuthority:
        """Preallocate exact receipt authority before any canonical mutation."""

        facts = self._snapshot_preparation_receipt(receipt)
        if facts is None:
            raise StateError("Source timing expected receipt is malformed")
        receipt_id = id(receipt)
        owner_ref = ref(self)

        def remove_collected(
            receipt_ref: ReferenceType[SourceTimingPreparationReceipt],
        ) -> None:
            owner = owner_ref()
            if owner is None:
                return
            with owner._preparation_authority_lock:
                authority = owner._committed_preparation_receipts.get(receipt_id)
                if authority is not None and authority.receipt_ref is receipt_ref:
                    owner._remove_preparation_receipt_authority_locked(
                        receipt_id,
                        authority,
                    )

        receipt_ref = ref(receipt, remove_collected)
        authority = _SourceTimingReceiptAuthority(receipt_ref, facts, generation_marker)
        semantic_bytes = _source_timing_receipt_semantic_bytes(receipt_id, authority)
        with self._preparation_authority_lock:
            if len(self._committed_preparation_receipts) >= self._preparation_authority_capacity:
                raise StateError("Source timing preparation receipt capacity is exhausted")
            if receipt_id in self._committed_preparation_receipts:
                raise StateError("Source timing receipt identity is already retained")
            self._committed_preparation_receipts[receipt_id] = authority
            self._preparation_receipt_semantic_bytes += semantic_bytes
            self._preparation_receipt_high_water = max(
                self._preparation_receipt_high_water,
                len(self._committed_preparation_receipts),
            )
        return authority

    def _discard_expected_preparation_receipt(
        self,
        receipt: SourceTimingPreparationReceipt,
    ) -> None:
        """Discard one unpublished exact receipt authority after claim abort."""

        with self._preparation_authority_lock:
            receipt_identity = id(receipt)
            authority = self._committed_preparation_receipts.get(receipt_identity)
            if (
                authority is not None
                and not authority.committed
                and authority.receipt_ref() is receipt
            ):
                self._remove_preparation_receipt_authority_locked(
                    receipt_identity,
                    authority,
                )

    def preparation_authority_census(self) -> SourceTimingPreparationAuthorityCensus:
        """Return exact bounded preparation and terminal-receipt counts."""

        with self._preparation_authority_lock:
            return SourceTimingPreparationAuthorityCensus(
                retained_preparations=len(self._preparation_claim_records),
                active_claims=self._active_preparation_claims,
                terminal_preparations=self._terminal_preparations,
                retained_receipts=len(self._committed_preparation_receipts),
                retained_plan_operations=self._retained_preparation_plan_operations,
                high_water_preparations=self._preparation_authority_high_water,
                high_water_receipts=self._preparation_receipt_high_water,
                capacity=self._preparation_authority_capacity,
            )

    def _bounded_indexes(self) -> tuple[tuple[str, _SourceTimingCache], ...]:
        """Return the fixed bounded cross-event index inventory."""

        return (
            ("ecar_process_create", self._ecar_process_create_times),
            ("runtime_process_create", self._runtime_process_create_times),
            (
                "runtime_cross_source_sysmon_create",
                self._runtime_cross_source_sysmon_create_times,
            ),
            ("sysmon_process_render_create", self._sysmon_process_render_create_times),
            ("process_dependent_create", self._process_dependent_create_times),
            ("kerberos_service", self._kerberos_service_times),
            ("latest_session_start", self._latest_session_start_times),
            ("latest_session_dependent", self._latest_session_dependent_times),
            (
                "latest_session_dependent_description",
                self._latest_session_dependent_descriptions,
            ),
            ("admitted_ecar_remote_transport", self._admitted_ecar_remote_transports),
            (
                "admitted_windows_remote_transport",
                self._admitted_windows_remote_transports,
            ),
            (
                "admitted_ecar_transport_transaction",
                self._admitted_ecar_transport_transactions,
            ),
            ("ecar_transport_close_deadline", self._ecar_transport_close_deadlines),
            (
                "admitted_windows_transport_transaction",
                self._admitted_windows_transport_transactions,
            ),
            ("admitted_ecar_ssh_transport", self._admitted_ecar_ssh_transports),
            ("admitted_ecar_smb_transport", self._admitted_ecar_smb_transports),
        )

    @property
    def index_family_specs(self) -> tuple[SourceTimingIndexFamilySpec, ...]:
        """Return immutable public shapes for every bounded planner index."""

        return PRODUCTION_SOURCE_TIMING_INDEX_FAMILIES

    def load_probe_entry(
        self,
        family: str,
        ordinal: int,
        at: datetime,
    ) -> SourceTimingProbeLoadResult:
        """Load one representative production-shaped entry for a scale probe."""

        if ordinal < 0:
            raise ValueError("Source timing probe ordinal must be non-negative")
        timestamp = ensure_utc(at)
        cache = next(
            (candidate for name, candidate in self._bounded_indexes() if name == family),
            None,
        )
        if cache is None:
            raise KeyError(f"Unknown source timing index family: {family}")
        key, value, deadline = self._probe_entry(family, ordinal, timestamp)
        inserted = cache.raw_get(key) is None
        cache.set(key, value, deadline=deadline)
        return SourceTimingProbeLoadResult(
            inserted=inserted,
            replaced=not inserted,
            key=key,
            deadline=deadline,
        )

    @staticmethod
    def _probe_entry(
        family: str,
        ordinal: int,
        timestamp: datetime,
    ) -> tuple[Any, Any, datetime]:
        """Build one fixed-shape probe entry without inspecting retained state."""

        host = f"host-{ordinal % 4_096:04d}"
        object_id = f"process:{host}:{10_000 + ordinal}:{timestamp.isoformat()}"
        source_instance = f"endpoint:{host}:agent"
        transaction_id = f"transaction-{ordinal:016x}"
        src_ip = f"10.{(ordinal // 65_536) % 256}.{(ordinal // 256) % 256}.{ordinal % 256}"
        dst_ip = f"172.20.{(ordinal // 256) % 256}.{ordinal % 256}"
        network_tuple = (src_ip, 10_000 + ordinal % 50_000, dst_ip, 445, "tcp")
        lifecycle_deadline = _lifecycle_retention_deadline(timestamp)
        transport_deadline = _transport_retention_deadline(timestamp)
        if family == "ecar_process_create":
            return object_id, timestamp, lifecycle_deadline
        if family in {"runtime_process_create", "process_dependent_create"}:
            return (
                ("ecar", source_instance, object_id),
                timestamp,
                lifecycle_deadline,
            )
        if family == "runtime_cross_source_sysmon_create":
            rendered = timestamp + timedelta(microseconds=ordinal % 997 + 1)
            return (host, object_id), (timestamp, rendered), lifecycle_deadline
        if family == "sysmon_process_render_create":
            return (host, object_id), timestamp, lifecycle_deadline
        if family == "kerberos_service":
            return (
                ("windows_event_security", f"machine-{ordinal}$", src_ip, host),
                timestamp,
                _ticket_retention_deadline(timestamp),
            )
        if family in {
            "latest_session_start",
            "latest_session_dependent",
            "latest_session_dependent_description",
        }:
            value: Any = (
                f"event=process_terminate source={timestamp.isoformat()}"
                if family == "latest_session_dependent_description"
                else timestamp
            )
            return ("ecar", f"session-{ordinal:016x}"), value, lifecycle_deadline
        if family in {
            "admitted_ecar_remote_transport",
            "admitted_windows_remote_transport",
        }:
            return (
                (
                    f"action-{ordinal:016x}",
                    transaction_id,
                    host,
                    *network_tuple,
                ),
                timestamp,
                transport_deadline,
            )
        if family in {
            "admitted_ecar_transport_transaction",
            "ecar_transport_close_deadline",
            "admitted_windows_transport_transaction",
        }:
            return (
                (transaction_id, host, *network_tuple),
                timestamp,
                transport_deadline,
            )
        if family in {"admitted_ecar_ssh_transport", "admitted_ecar_smb_transport"}:
            dst_port = 22 if family == "admitted_ecar_ssh_transport" else 445
            return (
                (host, src_ip, network_tuple[1], dst_ip, dst_port, "tcp"),
                timestamp,
                transport_deadline,
            )
        raise KeyError(f"Unknown source timing index family: {family}")

    def advance_watermark(self, cutoff: datetime, *, page_limit: int = 4_096) -> int:
        """Advance logical expiry and reclaim one bounded page from every index."""

        canonical_cutoff = ensure_utc(cutoff)
        self._enter_public_mutation_lane()
        try:
            if self._watermark is not None and canonical_cutoff < self._watermark:
                raise ValueError("Source timing watermark cannot move backward")
            self._watermark = canonical_cutoff
            return sum(
                len(cache.advance_watermark(canonical_cutoff, limit=page_limit))
                for _name, cache in self._bounded_indexes()
            )
        finally:
            self._leave_public_mutation_lane()

    def census(self, *, estimate_bytes: bool = False) -> SourceTimingPlannerCensus:
        """Return constant-time bounded-index and shared-runtime diagnostics."""

        families: list[SourceTimingIndexCensus] = []
        for name, cache in self._bounded_indexes():
            metrics = cache.metrics(estimate_bytes=estimate_bytes)
            families.append(
                SourceTimingIndexCensus(
                    name=name,
                    live_entries=metrics.live_entries,
                    backing_entries=metrics.backing_entries,
                    stale_entries=metrics.stale_entries,
                    high_water_mark=metrics.high_water_mark,
                    estimated_bytes=metrics.estimated_bytes,
                    lookup_candidates_inspected=cache.lookup_candidates_inspected,
                    expiry_work=cache.expiry_work,
                )
            )
        indexes = tuple(families)
        runtime = self.timing_runtime.census(estimate_bytes=estimate_bytes)
        estimated_index_bytes = sum(index.estimated_bytes for index in indexes)
        return SourceTimingPlannerCensus(
            index_count=len(indexes),
            live_entries=sum(index.live_entries for index in indexes),
            backing_entries=sum(index.backing_entries for index in indexes),
            stale_entries=sum(index.stale_entries for index in indexes),
            high_water_entries=sum(index.high_water_mark for index in indexes),
            estimated_index_bytes=estimated_index_bytes,
            estimated_total_bytes=(
                sys.getsizeof(self) + estimated_index_bytes + runtime.estimated_bytes
                if estimate_bytes
                else 0
            ),
            lookup_candidates_inspected=sum(index.lookup_candidates_inspected for index in indexes),
            expiry_work=sum(index.expiry_work for index in indexes),
            watermark=self._watermark,
            indexes=indexes,
            runtime=runtime,
        )

    def state_digest(self) -> str:
        """Return a constant-time digest of planner, runtime, and diagnostic versions."""

        indexes: list[tuple[Any, ...]] = []
        for name, cache in self._bounded_indexes():
            metrics = cache.metrics()
            indexes.append(
                (
                    name,
                    cache.mutation_version,
                    metrics.live_entries,
                    metrics.backing_entries,
                    metrics.stale_entries,
                    metrics.high_water_mark,
                    cache.lookup_candidates_inspected,
                    cache.expiry_work,
                )
            )
        payload = (
            self._watermark.isoformat() if self._watermark is not None else "",
            tuple(indexes),
            self.timing_runtime.state_digest(),
        )
        return hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()

    @contextmanager
    def prepared_planning(self) -> Iterator[SourceTimingPreparation]:
        """Stage a related source-timing family without canonical mutation."""

        active = _ACTIVE_SOURCE_TIMING_PREPARATION.get()
        if type(active) is SourceTimingPreparation and active._owner is self:
            raise StateError("Nested source timing preparations are not supported")
        with self._preparation_lock:
            marker = object()
            self._install_preparation_lane(marker)
            preparation_id = self._next_preparation_id
            self._next_preparation_id += 1
            try:
                preparation = SourceTimingPreparation(
                    self,
                    preparation_id=preparation_id,
                    lane_marker=marker,
                )
                self._bind_preparation_lane(preparation, marker)
            except BaseException:
                with self._preparation_admission_lock:
                    self._preparation_lane = None
                    self._preparation_lane_marker = None
                    self._set_preparation_lane_generation_locked(None)
                    self.timing_runtime._release_owner_lane(marker)
                    self._preparation_lane_epoch += 1
                raise
        context_token: Token[Any] = _ACTIVE_SOURCE_TIMING_PREPARATION.set(preparation)
        try:
            yield preparation
            preparation.seal()
        except BaseException:
            if not preparation.committed:
                preparation.cancel()
            raise
        finally:
            _ACTIVE_SOURCE_TIMING_PREPARATION.reset(context_token)

    def _snapshot_preparation_token(self, token: object) -> _SourceTimingTokenFacts | None:
        """Read every public token slot once before performing typed comparisons."""

        if type(token) is not SourceTimingPreparationToken:
            return None
        try:
            preparation_id = object.__getattribute__(token, "preparation_id")
            base_value = object.__getattribute__(token, "base_state_digest")
            integrity = object.__getattribute__(token, "_integrity")
            if type(preparation_id) is not int or preparation_id < 1 or type(integrity) is not str:
                return None
            base_digest = _exact_sha256_hex(
                base_value,
                "source timing preparation base-state digest",
            )
            expected = self._preparation_token_integrity(preparation_id, base_digest)
            if not hmac.compare_digest(integrity, expected):
                return None
            return _SourceTimingTokenFacts(
                token=token,
                preparation_id=preparation_id,
                base_state_digest=base_digest,
                integrity=integrity,
            )
        except BaseException:
            return None

    def _snapshot_preparation_receipt(
        self,
        receipt: object,
    ) -> _SourceTimingReceiptFacts | None:
        """Read a receipt and nested token once without invoking peer callbacks."""

        if type(receipt) is not SourceTimingPreparationReceipt:
            return None
        try:
            token = object.__getattribute__(receipt, "binding_token")
            overlay_value = object.__getattribute__(receipt, "overlay_digest")
            committed_value = object.__getattribute__(receipt, "committed_state_digest")
            integrity = object.__getattribute__(receipt, "_integrity")
            if type(integrity) is not str:
                return None
            token_facts = self._snapshot_preparation_token(token)
            if token_facts is None:
                return None
            overlay_digest = _exact_sha256_hex(
                overlay_value,
                "source timing receipt overlay digest",
            )
            committed_digest = _exact_sha256_hex(
                committed_value,
                "source timing receipt committed-state digest",
            )
            expected = self._preparation_receipt_integrity_from_fields(
                preparation_id=token_facts.preparation_id,
                token_integrity=token_facts.integrity,
                overlay_digest=overlay_digest,
                committed_state_digest=committed_digest,
            )
            if not hmac.compare_digest(integrity, expected):
                return None
            return _SourceTimingReceiptFacts(
                token=token_facts.token,
                preparation_id=token_facts.preparation_id,
                base_state_digest=token_facts.base_state_digest,
                token_integrity=token_facts.integrity,
                overlay_digest=overlay_digest,
                committed_state_digest=committed_digest,
                integrity=integrity,
            )
        except BaseException:
            return None

    @staticmethod
    def _receipt_facts_match(
        snapshot: _SourceTimingReceiptFacts,
        trusted: _SourceTimingReceiptFacts,
    ) -> bool:
        """Compare only exact primitive locals and exact retained carriers."""

        return bool(
            snapshot.token is trusted.token
            and snapshot.preparation_id == trusted.preparation_id
            and snapshot.base_state_digest == trusted.base_state_digest
            and hmac.compare_digest(snapshot.token_integrity, trusted.token_integrity)
            and snapshot.overlay_digest == trusted.overlay_digest
            and snapshot.committed_state_digest == trusted.committed_state_digest
            and hmac.compare_digest(snapshot.integrity, trusted.integrity)
        )

    def authenticates_binding_token(self, token: object) -> bool:
        """Return whether ``token`` belongs to this exact planner instance."""

        return self._snapshot_preparation_token(token) is not None

    def _detached_preparation_binding_integrity(
        self,
        *,
        binding_id: str,
        preparation_id: int,
        base_state_digest: str,
        overlay_digest: str,
        context_digest: str,
    ) -> str:
        """Authenticate one detached overlay/context proof with typed framing."""

        payload = _source_timing_detached_frame(
            b"source-timing-detached-preparation-v1",
            binding_id.encode("ascii"),
            preparation_id.to_bytes(8, "big", signed=False),
            base_state_digest.encode("ascii"),
            overlay_digest.encode("ascii"),
            context_digest.encode("ascii"),
        )
        return hmac.new(self._preparation_secret, payload, hashlib.sha256).hexdigest()

    def _detached_binding_collected(
        self,
        binding_identity: int,
        binding_ref: ReferenceType[SourceTimingDetachedPreparationBinding],
    ) -> None:
        """Reclaim one dead exact binding locator in constant time."""

        with self._preparation_authority_lock:
            record = self._detached_bindings.get(binding_identity)
            if (
                record is None
                or not self._owns_detached_binding_record(record)
                or record.binding_ref is not binding_ref
            ):
                return
            self._remove_detached_binding_record_locked(binding_identity, record)

    def _owns_detached_binding_record(
        self,
        record: _SourceTimingDetachedBindingRecord,
    ) -> bool:
        """Return whether one private record belongs to this exact planner owner."""

        return bool(
            record.owner_ref() is self
            and record.owner_marker is self._detached_binding_owner_marker
        )

    def _snapshot_sealed_preparation_for_detach(
        self,
        preparation: object,
    ) -> tuple[_SourceTimingSealedCarrierFacts, _SourceTimingLaneGenerationRecord] | None:
        """Snapshot public slots once, then resolve the exact private lane generation."""

        if type(preparation) is not SourceTimingPreparation:
            return None
        try:
            owner = object.__getattribute__(preparation, "_owner")
            state = object.__getattribute__(preparation, "_state")
            token = object.__getattribute__(preparation, "_binding_token")
            overlay_value = object.__getattribute__(preparation, "_sealed_overlay_digest")
            seal_integrity = object.__getattribute__(preparation, "_seal_integrity")
            lane_active = object.__getattribute__(preparation, "_lane_active")
            lane_marker = object.__getattribute__(preparation, "_lane_marker")
            context_closed = object.__getattribute__(preparation, "_context_closed")
            if (
                owner is not self
                or type(state) is not str
                or state != "sealed"
                or type(lane_active) is not bool
                or not lane_active
                or type(context_closed) is not bool
                or not context_closed
                or type(seal_integrity) is not str
            ):
                return None
            token_facts = self._snapshot_preparation_token(token)
            if token_facts is None:
                return None
            overlay_digest = _exact_sha256_hex(
                overlay_value,
                "detached timing overlay digest",
            )
            expected_seal = self._preparation_seal_integrity_from_fields(
                preparation_id=token_facts.preparation_id,
                token_integrity=token_facts.integrity,
                overlay_digest=overlay_digest,
            )
            if not hmac.compare_digest(seal_integrity, expected_seal):
                return None
            snapshot = _SourceTimingSealedCarrierFacts(
                preparation=preparation,
                token_facts=token_facts,
                overlay_digest=overlay_digest,
                seal_integrity=seal_integrity,
                lane_marker=lane_marker,
            )
            with self._preparation_admission_lock:
                generation = self._preparation_lane_generation
                if generation is None or not self._sealed_lane_generation_matches_locked(
                    generation,
                    snapshot,
                ):
                    return None
                return snapshot, generation
        except BaseException:
            return None

    def _sealed_lane_generation_matches_locked(
        self,
        generation: _SourceTimingLaneGenerationRecord | None,
        snapshot: _SourceTimingSealedCarrierFacts,
    ) -> bool:
        """Compare callback-free public locals with current private lane truth."""

        if generation is None:
            return False
        trusted_token = generation.token_facts
        public_token = snapshot.token_facts
        return bool(
            generation.sealed
            and generation.carrier_ref() is snapshot.preparation
            and self._preparation_lane is snapshot.preparation
            and generation.lane_marker is snapshot.lane_marker
            and self._preparation_lane_marker is generation.lane_marker
            and self._preparation_lane_epoch == generation.lane_epoch
            and public_token.token is trusted_token.token
            and public_token.preparation_id == trusted_token.preparation_id
            and public_token.base_state_digest == trusted_token.base_state_digest
            and hmac.compare_digest(public_token.integrity, trusted_token.integrity)
            and snapshot.overlay_digest == generation.overlay_digest
            and hmac.compare_digest(snapshot.seal_integrity, generation.seal_integrity)
        )

    @staticmethod
    def _detached_semantic_key(
        generation: _SourceTimingLaneGenerationRecord,
        context_digest: str,
    ) -> tuple[int, int, str]:
        return (
            generation.lane_epoch,
            generation.token_facts.preparation_id,
            context_digest,
        )

    def _remove_detached_binding_record_locked(
        self,
        binding_identity: int,
        record: _SourceTimingDetachedBindingRecord,
    ) -> bool:
        """Remove one exact-owner record while authority lock is held."""

        if (
            not self._owns_detached_binding_record(record)
            or self._detached_bindings.get(binding_identity) is not record
        ):
            return False
        self._detached_bindings.pop(binding_identity, None)
        semantic_key = (record.lane_epoch, record.preparation_id, record.context_digest)
        if self._detached_binding_by_context.get(semantic_key) == binding_identity:
            self._detached_binding_by_context.pop(semantic_key, None)
        self._detached_binding_semantic_bytes -= _source_timing_detached_binding_semantic_bytes(
            binding_identity, record
        )
        if not self._detached_bindings:
            self._detached_bindings.clear()
            if not self._detached_binding_by_context:
                self._detached_binding_by_context.clear()
        return True

    def _recover_detached_binding_locked(
        self,
        semantic_key: tuple[int, int, str],
        generation: _SourceTimingLaneGenerationRecord,
        context_digest: str,
    ) -> SourceTimingDetachedPreparationBinding | None:
        """Recover only an intact exact binding for the same private generation."""

        existing_identity = self._detached_binding_by_context.get(semantic_key)
        if existing_identity is None:
            return None
        record = self._detached_bindings.get(existing_identity)
        if record is None:
            raise StateError("Retained detached timing binding authority is inconsistent")
        if not self._owns_detached_binding_record(record):
            raise StateError("Retained detached timing binding belongs to another owner")
        binding = record.binding_ref()
        if binding is None:
            self._remove_detached_binding_record_locked(existing_identity, record)
            return None
        facts = self._snapshot_detached_preparation_binding(
            binding,
            context_digest=context_digest,
        )
        if (
            facts is None
            or not self._detached_binding_record_matches_facts(record, facts)
            or record.generation_marker is not generation.generation_marker
            or record.lane_epoch != generation.lane_epoch
            or record.binding_token is not generation.token_facts.token
        ):
            self._remove_detached_binding_record_locked(existing_identity, record)
            raise StateError("Retained detached timing binding is tampered or stale")
        return binding

    def detach_preparation_binding(
        self,
        preparation: SourceTimingPreparation,
        *,
        context_digest: str,
    ) -> SourceTimingDetachedPreparationBinding:
        """Detach one sealed overlay into an exact callback-free scalar proof.

        This method is called after staged projection facts are final but before
        any canonical owner commits.  The returned proof is cross-bound to a
        caller-supplied SHA-256 context digest and retains no preparation.
        """

        context = _exact_sha256_hex(context_digest, "detached timing context digest")
        sealed = self._snapshot_sealed_preparation_for_detach(preparation)
        if sealed is None:
            raise StateError("Detached timing bindings require this planner's sealed preparation")
        public_snapshot, generation = sealed
        token_facts = generation.token_facts
        preparation_id = token_facts.preparation_id
        base_digest = token_facts.base_state_digest
        overlay_digest = generation.overlay_digest
        semantic_key = self._detached_semantic_key(generation, context)

        # Lock order for detached admission is always admission -> authority.
        # All random/allocation work for a new binding happens after this first
        # check and before the same private generation is atomically revalidated
        # with its final authority insertion.
        with self._preparation_admission_lock:
            if not self._sealed_lane_generation_matches_locked(generation, public_snapshot):
                raise StateError(
                    "Detached timing bindings require this planner's sealed preparation"
                )
            with self._preparation_authority_lock:
                recovered = self._recover_detached_binding_locked(
                    semantic_key,
                    generation,
                    context,
                )
                if recovered is not None:
                    return recovered
                if len(self._detached_bindings) >= self._detached_binding_capacity:
                    raise StateError("Source timing detached-binding capacity is exhausted")

        binding_id = secrets.token_hex(32)
        integrity = self._detached_preparation_binding_integrity(
            binding_id=binding_id,
            preparation_id=preparation_id,
            base_state_digest=base_digest,
            overlay_digest=overlay_digest,
            context_digest=context,
        )
        binding = SourceTimingDetachedPreparationBinding(
            binding_id=binding_id,
            preparation_id=preparation_id,
            base_state_digest=base_digest.encode("ascii").decode("ascii"),
            overlay_digest=overlay_digest.encode("ascii").decode("ascii"),
            context_digest=context.encode("ascii").decode("ascii"),
            _integrity=integrity,
        )
        binding_identity = id(binding)
        detached_owner_ref = ref(self)

        def remove_collected(
            collected: ReferenceType[SourceTimingDetachedPreparationBinding],
            *,
            identity: int = binding_identity,
        ) -> None:
            owner = detached_owner_ref()
            if owner is not None:
                owner._detached_binding_collected(identity, collected)

        binding_ref = ref(
            binding,
            remove_collected,
        )
        record = _SourceTimingDetachedBindingRecord(
            owner_ref=detached_owner_ref,
            owner_marker=self._detached_binding_owner_marker,
            binding_ref=binding_ref,
            binding_id=binding_id,
            preparation_id=preparation_id,
            base_state_digest=base_digest,
            overlay_digest=overlay_digest,
            context_digest=context,
            integrity=integrity,
            generation_marker=generation.generation_marker,
            lane_epoch=generation.lane_epoch,
            binding_token=token_facts.token,
        )
        semantic_bytes = _source_timing_detached_binding_semantic_bytes(
            binding_identity,
            record,
        )
        with self._preparation_admission_lock:
            if (
                self._preparation_lane_generation is not generation
                or not self._sealed_lane_generation_matches_locked(generation, public_snapshot)
            ):
                raise StateError(
                    "Detached timing bindings require this planner's sealed preparation"
                )
            with self._preparation_authority_lock:
                recovered = self._recover_detached_binding_locked(
                    semantic_key,
                    generation,
                    context,
                )
                if recovered is not None:
                    return recovered
                if len(self._detached_bindings) >= self._detached_binding_capacity:
                    raise StateError("Source timing detached-binding capacity is exhausted")
                self._detached_bindings[binding_identity] = record
                self._detached_binding_by_context[semantic_key] = binding_identity
                self._detached_binding_semantic_bytes += semantic_bytes
                self._detached_binding_high_water = max(
                    self._detached_binding_high_water,
                    len(self._detached_bindings),
                )
        return binding

    def authenticates_detached_preparation_binding(
        self,
        binding: object,
        *,
        context_digest: str,
    ) -> bool:
        """Return whether one exact retained detached binding is intact."""

        return (
            self._authenticated_detached_preparation_binding_record(
                binding,
                context_digest=context_digest,
            )
            is not None
        )

    def _authenticated_detached_preparation_binding_record(
        self,
        binding: object,
        *,
        context_digest: str,
    ) -> _SourceTimingDetachedBindingRecord | None:
        """Snapshot public slots once, then resolve only private truth under lock."""

        facts = self._snapshot_detached_preparation_binding(
            binding,
            context_digest=context_digest,
        )
        if facts is None:
            return None
        binding_identity = id(binding)
        with self._preparation_authority_lock:
            record = self._detached_bindings.get(binding_identity)
            if (
                record is None
                or not self._owns_detached_binding_record(record)
                or record.binding_ref() is not binding
                or not self._detached_binding_record_matches_facts(record, facts)
                or self._detached_binding_by_context.get(
                    (record.lane_epoch, record.preparation_id, record.context_digest)
                )
                != binding_identity
            ):
                return None
            return record

    def _snapshot_detached_preparation_binding(
        self,
        binding: object,
        *,
        context_digest: str,
    ) -> _SourceTimingDetachedBindingFacts | None:
        """Read every public binding slot once and authenticate only exact primitives."""

        if type(binding) is not SourceTimingDetachedPreparationBinding:
            return None
        try:
            context = _exact_sha256_hex(context_digest, "detached timing context digest")
            binding_id_value = object.__getattribute__(binding, "binding_id")
            preparation_id = object.__getattribute__(binding, "preparation_id")
            base_state_value = object.__getattribute__(binding, "base_state_digest")
            overlay_value = object.__getattribute__(binding, "overlay_digest")
            retained_context_value = object.__getattribute__(binding, "context_digest")
            integrity = object.__getattribute__(binding, "_integrity")
            binding_id = _exact_sha256_hex(binding_id_value, "detached timing binding id")
            base_digest = _exact_sha256_hex(
                base_state_value,
                "detached timing base-state digest",
            )
            overlay_digest = _exact_sha256_hex(
                overlay_value,
                "detached timing overlay digest",
            )
            retained_context = _exact_sha256_hex(
                retained_context_value,
                "detached timing retained context digest",
            )
            if (
                type(preparation_id) is not int
                or preparation_id < 1
                or type(integrity) is not str
                or retained_context != context
            ):
                return None
            expected = self._detached_preparation_binding_integrity(
                binding_id=binding_id,
                preparation_id=preparation_id,
                base_state_digest=base_digest,
                overlay_digest=overlay_digest,
                context_digest=context,
            )
            if not hmac.compare_digest(integrity, expected):
                return None
            return _SourceTimingDetachedBindingFacts(
                binding=binding,
                binding_id=binding_id,
                preparation_id=preparation_id,
                base_state_digest=base_digest,
                overlay_digest=overlay_digest,
                context_digest=context,
                integrity=integrity,
            )
        except BaseException:
            return None

    @staticmethod
    def _detached_binding_record_matches_facts(
        record: _SourceTimingDetachedBindingRecord,
        facts: _SourceTimingDetachedBindingFacts,
    ) -> bool:
        return bool(
            record.binding_ref() is facts.binding
            and record.binding_id == facts.binding_id
            and record.preparation_id == facts.preparation_id
            and record.base_state_digest == facts.base_state_digest
            and record.overlay_digest == facts.overlay_digest
            and record.context_digest == facts.context_digest
            and hmac.compare_digest(record.integrity, facts.integrity)
        )

    def authenticates_committed_detached_preparation_binding(
        self,
        binding: object,
        receipt: object,
        *,
        context_digest: str,
    ) -> bool:
        """Cross-bind one exact detached proof to its exact committed receipt."""

        record = self._authenticated_detached_preparation_binding_record(
            binding,
            context_digest=context_digest,
        )
        if record is None:
            return False
        snapshot = self._snapshot_preparation_receipt(receipt)
        if (
            snapshot is None
            or snapshot.preparation_id != record.preparation_id
            or snapshot.base_state_digest != record.base_state_digest
            or snapshot.overlay_digest != record.overlay_digest
        ):
            return False
        with self._preparation_authority_lock:
            retained = self._detached_bindings.get(id(binding))
            authority = self._committed_preparation_receipts.get(id(receipt))
            return bool(
                retained is record
                and self._owns_detached_binding_record(record)
                and record.binding_ref() is binding
                and authority is not None
                and authority.committed
                and authority.receipt_ref() is receipt
                and authority.generation_marker is record.generation_marker
                and snapshot.token is record.binding_token
                and self._receipt_facts_match(snapshot, authority.facts)
            )

    def authenticates_expected_detached_preparation_binding(
        self,
        binding: object,
        receipt: object,
        *,
        context_digest: str,
    ) -> bool:
        """Cross-bind a detached proof to an exact preallocated receipt shell."""

        record = self._authenticated_detached_preparation_binding_record(
            binding,
            context_digest=context_digest,
        )
        if record is None:
            return False
        snapshot = self._snapshot_preparation_receipt(receipt)
        if (
            snapshot is None
            or snapshot.preparation_id != record.preparation_id
            or snapshot.base_state_digest != record.base_state_digest
            or snapshot.overlay_digest != record.overlay_digest
        ):
            return False
        with self._preparation_authority_lock:
            retained = self._detached_bindings.get(id(binding))
            authority = self._committed_preparation_receipts.get(id(receipt))
            return bool(
                retained is record
                and self._owns_detached_binding_record(record)
                and record.binding_ref() is binding
                and authority is not None
                and not authority.committed
                and authority.receipt_ref() is receipt
                and authority.generation_marker is record.generation_marker
                and snapshot.token is record.binding_token
                and self._receipt_facts_match(snapshot, authority.facts)
            )

    def discard_detached_preparation_binding(
        self,
        binding: SourceTimingDetachedPreparationBinding,
    ) -> None:
        """Release one exact detached proof after cancellation or activation."""

        if type(binding) is not SourceTimingDetachedPreparationBinding:
            raise StateError("Detached timing binding is copied, foreign, tampered, or stale")
        binding_identity = id(binding)
        with self._preparation_authority_lock:
            record = self._detached_bindings.get(binding_identity)
            if (
                record is None
                or not self._owns_detached_binding_record(record)
                or record.binding_ref() is not binding
            ):
                raise StateError("Detached timing binding is copied, foreign, tampered, or stale")
            if not self._remove_detached_binding_record_locked(binding_identity, record):
                raise StateError("Detached timing binding is copied, foreign, tampered, or stale")

    def detached_binding_census(
        self,
        *,
        estimate_bytes: bool = False,
    ) -> SourceTimingDetachedBindingCensus:
        """Return constant-time detached and supporting authority diagnostics."""

        # Detached snapshots follow the established admission -> authority order
        # so the current lane-generation charge and retained-table charges agree.
        with self._preparation_admission_lock:
            with self._preparation_authority_lock:
                if estimate_bytes:
                    binding_semantic_bytes = self._detached_binding_semantic_bytes
                    generation_semantic_bytes = self._preparation_generation_semantic_bytes
                    claim_semantic_bytes = self._preparation_claim_semantic_bytes
                    receipt_semantic_bytes = self._preparation_receipt_semantic_bytes
                    entry_semantic_bytes = (
                        binding_semantic_bytes
                        + generation_semantic_bytes
                        + claim_semantic_bytes
                        + receipt_semantic_bytes
                    )
                    table_backing_bytes = sum(
                        sys.getsizeof(table)
                        for table in (
                            self._preparation_claim_records,
                            self._committed_preparation_receipts,
                            self._detached_bindings,
                            self._detached_binding_by_context,
                        )
                    )
                else:
                    binding_semantic_bytes = 0
                    generation_semantic_bytes = 0
                    claim_semantic_bytes = 0
                    receipt_semantic_bytes = 0
                    entry_semantic_bytes = 0
                    table_backing_bytes = 0
                return SourceTimingDetachedBindingCensus(
                    retained_bindings=len(self._detached_bindings),
                    capacity=self._detached_binding_capacity,
                    high_water_bindings=self._detached_binding_high_water,
                    binding_semantic_bytes=binding_semantic_bytes,
                    generation_semantic_bytes=generation_semantic_bytes,
                    claim_semantic_bytes=claim_semantic_bytes,
                    receipt_semantic_bytes=receipt_semantic_bytes,
                    entry_semantic_bytes=entry_semantic_bytes,
                    table_backing_bytes=table_backing_bytes,
                    estimated_bytes=entry_semantic_bytes + table_backing_bytes,
                )

    def is_active_preparation(self, preparation: object) -> bool:
        """Return whether ``preparation`` owns the current planning context."""

        return bool(
            type(preparation) is SourceTimingPreparation
            and preparation._owner is self
            and preparation._planning_thread_id == get_ident()
            and preparation._state == "open"
            and preparation._lane_active
            and self._preparation_lane is preparation
            and self._preparation_lane_marker is preparation._lane_marker
            and _ACTIVE_SOURCE_TIMING_PREPARATION.get() is preparation
        )

    def authenticates_preparation(self, preparation: object) -> bool:
        """Authenticate one sealed or committed preparation and its overlay digest."""

        if type(preparation) is not SourceTimingPreparation:
            return False
        try:
            return preparation._authenticates(self)
        except BaseException:
            return False

    def authenticates_expected_preparation_receipt(
        self,
        receipt: object,
        *,
        preparation: object,
    ) -> bool:
        """Authenticate one exact precommit receipt against its active claim record."""

        if type(preparation) is not SourceTimingPreparation:
            return False
        snapshot = self._snapshot_preparation_receipt(receipt)
        if snapshot is None:
            return False
        record = self._active_preparation_claim_record(preparation)
        if (
            record is None
            or record.state not in {"claimed", "certified"}
            or record.expected_receipt is not receipt
            or not self._receipt_facts_match(snapshot, record.receipt_authority.facts)
            or not self._claim_record_matches_current_state(record)
        ):
            return False
        return True

    def authenticates_preparation_receipt(self, receipt: object) -> bool:
        """Authenticate a receipt that can exist only after one committed overlay."""

        snapshot = self._snapshot_preparation_receipt(receipt)
        if snapshot is None:
            return False
        with self._preparation_authority_lock:
            authority = self._committed_preparation_receipts.get(id(receipt))
            return bool(
                authority is not None
                and authority.committed
                and authority.receipt_ref() is receipt
                and self._receipt_facts_match(snapshot, authority.facts)
            )

    def _preparation_receipt_shape_authenticates(
        self,
        receipt: SourceTimingPreparationReceipt,
    ) -> bool:
        """Authenticate exact primitive receipt fields without terminal-state inference."""

        return self._snapshot_preparation_receipt(receipt) is not None

    def _preparation_token_integrity(self, preparation_id: int, base_digest: str) -> str:
        payload = f"source-timing-preparation\0{preparation_id}\0{base_digest}".encode()
        return hmac.new(self._preparation_secret, payload, hashlib.sha256).hexdigest()

    def _preparation_seal_integrity(
        self,
        token: SourceTimingPreparationToken,
        overlay_digest: str,
    ) -> str:
        return self._preparation_seal_integrity_from_fields(
            preparation_id=token.preparation_id,
            token_integrity=token._integrity,
            overlay_digest=overlay_digest,
        )

    def _preparation_seal_integrity_from_fields(
        self,
        *,
        preparation_id: int,
        token_integrity: str,
        overlay_digest: str,
    ) -> str:
        payload = (
            f"source-timing-seal\0{preparation_id}\0{token_integrity}\0{overlay_digest}"
        ).encode()
        return hmac.new(self._preparation_secret, payload, hashlib.sha256).hexdigest()

    def _preparation_receipt_integrity(
        self,
        token: SourceTimingPreparationToken,
        overlay_digest: str,
        committed_state_digest: str,
    ) -> str:
        return self._preparation_receipt_integrity_from_fields(
            preparation_id=token.preparation_id,
            token_integrity=token._integrity,
            overlay_digest=overlay_digest,
            committed_state_digest=committed_state_digest,
        )

    def _preparation_receipt_integrity_from_fields(
        self,
        *,
        preparation_id: int,
        token_integrity: str,
        overlay_digest: str,
        committed_state_digest: str,
    ) -> str:
        payload = (
            "source-timing-receipt\0"
            f"{preparation_id}\0{token_integrity}\0{overlay_digest}\0{committed_state_digest}"
        ).encode()
        return hmac.new(self._preparation_secret, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def sysmon_envelope_time(
        native_time: datetime,
        *,
        hostname: str,
        event_id: int,
        identity_parts: tuple[Any, ...] = (),
    ) -> datetime:
        """Project Sysmon semantic time through its provider event-envelope path."""

        timing = sysmon_envelope_timing(event_id)
        stable_id = f"{hostname}:{event_id}:" + ":".join(str(part) for part in identity_parts)
        native = ensure_utc(native_time)
        runtime = TimingRuntime(
            reference_time=native.replace(hour=0, minute=0, second=0, microsecond=0),
            namespace="sysmon-envelope-static-compatibility",
        )
        main = TruncatedLognormalDistribution(
            median=timing.median_us,
            sigma=timing.sigma,
            minimum=timing.min_us,
            maximum=timing.max_us,
        )
        distribution = main
        if timing.tail_probability > 0:
            tail = TruncatedLognormalDistribution(
                median=timing.tail_min_us + (timing.tail_max_us - timing.tail_min_us) * 0.28,
                sigma=max(0.35, timing.sigma),
                minimum=timing.tail_min_us,
                maximum=timing.tail_max_us,
            )
            distribution = MixtureDistribution(
                (
                    WeightedDistribution(1.0 - timing.tail_probability, main),
                    WeightedDistribution(timing.tail_probability, tail),
                )
            )
        delay = runtime.sampler.sample_timedelta(
            distribution,
            relationship_key="sysmon.provider.envelope",
            scope=TimingScope(
                stable_id=stable_id,
                host=hostname,
                source="sysmon",
                lifecycle_id=stable_id,
            ),
            sample_key="envelope",
        )
        return native + delay

    def plan_event(
        self,
        event: TimingOccurrence,
        format_name: str | None = None,
        *,
        observation_delay: timedelta = timedelta(0),
        source_instance: str = "",
        source_hostname: str = "",
        projection_role: str = "",
        output_end_time: datetime | None = None,
    ) -> TimingOccurrence:
        """Return a source projection while retaining immutable canonical time."""

        active = _ACTIVE_SOURCE_TIMING_PREPARATION.get()
        if type(active) is SourceTimingPreparation and active._owner is self:
            return active.plan_event(
                event,
                format_name,
                observation_delay=observation_delay,
                source_instance=source_instance,
                source_hostname=source_hostname,
                projection_role=projection_role,
                output_end_time=output_end_time,
            )
        self._require_public_planning_entry()

        if observation_delay < timedelta(0):
            raise ValueError("observation_delay must be non-negative")
        event = self.initialize_event(event)
        plan = self._ensure_plan(event)
        if format_name is not None:
            plan.observation_delays[source_instance or format_name] = observation_delay
        runtime_owned = self._runtime_owns_projection(event, format_name)
        if observation_delay and not runtime_owned:
            event = replace(
                event,
                timestamp=plan.canonical_timestamp + observation_delay,
            )
        if format_name in {None, "ecar"}:
            self._plan_ecar_identity_times(event)
        if format_name == "ecar":
            self._plan_ecar_render_times(
                event,
                source_instance=source_instance,
                source_hostname=source_hostname,
                projection_role=projection_role,
            )
        if format_name == "windows_event_sysmon":
            self._plan_sysmon_process_times(
                event,
                source_instance=source_instance,
                source_hostname=source_hostname,
            )
        if format_name in {"windows_security", "windows_event_security"}:
            self._plan_windows_process_times(
                event,
                source_instance=source_instance,
                source_hostname=source_hostname,
            )
        if format_name in {
            "ecar",
            "windows_event_sysmon",
            "windows_security",
            "windows_event_security",
        }:
            self._plan_endpoint_event_times(
                event,
                format_name,
                source_instance=source_instance,
                source_hostname=source_hostname,
                output_end_time=output_end_time,
            )
        if format_name is not None and format_name not in {
            "ecar",
            "windows_event_sysmon",
            "windows_security",
            "windows_event_security",
        }:
            event = self._plan_session_lifecycle_time(event, format_name)
        return event

    @staticmethod
    def _runtime_owns_projection(
        event: TimingOccurrence,
        format_name: str | None,
    ) -> bool:
        """Return whether the shared runtime owns this migrated projection timestamp."""

        from evidenceforge.generation.network_observation import (
            network_observation_owns_format_timing,
        )

        if format_name in {
            "ecar",
            "windows_event_sysmon",
            "windows_security",
            "windows_event_security",
        }:
            return True
        return network_observation_owns_format_timing(event, format_name)

    def initialize_event(self, event: TimingOccurrence) -> TimingOccurrence:
        """Retain canonical time before source observation delay is applied.

        Initialization deliberately does not plan identities or render timestamps;
        those decisions belong to the visible source path selected by the
        dispatcher.
        """

        if event.source_timing is None:
            plan = SourceTimingPlan(
                canonical_timestamp=event.timestamp,
                clock_profile_name=self.clock_profile_name,
            )
            if isinstance(event, OccurrenceBuilder):
                event.source_timing = plan
                return event
            return replace(event, source_timing=plan)
        if not event.source_timing.clock_profile_name:
            event.source_timing.clock_profile_name = self.clock_profile_name
        return event

    def record_admitted_source_event(
        self,
        event: TimingOccurrence,
        format_name: str,
    ) -> None:
        """Publish an admitted transport anchor for later authentication siblings."""

        if (
            format_name
            in {
                "ecar",
                "windows_event_sysmon",
                "windows_security",
                "windows_event_security",
            }
            and event.lifecycle is not None
        ):
            family = _endpoint_format_family(format_name)
            timestamp = self.admission_time(event, format_name)
            if event.event_type in {"logon", "machine_logon", "ssh_session"}:
                key = (family, event.lifecycle.group_id)
                previous = self._latest_session_start_times.get(key)
                if previous is None or timestamp > previous:
                    self._latest_session_start_times[key] = timestamp
            session_group = (
                event.lifecycle.parent_group_id
                if event.event_type in _PROCESS_START_EVENT_TYPES | _PROCESS_END_EVENT_TYPES
                else event.lifecycle.group_id
                if event.lifecycle.phase == "dependent"
                else None
            )
            if session_group:
                key = (family, session_group)
                previous = self._latest_session_dependent_times.get(key)
                if previous is None or timestamp > previous:
                    self._latest_session_dependent_times[key] = timestamp
                    self._latest_session_dependent_descriptions.set(
                        key,
                        f"event={event.event_type} source={timestamp.isoformat()}",
                        deadline=_retained_until(
                            timestamp,
                            _SOURCE_TIMING_LIFECYCLE_RETENTION,
                        ),
                    )
            if event.event_type == "logoff":
                key = (family, event.lifecycle.group_id)
                self._latest_session_start_times.pop(key)
                self._latest_session_dependent_times.pop(key)
                self._latest_session_dependent_descriptions.pop(key)

        if (
            format_name in {"windows_security", "windows_event_security"}
            and event.event_type == "kerberos_service"
            and event.kerberos is not None
            and event.dst_host is not None
        ):
            key = self._kerberos_prerequisite_key(
                format_name,
                event.kerberos.target_username,
                event.kerberos.source_ip,
                event.dst_host.hostname,
            )
            timestamp = self.admission_time(event, format_name)
            previous = self._kerberos_service_times.get(key)
            if previous is None or timestamp > previous:
                self._kerberos_service_times[key] = timestamp

        network = event.network
        lifecycle = event.lifecycle
        if (
            format_name == "ecar"
            and event.event_type == "connection"
            and network is not None
            and event.dst_host is not None
        ):
            timestamp = self._latest_ecar_endpoint_flow_time(event)
            if timestamp is not None:
                transaction_key = self._transaction_transport_key(
                    network.stable_id,
                    event.dst_host.hostname,
                    network.src_ip,
                    network.src_port,
                    network.dst_ip,
                    network.dst_port,
                    network.protocol,
                )
                self._admitted_ecar_transport_transactions[transaction_key] = timestamp
                close_candidates = [network.closed_at]
                close_candidates.extend(
                    observation.observed_close_time for observation in event.network_observations
                )
                close_candidates = [
                    candidate for candidate in close_candidates if candidate is not None
                ]
                if close_candidates:
                    self._ecar_transport_close_deadlines[transaction_key] = min(close_candidates)
        if (
            format_name in {"windows_security", "windows_event_security"}
            and event.event_type == "wfp_connection"
            and network is not None
            and lifecycle is not None
        ):
            host = event.src_host or event.dst_host
            timestamp = self._finalized_time(event, _WINDOWS_WFP_RENDER_KEY)
            if host is not None and timestamp is not None:
                self._admitted_windows_transport_transactions[
                    self._transaction_transport_key(
                        lifecycle.group_id,
                        host.hostname,
                        network.src_ip,
                        network.src_port,
                        network.dst_ip,
                        network.dst_port,
                        network.protocol,
                    )
                ] = timestamp

        if (
            format_name == "ecar"
            and event.event_type == "connection"
            and network is not None
            and network.protocol.lower() == "tcp"
            and network.dst_port == 445
            and event.dst_host is not None
        ):
            timestamp = self._latest_ecar_endpoint_flow_time(event)
            if timestamp is not None:
                self._admitted_ecar_smb_transports[
                    self._smb_transport_key(
                        event.dst_host.hostname,
                        network.src_ip,
                        network.src_port,
                        network.dst_ip,
                        network.dst_port,
                        network.protocol,
                    )
                ] = timestamp
        if (
            format_name == "ecar"
            and event.event_type == "connection"
            and network is not None
            and network.protocol.lower() == "tcp"
            and network.dst_port == 22
            and event.dst_host is not None
        ):
            timestamp = self._finalized_time(
                event,
                ecar_flow_render_key("inbound", event.dst_host.hostname),
            )
            if timestamp is not None:
                self._admitted_ecar_ssh_transports[
                    self._ssh_transport_key(
                        event.dst_host.hostname,
                        network.src_ip,
                        network.src_port,
                        network.dst_ip,
                        network.dst_port,
                        network.protocol,
                    )
                ] = timestamp

        if lifecycle is None or network is None or lifecycle.parent_group_id is None:
            return
        if not lifecycle.parent_group_id.startswith("windows-remote-auth-"):
            return
        target_host = event.dst_host or event.src_host
        target_hostname = getattr(target_host, "hostname", "")
        if not target_hostname:
            return
        if event.event_type == "connection":
            transaction_id = network.stable_id
            if format_name == "ecar" and event.dst_host is not None:
                timestamp = self._latest_ecar_endpoint_flow_time(event)
                if timestamp is not None:
                    self._admitted_ecar_remote_transports[
                        self._remote_transport_key(
                            lifecycle.parent_group_id,
                            transaction_id,
                            target_hostname,
                            network.src_ip,
                            network.src_port,
                            network.dst_ip,
                            network.dst_port,
                            network.protocol,
                        )
                    ] = timestamp
            return
        if event.event_type != "wfp_connection" or format_name not in {
            "windows_security",
            "windows_event_security",
        }:
            return
        host = event.src_host or event.dst_host
        if host is None or network.dst_ip != host.ip:
            return
        timestamp = self._finalized_time(event, _WINDOWS_WFP_RENDER_KEY)
        if timestamp is not None:
            self._admitted_windows_remote_transports[
                self._remote_transport_key(
                    lifecycle.parent_group_id,
                    lifecycle.group_id,
                    host.hostname,
                    network.src_ip,
                    network.src_port,
                    network.dst_ip,
                    network.dst_port,
                    network.protocol,
                )
            ] = timestamp

    def _plan_ecar_render_times(
        self,
        event: TimingOccurrence,
        *,
        source_instance: str = "",
        source_hostname: str = "",
        projection_role: str = "",
    ) -> None:
        """Finalize migrated eCAR row times before emitter admission."""

        if event.event_type in _PROCESS_START_EVENT_TYPES | _PROCESS_END_EVENT_TYPES:
            self._plan_ecar_process_time(
                event,
                source_instance=source_instance,
                source_hostname=source_hostname,
            )
            return

        if event.event_type == "connection" and event.network is not None:
            self._plan_ecar_flow_times(
                event,
                source_instance=source_instance,
                source_hostname=source_hostname,
                projection_role=projection_role,
            )
        # Remaining endpoint rows are finalized by `_plan_endpoint_event_times`.

    def _plan_ecar_process_time(
        self,
        event: TimingOccurrence,
        *,
        source_instance: str,
        source_hostname: str,
    ) -> None:
        """Freeze one eCAR PROCESS lifecycle timestamp from the shared runtime."""

        host = event.src_host or event.dst_host
        process = event.process
        if host is None or process is None:
            return
        # Finalized-time keys are part of the canonical event contract and must
        # retain the event's hostname spelling.  ``source_hostname`` identifies
        # the compiled source instance and is intentionally allowed to be
        # normalized (for example, lower-cased) by deployment planning.
        hostname = host.hostname
        identity = self._subject_process_identity(event)
        start_time = (
            identity.started_at
            if identity is not None
            else process.start_time or self._ensure_plan(event).canonical_timestamp
        )
        object_id, lifecycle_id = self._process_scope_ids(
            event,
            identity,
            hostname=hostname,
            pid=process.pid,
            started_at=start_time,
        )
        object_id = self._sysmon_process_object_id(
            hostname,
            process.pid,
            start_time,
        )
        instance = source_instance or f"ecar:{hostname.casefold()}"
        if event.event_type in _PROCESS_START_EVENT_TYPES:
            timestamp = self._runtime_process_create_time(
                event,
                family="ecar",
                source_key="source.ecar_process_create",
                source_instance=instance,
                hostname=hostname,
                os_category=host.os_category,
                object_id=object_id,
                lifecycle_id=lifecycle_id,
                canonical_start=start_time,
            )
            if identity is not None:
                self._ecar_process_create_times[identity.object_id] = timestamp
            self._ensure_plan(event).finalized_times[
                ecar_process_render_key("create", hostname)
            ] = timestamp
            return

        create_time = self._runtime_process_create_time(
            event,
            family="ecar",
            source_key="source.ecar_process_create",
            source_instance=instance,
            hostname=hostname,
            os_category=host.os_category,
            object_id=object_id,
            lifecycle_id=lifecycle_id,
            canonical_start=start_time,
        )
        canonical_end = self._ensure_plan(event).canonical_timestamp
        timestamp = self._runtime_process_termination_time(
            event,
            family="ecar",
            source_key="source.ecar_process_terminate",
            source_instance=instance,
            hostname=hostname,
            os_category=host.os_category,
            object_id=object_id,
            lifecycle_id=lifecycle_id,
            canonical_start=start_time,
            canonical_end=canonical_end,
            create_time=create_time,
        )
        plan = self._ensure_plan(event)
        plan.finalized_times[ecar_process_render_key("create", hostname)] = create_time
        plan.finalized_times[ecar_process_render_key("terminate", hostname)] = timestamp

    def _plan_sysmon_process_times(
        self,
        event: TimingOccurrence,
        *,
        source_instance: str,
        source_hostname: str,
    ) -> None:
        """Freeze Sysmon PROCESS native and provider-envelope timestamps."""

        if event.event_type not in _PROCESS_START_EVENT_TYPES | _PROCESS_END_EVENT_TYPES:
            return
        host = event.src_host or event.dst_host
        process = event.process
        if host is None or process is None:
            return
        # Keep canonical event identity in finalized keys; the separately
        # supplied source-instance name is only a clock/sampling scope.
        hostname = host.hostname
        identity = self._subject_process_identity(event)
        start_time = (
            identity.started_at
            if identity is not None
            else process.start_time or self._ensure_plan(event).canonical_timestamp
        )
        object_id, lifecycle_id = self._process_scope_ids(
            event,
            identity,
            hostname=hostname,
            pid=process.pid,
            started_at=start_time,
        )
        # ProcessGuid identity is the host/PID/start tuple, not the occurrence-local
        # process object carried by a particular row.  Event 1 may be collection-
        # dropped, so dependent Event 3/7/8 rows must enter the same timing cache.
        object_id = self._sysmon_process_object_id(hostname, process.pid, start_time)
        instance = source_instance or f"sysmon:{hostname.casefold()}"
        create_native, shared_create_render = self._runtime_shared_sysmon_process_create_time(
            event,
            hostname=hostname,
            object_id=object_id,
            lifecycle_id=lifecycle_id,
            canonical_start=start_time,
        )
        create_cache_key = (instance, object_id)
        create_render = self._sysmon_process_render_create_times.get(create_cache_key)
        if create_render is None:
            create_render = shared_create_render
        parent = (
            event.identity_plan.actor
            if event.identity_plan is not None
            and event.event_type in _PROCESS_START_EVENT_TYPES
            and isinstance(event.identity_plan.actor, ProcessIdentity)
            else None
        )
        parent_render = None
        if parent is not None:
            parent_object_id = self._sysmon_process_object_id(
                hostname,
                parent.pid,
                parent.started_at,
            )
            parent_cache_key = (instance, parent_object_id)
            parent_render = self._sysmon_process_render_create_times.get(parent_cache_key)
            if parent_render is None:
                _parent_native, parent_render = self._runtime_shared_sysmon_process_create_time(
                    event,
                    hostname=hostname,
                    object_id=parent_object_id,
                    lifecycle_id=parent.lifecycle_group_id,
                    canonical_start=parent.started_at,
                )
                self._sysmon_process_render_create_times[parent_cache_key] = parent_render
        if parent_render is not None and create_render <= parent_render:
            self.timing_runtime.audit.record_repair("sysmon.process.parent_before_child")
            create_render = self._sample_after_floor(
                parent_render,
                relationship_key="sysmon.process.parent_before_child",
                scope=TimingScope(
                    stable_id=object_id,
                    host=hostname,
                    source=instance,
                    lifecycle_id=lifecycle_id,
                ),
                maximum_us=2_500,
            )
        self._sysmon_process_render_create_times[create_cache_key] = create_render
        plan = self._ensure_plan(event)
        plan.finalized_times[sysmon_process_native_key("create", hostname)] = create_native
        plan.finalized_times[sysmon_process_render_key("create", hostname)] = create_render
        if parent_render is not None:
            plan.finalized_times[sysmon_parent_process_render_key(hostname)] = parent_render
        if event.event_type in _PROCESS_START_EVENT_TYPES:
            return

        canonical_end = plan.canonical_timestamp
        terminate_native = self._runtime_process_termination_time(
            event,
            family="sysmon",
            source_key="source.sysmon_process_terminate",
            source_instance=instance,
            hostname=hostname,
            os_category="windows",
            object_id=object_id,
            lifecycle_id=lifecycle_id,
            canonical_start=start_time,
            canonical_end=canonical_end,
            create_time=create_native,
        )
        terminate_render = self._sysmon_runtime_envelope_time(
            terminate_native,
            event_id=5,
            source_instance=instance,
            hostname=hostname,
            object_id=object_id,
            lifecycle_id=lifecycle_id,
        )
        render_floor = create_render + max(
            timedelta(microseconds=1),
            canonical_end - start_time,
        )
        if terminate_render <= render_floor:
            self.timing_runtime.audit.record_repair("sysmon.process.envelope_containment")
            terminate_render = self._sample_after_floor(
                render_floor,
                relationship_key="sysmon.process.envelope_containment",
                scope=TimingScope(
                    stable_id=object_id,
                    host=hostname,
                    source=instance,
                    lifecycle_id=lifecycle_id,
                    ordinal=5,
                ),
                maximum_us=4_000,
            )
        plan.finalized_times[sysmon_process_native_key("terminate", hostname)] = terminate_native
        plan.finalized_times[sysmon_process_render_key("terminate", hostname)] = terminate_render

    def _freeze_sysmon_process_identity_times(
        self,
        event: TimingOccurrence,
        *,
        source_instance: str,
        hostname: str,
    ) -> None:
        """Freeze every ProcessGuid seed needed by one Sysmon occurrence."""

        identities: list[tuple[str, str, int, datetime]] = []
        identity_plan = event.identity_plan
        if identity_plan is not None:
            for identity in (
                identity_plan.actor,
                identity_plan.subject,
                identity_plan.target,
            ):
                if (
                    isinstance(identity, ProcessIdentity)
                    and identity.hostname.casefold() == hostname.casefold()
                ):
                    identities.append(
                        (
                            identity.object_id,
                            identity.lifecycle_group_id,
                            identity.pid,
                            identity.started_at,
                        )
                    )
        process = event.process
        if process is not None and process.pid > 0:
            started_at = process.start_time or self._ensure_plan(event).canonical_timestamp
            raw_object_id, raw_lifecycle_id = self._process_scope_ids(
                event,
                None,
                hostname=hostname,
                pid=process.pid,
                started_at=started_at,
            )
            identities.append((raw_object_id, raw_lifecycle_id, process.pid, started_at))
        query_process = event.dns.query_process if event.dns is not None else None
        if query_process is not None and query_process.pid > 0:
            started_at = query_process.start_time or self._ensure_plan(event).canonical_timestamp
            raw_object_id, raw_lifecycle_id = self._process_scope_ids(
                event,
                None,
                hostname=hostname,
                pid=query_process.pid,
                started_at=started_at,
            )
            identities.append((raw_object_id, raw_lifecycle_id, query_process.pid, started_at))

        plan = self._ensure_plan(event)
        seen: set[tuple[int, datetime]] = set()
        for object_id, lifecycle_id, pid, started_at in identities:
            exact_identity = (pid, ensure_utc(started_at))
            if exact_identity in seen:
                continue
            seen.add(exact_identity)
            object_id = self._sysmon_process_object_id(hostname, pid, started_at)
            cache_key = (source_instance, object_id)
            rendered = self._sysmon_process_render_create_times.get(cache_key)
            if rendered is None:
                _native, rendered = self._runtime_shared_sysmon_process_create_time(
                    event,
                    hostname=hostname,
                    object_id=object_id,
                    lifecycle_id=lifecycle_id,
                    canonical_start=started_at,
                )
                self._sysmon_process_render_create_times[cache_key] = rendered
            plan.finalized_times[sysmon_process_identity_render_key(hostname, pid, started_at)] = (
                rendered
            )
            plan.finalized_times[sysmon_process_pid_render_key(hostname, pid)] = rendered

    def _plan_windows_process_times(
        self,
        event: TimingOccurrence,
        *,
        source_instance: str,
        source_hostname: str,
    ) -> None:
        """Freeze Security 4688/4689 timestamps through the shared endpoint runtime."""

        if event.event_type not in _PROCESS_START_EVENT_TYPES | _PROCESS_END_EVENT_TYPES:
            return
        host = event.src_host or event.dst_host
        process = event.process
        if host is None or process is None:
            return
        hostname = host.hostname
        identity = self._subject_process_identity(event)
        start_time = (
            identity.started_at
            if identity is not None
            else process.start_time or self._ensure_plan(event).canonical_timestamp
        )
        object_id, lifecycle_id = self._process_scope_ids(
            event,
            identity,
            hostname=hostname,
            pid=process.pid,
            started_at=start_time,
        )
        instance = source_instance or f"windows_security:{hostname.casefold()}"
        create_time = self._runtime_windows_process_create_time(
            event,
            source_instance=instance,
            hostname=hostname,
            object_id=object_id,
            lifecycle_id=lifecycle_id,
            pid=process.pid,
            canonical_start=start_time,
        )
        plan = self._ensure_plan(event)
        plan.finalized_times[
            endpoint_event_native_key("windows_security", hostname, "process_create")
        ] = create_time
        plan.finalized_times[
            endpoint_event_render_key("windows_security", hostname, "process_create")
        ] = create_time
        if event.event_type in _PROCESS_START_EVENT_TYPES:
            return
        terminate_time = self._runtime_process_termination_time(
            event,
            family="windows_security",
            source_key="source.windows_security_process_terminate",
            source_instance=instance,
            hostname=hostname,
            os_category="windows",
            object_id=object_id,
            lifecycle_id=lifecycle_id,
            canonical_start=start_time,
            canonical_end=plan.canonical_timestamp,
            create_time=create_time,
        )
        plan.finalized_times[
            endpoint_event_native_key("windows_security", hostname, "process_terminate")
        ] = terminate_time
        plan.finalized_times[
            endpoint_event_render_key("windows_security", hostname, "process_terminate")
        ] = terminate_time

    def _plan_endpoint_event_times(
        self,
        event: TimingOccurrence,
        format_name: str,
        *,
        source_instance: str,
        source_hostname: str,
        output_end_time: datetime | None = None,
    ) -> None:
        """Freeze remaining endpoint payload/envelope times before rendering."""

        family = _endpoint_format_family(format_name)
        for host in self._endpoint_projection_hosts(
            event,
            family=family,
            source_hostname=source_hostname,
        ):
            hostname = host.hostname
            default_instance = f"{family}:{hostname.casefold()}"
            instance = (
                source_instance
                if source_instance
                and (not source_hostname or hostname.casefold() == source_hostname.casefold())
                else default_instance
            )
            if family == "sysmon":
                self._freeze_sysmon_process_identity_times(
                    event,
                    source_instance=instance,
                    hostname=hostname,
                )
            phases = self._endpoint_event_phases(event, family)
            phase_times: dict[str, datetime] = {}
            for phase in phases:
                specialized = self._specialized_endpoint_times(
                    event,
                    family=family,
                    hostname=hostname,
                    phase=phase,
                )
                native_time = (
                    specialized[0]
                    if specialized is not None
                    else self._runtime_endpoint_event_time(
                        event,
                        family=family,
                        phase=phase,
                        source_instance=instance,
                        hostname=hostname,
                        os_category=host.os_category,
                    )
                )
                native_time = self._apply_runtime_transport_constraints(
                    event,
                    family=family,
                    source_instance=instance,
                    hostname=hostname,
                    preferred=native_time,
                )
                predecessor = (
                    "base"
                    if phase in {"privilege", "smb_object_open"}
                    else "client_file"
                    if phase == "client_delete"
                    else None
                )
                if predecessor is not None and predecessor in phase_times:
                    native_time = self._sample_after_floor(
                        phase_times[predecessor],
                        relationship_key=f"{family}.{phase}_after_{predecessor}",
                        scope=TimingScope(
                            stable_id=self._endpoint_event_object_id(event, hostname, phase),
                            host=hostname,
                            source=instance,
                            lifecycle_id=self._endpoint_event_lifecycle_id(event),
                        ),
                        maximum_us=85_000,
                    )
                if event.event_type == "logoff" and family in {
                    "ecar",
                    "windows_security",
                }:
                    native_time = self._runtime_session_closure_time(
                        event,
                        family=family,
                        source_instance=instance,
                        hostname=hostname,
                        os_category=host.os_category,
                        preferred=native_time,
                        output_end_time=output_end_time,
                    )
                else:
                    native_time = self._apply_runtime_session_constraints(
                        event,
                        family=family,
                        source_instance=instance,
                        hostname=hostname,
                        preferred=native_time,
                    )
                phase_times[phase] = native_time
                render_time = specialized[1] if specialized is not None else native_time
                if family == "sysmon":
                    if specialized is None:
                        render_time = self._sysmon_runtime_envelope_time(
                            native_time,
                            event_id=self._sysmon_event_id(event, phase),
                            source_instance=instance,
                            hostname=hostname,
                            object_id=self._endpoint_event_object_id(event, hostname, phase),
                            lifecycle_id=self._endpoint_event_lifecycle_id(event),
                        )
                plan = self._ensure_plan(event)
                plan.finalized_times[endpoint_event_native_key(format_name, hostname, phase)] = (
                    native_time
                )
                plan.finalized_times[endpoint_event_render_key(format_name, hostname, phase)] = (
                    render_time
                )
                self._publish_endpoint_compatibility_time(
                    event,
                    family=family,
                    hostname=hostname,
                    phase=phase,
                    timestamp=render_time,
                )

    def _runtime_endpoint_event_time(
        self,
        event: TimingOccurrence,
        *,
        family: str,
        phase: str,
        source_instance: str,
        hostname: str,
        os_category: str,
    ) -> datetime:
        """Plan one typed endpoint row time with process-lifecycle containment."""

        canonical_time = self._ensure_plan(event).canonical_timestamp
        source_key = self._endpoint_event_source_key(event, family, phase)
        object_id = self._endpoint_event_object_id(event, hostname, phase)
        lifecycle_id = self._endpoint_event_lifecycle_id(event)
        latency_phase = phase
        if event.event_type.startswith("smb_") and event.lifecycle is not None:
            source_key = f"source.{family}_smb_lifecycle"
            object_id = f"smb:{event.lifecycle.group_id}"
            lifecycle_id = event.lifecycle.group_id
            latency_phase = "smb-lifecycle"
        timestamp = self._runtime_endpoint_clock_time(
            canonical_time,
            hostname=hostname,
            os_category=os_category,
        ) + self._coherent_runtime_latency(
            source_key,
            canonical_time=canonical_time,
            source_instance=source_instance,
            hostname=hostname,
            object_id=object_id,
            lifecycle_id=lifecycle_id,
            phase=latency_phase,
        )
        process_scope = self._endpoint_process_scope(event, hostname)
        if process_scope is None or event.event_type in (
            _PROCESS_START_EVENT_TYPES | _PROCESS_END_EVENT_TYPES
        ):
            return timestamp
        process_object_id, process_lifecycle_id, pid, started_at = process_scope
        create_time = self._runtime_process_create_time(
            event,
            family=family,
            source_key=self._endpoint_process_source_key(family),
            source_instance=source_instance,
            hostname=hostname,
            os_category=os_category,
            object_id=process_object_id,
            lifecycle_id=process_lifecycle_id,
            canonical_start=started_at,
        )
        if event.image_load is not None:
            timestamp = self._runtime_process_module_time(
                event,
                family=family,
                source_instance=source_instance,
                hostname=hostname,
                object_id=process_object_id,
                lifecycle_id=process_lifecycle_id,
                process_create_time=create_time,
                preferred=timestamp,
            )
        elif timestamp <= create_time:
            self.timing_runtime.audit.record_repair(f"{family}.dependent_after_process_create")
            timestamp = self._sample_after_floor(
                create_time,
                relationship_key=f"{family}.dependent_after_process_create",
                scope=TimingScope(
                    stable_id=process_object_id,
                    host=hostname,
                    source=source_instance,
                    lifecycle_id=process_lifecycle_id,
                    ordinal=max(0, pid),
                ),
                maximum_us=4_000,
            )
        dependent_key = (family, source_instance, process_object_id)
        previous = self._process_dependent_create_times.get(dependent_key)
        if previous is None or timestamp > previous:
            self._process_dependent_create_times[dependent_key] = timestamp
        return timestamp

    def _runtime_process_module_time(
        self,
        event: TimingOccurrence,
        *,
        family: str,
        source_instance: str,
        hostname: str,
        object_id: str,
        lifecycle_id: str,
        process_create_time: datetime,
        preferred: datetime,
    ) -> datetime:
        """Place one module row after process create with typed ordered gaps."""

        image_load = event.image_load
        if image_load is None:
            return preferred
        scope = TimingScope(
            stable_id=object_id,
            host=hostname,
            source=source_instance,
            lifecycle_id=lifecycle_id,
        )
        if image_load.load_phase != "startup":
            return (
                preferred
                if preferred > process_create_time
                else self._sample_after_floor(
                    process_create_time,
                    relationship_key=f"{family}.module_after_process_create",
                    scope=scope,
                    maximum_us=8_000,
                )
            )
        timing = startup_module_observation_timing()
        initial = self.timing_runtime.sampler.sample_microseconds(
            self._right_skew_distribution(
                timing.initial_delay_min_us,
                timing.initial_delay_max_us + 1,
            ),
            relationship_key=f"{family}.startup_module.initial_delay",
            scope=scope,
            sample_key="initial",
        )
        elapsed_us = initial
        for module_index in range(1, max(1, image_load.load_order)):
            elapsed_us += self.timing_runtime.sampler.sample_microseconds(
                TruncatedLognormalDistribution(
                    median=float(timing.inter_load_gap_median_us),
                    sigma=timing.inter_load_gap_sigma,
                    minimum=float(timing.inter_load_gap_min_us),
                    maximum=float(timing.inter_load_gap_max_us + 1),
                ),
                relationship_key=f"{family}.startup_module.inter_load_gap",
                scope=replace(scope, ordinal=module_index),
                sample_key="gap",
            )
        return process_create_time + timedelta(microseconds=elapsed_us)

    @staticmethod
    def _endpoint_projection_hosts(
        event: TimingOccurrence,
        *,
        family: str,
        source_hostname: str,
    ) -> tuple[Any, ...]:
        """Return endpoint hosts whose rows can be rendered by this projection."""

        candidates = tuple(
            host
            for index, host in enumerate((event.src_host, event.dst_host))
            if host is not None
            and all(
                previous is None or previous.hostname.casefold() != host.hostname.casefold()
                for previous in (event.src_host, event.dst_host)[:index]
            )
        )
        if not candidates:
            return ()
        # One eCAR SMB projection fans out both the server-local FILE row and,
        # when the operation has a client-side effect, a client-local FILE row.
        # Freeze both host clocks before the prepared projection is handed to
        # the emitter even when the compiled source instance is hosted on one
        # endpoint.  Returning only the matching source host here leaves the
        # other row with an engine-owned but incomplete timing plan and would
        # force the renderer through the compatibility adapter.
        if family == "ecar" and event.event_type.startswith("smb_"):
            return candidates
        normalized_source = source_hostname.casefold()
        matched = tuple(
            host for host in candidates if host.hostname.casefold() == normalized_source
        )
        if matched:
            return matched
        if family == "sysmon":
            return (event.src_host or event.dst_host,)
        if family == "windows_security":
            destination_types = {
                "logon",
                "logoff",
                "failed_logon",
                "machine_logon",
                "kerberos_tgt",
                "kerberos_tgt_renewal",
                "kerberos_service",
                "ntlm_validation",
                "kerberos_preauth_failed",
                "explicit_credentials",
                "account_created",
                "account_deleted",
                "account_changed",
                "password_change",
                "password_reset",
                "group_member_added_global",
                "group_member_removed_global",
                "group_member_added_local",
                "group_member_removed_local",
                "group_member_added_universal",
                "group_member_removed_universal",
                "workstation_locked",
                "workstation_unlocked",
                "smb_tree_connect",
                "smb_file_open",
                "smb_file_read",
                "smb_file_write",
                "smb_file_rename",
                "smb_file_delete",
                "smb_file_close",
            }
            host = (
                event.dst_host or event.src_host
                if event.event_type in destination_types
                else event.src_host or event.dst_host
            )
            return (host,) if host is not None else ()
        if event.event_type in {"logon", "machine_logon", "logoff", "failed_logon", "ssh_session"}:
            host = event.dst_host or event.src_host
            return (host,) if host is not None else ()
        if event.event_type.startswith("smb_"):
            return candidates
        host = event.src_host or event.dst_host
        return (host,) if host is not None else ()

    @staticmethod
    def _endpoint_event_phases(event: TimingOccurrence, family: str) -> tuple[str, ...]:
        """Return the source-native rows emitted for one endpoint occurrence."""

        if event.event_type in _PROCESS_START_EVENT_TYPES:
            return ("process_create",)
        if event.event_type in _PROCESS_END_EVENT_TYPES:
            return ("process_terminate",)
        if family == "sysmon" and event.event_type == "connection":
            return ("network", "dns") if event.dns is not None else ("network",)
        if family == "windows_security" and event.event_type in {"logon", "machine_logon"}:
            return ("base", "privilege")
        if (
            family == "windows_security"
            and event.event_type == "smb_file_open"
            and event.smb is not None
            and event.smb.audit == "high"
            and event.smb.result == "success"
        ):
            return ("base", "smb_object_open")
        if family == "ecar" and event.event_type.startswith("smb_"):
            return ("base", "client_file", "client_delete")
        return ("base",)

    @staticmethod
    def _specialized_endpoint_times(
        event: TimingOccurrence,
        *,
        family: str,
        hostname: str,
        phase: str,
    ) -> tuple[datetime, datetime] | None:
        """Return an already finalized specialized native/envelope pair."""

        plan = event.source_timing
        if plan is None:
            return None
        native = plan.finalized_times.get(endpoint_event_native_key(family, hostname, phase))
        rendered = plan.finalized_times.get(endpoint_event_render_key(family, hostname, phase))
        if native is not None and rendered is not None:
            return native, rendered
        if family == "ecar":
            if phase in {"process_create", "process_terminate"}:
                lifecycle = phase.removeprefix("process_")
                timestamp = plan.finalized_times.get(ecar_process_render_key(lifecycle, hostname))
                return (timestamp, timestamp) if timestamp is not None else None
            if event.event_type == "connection":
                direction = (
                    "outbound"
                    if event.src_host is not None
                    and event.src_host.hostname.casefold() == hostname.casefold()
                    else "inbound"
                )
                timestamp = plan.finalized_times.get(ecar_flow_render_key(direction, hostname))
                return (timestamp, timestamp) if timestamp is not None else None
        if family == "sysmon" and phase in {"process_create", "process_terminate"}:
            lifecycle = phase.removeprefix("process_")
            native = plan.finalized_times.get(sysmon_process_native_key(lifecycle, hostname))
            rendered = plan.finalized_times.get(sysmon_process_render_key(lifecycle, hostname))
            return (native, rendered) if native is not None and rendered is not None else None
        if family == "windows_security":
            if phase in {"process_create", "process_terminate"}:
                native = plan.finalized_times.get(
                    endpoint_event_native_key(family, hostname, phase)
                )
                rendered = plan.finalized_times.get(
                    endpoint_event_render_key(family, hostname, phase)
                )
                return (native, rendered) if native is not None and rendered is not None else None
        return None

    @staticmethod
    def _endpoint_event_source_key(
        event: TimingOccurrence,
        family: str,
        phase: str,
    ) -> str:
        """Return the configured timing profile for one endpoint row."""

        if family == "sysmon" and phase == "network":
            return "source.sysmon_network_connection"
        if family == "sysmon" and phase == "dns":
            return "source.sysmon_dns_query"
        if family == "sysmon" and event.image_load is not None:
            return "source.sysmon_module_after_process_create"
        if family == "ecar" and event.event_type == "create_remote_thread":
            return "source.ecar_remote_thread"
        if family == "ecar" and event.event_type in {
            "file_read",
            "file_create",
            "file_modify",
            "file_delete",
            "registry_modify",
            "image_load",
            "process_access",
        }:
            return "source.ecar_dependent_after_process_create"
        if family == "ecar" and event.event_type in {
            "logon",
            "machine_logon",
            "failed_logon",
            "ssh_session",
        }:
            return "source.ecar_session"
        if family == "windows_security" and event.event_type == "wfp_connection":
            return "source.windows_wfp_connection"
        return f"source.{family}_{event.event_type}_{phase}"

    @staticmethod
    def _endpoint_process_source_key(family: str) -> str:
        return {
            "ecar": "source.ecar_process_create",
            "sysmon": "source.sysmon_process_create",
            "windows_security": "source.windows_security_process_create",
        }[family]

    @staticmethod
    def _endpoint_event_object_id(
        event: TimingOccurrence,
        hostname: str,
        phase: str,
    ) -> str:
        identity = event.identity_plan
        if identity is not None and identity.object_id:
            return f"{str(identity.object_id)}:{phase}"
        if event.occurrence_id:
            return f"{str(event.occurrence_id)}:{phase}"
        return f"{event.event_type}:{hostname}:{ensure_utc(event.timestamp).isoformat()}:{phase}"

    @staticmethod
    def _endpoint_event_lifecycle_id(event: TimingOccurrence) -> str:
        lifecycle = event.lifecycle
        if lifecycle is not None:
            return str(lifecycle.group_id)
        identity = event.identity_plan
        if identity is not None:
            for candidate in (identity.subject, identity.actor, identity.target, identity.session):
                group_id = str(getattr(candidate, "lifecycle_group_id", "") or "")
                if group_id:
                    return group_id
        return event.occurrence_id or event.event_type

    @staticmethod
    def _endpoint_process_scope(
        event: TimingOccurrence,
        hostname: str,
    ) -> tuple[str, str, int, datetime] | None:
        plan = event.identity_plan
        identities = () if plan is None else (plan.actor, plan.subject, plan.target)
        for identity in identities:
            if (
                isinstance(identity, ProcessIdentity)
                and identity.hostname.casefold() == hostname.casefold()
            ):
                return (
                    identity.object_id,
                    identity.lifecycle_group_id,
                    identity.pid,
                    identity.started_at,
                )
        process = event.process
        if process is None or process.pid <= 0:
            return None
        started_at = process.start_time or event.timestamp
        lifecycle_id = (
            event.lifecycle.group_id
            if event.lifecycle is not None
            else f"process:{hostname}:{process.pid}:{ensure_utc(started_at).isoformat()}"
        )
        object_id = f"process:{hostname}:{process.pid}:{ensure_utc(started_at).isoformat()}"
        return object_id, lifecycle_id, process.pid, started_at

    @staticmethod
    def _sysmon_event_id(event: TimingOccurrence, phase: str) -> int:
        """Return the provider event ID whose envelope is being planned."""

        if phase == "network":
            return 3
        if phase == "dns":
            return 22
        return {
            "process_create": 1,
            "system_process_create": 1,
            "process_terminate": 5,
            "create_remote_thread": 8,
            "process_access": 10,
            "file_create": 11,
            "file_modify": 11,
            "registry_modify": 13,
            "image_load": 7,
        }.get(event.event_type, 0)

    def _apply_runtime_transport_constraints(
        self,
        event: TimingOccurrence,
        *,
        family: str,
        source_instance: str,
        hostname: str,
        preferred: datetime,
    ) -> datetime:
        """Place endpoint authentication strictly after its admitted transport view."""

        if event.event_type not in {
            "logon",
            "machine_logon",
            "failed_logon",
            "ssh_session",
        }:
            return preferred
        anchor: datetime | None = None
        minimum_us = 8_000
        maximum_us = 140_000
        relationship = f"{family}.authentication_after_transport"
        if family == "ecar":
            anchor = self._remote_auth_transport_anchor(
                event,
                self._admitted_ecar_remote_transports,
                self._admitted_ecar_transport_transactions,
            )
            if anchor is None and event.event_type == "ssh_session":
                anchor = self._ssh_transport_anchor(event)
                relationship = "ecar.ssh_session_after_transport"
            if anchor is None and event.auth is not None and event.auth.session_kind == "smb":
                anchor = self._smb_transport_anchor(event)
                relationship = "ecar.smb_session_after_transport"
        elif family == "windows_security":
            anchor = self._remote_auth_transport_anchor(
                event,
                self._admitted_windows_remote_transports,
                self._admitted_windows_transport_transactions,
            )
        ticket_anchor: datetime | None = None
        if family == "windows_security" and event.event_type == "machine_logon":
            ticket_anchor = self._machine_ticket_anchor(event)
            if ticket_anchor is not None and (anchor is None or ticket_anchor > anchor):
                anchor = ticket_anchor
                minimum_us = 3_000
                maximum_us = 135_000
                relationship = "windows_security.machine_logon_after_service_ticket"
        if anchor is None:
            return preferred
        scope = TimingScope(
            stable_id=self._endpoint_event_object_id(event, hostname, "authentication"),
            host=hostname,
            source=source_instance,
            lifecycle_id=self._endpoint_event_lifecycle_id(event),
        )
        timestamp = anchor + self.timing_runtime.sampler.sample_timedelta(
            self._right_skew_distribution(minimum_us, maximum_us),
            relationship_key=relationship,
            scope=scope,
            sample_key="after_anchor",
        )
        primary_transport = (
            event.remote_auth.primary_transport if event.remote_auth is not None else None
        )
        if primary_transport is None or primary_transport.closed_at is None:
            return timestamp
        close_time = ensure_utc(primary_transport.closed_at)
        if ticket_anchor is not None and ticket_anchor >= close_time:
            # Kerberos service-ticket acquisition is a prerequisite, not an
            # application-session transport interval.  A machine-account logon
            # may legitimately follow the completed ticket exchange, so do not
            # force that endpoint row back inside an unrelated earlier socket.
            return timestamp
        if timestamp < close_time:
            return timestamp
        available_us = round((close_time - anchor).total_seconds() * 1_000_000)
        if available_us <= 2:
            self.timing_runtime.audit.record_saturation(f"{family}.authentication_transport_window")
            raise StateError(
                "Authentication source window cannot fit after its admitted transport: "
                f"family={family} anchor={anchor.isoformat()} close={close_time.isoformat()}"
            )
        admissible_minimum = minimum_us if available_us > minimum_us + 1 else 0
        return anchor + self.timing_runtime.sampler.sample_timedelta(
            self._right_skew_distribution(admissible_minimum, available_us),
            relationship_key=f"{relationship}.admissible",
            scope=scope,
            sample_key=f"before_close:{available_us}",
        )

    def _machine_ticket_anchor(self, event: TimingOccurrence) -> datetime | None:
        """Return the latest admitted matching service ticket near a machine logon."""

        if event.auth is None:
            return None
        host = event.dst_host or event.src_host
        if host is None:
            return None
        candidate = self._kerberos_service_times.get(
            self._kerberos_prerequisite_key(
                "windows_event_security",
                event.auth.username,
                event.auth.source_ip,
                host.hostname,
            ),
        )
        if candidate is None:
            return None
        if abs((candidate - self._ensure_plan(event).canonical_timestamp).total_seconds()) > 5.0:
            return None
        return candidate

    def _publish_endpoint_compatibility_time(
        self,
        event: TimingOccurrence,
        *,
        family: str,
        hostname: str,
        phase: str,
        timestamp: datetime,
    ) -> None:
        """Publish legacy lookup aliases from the frozen runtime-owned plan."""

        if phase != "base":
            return
        plan = self._ensure_plan(event)
        if family == "ecar" and event.event_type in {
            "logon",
            "machine_logon",
            "failed_logon",
            "logoff",
            "ssh_session",
        }:
            lifecycle = (
                "logout"
                if event.event_type == "logoff"
                else "failed_login"
                if event.event_type == "failed_logon"
                else "login"
            )
            plan.finalized_times[ecar_session_render_key(lifecycle)] = timestamp
        if family == "windows_security":
            if event.event_type == "wfp_connection":
                plan.finalized_times[_WINDOWS_WFP_RENDER_KEY] = timestamp
            elif event.event_type in {"logon", "machine_logon", "failed_logon"}:
                plan.finalized_times["windows.remote_authentication"] = timestamp

    def _apply_runtime_session_constraints(
        self,
        event: TimingOccurrence,
        *,
        family: str,
        source_instance: str,
        hostname: str,
        preferred: datetime,
    ) -> datetime:
        """Keep endpoint login/dependent rows inside one source session lifecycle."""

        lifecycle = event.lifecycle
        if lifecycle is None:
            return preferred
        if event.event_type in {"logon", "machine_logon", "ssh_session"}:
            return preferred
        session_group = (
            lifecycle.parent_group_id
            if event.event_type in _PROCESS_START_EVENT_TYPES | _PROCESS_END_EVENT_TYPES
            else lifecycle.group_id
            if lifecycle.phase == "dependent"
            else None
        )
        if not session_group:
            return preferred
        key = (family, session_group)
        visible_start = self._latest_session_start_times.get(key)
        timestamp = preferred
        if visible_start is not None and timestamp <= visible_start:
            self.timing_runtime.audit.record_repair(f"{family}.session.dependent_after_login")
            timestamp = self._sample_after_floor(
                visible_start,
                relationship_key=f"{family}.session.dependent_after_login",
                scope=TimingScope(
                    stable_id=self._endpoint_event_object_id(event, hostname, "session"),
                    host=hostname,
                    source=source_instance,
                    lifecycle_id=session_group,
                ),
                maximum_us=8_000,
            )
        previous = self._latest_session_dependent_times.get(key)
        if previous is not None and timestamp <= previous:
            self.timing_runtime.audit.record_repair(f"{family}.session.dependent_order")
            timestamp = self._sample_after_floor(
                previous,
                relationship_key=f"{family}.session.dependent_order",
                scope=TimingScope(
                    stable_id=self._endpoint_event_object_id(event, hostname, "session-order"),
                    host=hostname,
                    source=source_instance,
                    lifecycle_id=session_group,
                ),
                maximum_us=4_000,
            )
        return timestamp

    def _runtime_session_closure_time(
        self,
        event: TimingOccurrence,
        *,
        family: str,
        source_instance: str,
        hostname: str,
        os_category: str,
        preferred: datetime,
        output_end_time: datetime | None = None,
    ) -> datetime:
        """Resolve one session close with sampled interior slack and no bound atom."""

        lifecycle = event.lifecycle
        if lifecycle is None:
            return preferred
        canonical_end = self._ensure_plan(event).canonical_timestamp
        clock_end = self._runtime_endpoint_clock_time(
            canonical_end,
            hostname=hostname,
            os_category=os_category,
        )
        key = (family, lifecycle.group_id)
        earliest = clock_end
        visible_start = self._latest_session_start_times.get(key)
        if visible_start is not None:
            canonical_duration = max(
                timedelta(microseconds=1),
                canonical_end - ensure_utc(lifecycle.canonical_start),
            )
            earliest = max(earliest, visible_start + canonical_duration)
        latest_dependent = self._latest_session_dependent_times.get(key)
        if latest_dependent is not None:
            earliest = max(latest_dependent, earliest)
        format_name = "ecar" if family == "ecar" else "windows_security"
        latest_allowed = clock_end + self.session_closure_tail(format_name)
        if output_end_time is not None:
            latest_allowed = min(latest_allowed, ensure_utc(output_end_time))
        available_us = round((latest_allowed - earliest).total_seconds() * 1_000_000)
        if available_us <= 2:
            if output_end_time is not None and latest_allowed == ensure_utc(output_end_time):
                # A canonical close at/after the exclusive output fence has no
                # admissible rendered instant. Keep it outside the window so
                # dispatcher admission drops it; never clamp it onto the fence.
                self.timing_runtime.audit.record_fallback(
                    f"{family}.session.closure_outside_output"
                )
                return earliest
            self.timing_runtime.audit.record_saturation(f"{family}.session.closure_window")
            raise StateError(
                "Source-visible session dependents exceed the closure tail bound: "
                f"format={format_name} group={lifecycle.group_id} "
                f"dependent={earliest.isoformat()} end={canonical_end.isoformat()}"
            )
        if earliest < preferred < latest_allowed:
            timestamp = preferred
        else:
            timestamp = earliest + self.timing_runtime.sampler.sample_timedelta(
                self._right_skew_distribution(0, available_us),
                relationship_key=f"{family}.session.closure_repair",
                scope=TimingScope(
                    stable_id=self._endpoint_event_object_id(event, hostname, "closure"),
                    host=hostname,
                    source=source_instance,
                    lifecycle_id=lifecycle.group_id,
                ),
                sample_key="admissible",
            )
        return timestamp

    def _runtime_process_create_time(
        self,
        event: TimingOccurrence,
        *,
        family: str,
        source_key: str,
        source_instance: str,
        hostname: str,
        os_category: str,
        object_id: str,
        lifecycle_id: str,
        canonical_start: datetime,
    ) -> datetime:
        """Return a stable process-create observation in one endpoint clock."""

        cache_key = (family, source_instance, object_id)
        cached = self._runtime_process_create_times.get(cache_key)
        if cached is not None:
            self._record_process_create_dependency(
                event,
                family,
                source_instance,
                object_id,
                cached,
            )
            return cached
        identity = self._subject_process_identity(event)
        parent = (
            event.identity_plan.actor
            if event.identity_plan is not None
            and event.event_type in _PROCESS_START_EVENT_TYPES
            and isinstance(event.identity_plan.actor, ProcessIdentity)
            else None
        )
        parent_time = None
        if identity is not None and identity.object_id == object_id and parent is not None:
            parent_time = self._runtime_process_create_time(
                event,
                family=family,
                source_key=source_key,
                source_instance=source_instance,
                hostname=hostname,
                os_category=os_category,
                object_id=parent.object_id,
                lifecycle_id=parent.lifecycle_group_id,
                canonical_start=parent.started_at,
            )

        clock_time = self._runtime_endpoint_clock_time(
            canonical_start,
            hostname=hostname,
            os_category=os_category,
        )
        latency = self._coherent_runtime_latency(
            source_key,
            canonical_time=canonical_start,
            source_instance=source_instance,
            hostname=hostname,
            object_id=object_id,
            lifecycle_id=lifecycle_id,
            phase="create",
        )
        timestamp = clock_time + latency

        if parent_time is not None and timestamp <= parent_time:
            self.timing_runtime.audit.record_repair(f"{family}.process.parent_before_child")
            timestamp = self._sample_after_floor(
                parent_time,
                relationship_key=f"{family}.process.parent_before_child",
                scope=TimingScope(
                    stable_id=object_id,
                    host=hostname,
                    source=source_instance,
                    lifecycle_id=lifecycle_id,
                ),
                maximum_us=2_500,
            )
        self._runtime_process_create_times[cache_key] = timestamp
        self._record_process_create_dependency(
            event,
            family,
            source_instance,
            object_id,
            timestamp,
        )
        return timestamp

    def _runtime_shared_sysmon_process_create_time(
        self,
        event: TimingOccurrence,
        *,
        hostname: str,
        object_id: str,
        lifecycle_id: str,
        canonical_start: datetime,
    ) -> tuple[datetime, datetime]:
        """Return the host-shared Sysmon create/envelope anchor for endpoint sources."""

        key = (hostname.casefold(), object_id)
        cached = self._runtime_cross_source_sysmon_create_times.get(key)
        if cached is not None:
            return cached
        source_instance = f"sysmon:{hostname.casefold()}:host-agent"
        native = self._runtime_process_create_time(
            event,
            family="sysmon",
            source_key="source.sysmon_process_create",
            source_instance=source_instance,
            hostname=hostname,
            os_category="windows",
            object_id=object_id,
            lifecycle_id=lifecycle_id,
            canonical_start=canonical_start,
        )
        rendered = self._sysmon_runtime_envelope_time(
            native,
            event_id=1,
            source_instance=source_instance,
            hostname=hostname,
            object_id=object_id,
            lifecycle_id=lifecycle_id,
        )
        result = (native, rendered)
        self._runtime_cross_source_sysmon_create_times[key] = result
        return result

    def _runtime_windows_process_create_time(
        self,
        event: TimingOccurrence,
        *,
        source_instance: str,
        hostname: str,
        object_id: str,
        lifecycle_id: str,
        pid: int,
        canonical_start: datetime,
    ) -> datetime:
        """Place Security 4688 after the host-shared Sysmon Event 1 envelope."""

        cache_key = ("windows_security", source_instance, object_id)
        cached = self._runtime_process_create_times.get(cache_key)
        if cached is not None:
            self._record_process_create_dependency(
                event,
                "windows_security",
                source_instance,
                object_id,
                cached,
            )
            return cached
        _sysmon_native, sysmon_render = self._runtime_shared_sysmon_process_create_time(
            event,
            hostname=hostname,
            object_id=self._sysmon_process_object_id(hostname, pid, canonical_start),
            lifecycle_id=lifecycle_id,
            canonical_start=canonical_start,
        )
        window = get_timing_window(
            "source.windows_security_after_sysmon_process_create_gap",
            default_min_ms=35,
            default_max_ms=650,
            default_position="after",
            default_class="source_latency",
        )
        timestamp = sysmon_render + self.timing_runtime.sampler.sample_timedelta(
            self._right_skew_distribution(window.min_ms * 1_000, window.max_ms * 1_000 + 1),
            relationship_key="windows_security.process_create_after_sysmon",
            scope=TimingScope(
                stable_id=object_id,
                host=hostname,
                source=source_instance,
                lifecycle_id=lifecycle_id,
            ),
            sample_key="after_sysmon",
        )
        self._runtime_process_create_times[cache_key] = timestamp
        self._record_process_create_dependency(
            event,
            "windows_security",
            source_instance,
            object_id,
            timestamp,
        )
        return timestamp

    def _record_process_create_dependency(
        self,
        event: TimingOccurrence,
        family: str,
        source_instance: str,
        object_id: str,
        timestamp: datetime,
    ) -> None:
        """Retain a child's visible create as a floor for its parent close."""

        parent = (
            event.identity_plan.actor
            if event.identity_plan is not None
            and event.event_type in _PROCESS_START_EVENT_TYPES
            and isinstance(event.identity_plan.actor, ProcessIdentity)
            else None
        )
        subject = self._subject_process_identity(event)
        if parent is None or subject is None or subject.object_id != object_id:
            return
        key = (family, source_instance, parent.object_id)
        previous = self._process_dependent_create_times.get(key)
        if previous is None or timestamp > previous:
            self._process_dependent_create_times[key] = timestamp

    def _runtime_process_termination_time(
        self,
        event: TimingOccurrence,
        *,
        family: str,
        source_key: str,
        source_instance: str,
        hostname: str,
        os_category: str,
        object_id: str,
        lifecycle_id: str,
        canonical_start: datetime,
        canonical_end: datetime,
        create_time: datetime,
    ) -> datetime:
        """Return a lifecycle-contained process termination observation."""

        clock_end = self._runtime_endpoint_clock_time(
            canonical_end,
            hostname=hostname,
            os_category=os_category,
        )
        preferred = clock_end + self._coherent_runtime_latency(
            source_key,
            canonical_time=canonical_end,
            source_instance=source_instance,
            hostname=hostname,
            object_id=object_id,
            lifecycle_id=lifecycle_id,
            phase="terminate",
        )
        canonical_lifetime = max(timedelta(microseconds=1), canonical_end - canonical_start)
        lifecycle_floor = create_time + canonical_lifetime
        dependent_create = self._process_dependent_create_times.get(
            (family, source_instance, object_id)
        )
        if dependent_create is not None:
            lifecycle_floor = max(lifecycle_floor, dependent_create + _SOURCE_EPSILON)
        if preferred > lifecycle_floor:
            return preferred
        self.timing_runtime.audit.record_repair(f"{family}.process.lifecycle_containment")
        return self._sample_after_floor(
            lifecycle_floor,
            relationship_key=f"{family}.process.lifecycle_containment",
            scope=TimingScope(
                stable_id=object_id,
                host=hostname,
                source=source_instance,
                lifecycle_id=lifecycle_id,
                ordinal=1,
            ),
            maximum_us=4_000,
        )

    def _coherent_runtime_latency(
        self,
        source_key: str,
        *,
        canonical_time: datetime,
        source_instance: str,
        hostname: str,
        object_id: str,
        lifecycle_id: str,
        phase: str,
    ) -> timedelta:
        """Sample a right-skew queue delay with smooth source-local coherence."""

        window = get_timing_window(
            source_key,
            default_min_ms=1,
            default_max_ms=100,
            default_position="after",
            default_class="source_latency",
        )
        minimum_us = window.min_ms * 1_000
        maximum_us = window.max_ms * 1_000
        if maximum_us <= minimum_us:
            return timedelta(microseconds=minimum_us)

        span_us = maximum_us - minimum_us
        residual_max_us = min(2_500, max(3, span_us // 16))
        base_max_us = maximum_us - residual_max_us
        if base_max_us <= minimum_us + 2:
            scope = TimingScope(
                stable_id=object_id,
                host=hostname,
                source=source_instance,
                lifecycle_id=lifecycle_id,
            )
            return self.timing_runtime.sampler.sample_timedelta(
                self._right_skew_distribution(minimum_us, maximum_us),
                relationship_key=source_key,
                scope=scope,
                sample_key=phase,
            )

        reference = self.timing_runtime.clocks.reference_time
        interval_us = 15 * 60 * 1_000_000
        elapsed_us = round((ensure_utc(canonical_time) - reference).total_seconds() * 1_000_000)
        left_ordinal = math.floor(elapsed_us / interval_us)
        fraction = (elapsed_us - left_ordinal * interval_us) / interval_us
        queue_distribution = self._right_skew_distribution(minimum_us, base_max_us)

        def queue_knot(ordinal: int) -> int:
            return self.timing_runtime.sampler.sample_microseconds(
                queue_distribution,
                relationship_key=f"{source_key}.coherent_queue",
                scope=TimingScope(
                    stable_id=f"queue:{source_instance}",
                    host=hostname,
                    source=source_instance,
                    ordinal=ordinal,
                ),
                sample_key="queue",
            )

        left = queue_knot(left_ordinal)
        right = queue_knot(left_ordinal + 1)
        smooth_fraction = fraction * fraction * (3.0 - 2.0 * fraction)
        base_us = round(left + ((right - left) * smooth_fraction))
        residual = self.timing_runtime.sampler.sample_microseconds(
            self._right_skew_distribution(0, residual_max_us),
            relationship_key=f"{source_key}.lifecycle_residual",
            scope=TimingScope(
                stable_id=object_id,
                host=hostname,
                source=source_instance,
                lifecycle_id=lifecycle_id,
            ),
            sample_key=phase,
        )
        return timedelta(microseconds=base_us + residual)

    def _sysmon_runtime_envelope_time(
        self,
        native_time: datetime,
        *,
        event_id: int,
        source_instance: str,
        hostname: str,
        object_id: str,
        lifecycle_id: str,
    ) -> datetime:
        """Project a migrated Sysmon row through a typed provider envelope."""

        timing = sysmon_envelope_timing(event_id)
        main = TruncatedLognormalDistribution(
            median=float(timing.median_us),
            sigma=timing.sigma,
            minimum=float(timing.min_us),
            maximum=float(timing.max_us),
        )
        distribution = main
        if timing.tail_probability > 0 and timing.tail_max_us > timing.tail_min_us:
            tail = TruncatedLognormalDistribution(
                median=float(timing.tail_min_us + (timing.tail_max_us - timing.tail_min_us) // 4),
                sigma=max(0.35, timing.sigma),
                minimum=float(timing.tail_min_us),
                maximum=float(timing.tail_max_us),
            )
            distribution = MixtureDistribution(
                (
                    WeightedDistribution(1.0 - timing.tail_probability, main),
                    WeightedDistribution(timing.tail_probability, tail),
                )
            )
        delay = self.timing_runtime.sampler.sample_timedelta(
            distribution,
            relationship_key="sysmon.provider_envelope",
            scope=TimingScope(
                stable_id=object_id,
                host=hostname,
                source=source_instance,
                lifecycle_id=lifecycle_id,
                ordinal=event_id,
            ),
            sample_key="envelope",
        )
        return native_time + delay

    def _runtime_endpoint_clock_time(
        self,
        canonical_time: datetime,
        *,
        hostname: str,
        os_category: str,
    ) -> datetime:
        """Project canonical time through the engine-owned endpoint clock."""

        if not hostname or os_category not in {"windows", "linux"}:
            return ensure_utc(canonical_time)
        timing = endpoint_clock_timing(self.clock_profile_name, os_category)
        spec = SourceClockSpec(
            offset_microseconds=self._clock_distribution(
                timing.host_offset_min_ms * 1_000,
                timing.host_offset_max_ms * 1_000,
            ),
            drift_ppm=self._clock_distribution(
                timing.host_drift_min_ppm,
                timing.host_drift_max_ppm,
            ),
        )
        return self.timing_runtime.clocks.project(
            ensure_utc(canonical_time),
            key=SourceClockKey(
                kind="endpoint-host",
                identity=hostname.casefold(),
                profile=self.clock_profile_name,
            ),
            spec=spec,
        )

    @staticmethod
    def _clock_distribution(
        minimum: int, maximum: int
    ) -> ConstantDistribution | TriangularDistribution:
        """Return a typed source-clock distribution for one configured range."""

        if maximum <= minimum:
            return ConstantDistribution(float(minimum))
        mode = min(float(maximum), max(float(minimum), 0.0))
        return TriangularDistribution(float(minimum), mode, float(maximum))

    @staticmethod
    def _right_skew_distribution(
        minimum_us: int,
        maximum_us: int,
    ) -> TruncatedLognormalDistribution:
        """Build an open-support lognormal shaped toward the lower delay tail."""

        width = maximum_us - minimum_us
        median = minimum_us + max(1.0, width * 0.16)
        return TruncatedLognormalDistribution(
            median=float(median),
            sigma=0.9,
            minimum=float(minimum_us),
            maximum=float(maximum_us),
        )

    def _sample_profile_delay(
        self,
        event: TimingOccurrence,
        relationship_key: str,
        *,
        seed_parts: tuple[Any, ...],
        sample_key: str,
    ) -> timedelta:
        """Sample one configured relationship through the engine timing runtime."""

        window = get_timing_window(
            relationship_key,
            default_min_ms=0,
            default_max_ms=0,
            default_position="after",
        )
        minimum_us = window.min_ms * 1_000
        maximum_us = window.max_ms * 1_000
        distribution = (
            ConstantDistribution(float(minimum_us))
            if maximum_us <= minimum_us
            else self._right_skew_distribution(minimum_us, maximum_us + 1)
        )
        host = event.src_host or event.dst_host
        hostname = str(getattr(host, "hostname", "") or "")
        lifecycle_id = event.lifecycle.group_id if event.lifecycle is not None else ""
        effective_seed = seed_parts or self._event_seed_parts(event)
        return self.timing_runtime.sampler.sample_timedelta(
            distribution,
            relationship_key=relationship_key,
            scope=TimingScope(
                stable_id=self._cache_key(
                    f"runtime-profile:{relationship_key}",
                    effective_seed,
                ),
                host=hostname,
                source=relationship_key,
                lifecycle_id=lifecycle_id,
            ),
            sample_key=sample_key,
        )

    def _sample_after_floor(
        self,
        floor: datetime,
        *,
        relationship_key: str,
        scope: TimingScope,
        maximum_us: int,
    ) -> datetime:
        """Sample admissible positive slack rather than clamping onto a floor."""

        return floor + self.timing_runtime.sampler.sample_timedelta(
            self._right_skew_distribution(0, maximum_us),
            relationship_key=relationship_key,
            scope=scope,
            sample_key="repair_slack",
        )

    @staticmethod
    def _subject_process_identity(event: TimingOccurrence) -> ProcessIdentity | None:
        """Return the canonical process subject when the event owns one."""

        identity = event.identity_plan
        return (
            identity.subject
            if identity is not None and isinstance(identity.subject, ProcessIdentity)
            else None
        )

    @staticmethod
    def _process_scope_ids(
        event: TimingOccurrence,
        identity: ProcessIdentity | None,
        *,
        hostname: str,
        pid: int,
        started_at: datetime,
    ) -> tuple[str, str]:
        """Return durable process and lifecycle IDs for semantic timing draws."""

        if identity is not None:
            return identity.object_id, identity.lifecycle_group_id
        lifecycle_id = (
            event.lifecycle.group_id
            if event.lifecycle is not None and isinstance(event.lifecycle.group_id, str)
            else ""
        )
        object_id = f"process:{hostname}:{pid}:{ensure_utc(started_at).isoformat()}"
        return object_id, lifecycle_id or object_id

    @staticmethod
    def _sysmon_process_object_id(
        hostname: str,
        pid: int,
        started_at: datetime,
    ) -> str:
        """Return the identity shared by visible or collection-dropped Event 1 rows."""

        return f"process:{hostname.casefold()}:{pid}:{ensure_utc(started_at).isoformat()}"

    def _plan_windows_remote_auth_time(self, event: TimingOccurrence) -> TimingOccurrence:
        """Finalize source-local WFP-before-authentication ordering."""

        if event.event_type == "wfp_connection" and event.network is not None:
            host = event.src_host or event.dst_host
            timestamp = self.source_time(
                event,
                "source.windows_wfp_connection",
                seed_parts=(
                    getattr(host, "hostname", ""),
                    event.network.initiating_pid if event.network.initiating_pid > 0 else 4,
                    event.network.src_ip,
                    event.network.src_port,
                    event.network.dst_ip,
                    event.network.dst_port,
                    event.timestamp,
                ),
                not_before=event.timestamp,
            )
            self._ensure_plan(event).finalized_times[_WINDOWS_WFP_RENDER_KEY] = timestamp
            return event
        if (
            event.event_type not in {"logon", "machine_logon", "failed_logon"}
            or event.remote_auth is None
        ):
            return event
        anchor = self._remote_auth_transport_anchor(
            event,
            self._admitted_windows_remote_transports,
            self._admitted_windows_transport_transactions,
        )
        ticket_time: datetime | None = None
        if event.event_type == "machine_logon" and event.auth is not None:
            host = event.dst_host or event.src_host
            if host is not None:
                candidate = self._kerberos_service_times.get(
                    self._kerberos_prerequisite_key(
                        "windows_event_security",
                        event.auth.username,
                        event.auth.source_ip,
                        host.hostname,
                    ),
                )
                if (
                    candidate is not None
                    and abs((candidate - event.timestamp).total_seconds()) <= 5.0
                ):
                    ticket_time = candidate
        if anchor is None:
            if ticket_time is not None:
                timestamp = max(
                    event.timestamp,
                    ticket_time + self._machine_logon_after_ticket_delay(event, ticket_time),
                )
                self._ensure_plan(event).finalized_times["windows.remote_authentication"] = (
                    timestamp
                )
                return replace(event, timestamp=timestamp)
            return event
        timestamp = anchor + self._sample_profile_delay(
            event,
            "windows.network_logon_after_transport",
            seed_parts=(
                "windows_security",
                event.remote_auth.stable_id,
                event.remote_auth.primary_transport.transaction_id,
                event.event_type,
            ),
            sample_key="remote_authentication",
        )
        if ticket_time is not None:
            timestamp = max(
                timestamp,
                ticket_time + self._machine_logon_after_ticket_delay(event, ticket_time),
            )
        self._ensure_plan(event).finalized_times["windows.remote_authentication"] = timestamp
        return replace(event, timestamp=timestamp)

    def _machine_logon_after_ticket_delay(
        self,
        event: TimingOccurrence,
        ticket_time: datetime,
    ) -> timedelta:
        """Return one runtime-owned source-native delay for a machine auth lifecycle."""
        remote_auth = event.remote_auth
        auth = event.auth
        return self._sample_profile_delay(
            event,
            "windows.machine_logon_after_service_ticket",
            seed_parts=(
                remote_auth.stable_id if remote_auth is not None else "",
                auth.username if auth is not None else "",
                auth.source_ip if auth is not None else "",
                auth.source_port if auth is not None else "",
                ticket_time,
            ),
            sample_key="after_service_ticket",
        )

    @staticmethod
    def _kerberos_prerequisite_key(
        format_name: str,
        username: str,
        source_ip: str,
        dc_hostname: str,
    ) -> tuple[str, str, str, str]:
        """Return a normalized source-local machine-ticket dependency key."""

        principal = username.split("@", maxsplit=1)[0].lower()
        return (
            format_name,
            principal,
            source_ip.removeprefix("::ffff:"),
            dc_hostname.lower(),
        )

    def _remote_auth_transport_anchor(
        self,
        event: TimingOccurrence,
        registry: BoundedRuntimeCache[_REMOTE_TRANSPORT_KEY, datetime],
        transaction_registry: BoundedRuntimeCache[_TRANSACTION_TRANSPORT_KEY, datetime],
    ) -> datetime | None:
        remote_auth = event.remote_auth
        if remote_auth is None or remote_auth.primary_transport is None:
            return None
        transport = remote_auth.primary_transport
        tuple_view = transport.tuple
        action_anchor = registry.get(
            SourceTimingPlanner._remote_transport_key(
                remote_auth.stable_id,
                transport.transaction_id,
                remote_auth.target_hostname,
                tuple_view.src_ip,
                tuple_view.src_port,
                tuple_view.dst_ip,
                tuple_view.dst_port,
                tuple_view.protocol,
            )
        )
        if action_anchor is not None:
            return action_anchor
        return transaction_registry.get(
            self._transaction_transport_key(
                transport.transaction_id,
                remote_auth.target_hostname,
                tuple_view.src_ip,
                tuple_view.src_port,
                tuple_view.dst_ip,
                tuple_view.dst_port,
                tuple_view.protocol,
            )
        )

    @staticmethod
    def _remote_transport_key(
        action_group_id: str,
        transaction_id: str,
        target_hostname: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
    ) -> _REMOTE_TRANSPORT_KEY:
        """Return the exact source-view key for one remote-auth transport."""

        return (
            action_group_id,
            transaction_id,
            target_hostname,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol.lower(),
        )

    @staticmethod
    def _transaction_transport_key(
        transaction_id: str,
        target_hostname: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
    ) -> _TRANSACTION_TRANSPORT_KEY:
        """Return an exact source-view key independent of the parent bundle."""

        return (
            transaction_id,
            target_hostname,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol.lower(),
        )

    def _ssh_transport_anchor(self, event: TimingOccurrence) -> datetime | None:
        """Return the admitted exact-tuple SSH FLOW time for a session event."""

        auth = event.auth
        host = event.dst_host or event.src_host
        if auth is None or host is None or not auth.source_ip or auth.source_port <= 0:
            return None
        return self._admitted_ecar_ssh_transports.get(
            self._ssh_transport_key(
                host.hostname,
                auth.source_ip,
                auth.source_port,
                host.ip,
                22,
                "tcp",
            )
        )

    def _smb_transport_anchor(self, event: TimingOccurrence) -> datetime | None:
        """Return the admitted exact-tuple SMB FLOW time for a Samba session."""

        auth = event.auth
        host = event.dst_host or event.src_host
        if auth is None or host is None or not auth.source_ip or auth.source_port <= 0:
            return None
        return self._admitted_ecar_smb_transports.get(
            self._smb_transport_key(
                host.hostname,
                auth.source_ip,
                auth.source_port,
                host.ip,
                445,
                "tcp",
            )
        )

    @staticmethod
    def _ssh_transport_key(
        target_hostname: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
    ) -> _SSH_TRANSPORT_KEY:
        """Return the exact target-view key for one admitted SSH transport."""

        return (
            target_hostname,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol.lower(),
        )

    @staticmethod
    def _smb_transport_key(
        target_hostname: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
    ) -> _SMB_TRANSPORT_KEY:
        """Return the exact target-view key for one admitted SMB transport."""

        return (
            target_hostname,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol.lower(),
        )

    @staticmethod
    def _finalized_time(event: TimingOccurrence, key: str) -> datetime | None:
        plan = event.source_timing
        return plan.finalized_times.get(key) if plan is not None else None

    @classmethod
    def _latest_ecar_endpoint_flow_time(cls, event: TimingOccurrence) -> datetime | None:
        """Return the later admitted endpoint observation for one eCAR transport."""

        timestamps = []
        if event.src_host is not None:
            timestamp = cls._finalized_time(
                event,
                ecar_flow_render_key("outbound", event.src_host.hostname),
            )
            if timestamp is not None:
                timestamps.append(timestamp)
        if event.dst_host is not None:
            timestamp = cls._finalized_time(
                event,
                ecar_flow_render_key("inbound", event.dst_host.hostname),
            )
            if timestamp is not None:
                timestamps.append(timestamp)
        return max(timestamps) if timestamps else None

    def _plan_ecar_flow_times(
        self,
        event: TimingOccurrence,
        *,
        source_instance: str = "",
        source_hostname: str = "",
        projection_role: str = "",
    ) -> None:
        """Finalize every host-local FLOW timestamp and attribution decision."""

        network = event.network
        if network is None:
            return
        identity_plan = event.identity_plan
        source_identity = (
            identity_plan.actor
            if identity_plan is not None and isinstance(identity_plan.actor, ProcessIdentity)
            else None
        )
        target_identity = (
            identity_plan.target
            if identity_plan is not None and isinstance(identity_plan.target, ProcessIdentity)
            else None
        )
        plan = self._ensure_plan(event)
        render_source = projection_role not in {"destination_endpoint"}
        render_destination = projection_role not in {"source_endpoint"}
        if event.src_host is not None and render_source:
            direction = "outbound"
            hostname = event.src_host.hostname
            not_before = (
                self._ecar_process_identity_not_before(event, source_identity)
                if source_identity is not None
                else None
            )
            timestamp, identity_safe = self._ecar_flow_source_time(
                event,
                seed_parts=(
                    direction,
                    hostname,
                    network.initiating_pid,
                    network.src_ip,
                    network.src_port,
                    network.dst_ip,
                    network.dst_port,
                    event.timestamp,
                ),
                not_before=not_before,
                drop_late_process_identity=(
                    network.protocol == "tcp" and network.dst_port in {22, 3389}
                ),
                source_instance=(
                    source_instance
                    if not source_hostname or source_hostname.casefold() == hostname.casefold()
                    else f"ecar:{hostname.casefold()}"
                ),
                hostname=hostname,
            )
            plan.finalized_times[ecar_flow_render_key(direction, hostname)] = timestamp
            plan.finalized_flags[ecar_flow_identity_key(direction, hostname)] = identity_safe
        if event.dst_host is not None and render_destination:
            direction = "inbound"
            hostname = event.dst_host.hostname
            not_before = (
                self._ecar_process_identity_not_before(event, target_identity)
                if target_identity is not None
                else None
            )
            timestamp, identity_safe = self._ecar_flow_source_time(
                event,
                seed_parts=(
                    direction,
                    hostname,
                    network.initiating_pid,
                    network.src_ip,
                    network.src_port,
                    network.dst_ip,
                    network.dst_port,
                    event.timestamp,
                ),
                not_before=not_before,
                drop_late_process_identity=(
                    network.protocol == "tcp" and network.dst_port in {22, 3389}
                ),
                source_instance=(
                    source_instance
                    if not source_hostname or source_hostname.casefold() == hostname.casefold()
                    else f"ecar:{hostname.casefold()}"
                ),
                hostname=hostname,
            )
            plan.finalized_times[ecar_flow_render_key(direction, hostname)] = timestamp
            plan.finalized_flags[ecar_flow_identity_key(direction, hostname)] = identity_safe

    def _ecar_process_identity_not_before(
        self,
        event: TimingOccurrence,
        identity: ProcessIdentity,
    ) -> datetime:
        """Return the earliest FLOW time that can safely claim a process."""

        if event.timestamp - identity.started_at >= timedelta(seconds=5):
            return identity.started_at
        create_time = self._prime_ecar_process_create_time(event, identity)
        return create_time + _SOURCE_EPSILON

    def _ecar_flow_source_time(
        self,
        event: TimingOccurrence,
        *,
        seed_parts: tuple[Any, ...],
        not_before: datetime | None,
        drop_late_process_identity: bool,
        source_instance: str,
        hostname: str,
    ) -> tuple[datetime, bool]:
        """Return a typed, right-skew FLOW time inside its local interval."""

        network = event.network
        if network is None:
            return self._ensure_plan(event).canonical_timestamp, False
        host = next(
            (
                candidate
                for candidate in (event.src_host, event.dst_host)
                if candidate is not None and candidate.hostname.casefold() == hostname.casefold()
            ),
            event.src_host or event.dst_host,
        )
        os_category = getattr(host, "os_category", "windows")
        canonical_start, canonical_end = self._ecar_flow_interval(event, seed_parts)
        interval_start = self._runtime_endpoint_clock_time(
            canonical_start,
            hostname=hostname,
            os_category=os_category,
        )
        not_after = (
            self._runtime_endpoint_clock_time(
                canonical_end,
                hostname=hostname,
                os_category=os_category,
            )
            if canonical_end is not None
            else None
        )
        identity_safe = not_before is None
        lower_bound = interval_start
        if not_before is not None:
            if not_after is None or not_before < not_after:
                lower_bound = max(lower_bound, not_before)
                identity_safe = True
            elif drop_late_process_identity:
                identity_safe = False

        lifecycle = event.lifecycle
        parent_group_id = (
            lifecycle.parent_group_id
            if lifecycle is not None and isinstance(lifecycle.parent_group_id, str)
            else ""
        )
        group_id = (
            lifecycle.group_id
            if lifecycle is not None and isinstance(lifecycle.group_id, str)
            else ""
        )
        stable_id = network.stable_id or network.zeek_uid
        lifecycle_id = parent_group_id or group_id or stable_id
        scope = TimingScope(
            stable_id=stable_id,
            host=hostname,
            source=source_instance or f"ecar:{hostname.casefold()}",
            lifecycle_id=lifecycle_id,
            ordinal=0 if str(seed_parts[0]).lower() == "outbound" else 1,
        )
        timestamp = self._sample_admissible_flow_time(
            lower_bound,
            not_after,
            scope=scope,
            lifecycle_coherent=bool(parent_group_id.startswith("proxy-transaction-")),
        )
        return timestamp, identity_safe and (not_before is None or timestamp >= not_before)

    def _sample_admissible_flow_time(
        self,
        lower_bound: datetime,
        upper_bound: datetime | None,
        *,
        scope: TimingScope,
        lifecycle_coherent: bool,
    ) -> datetime:
        """Sample FLOW queue slack from the interval that is actually available."""

        window = get_timing_window(
            "source.ecar_flow",
            default_min_ms=180,
            default_max_ms=1800,
            default_position="after",
            default_class="source_latency",
        )
        relationship_key = (
            "source.ecar_flow.lifecycle_queue"
            if lifecycle_coherent
            else "source.ecar_flow.endpoint_queue"
        )
        sample_scope = (
            TimingScope(
                stable_id=f"lifecycle:{scope.lifecycle_id}",
                host=scope.host,
                source=scope.source,
                lifecycle_id=scope.lifecycle_id,
            )
            if lifecycle_coherent
            else scope
        )
        if upper_bound is None:
            distribution = self._right_skew_distribution(
                window.min_ms * 1_000,
                window.max_ms * 1_000,
            )
            return self.timing_runtime.sampler.after(
                lower_bound,
                distribution,
                relationship_key=relationship_key,
                scope=sample_scope,
                sample_key="flow",
            )

        available_us = round((upper_bound - lower_bound).total_seconds() * 1_000_000)
        if available_us <= 2:
            self.timing_runtime.audit.record_saturation("source.ecar_flow.admissible_window")
            return lower_bound
        preferred_minimum = window.min_ms * 1_000
        if available_us <= preferred_minimum + 2:
            minimum_us = 18_000 if available_us > 18_002 else 0
        else:
            minimum_us = preferred_minimum
        maximum_us = min(window.max_ms * 1_000, available_us)
        if maximum_us <= minimum_us + 1:
            minimum_us = 0
        try:
            delay = self.timing_runtime.sampler.sample_timedelta(
                self._right_skew_distribution(minimum_us, maximum_us),
                relationship_key=relationship_key,
                scope=sample_scope,
                sample_key=f"flow:{available_us}",
            )
        except TimingDistributionError:
            self.timing_runtime.audit.record_saturation("source.ecar_flow.admissible_window")
            delay = timedelta(microseconds=max(1, available_us // 2))
        return lower_bound + delay

    @staticmethod
    def _ecar_flow_interval(
        event: TimingOccurrence,
        seed_parts: tuple[Any, ...],
    ) -> tuple[datetime, datetime | None]:
        """Return the finalized canonical interval for an endpoint FLOW."""

        del seed_parts
        network = event.network
        if network is None:
            return event.timestamp, None
        # A connection occurrence without a modeled close interval is anchored
        # by the canonical occurrence timestamp.  Compatibility callers may
        # construct a sparse NetworkTransactionPlan whose default ``started_at``
        # is merely a factory epoch; that value must never replace the date of
        # the occurrence.  Once an interval is modeled, its canonical start and
        # close remain authoritative and immutable.
        start_time = (
            event.timestamp
            if network.duration is None and network.closed_at is None
            else network.started_at
        )
        if network.duration is None:
            if network.conn_state in {"S0", "REJ", "RSTO", "RSTR", "SH", "SHR"}:
                return start_time, start_time + timedelta(milliseconds=665)
            return start_time, None
        close_time = network.closed_at or (
            start_time + timedelta(seconds=max(0.0, network.duration))
        )
        return start_time, close_time

    def _plan_session_lifecycle_time(
        self,
        event: TimingOccurrence,
        format_name: str,
    ) -> TimingOccurrence:
        """Order same-source process termination and session closure observations."""

        lifecycle = event.lifecycle
        if lifecycle is None:
            return event
        if event.event_type in {"logon", "machine_logon", "ssh_session"}:
            source_time = event.timestamp
            if format_name == "ecar" and event.source_timing is not None:
                source_time = event.source_timing.finalized_times.get(
                    ecar_session_render_key("login"),
                    source_time,
                )
            key = (format_name, lifecycle.group_id)
            previous = self._latest_session_start_times.get(key)
            if previous is None or source_time > previous:
                self._latest_session_start_times[key] = source_time
            return event
        if event.event_type == "process_terminate" and lifecycle.parent_group_id:
            source_time = self._process_termination_source_time(event, format_name)
            key = (format_name, lifecycle.parent_group_id)
            previous = self._latest_session_dependent_times.get(key)
            if previous is None or source_time > previous:
                self._latest_session_dependent_times[key] = source_time
                process = event.process
                identity = (
                    event.identity_plan.subject
                    if event.identity_plan is not None
                    and isinstance(event.identity_plan.subject, ProcessIdentity)
                    else None
                )
                create_time = (
                    self._ecar_process_create_times.get(identity.object_id)
                    if identity is not None
                    else None
                )
                self._latest_session_dependent_descriptions.set(
                    key,
                    f"event={event.event_type} host={event.src_host.hostname if event.src_host else ''} "
                    f"pid={process.pid if process is not None else ''} "
                    f"image={process.image if process is not None else ''} "
                    f"process_start={process.start_time.isoformat() if process is not None and process.start_time is not None else ''} "
                    f"source_create={create_time.isoformat() if create_time is not None else ''} "
                    f"canonical_terminate={event.timestamp.isoformat()} "
                    f"source_terminate={source_time.isoformat()}",
                    deadline=_retained_until(
                        source_time,
                        _SOURCE_TIMING_LIFECYCLE_RETENTION,
                    ),
                )
            return event
        if lifecycle.phase == "dependent":
            key = (format_name, lifecycle.group_id)
            visible_start = self._latest_session_start_times.get(key)
            source_time = event.timestamp
            if visible_start is not None:
                source_time = max(
                    source_time,
                    visible_start
                    + self._sample_profile_delay(
                        event,
                        "source.session_dependent_after_login",
                        seed_parts=(
                            format_name,
                            lifecycle.group_id,
                            event.event_type,
                            event.timestamp,
                        ),
                        sample_key="dependent_after_login",
                    ),
                )
                event = replace(event, timestamp=source_time)
            previous = self._latest_session_dependent_times.get(key)
            if previous is not None:
                source_time = max(source_time, previous + _SOURCE_EPSILON)
                event = replace(event, timestamp=source_time)
            self._latest_session_dependent_times[key] = source_time
            self._latest_session_dependent_descriptions.set(
                key,
                f"event={event.event_type} source={source_time.isoformat()}",
                deadline=_retained_until(
                    source_time,
                    _SOURCE_TIMING_LIFECYCLE_RETENTION,
                ),
            )
            return event
        if event.event_type != "logoff" or format_name not in _SESSION_CLOSURE_SOURCE_KEYS:
            return event
        timestamp = self.session_closure_source_time(event, format_name)
        key = (format_name, lifecycle.group_id)
        self._latest_session_start_times.pop(key)
        self._latest_session_dependent_times.pop(key)
        self._latest_session_dependent_descriptions.pop(key)
        return replace(event, timestamp=timestamp)

    def _process_termination_source_time(
        self,
        event: TimingOccurrence,
        format_name: str,
    ) -> datetime:
        """Return the timestamp a source will render for a process termination."""

        process = event.process
        host = event.src_host
        if process is None or host is None:
            return event.timestamp
        plan = self._ensure_plan(event)
        if format_name == "ecar":
            finalized = plan.finalized_times.get(
                ecar_process_render_key("terminate", host.hostname)
            )
            if finalized is not None:
                return finalized
        if format_name == "windows_event_sysmon":
            finalized = plan.finalized_times.get(
                sysmon_process_render_key("terminate", host.hostname)
            )
            if finalized is not None:
                return finalized
        start_time = process.start_time or event.timestamp
        if format_name in {"windows_security", "windows_event_security"}:
            return self.source_time(
                event,
                "source.windows_security_process_terminate",
                seed_parts=(host.hostname, process.pid, start_time, event.timestamp),
                not_before=event.timestamp,
            )
        if format_name == "ecar":
            identity = (
                event.identity_plan.subject
                if event.identity_plan is not None
                and isinstance(event.identity_plan.subject, ProcessIdentity)
                else None
            )
            process_start = identity.started_at if identity is not None else start_time
            create_time = (
                self._prime_ecar_process_create_time(event, identity)
                if identity is not None
                else process_start
            )
            canonical_lifetime = max(
                timedelta(milliseconds=100),
                event.timestamp - process_start,
            )
            return self.source_time(
                event,
                "source.ecar_process_terminate",
                seed_parts=(host.hostname, process.pid, process_start, event.timestamp),
                not_before=max(event.timestamp, create_time + canonical_lifetime),
            )
        return event.timestamp

    @staticmethod
    def session_closure_tail(format_name: str) -> timedelta:
        """Return the maximum source-visible tail for one session format."""

        try:
            return _SESSION_CLOSURE_TAILS[format_name]
        except KeyError as exc:
            raise ValueError(f"unsupported session closure format: {format_name!r}") from exc

    @classmethod
    def max_session_closure_tail(cls, format_names: Iterable[str]) -> timedelta:
        """Return the maximum source-visible tail across selected formats."""

        return max((cls.session_closure_tail(name) for name in format_names), default=timedelta())

    def session_closure_source_time(
        self,
        event: TimingOccurrence,
        format_name: str,
    ) -> datetime:
        """Return the bounded source-native closure time for one session group."""

        lifecycle = event.lifecycle
        source_key = _SESSION_CLOSURE_SOURCE_KEYS.get(format_name)
        if lifecycle is None or source_key is None:
            return event.timestamp
        plan = self._ensure_plan(event)
        canonical_end = ensure_utc(plan.canonical_timestamp)
        seed_parts = (
            "session-closure",
            format_name,
            lifecycle.group_id,
            getattr(event.auth, "logon_id", ""),
            canonical_end,
        )
        cache_key = self._cache_key(source_key, seed_parts)
        preferred = plan.source_times.get(cache_key)
        if preferred is None:
            preferred = canonical_end
        latest = self._latest_session_dependent_times.get((format_name, lifecycle.group_id))
        earliest = canonical_end
        visible_start = self._latest_session_start_times.get((format_name, lifecycle.group_id))
        if visible_start is not None:
            canonical_start = ensure_utc(lifecycle.canonical_start)
            canonical_duration = max(_SOURCE_EPSILON, canonical_end - canonical_start)
            earliest = max(earliest, visible_start + canonical_duration)
        if latest is not None:
            earliest = max(
                earliest,
                latest
                + self._sample_profile_delay(
                    event,
                    "windows.logoff_after_rendered_dependents",
                    seed_parts=(format_name, lifecycle.group_id, latest),
                    sample_key="closure_after_dependents",
                ),
            )
        latest_allowed = canonical_end + self.session_closure_tail(format_name)
        if earliest > latest_allowed:
            description = self._latest_session_dependent_descriptions.get(
                (format_name, lifecycle.group_id),
                "",
            )
            raise StateError(
                "Source-visible session dependents exceed the closure tail bound: "
                f"format={format_name} group={lifecycle.group_id} "
                f"start={visible_start.isoformat() if visible_start is not None else ''} "
                f"dependent={earliest.isoformat()} end={canonical_end.isoformat()} "
                f"{description}"
            )
        closure_time = min(max(preferred, earliest), latest_allowed)
        plan.source_times[cache_key] = closure_time
        return closure_time

    def session_start_source_time(
        self,
        format_name: str,
        lifecycle_group_id: str,
    ) -> datetime | None:
        """Return the admitted source-native start time for a session group."""

        return self._latest_session_start_times.get((format_name, lifecycle_group_id))

    def plan_endpoint_session_ready_time(
        self,
        event: TimingOccurrence,
        format_name: str,
        *,
        not_before: datetime,
        relationship_key: str,
    ) -> datetime:
        """Freeze an endpoint login after a bundle-owned native readiness barrier."""

        event = self.initialize_event(event)
        family = _endpoint_format_family(format_name)
        host = event.dst_host or event.src_host
        if host is None:
            raise ValueError("Endpoint session timing requires a projected host")
        hostname = host.hostname
        source_instance = f"{family}:{hostname.casefold()}:session"
        anchor = ensure_utc(not_before)
        if family == "ecar":
            transport_anchor = self._remote_auth_transport_anchor(
                event,
                self._admitted_ecar_remote_transports,
                self._admitted_ecar_transport_transactions,
            )
            if transport_anchor is None and event.event_type == "ssh_session":
                transport_anchor = self._ssh_transport_anchor(event)
            if transport_anchor is not None:
                anchor = max(anchor, transport_anchor)
        window = get_timing_window(
            relationship_key,
            default_min_ms=275,
            default_max_ms=650,
            default_position="after",
            default_class="source_latency",
        )
        timestamp = anchor + self.timing_runtime.sampler.sample_timedelta(
            self._right_skew_distribution(window.min_ms * 1_000, window.max_ms * 1_000 + 1),
            relationship_key=f"{family}.session_after_native_readiness",
            scope=TimingScope(
                stable_id=self._endpoint_event_object_id(event, hostname, "session-ready"),
                host=hostname,
                source=source_instance,
                lifecycle_id=self._endpoint_event_lifecycle_id(event),
            ),
            sample_key=relationship_key,
        )
        plan = self._ensure_plan(event)
        plan.finalized_times[endpoint_event_native_key(format_name, hostname)] = timestamp
        plan.finalized_times[endpoint_event_render_key(format_name, hostname)] = timestamp
        if family == "ecar":
            plan.finalized_times[ecar_session_render_key("login")] = timestamp
        return timestamp

    def record_session_closure_source_time(
        self,
        event: TimingOccurrence,
        format_name: str,
        timestamp: datetime,
    ) -> None:
        """Record a bundle-planned closure time for a source before dispatch."""

        lifecycle = event.lifecycle
        source_key = _SESSION_CLOSURE_SOURCE_KEYS.get(format_name)
        if lifecycle is None or source_key is None:
            return
        plan = self._ensure_plan(event)
        canonical_end = ensure_utc(plan.canonical_timestamp)
        seed_parts = (
            "session-closure",
            format_name,
            lifecycle.group_id,
            getattr(event.auth, "logon_id", ""),
            canonical_end,
        )
        plan.source_times[self._cache_key(source_key, seed_parts)] = ensure_utc(timestamp)

    def _plan_ecar_identity_times(self, event: TimingOccurrence) -> None:
        """Prime stable process-create anchors for eCAR lifecycle consumers.

        Process creation and dependent telemetry are separate canonical events.
        Their independent source-latency samples must still share the exact
        source-visible process-create anchor, including parent-before-child
        ordering. The dispatcher-owned planner retains that cross-event state;
        emitters only consume the timestamp recorded on each event plan.
        """

        identity_plan = event.identity_plan
        if identity_plan is None:
            return
        identities: list[ProcessIdentity] = []
        for identity in (
            identity_plan.subject,
            identity_plan.actor,
            identity_plan.target,
        ):
            if isinstance(identity, ProcessIdentity) and identity not in identities:
                identities.append(identity)
        if not identities:
            return

        subject = (
            identity_plan.subject if isinstance(identity_plan.subject, ProcessIdentity) else None
        )
        parent = (
            identity_plan.actor
            if event.event_type in _PROCESS_START_EVENT_TYPES
            and isinstance(identity_plan.actor, ProcessIdentity)
            else None
        )
        parent_time = self._ecar_process_create_times.get(parent.object_id) if parent else None
        if parent is not None and parent_time is None:
            parent_time = self._prime_ecar_process_create_time(event, parent)
        lifecycle = event.lifecycle
        auth = event.auth
        session_ready_time = None
        if (
            lifecycle is not None
            and lifecycle.parent_group_id
            and auth is not None
            and auth.logon_id not in {"", "-", "0x3e4", "0x3e5", "0x3e7"}
        ):
            session_ready_time = self._latest_session_start_times.get(
                ("ecar", lifecycle.parent_group_id)
            )

        for identity in identities:
            anchor_timestamp = (
                event.timestamp
                if event.event_type in _PROCESS_START_EVENT_TYPES and identity is subject
                else identity.started_at
            )
            not_before = None
            if identity is subject and parent_time is not None:
                not_before = parent_time + self._sample_profile_delay(
                    event,
                    "source.ecar_dependent_after_process_create",
                    seed_parts=(
                        "parent-before-child",
                        parent.object_id,
                        identity.object_id,
                    ),
                    sample_key="parent_before_child",
                )
            if identity is subject and session_ready_time is not None:
                session_floor = session_ready_time + _SOURCE_EPSILON
                not_before = session_floor if not_before is None else max(not_before, session_floor)
            create_time = self._prime_ecar_process_create_time(
                event,
                identity,
                anchor_timestamp=anchor_timestamp,
                not_before=not_before,
            )
            self.record_source_time(
                event,
                "source.ecar_process_create",
                create_time,
                seed_parts=(identity.hostname, identity.pid, identity.started_at),
            )

    def _prime_ecar_process_create_time(
        self,
        event: TimingOccurrence,
        identity: ProcessIdentity,
        *,
        anchor_timestamp: datetime | None = None,
        not_before: datetime | None = None,
    ) -> datetime:
        """Return and retain one source-visible eCAR create time per process object."""

        cached = self._ecar_process_create_times.get(identity.object_id)
        if cached is not None:
            if not_before is not None and cached < not_before:
                self.timing_runtime.audit.record_repair("ecar.process.visibility_floor")
                cached = self._sample_after_floor(
                    not_before,
                    relationship_key="ecar.process.visibility_floor",
                    scope=TimingScope(
                        stable_id=identity.object_id,
                        host=identity.hostname,
                        source=f"ecar:{identity.hostname.casefold()}",
                        lifecycle_id=identity.lifecycle_group_id,
                    ),
                    maximum_us=2_500,
                )
                self._ecar_process_create_times[identity.object_id] = cached
            return cached
        if event.source_timing is not None:
            # Process bundles can pre-plan a hard dependency deadline before
            # identity finalization. Reuse that constrained observation instead
            # of sampling an unconstrained replacement for the same identity.
            planned_key = self._cache_key(
                "source.ecar_process_create",
                (identity.hostname, identity.pid, identity.started_at),
            )
            cached = event.source_timing.source_times.get(planned_key)
            if cached is not None:
                if not_before is not None and cached < not_before:
                    self.timing_runtime.audit.record_repair("ecar.process.visibility_floor")
                    cached = self._sample_after_floor(
                        not_before,
                        relationship_key="ecar.process.visibility_floor",
                        scope=TimingScope(
                            stable_id=identity.object_id,
                            host=identity.hostname,
                            source=f"ecar:{identity.hostname.casefold()}",
                            lifecycle_id=identity.lifecycle_group_id,
                        ),
                        maximum_us=2_500,
                    )
                self._ecar_process_create_times[identity.object_id] = cached
                return cached
        host = next(
            (
                candidate
                for candidate in (event.src_host, event.dst_host)
                if candidate is not None
                and candidate.hostname.casefold() == identity.hostname.casefold()
            ),
            event.src_host or event.dst_host,
        )
        create_time = self._runtime_process_create_time(
            event,
            family="ecar",
            source_key="source.ecar_process_create",
            source_instance=f"ecar:{identity.hostname.casefold()}",
            hostname=identity.hostname,
            os_category=getattr(host, "os_category", "windows"),
            object_id=identity.object_id,
            lifecycle_id=identity.lifecycle_group_id,
            canonical_start=anchor_timestamp or identity.started_at,
        )
        if not_before is not None and create_time < not_before:
            self.timing_runtime.audit.record_repair("ecar.process.visibility_floor")
            create_time = self._sample_after_floor(
                not_before,
                relationship_key="ecar.process.visibility_floor",
                scope=TimingScope(
                    stable_id=identity.object_id,
                    host=identity.hostname,
                    source=f"ecar:{identity.hostname.casefold()}",
                    lifecycle_id=identity.lifecycle_group_id,
                ),
                maximum_us=2_500,
            )
        self._ecar_process_create_times[identity.object_id] = create_time
        return create_time

    def admission_time(self, event: TimingOccurrence, format_name: str) -> datetime:
        """Return the finalized source-visible timestamp used for window admission."""

        from evidenceforge.generation.network_observation import (
            network_observation_owns_format_timing,
        )

        if event.source_timing is not None:
            if format_name in {
                "ecar",
                "windows_event_sysmon",
                "windows_security",
                "windows_event_security",
            }:
                family = _endpoint_format_family(format_name)
                prefix = f"{family}.event."
                endpoint_times = [
                    timestamp
                    for key, timestamp in event.source_timing.finalized_times.items()
                    if key.startswith(prefix) and ".render." in key
                ]
                if endpoint_times:
                    return max(endpoint_times)
            if format_name == "ecar":
                host = event.src_host or event.dst_host
                if (
                    host is not None
                    and event.event_type in _PROCESS_START_EVENT_TYPES | _PROCESS_END_EVENT_TYPES
                ):
                    lifecycle = (
                        "terminate" if event.event_type in _PROCESS_END_EVENT_TYPES else "create"
                    )
                    process_time = event.source_timing.finalized_times.get(
                        ecar_process_render_key(lifecycle, host.hostname)
                    )
                    if process_time is not None:
                        return process_time
                ecar_times = [
                    timestamp
                    for key, timestamp in event.source_timing.finalized_times.items()
                    if key.startswith("ecar.flow.") or key.startswith("ecar.session.")
                ]
                if ecar_times:
                    return max(ecar_times)
            if format_name in {"windows_security", "windows_event_security"}:
                windows_time = event.source_timing.finalized_times.get(
                    "windows.remote_authentication"
                ) or event.source_timing.finalized_times.get(_WINDOWS_WFP_RENDER_KEY)
                if windows_time is not None:
                    return windows_time
            if format_name == "windows_event_sysmon":
                host = event.src_host or event.dst_host
                if (
                    host is not None
                    and event.event_type in _PROCESS_START_EVENT_TYPES | _PROCESS_END_EVENT_TYPES
                ):
                    lifecycle = (
                        "terminate" if event.event_type in _PROCESS_END_EVENT_TYPES else "create"
                    )
                    process_time = event.source_timing.finalized_times.get(
                        sysmon_process_render_key(lifecycle, host.hostname)
                    )
                    if process_time is not None:
                        return process_time
        if network_observation_owns_format_timing(event, format_name):
            prefix = f"{format_name}:"
            source_times = [
                timestamp
                for observation in event.network_observations
                if format_name in observation.visible_formats
                for key, timestamp in observation.source_times
                if key == format_name or key.startswith(prefix)
            ]
            if source_times:
                return max(source_times)
        if format_name == "proxy_access" and event.protocol.proxy is not None:
            transaction = event.protocol.proxy.transaction
            if transaction is not None:
                return transaction.request_at
        if format_name == "zeek_http" and event.protocol.http is not None:
            request_time = event.protocol.http.canonical_request_time
            if request_time is not None:
                observation = next(
                    (
                        candidate
                        for candidate in event.network_observations
                        if format_name in candidate.visible_formats
                    ),
                    None,
                )
                if observation is not None:
                    return observation.observed_start_time + (request_time - event.timestamp)
                return request_time
        if event.network_observations:
            observed = [
                observation.observed_start_time
                for observation in event.network_observations
                if format_name in observation.visible_formats
            ]
            if observed:
                return min(observed)
        return event.timestamp

    def source_time(
        self,
        event: TimingOccurrence,
        source_key: str,
        seed_parts: tuple[Any, ...] = (),
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        within: tuple[datetime, datetime] | None = None,
    ) -> datetime:
        """Return a deterministic source timestamp for ``event``.

        The sampled profile gives the source's preferred observation time; the
        optional bounds then clamp it so declared causal relationships cannot be
        inverted by jitter. If bounds conflict, the lower bound wins because
        preserving causality is more important than preserving a sampled delay.
        """
        active = _ACTIVE_SOURCE_TIMING_PREPARATION.get()
        if type(active) is SourceTimingPreparation and active._owner is self:
            return active.source_time(
                event,
                source_key,
                seed_parts=seed_parts,
                not_before=not_before,
                not_after=not_after,
                within=within,
            )
        self._require_public_planning_entry()
        plan = self._ensure_plan(event)
        effective_seed = seed_parts or self._event_seed_parts(event)
        cache_key = self._cache_key(source_key, effective_seed)
        preferred_time = plan.source_times.get(cache_key)
        if preferred_time is None:
            preferred_time = self._sample_source_time(event, source_key, effective_seed)
        if not_before is not None and preferred_time < not_before:
            preferred_time = self._source_floor_repair_time(
                event,
                source_key,
                effective_seed,
                not_before,
            )
        constrained_time = self._apply_constraints(
            preferred_time,
            not_before=not_before,
            not_after=not_after,
            within=within,
        )
        plan.source_times[cache_key] = constrained_time
        return constrained_time

    def packet_child_time(
        self,
        event: TimingOccurrence,
        source_key: str,
        *,
        seed_parts: tuple[Any, ...] = (),
        preferred_time: datetime | None = None,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        within: tuple[datetime, datetime] | None = None,
    ) -> datetime:
        """Return a packet-derived child timestamp with sub-millisecond texture."""
        effective_seed = seed_parts or self._event_seed_parts(event)
        base_time = preferred_time or self.source_time(
            event,
            source_key,
            seed_parts=effective_seed,
            not_before=not_before,
            not_after=not_after,
            within=within,
        )
        host = event.src_host or event.dst_host
        hostname = str(getattr(host, "hostname", "") or "")
        lifecycle_id = event.lifecycle.group_id if event.lifecycle is not None else ""
        noise = self.timing_runtime.sampler.sample_timedelta(
            self._right_skew_distribution(36, 998),
            relationship_key="source.packet_child_micro_noise",
            scope=TimingScope(
                stable_id=self._cache_key(
                    f"packet-child-texture:{source_key}",
                    effective_seed,
                ),
                host=hostname,
                source=source_key,
                lifecycle_id=lifecycle_id,
            ),
            sample_key="packet_child",
        )
        return self._apply_constraints(
            base_time + noise,
            not_before=not_before,
            not_after=not_after,
            within=within,
        )

    def process_module_source_time(
        self,
        event: TimingOccurrence,
        format_name: str,
        process_create_time: datetime,
    ) -> datetime:
        """Place a module observation after its source-visible process creation."""
        process = event.process
        image_load = event.image_load
        if process is None or image_load is None:
            return event.timestamp

        seed_parts = (
            format_name,
            getattr(event.src_host, "hostname", ""),
            process.pid,
            process.start_time,
            image_load.image_loaded,
            image_load.load_phase,
            image_load.load_order,
        )
        if image_load.load_phase == "startup":
            order = max(1, image_load.load_order)
            timing = startup_module_observation_timing()
            hostname = getattr(event.src_host, "hostname", "")
            stable_id = (
                f"{format_name}:{hostname}:{process.pid}:"
                f"{process.start_time.isoformat() if process.start_time is not None else ''}"
            )
            scope = TimingScope(
                stable_id=stable_id,
                host=hostname,
                source=format_name,
                lifecycle_id=f"process:{hostname}:{process.pid}",
            )
            elapsed = self.timing_runtime.sampler.sample_timedelta(
                TriangularDistribution(
                    timing.initial_delay_min_us,
                    timing.initial_delay_min_us
                    + (timing.initial_delay_max_us - timing.initial_delay_min_us) * 0.3,
                    timing.initial_delay_max_us,
                ),
                relationship_key="endpoint.module.startup_initial_delay",
                scope=scope,
                sample_key="initial",
            )
            for module_index in range(1, order):
                elapsed += self.timing_runtime.sampler.sample_timedelta(
                    TruncatedLognormalDistribution(
                        median=timing.inter_load_gap_median_us,
                        sigma=timing.inter_load_gap_sigma,
                        minimum=timing.inter_load_gap_min_us,
                        maximum=timing.inter_load_gap_max_us,
                    ),
                    relationship_key="endpoint.module.startup_inter_load_gap",
                    scope=replace(scope, ordinal=module_index),
                    sample_key="gap",
                )
            return process_create_time + elapsed

        source_key = (
            "source.ecar_dependent_after_process_create"
            if format_name == "ecar"
            else "source.sysmon_module_after_process_create"
        )
        return self.source_time(
            event,
            source_key,
            seed_parts=seed_parts,
            not_before=max(event.timestamp, process_create_time + _SOURCE_EPSILON),
        )

    def lifecycle_child_source_time(
        self,
        event: TimingOccurrence,
        source_key: str,
        *,
        host_key: str,
        seed_parts: tuple[Any, ...] = (),
        within: tuple[datetime, datetime] | None = None,
    ) -> datetime | None:
        """Return a coherent host-local timestamp for one nested action child.

        Independent source-latency samples can invert sibling transports that are
        phases of one higher-level action (for example proxy ingress followed by
        proxy-origin egress). Nested children on the same host therefore share a
        small, deterministic observation offset from each child's canonical start.
        The offset stays source-owned and preserves the action bundle's phase gaps.
        """

        lifecycle = event.lifecycle
        if lifecycle is None or lifecycle.parent_group_id is None:
            return None
        network = event.network
        if network is None:
            return None

        parent_group_id = lifecycle.parent_group_id
        anchor = network.started_at
        effective_seed = seed_parts or self._event_seed_parts(event)
        cache_seed = ("lifecycle-child", parent_group_id, host_key, *effective_seed)
        cache_key = self._cache_key(source_key, cache_seed)
        plan = self._ensure_plan(event)
        cached = plan.source_times.get(cache_key)
        if cached is not None:
            return cached

        observation_offset = self.timing_runtime.sampler.sample_timedelta(
            self._right_skew_distribution(249, 1_001),
            relationship_key="source.lifecycle_child_observation_offset",
            scope=TimingScope(
                stable_id=f"lifecycle-child:{parent_group_id}",
                host=host_key,
                source=source_key,
                lifecycle_id=parent_group_id,
            ),
            sample_key="shared_offset",
        )
        preferred_time = anchor + observation_offset
        constrained_time = self._apply_constraints(
            preferred_time,
            not_before=None,
            not_after=None,
            within=within,
        )
        plan.source_times[cache_key] = constrained_time
        return constrained_time

    def record_source_time(
        self,
        event: TimingOccurrence,
        source_key: str,
        timestamp: datetime,
        seed_parts: tuple[Any, ...] = (),
    ) -> None:
        """Record a finalized source timestamp for later correlated renderers.

        Some emitters perform source-native ordering repairs that depend on
        previously rendered rows from the same log. Once an emitter has chosen
        that final timestamp, downstream correlated sources should reuse it
        instead of recomputing the pre-repair preferred time.
        """
        plan = self._ensure_plan(event)
        effective_seed = seed_parts or self._event_seed_parts(event)
        plan.source_times[self._cache_key(source_key, effective_seed)] = timestamp

    def source_time_after_source(
        self,
        event: TimingOccurrence,
        source_key: str,
        *,
        after_source_key: str,
        gap_key: str,
        seed_parts: tuple[Any, ...] = (),
        after_seed_parts: tuple[Any, ...] = (),
        after_not_before: datetime | None = None,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        within: tuple[datetime, datetime] | None = None,
    ) -> datetime:
        """Return a source timestamp constrained after another source observation."""
        effective_seed = seed_parts or self._event_seed_parts(event)
        anchor_seed = after_seed_parts or effective_seed

        anchor_cache_key = self._cache_key(after_source_key, anchor_seed)
        source_cache_key = self._cache_key(source_key, effective_seed)
        graph = TemporalConstraintGraph(
            timing_runtime=self.timing_runtime,
            scope=TimingScope(
                stable_id=f"source-constraint:{self._cache_key(source_key, effective_seed)}",
                source=source_key,
                lifecycle_id=self._cache_key(after_source_key, anchor_seed),
            ),
            relationship_key="source.constraint.repair",
        )
        graph.add_node(
            "anchor",
            self._preferred_source_time(event, after_source_key, anchor_seed),
            not_before=after_not_before,
        )
        graph.add_node(
            "source",
            self._preferred_source_time(event, source_key, effective_seed),
            not_before=not_before,
            not_after=not_after,
            within=within,
        )
        graph.constrain_after(
            "source",
            "anchor",
            min_gap=self._sample_profile_delay(
                event,
                gap_key,
                seed_parts=effective_seed,
                sample_key="constraint_gap",
            ),
        )
        resolved = graph.resolve()

        plan = self._ensure_plan(event)
        plan.source_times[anchor_cache_key] = resolved["anchor"]
        plan.source_times[source_cache_key] = resolved["source"]
        return resolved["source"]

    def ordered_pair(
        self,
        before_event: TimingOccurrence,
        after_event: TimingOccurrence,
        source_key: str,
        min_gap_ms: int = 1,
    ) -> tuple[datetime, datetime]:
        """Plan a same-source causal pair such that ``before < after``."""
        gap = max(timedelta(milliseconds=max(1, min_gap_ms)), _SOURCE_EPSILON)
        before_seed = ("ordered-before", *self._event_seed_parts(before_event))
        after_seed = ("ordered-after", *self._event_seed_parts(after_event))

        graph = TemporalConstraintGraph(
            timing_runtime=self.timing_runtime,
            scope=TimingScope(
                stable_id=f"ordered-pair:{self._cache_key(source_key, before_seed)}",
                source=source_key,
                lifecycle_id=self._cache_key(source_key, after_seed),
            ),
            relationship_key="source.ordered_pair.repair",
        )
        graph.add_node(
            "before",
            self._preferred_source_time(before_event, source_key, before_seed),
        )
        graph.add_node(
            "after",
            self._preferred_source_time(after_event, source_key, after_seed),
        )
        graph.constrain_after("after", "before", min_gap=gap)
        resolved = graph.resolve()

        before_time = resolved["before"]
        after_time = resolved["after"]
        self._ensure_plan(before_event).source_times[self._cache_key(source_key, before_seed)] = (
            before_time
        )
        self._ensure_plan(after_event).source_times[self._cache_key(source_key, after_seed)] = (
            after_time
        )
        return before_time, after_time

    def sensor_observation_time(
        self,
        event: TimingOccurrence,
        sensor: str,
        route_key: str,
        source_key: str,
    ) -> datetime:
        """Return a runtime-owned source-instance sensor timestamp."""

        del source_key
        from evidenceforge.generation.network_observation import NetworkObservationPlanner

        timing = network_sensor_observation_timing()
        observed_at = ensure_utc(event.timestamp)
        key = NetworkObservationPlanner._sensor_clock_key(sensor, timing.profile_name)
        spec = NetworkObservationPlanner._sensor_clock_spec(timing)
        projected = self.timing_runtime.clocks.project(observed_at, key=key, spec=spec)
        scope = TimingScope(
            stable_id=str(route_key),
            source=sensor.casefold(),
            lifecycle_id=str(route_key),
        )
        route_delay = self.timing_runtime.sampler.sample_timedelta(
            NetworkObservationPlanner._right_skew_distribution(
                timing.route_delay_min_us,
                timing.route_delay_max_us,
            ),
            relationship_key="network.sensor.route_delay",
            scope=scope,
            sample_key="compatibility",
        )
        return projected + route_delay

    def canonical_time_in_source_clock(
        self,
        event: TimingOccurrence,
        source_key: str,
        canonical_time: datetime,
        seed_parts: tuple[Any, ...] = (),
    ) -> datetime:
        """Translate a canonical causal bound into one endpoint source's clock frame."""

        effective_seed = seed_parts or self._event_seed_parts(event)
        return canonical_time + self._endpoint_clock_adjustment(
            event,
            source_key,
            effective_seed,
        )

    def _ensure_plan(self, event: TimingOccurrence) -> SourceTimingPlan:
        """Attach and return a mutable source timing plan for ``event``."""
        if event.source_timing is None:
            if not isinstance(event, OccurrenceBuilder):
                raise RuntimeError("Sealed occurrences require source timing initialization")
            event.source_timing = SourceTimingPlan(
                canonical_timestamp=event.timestamp,
                clock_profile_name=self.clock_profile_name,
            )
        elif not event.source_timing.clock_profile_name:
            event.source_timing.clock_profile_name = self.clock_profile_name
        return event.source_timing

    def _sample_source_time(
        self,
        event: TimingOccurrence,
        source_key: str,
        seed_parts: tuple[Any, ...],
    ) -> datetime:
        """Sample the preferred source timestamp from timing profiles."""
        window = get_timing_window(
            source_key,
            default_min_ms=0,
            default_max_ms=0,
            default_position="after",
        )
        if source_key == "source.ecar_process_create":
            delta = self._coherent_ecar_process_create_latency(event, source_key)
        else:
            delta = self._sample_profile_delay(
                event,
                source_key,
                seed_parts=seed_parts,
                sample_key="source_delay",
            )
        micro_noise = (
            self._source_micro_noise(event, source_key, seed_parts)
            if window.relationship_class == "same_observation"
            and source_key != "source.zeek_conn_start"
            else timedelta(0)
        )
        canonical_time = event.timestamp
        if window.position == "before":
            source_time = canonical_time - delta - micro_noise
        else:
            source_time = canonical_time + delta + micro_noise
        return source_time + self._endpoint_clock_adjustment(event, source_key, seed_parts)

    def _coherent_ecar_process_create_latency(
        self,
        event: TimingOccurrence,
        source_key: str,
    ) -> timedelta:
        """Return runtime-owned coherent eCAR process observation latency.

        Independent per-process latency samples can visibly reorder successive
        process creates even when their canonical starts and PIDs are ordered.
        The shared runtime's source-local queue knots keep that latency coherent
        without a separate stable-seed timing implementation.
        """

        host = event.src_host or event.dst_host
        hostname = str(getattr(host, "hostname", "") or "unknown-host")
        process = event.process
        identity = self._subject_process_identity(event)
        if process is not None:
            started_at = process.start_time or self._ensure_plan(event).canonical_timestamp
            object_id, lifecycle_id = self._process_scope_ids(
                event,
                identity,
                hostname=hostname,
                pid=process.pid,
                started_at=started_at,
            )
        else:
            object_id = self._endpoint_event_object_id(event, hostname, "process_create")
            lifecycle_id = self._endpoint_event_lifecycle_id(event)
        return self._coherent_runtime_latency(
            source_key,
            canonical_time=self._ensure_plan(event).canonical_timestamp,
            source_instance=f"ecar:{hostname.casefold()}:host-agent",
            hostname=hostname,
            object_id=object_id,
            lifecycle_id=lifecycle_id,
            phase="create",
        )

    def _preferred_source_time(
        self,
        event: TimingOccurrence,
        source_key: str,
        seed_parts: tuple[Any, ...],
    ) -> datetime:
        """Return cached or sampled preferred source time before graph constraints."""

        plan = self._ensure_plan(event)
        cache_key = self._cache_key(source_key, seed_parts)
        preferred_time = plan.source_times.get(cache_key)
        if preferred_time is not None:
            return preferred_time
        return self._sample_source_time(event, source_key, seed_parts)

    def _endpoint_clock_adjustment(
        self,
        event: TimingOccurrence,
        source_key: str,
        seed_parts: tuple[Any, ...],
    ) -> timedelta:
        """Return shared host-clock adjustment for host-resident endpoint sources."""
        scope = self._endpoint_clock_scope(event, source_key, seed_parts)
        if scope is None:
            return timedelta(0)
        host_key, os_category = scope
        return self.endpoint_clock_adjustment_for_host(
            hostname=host_key,
            os_category=os_category,
            timestamp=event.timestamp,
        )

    def endpoint_clock_adjustment_for_host(
        self,
        *,
        hostname: str,
        os_category: str,
        timestamp: datetime,
    ) -> timedelta:
        """Return the active profile's deterministic clock adjustment for one host."""

        if not hostname or os_category not in {"windows", "linux"}:
            return timedelta(0)
        projected = self._runtime_endpoint_clock_time(
            timestamp,
            hostname=hostname,
            os_category=os_category,
        )
        return projected - ensure_utc(timestamp)

    @staticmethod
    def _endpoint_clock_scope(
        event: TimingOccurrence,
        source_key: str,
        seed_parts: tuple[Any, ...],
    ) -> tuple[str, str] | None:
        """Return ``(host, os_category)`` for endpoint sources, else ``None``."""
        if source_key.startswith(("source.zeek_", "network.")):
            return None
        if source_key.startswith(("source.windows_", "source.sysmon_")):
            host = event.src_host or event.dst_host
            hostname = getattr(host, "hostname", "") or ""
            return (hostname, "windows") if hostname else None
        if source_key.startswith("source.ecar_"):
            direction = str(seed_parts[0]).lower() if seed_parts else ""
            if source_key == "source.ecar_flow" and direction == "inbound":
                host = event.dst_host or event.src_host
            else:
                host = event.src_host or event.dst_host
            hostname = getattr(host, "hostname", "") or ""
            os_category = getattr(host, "os_category", "") or ""
            if os_category not in {"windows", "linux"}:
                return None
            return (hostname, os_category) if hostname else None
        if source_key.startswith(("source.syslog_", "source.bash_history_")):
            host = event.src_host or event.dst_host
            hostname = getattr(host, "hostname", "") or ""
            return (hostname, "linux") if hostname else None
        return None

    def _source_micro_noise(
        self,
        event: TimingOccurrence,
        source_key: str,
        seed_parts: tuple[Any, ...],
    ) -> timedelta:
        """Return runtime-owned sub-millisecond texture for packet-like source rows."""

        host = event.src_host or event.dst_host
        hostname = str(getattr(host, "hostname", "") or "")
        lifecycle_id = event.lifecycle.group_id if event.lifecycle is not None else ""
        return self.timing_runtime.sampler.sample_timedelta(
            self._right_skew_distribution(36, 998),
            relationship_key="source.same_observation_micro_noise",
            scope=TimingScope(
                stable_id=self._cache_key(
                    f"source-micro-noise:{source_key}",
                    seed_parts,
                ),
                host=hostname,
                source=source_key,
                lifecycle_id=lifecycle_id,
            ),
            sample_key="micro_noise",
        )

    def _source_floor_repair_time(
        self,
        event: TimingOccurrence,
        source_key: str,
        seed_parts: tuple[Any, ...],
        lower_bound: datetime,
    ) -> datetime:
        """Keep clamped process-create sources source-native after a shared floor."""
        if source_key not in _PROCESS_CREATE_SOURCE_KEYS:
            return lower_bound
        if source_key == "source.ecar_process_create":
            delay = self._coherent_ecar_process_create_latency(event, source_key)
        else:
            delay = self._sample_profile_delay(
                event,
                source_key,
                seed_parts=("floor-repair", source_key, *seed_parts),
                sample_key="floor_repair",
            )
        return lower_bound + max(delay, _SOURCE_EPSILON)

    @staticmethod
    def _apply_constraints(
        preferred_time: datetime,
        *,
        not_before: datetime | None,
        not_after: datetime | None,
        within: tuple[datetime, datetime] | None,
    ) -> datetime:
        """Clamp preferred time to hard causal bounds."""
        lower = not_before
        upper = not_after
        if within is not None:
            start, end = within
            lower = start if lower is None else max(lower, start)
            upper = end if upper is None else min(upper, end)
        if lower is not None and upper is not None and upper < lower:
            return lower
        result = preferred_time
        if lower is not None and result < lower:
            result = lower
        if upper is not None and result > upper:
            result = upper
        return result

    @staticmethod
    def _cache_key(source_key: str, seed_parts: tuple[Any, ...]) -> str:
        """Build a deterministic cache key for a source observation."""
        return source_key + "|" + "|".join(str(part) for part in seed_parts)

    @staticmethod
    def _event_seed_parts(event: TimingOccurrence) -> tuple[Any, ...]:
        """Return stable content-derived identity parts for a OccurrenceBuilder."""
        net = event.network
        proc = event.process
        auth = event.auth
        krb = event.kerberos
        identity = event.identity_plan
        return (
            event.event_type,
            event.timestamp.isoformat(),
            getattr(event.src_host, "hostname", ""),
            getattr(event.dst_host, "hostname", ""),
            getattr(proc, "pid", ""),
            getattr(proc, "start_time", ""),
            getattr(net, "zeek_uid", ""),
            getattr(net, "src_ip", ""),
            getattr(net, "src_port", ""),
            getattr(net, "dst_ip", ""),
            getattr(net, "dst_port", ""),
            getattr(auth, "logon_id", ""),
            getattr(krb, "service_name", ""),
            getattr(krb, "source_ip", ""),
            getattr(krb, "source_port", ""),
            identity.object_id if identity is not None else "",
            event.storyline_cluster_id or "",
        )


class SourceTimingPreparation:
    """Authenticated copy-on-write planner and runtime transaction."""

    __slots__ = (
        "__weakref__",
        "_binding_token",
        "_cache_overlays",
        "_claim_thread_id",
        "_commit_state_digest",
        "_committed_receipt",
        "_composite_certified_receipt",
        "_context_closed",
        "_expected_receipt",
        "_lane_active",
        "_lane_marker",
        "_overlay_planner",
        "_owner",
        "_planning_thread_id",
        "_planning_runtime",
        "_runtime_preparation",
        "_seal_integrity",
        "_sealed_overlay_digest",
        "_state",
        "_watermark",
    )

    def __init__(
        self,
        owner: SourceTimingPlanner,
        *,
        preparation_id: int,
        lane_marker: object,
    ) -> None:
        self._owner = owner
        self._planning_thread_id = get_ident()
        self._lane_marker = lane_marker
        self._lane_active = True
        self._watermark = owner._watermark
        self._runtime_preparation: TimingRuntimePreparation | None = (
            owner.timing_runtime._prepared_for_owner(lane_marker)
        )
        runtime_preparation = self._runtime_preparation
        self._planning_runtime = SourceTimingPlanningRuntime(self)
        cache_overlays: list[tuple[str, _SourceTimingCache, _PreparedSourceTimingCache]] = []
        cache_by_identity: dict[int, _PreparedSourceTimingCache] = {}
        for name, cache in owner._bounded_indexes():
            prepared_cache = _PreparedSourceTimingCache(cache)
            cache_overlays.append((name, cache, prepared_cache))
            cache_by_identity[id(cache)] = prepared_cache
        self._cache_overlays = tuple(cache_overlays)

        overlay_planner = object.__new__(SourceTimingPlanner)
        overlay_planner.__dict__ = owner.__dict__.copy()
        overlay_planner._isolate_preparation_authority_for_overlay()
        overlay_planner.timing_runtime = runtime_preparation
        for attribute, value in tuple(overlay_planner.__dict__.items()):
            prepared_cache = cache_by_identity.get(id(value))
            if prepared_cache is not None:
                setattr(overlay_planner, attribute, prepared_cache)
        self._overlay_planner = overlay_planner

        base_state_digest = owner.state_digest()
        integrity = owner._preparation_token_integrity(preparation_id, base_state_digest)
        self._binding_token = SourceTimingPreparationToken(
            preparation_id=preparation_id,
            base_state_digest=base_state_digest,
            _integrity=integrity,
        )
        self._state = "open"
        self._context_closed = False
        self._sealed_overlay_digest = ""
        self._seal_integrity = ""
        self._commit_state_digest = ""
        self._expected_receipt: SourceTimingPreparationReceipt | None = None
        self._committed_receipt: SourceTimingPreparationReceipt | None = None
        self._composite_certified_receipt: SourceTimingPreparationReceipt | None = None
        self._claim_thread_id: int | None = None
        runtime_preparation._source_timing_owner = self

    @property
    def owner(self) -> SourceTimingPlanner:
        """Return the exact planner that issued this preparation."""

        return self._owner

    @property
    def planning_runtime(self) -> SourceTimingPlanningRuntime:
        """Return a non-owning view of the open staged timing runtime."""

        if not self._owner.is_active_preparation(self):
            raise StateError("Source timing preparation is not open for planning")
        return self._planning_runtime

    @property
    def binding_token(self) -> SourceTimingPreparationToken:
        """Return the stable token shared across related prepared dispatches."""

        return self._binding_token

    @property
    def committed(self) -> bool:
        """Return whether the staged timing state committed once."""

        owner = self._owner
        if type(owner) is not SourceTimingPlanner:
            return False
        record = owner._active_preparation_claim_record(self)
        return record is not None and record.state == "committed"

    @property
    def sealed(self) -> bool:
        """Return whether staging is closed and integrity-authenticated."""

        return self._state in {"sealed", "claimed", "committed"}

    @property
    def receipt(self) -> SourceTimingPreparationReceipt | None:
        """Return the authenticated commit receipt after successful publication."""

        owner = self._owner
        if type(owner) is not SourceTimingPlanner:
            return None
        record = owner._active_preparation_claim_record(self)
        if record is None or record.state != "committed":
            return None
        return record.expected_receipt

    @property
    def expected_receipt(self) -> SourceTimingPreparationReceipt:
        """Return the exact immutable receipt sealed by the active claim."""

        owner = self._owner
        if type(owner) is not SourceTimingPlanner:
            raise StateError("Source timing preparation has no active expected receipt")
        record = owner._active_preparation_claim_record(self)
        if record is None or record.state not in {"claimed", "certified", "committed"}:
            raise StateError("Source timing preparation has no active expected receipt")
        return record.expected_receipt

    @property
    def staged_cache_operations(self) -> int:
        """Return bounded staged cache mutations without scanning canonical state."""

        return sum(len(prepared.operations) for _name, _cache, prepared in self._cache_overlays)

    @property
    def staged_audit_operations(self) -> int:
        """Return staged audit mutations."""

        runtime_preparation = self._runtime_preparation
        return 0 if runtime_preparation is None else len(runtime_preparation.audit.operations)

    @property
    def overlay_digest(self) -> str:
        """Return the authenticated overlay digest after normal context exit."""

        return self._sealed_overlay_digest

    def census(self) -> SourceTimingPreparationCensus:
        """Return constant-time staged retention and clock-capacity diagnostics."""

        runtime_preparation = self._runtime_preparation
        clock_census = (
            runtime_preparation.clocks.census() if runtime_preparation is not None else None
        )
        return SourceTimingPreparationCensus(
            state=self._state,
            cache_family_count=len(self._cache_overlays),
            staged_cache_keys=sum(
                prepared.staged_keys for _name, _cache, prepared in self._cache_overlays
            ),
            staged_cache_operations=self.staged_cache_operations,
            staged_audit_operations=self.staged_audit_operations,
            clock_live_entries=clock_census.live_entries if clock_census is not None else 0,
            clock_capacity=clock_census.capacity if clock_census is not None else 0,
        )

    def plan_event(
        self,
        event: TimingOccurrence,
        format_name: str | None = None,
        *,
        observation_delay: timedelta = timedelta(0),
        source_instance: str = "",
        source_hostname: str = "",
        projection_role: str = "",
        output_end_time: datetime | None = None,
    ) -> TimingOccurrence:
        """Plan one event against canonical plus staged timing state."""

        if not self._owner.is_active_preparation(self):
            raise StateError("Source timing preparation is sealed and cannot stage more events")
        return self._overlay_planner.plan_event(
            event,
            format_name,
            observation_delay=observation_delay,
            source_instance=source_instance,
            source_hostname=source_hostname,
            projection_role=projection_role,
            output_end_time=output_end_time,
        )

    def source_time(
        self,
        event: TimingOccurrence,
        source_key: str,
        seed_parts: tuple[Any, ...] = (),
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        within: tuple[datetime, datetime] | None = None,
    ) -> datetime:
        """Sample one direct source relationship against the staged runtime."""

        if not self._owner.is_active_preparation(self):
            raise StateError("Source timing preparation is sealed and cannot stage more events")
        return self._overlay_planner.source_time(
            event,
            source_key,
            seed_parts=seed_parts,
            not_before=not_before,
            not_after=not_after,
            within=within,
        )

    def record_admitted_source_event(
        self,
        event: TimingOccurrence,
        format_name: str,
    ) -> None:
        """Stage one admitted-source index update in this preparation's overlay."""

        if not self._owner.is_active_preparation(self):
            raise StateError("Source timing preparation is sealed and cannot stage admitted events")
        self._overlay_planner.record_admitted_source_event(event, format_name)

    def seal(self) -> None:
        """Authenticate the final overlay while leaving canonical state untouched."""

        if self._planning_thread_id != get_ident():
            raise StateError("Source timing preparation must seal on its planning thread")
        if self._state == "sealed":
            return
        if self._state != "open":
            raise StateError(f"Source timing preparation cannot seal from {self._state!r}")
        overlay_digest = self._current_overlay_digest()
        binding_token, seal_integrity = self._owner._seal_preparation_lane_generation(
            self,
            overlay_digest,
        )
        self._binding_token = binding_token
        self._sealed_overlay_digest = overlay_digest
        self._seal_integrity = seal_integrity
        self._state = "sealed"
        self._context_closed = True

    def _freeze_claim_record(
        self,
        *,
        owner: SourceTimingPlanner,
        generation: _SourceTimingLaneGenerationRecord,
        claim_thread_id: int,
        binding_token: SourceTimingPreparationToken,
        cache_overlays: tuple[tuple[str, _SourceTimingCache, _PreparedSourceTimingCache], ...],
        runtime_preparation: TimingRuntimePreparation,
        sealed_overlay_digest: str,
        seal_integrity: str,
        commit_state_digest: str,
        expected_receipt: SourceTimingPreparationReceipt,
    ) -> _SourceTimingClaimRecord:
        """Freeze only staged deltas and prebuilt clock state before yielding."""

        cache_plans: list[_SourceTimingCacheCommitPlan] = []
        for _name, cache, prepared in cache_overlays:
            operations = tuple(
                _PreparedCacheOperation(
                    kind=operation.kind,
                    key=operation.key,
                    value=operation.value,
                    deadline_seconds=operation.deadline_seconds,
                )
                for operation in prepared.operations
            )
            cache_plans.append(
                _SourceTimingCacheCommitPlan(
                    target=cache,
                    operations=operations,
                    lookup_candidate_delta=prepared.lookup_candidate_delta,
                    version_delta=prepared.version_delta,
                )
            )

        runtime_base = runtime_preparation._base
        audit_target = runtime_base.audit
        audit_operations = tuple(
            tuple(operation) for operation in runtime_preparation.audit.operations
        )
        clocks_target = runtime_base.clocks
        prepared_clocks = runtime_preparation.clocks
        runtime_plan = _SourceTimingRuntimeCommitPlan(
            preparation=runtime_preparation,
            audit_target=audit_target,
            audit_operations=audit_operations,
            clocks_target=clocks_target,
            clock_states=prepared_clocks._states,
            discarded_clock_states=prepared_clocks._states.__class__(),
            clock_high_water_mark=prepared_clocks._high_water_mark,
            clock_cache_entry_estimated_bytes=(prepared_clocks._cache_entry_estimated_bytes),
            clock_lookup_count=prepared_clocks._lookup_count,
            clock_cache_hit_count=prepared_clocks._cache_hit_count,
            clock_cache_miss_count=prepared_clocks._cache_miss_count,
            clock_eviction_count=prepared_clocks._eviction_count,
            clock_mutation_version=(
                clocks_target._mutation_version + prepared_clocks._version_delta
            ),
        )
        receipt_authority = owner._retain_expected_preparation_receipt(
            expected_receipt,
            generation_marker=generation.generation_marker,
        )
        preparation_id = id(self)
        owner_ref = ref(owner)

        def remove_collected(
            preparation_ref: ReferenceType[SourceTimingPreparation],
        ) -> None:
            canonical_owner = owner_ref()
            if canonical_owner is not None:
                canonical_owner._preparation_carrier_collected(
                    preparation_id,
                    preparation_ref,
                )

        return _SourceTimingClaimRecord(
            preparation_id=preparation_id,
            preparation_ref=ref(self, remove_collected),
            owner=owner,
            claim_thread_id=claim_thread_id,
            lane_marker=generation.lane_marker,
            lane_epoch=generation.lane_epoch,
            generation_marker=generation.generation_marker,
            base_watermark=self._watermark,
            binding_token=binding_token,
            sealed_overlay_digest=sealed_overlay_digest,
            seal_integrity=seal_integrity,
            commit_state_digest=commit_state_digest,
            expected_receipt=expected_receipt,
            receipt_authority=receipt_authority,
            admitted_cache_overlays=cache_overlays,
            admitted_runtime_preparation=runtime_preparation,
            cache_plans=tuple(cache_plans),
            runtime_plan=runtime_plan,
            retained_plan_operations=(
                sum(len(plan.operations) for plan in cache_plans)
                + len(audit_operations)
                + len(prepared_clocks._operations)
            ),
        )

    def _release_owner_lane(self) -> None:
        """Release this exact planner/runtime lane once cleanup is complete."""

        if not self._lane_active:
            return
        self._owner._release_preparation_lane(self, self._lane_marker)
        self._lane_active = False

    def _discard_staged_payload(self) -> None:
        """Discard bulky staged state once it can no longer be published."""

        for _name, _cache, prepared in self._cache_overlays:
            prepared._operations.clear()
            prepared._overlay.clear()
        runtime_preparation = self._runtime_preparation
        if runtime_preparation is not None:
            runtime_preparation._source_timing_owner = None
            runtime_preparation.audit._operations.clear()
            runtime_preparation.clocks._states.clear()
            runtime_preparation.clocks._operations.clear()
            runtime_preparation.clocks._cache_entry_estimated_bytes = 0
        self._cache_overlays = ()
        self._runtime_preparation = None
        self._overlay_planner = None
        self._planning_runtime = None

    def cancel(self) -> None:
        """Discard an uncommitted overlay with exact zero canonical residue."""

        owner = self._owner
        if (
            type(owner) is SourceTimingPlanner
            and owner._active_preparation_claim_record(self) is not None
        ):
            raise StateError("Claimed source timing preparation cannot cancel directly")
        if self._state == "cancelled":
            return
        if self._state == "committed":
            raise StateError("Committed source timing preparation cannot cancel")
        if self._planning_thread_id != get_ident():
            raise StateError("Source timing preparation must cancel on its planning thread")
        if (
            type(owner) is not SourceTimingPlanner
            or not self._lane_active
            or owner._preparation_lane is not self
            or owner._preparation_lane_marker is not self._lane_marker
        ):
            raise StateError("Source timing preparation is not the exact active owner")
        runtime_preparation = self._runtime_preparation
        if runtime_preparation is not None:
            runtime_preparation.cancel()
        self._discard_staged_payload()
        self._expected_receipt = None
        self._composite_certified_receipt = None
        self._state = "cancelled"
        self._context_closed = True
        self._release_owner_lane()

    @contextmanager
    def claimed_commit(self) -> Iterator[SourceTimingPreparation]:
        """Claim timing locks before State/Lifecycle and expose a no-fail callback."""

        owner = self._owner
        if type(owner) is not SourceTimingPlanner:
            raise StateError("Source timing preparation owner is malformed")
        if self._state != "sealed":
            raise StateError("Source timing preparation must be sealed before claim")
        if self._planning_thread_id != get_ident():
            raise StateError("Source timing preparation must claim on its planning thread")
        sealed = owner._snapshot_sealed_preparation_for_detach(self)
        if sealed is None:
            raise StateError("Source timing preparation integrity check failed")
        public_snapshot, generation = sealed

        preparation_lock = owner._preparation_lock
        watermark = self._watermark
        cache_overlays = self._cache_overlays
        runtime_preparation = self._runtime_preparation
        if (
            runtime_preparation is None
            or not self._lane_active
            or owner._preparation_lane is not self
            or owner._preparation_lane_marker is not self._lane_marker
        ):
            raise StateError("Source timing preparation owner lane is not active")
        binding_token = generation.token_facts.token
        sealed_overlay_digest = generation.overlay_digest
        seal_integrity = generation.seal_integrity
        preparation_lock.acquire()
        acquired_cache_locks: list[RLock] = []
        runtime_claimed = False
        runtime_audit_lock = runtime_preparation._base.audit._lock
        runtime_clock_lock = runtime_preparation._base.clocks._lock
        expected_receipt: SourceTimingPreparationReceipt | None = None
        record: _SourceTimingClaimRecord | None = None
        try:
            if owner._watermark != watermark:
                raise StateError("Source timing preparation is stale after watermark advance")
            for _name, cache, prepared in cache_overlays:
                cache_lock = cache._lock
                cache_lock.acquire()
                acquired_cache_locks.append(cache_lock)
                if cache._mutation_version != prepared.base_version:
                    raise StateError("Source timing preparation is stale")
            runtime_preparation._acquire_claim()
            runtime_claimed = True
            with owner._preparation_admission_lock:
                if (
                    owner._preparation_lane_generation is not generation
                    or not owner._sealed_lane_generation_matches_locked(
                        generation,
                        public_snapshot,
                    )
                ):
                    raise StateError("Source timing preparation private generation is stale")
            self._state = "claimed"
            claim_thread_id = get_ident()
            self._claim_thread_id = claim_thread_id
            commit_state_digest = hashlib.sha256(
                repr(
                    (
                        binding_token.base_state_digest,
                        sealed_overlay_digest,
                        tuple(
                            (name, prepared.version_delta)
                            for name, _cache, prepared in cache_overlays
                        ),
                        runtime_preparation.base_versions,
                    )
                ).encode("utf-8")
            ).hexdigest()
            self._commit_state_digest = commit_state_digest
            expected_receipt = SourceTimingPreparationReceipt(
                binding_token=binding_token,
                overlay_digest=sealed_overlay_digest,
                committed_state_digest=commit_state_digest,
                _integrity=owner._preparation_receipt_integrity(
                    binding_token,
                    sealed_overlay_digest,
                    commit_state_digest,
                ),
            )
            self._expected_receipt = expected_receipt
            record = self._freeze_claim_record(
                owner=owner,
                generation=generation,
                claim_thread_id=claim_thread_id,
                binding_token=binding_token,
                cache_overlays=cache_overlays,
                runtime_preparation=runtime_preparation,
                sealed_overlay_digest=sealed_overlay_digest,
                seal_integrity=seal_integrity,
                commit_state_digest=commit_state_digest,
                expected_receipt=expected_receipt,
            )
            owner._install_preparation_claim_record(self, record)
            try:
                yield self
            except BaseException:
                if record.state != "committed":
                    owner._discard_preparation_claim_record(self)
                    owner._discard_expected_preparation_receipt(expected_receipt)
                    self._state = "sealed"
                    self._expected_receipt = None
                    self._composite_certified_receipt = None
                raise
            else:
                if record.state != "committed":
                    owner._discard_preparation_claim_record(self)
                    owner._discard_expected_preparation_receipt(expected_receipt)
                    self._state = "sealed"
                    self._expected_receipt = None
                    self._composite_certified_receipt = None
                    raise StateError(
                        "Claimed source timing preparation exited without commit_no_fail"
                    )
        finally:
            self._claim_thread_id = None
            if record is None or record.state != "committed":
                owner._discard_preparation_claim_record(self)
                if expected_receipt is not None:
                    owner._discard_expected_preparation_receipt(expected_receipt)
                if self._state == "claimed":
                    self._state = "sealed"
                    self._expected_receipt = None
                    self._composite_certified_receipt = None
            if runtime_claimed:
                runtime_preparation._claim_held = False
                if record is None or record.state != "committed":
                    runtime_preparation._state = "open"
                runtime_clock_lock.release()
                runtime_audit_lock.release()
            for cache_lock in reversed(acquired_cache_locks):
                cache_lock.release()
            preparation_lock.release()
            if record is not None:
                if record.state != "committed":
                    runtime_preparation.cancel()
                    self._discard_staged_payload()
                    self._state = "cancelled"
                    self._expected_receipt = None
                    self._composite_certified_receipt = None
                self._release_owner_lane()

    def certify_composite_commit(
        self,
        expected_receipt: SourceTimingPreparationReceipt,
    ) -> None:
        """Certify one claim for a later validation-free composite primitive commit."""

        owner = self._owner
        if type(owner) is not SourceTimingPlanner:
            raise StateError("Source timing preparation owner is malformed")
        record = owner._active_preparation_claim_record(self)
        if record is None or record.state not in {"claimed", "certified"}:
            raise StateError("Source timing preparation is not claimed for certification")
        if record.certified_receipt is not None:
            raise StateError("Source timing composite commit is already certified")
        if self._claim_thread_id != get_ident():
            raise StateError("Source timing preparation must certify on its claiming thread")
        if (
            record.claim_thread_id != get_ident()
            or record.expected_receipt is not expected_receipt
            or self._expected_receipt is not expected_receipt
            or not owner.authenticates_expected_preparation_receipt(
                expected_receipt,
                preparation=self,
            )
            or not self._authenticates(owner)
            or not owner._claim_record_matches_current_state(record)
        ):
            raise StateError("Source timing composite expected receipt failed authentication")
        record.certified_receipt = expected_receipt
        record.state = "certified"
        self._composite_certified_receipt = expected_receipt

    def _commit_primitives_no_fail(
        self,
        record: _SourceTimingClaimRecord,
    ) -> SourceTimingPreparationReceipt:
        """Apply only prevalidated writes and install one exact immutable receipt."""

        runtime_plan = cast(_SourceTimingRuntimeCommitPlan, record.runtime_plan)
        expected_receipt = record.expected_receipt
        owner = record.owner
        for cache_plan in record.cache_plans:
            cache_plan.target._apply_operations_locked(
                cache_plan.operations,
                lookup_candidate_delta=cache_plan.lookup_candidate_delta,
                version_delta=cache_plan.version_delta,
            )
        audit_target = runtime_plan.audit_target
        audit_target._apply_prepared_operations_locked(runtime_plan.audit_operations)
        clocks_target = runtime_plan.clocks_target
        clocks_target._states = runtime_plan.clock_states
        clocks_target._high_water_mark = runtime_plan.clock_high_water_mark
        clocks_target._cache_entry_estimated_bytes = runtime_plan.clock_cache_entry_estimated_bytes
        clocks_target._lookup_count = runtime_plan.clock_lookup_count
        clocks_target._cache_hit_count = runtime_plan.clock_cache_hit_count
        clocks_target._cache_miss_count = runtime_plan.clock_cache_miss_count
        clocks_target._eviction_count = runtime_plan.clock_eviction_count
        clocks_target._mutation_version = runtime_plan.clock_mutation_version
        runtime_plan.preparation._state = "committed"
        runtime_plan.preparation._source_timing_owner = None
        for _name, _cache, prepared in record.admitted_cache_overlays:
            prepared._operations.clear()
            prepared._overlay.clear()
        runtime_plan.preparation.audit._operations.clear()
        runtime_plan.preparation.clocks._states = runtime_plan.discarded_clock_states
        runtime_plan.preparation.clocks._operations.clear()
        runtime_plan.preparation.clocks._cache_entry_estimated_bytes = 0
        self._owner = owner
        self._binding_token = record.binding_token
        self._cache_overlays = ()
        self._runtime_preparation = None
        self._overlay_planner = None
        self._planning_runtime = None
        self._sealed_overlay_digest = record.sealed_overlay_digest
        self._seal_integrity = record.seal_integrity
        self._commit_state_digest = record.commit_state_digest
        self._expected_receipt = expected_receipt
        self._composite_certified_receipt = record.certified_receipt
        self._committed_receipt = expected_receipt
        self._state = "committed"
        record.admitted_cache_overlays = ()
        record.admitted_runtime_preparation = None
        record.cache_plans = ()
        record.runtime_plan = None
        owner._terminalize_preparation_record_no_fail(record)
        return expected_receipt

    def commit_no_fail(self) -> SourceTimingPreparationReceipt:
        """Apply a preclaimed overlay inside the State/Lifecycle finalization fence."""

        owner = self._owner
        if type(owner) is not SourceTimingPlanner:
            raise StateError("Source timing preparation owner is malformed")
        record = owner._active_preparation_claim_record(self)
        if record is None or record.state not in {"claimed", "certified"}:
            raise StateError("Source timing preparation is not claimed for commit")
        if record.claim_thread_id != get_ident():
            raise StateError("Source timing preparation must commit on its claiming thread")
        if record.state == "certified":
            return self._commit_primitives_no_fail(record)
        expected_receipt = record.expected_receipt
        if (
            self._state != "claimed"
            or not self._commit_state_digest
            or self._expected_receipt is not expected_receipt
            or not owner.authenticates_expected_preparation_receipt(
                expected_receipt,
                preparation=self,
            )
            or not self._authenticates(owner)
            or not owner._claim_record_matches_current_state(record)
        ):
            raise StateError("Source timing preparation failed standalone commit validation")
        return self._commit_primitives_no_fail(record)

    def _current_overlay_digest(self) -> str:
        cache_digests = tuple(
            (name, prepared.overlay_digest()) for name, _cache, prepared in self._cache_overlays
        )
        payload = (cache_digests, self._runtime_preparation.overlay_digest())
        return hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()

    def _authenticates(self, owner: SourceTimingPlanner) -> bool:
        if owner is not self._owner or not owner.authenticates_binding_token(self._binding_token):
            return False
        if self._state in {"open", "cancelled"}:
            return False
        record = owner._active_preparation_claim_record(self)
        if self._state == "sealed":
            generation = owner._preparation_lane_generation
            if (
                record is not None
                or not self._lane_active
                or owner._preparation_lane is not self
                or owner._preparation_lane_marker is not self._lane_marker
                or generation is None
                or generation.carrier_ref() is not self
                or generation.lane_marker is not self._lane_marker
                or generation.lane_epoch != owner._preparation_lane_epoch
                or generation.token_facts.token is not self._binding_token
                or generation.overlay_digest != self._sealed_overlay_digest
                or not hmac.compare_digest(generation.seal_integrity, self._seal_integrity)
            ):
                return False
        elif self._state == "claimed":
            if (
                record is None
                or record.state not in {"claimed", "certified"}
                or not self._lane_active
            ):
                return False
        elif self._state == "committed":
            if record is None or record.state != "committed" or self._lane_active:
                return False
        else:
            return False
        if record is not None and (
            record.owner is not owner
            or record.binding_token is not self._binding_token
            or record.receipt_authority.generation_marker is not record.generation_marker
            or record.lane_marker is not self._lane_marker
            or record.admitted_cache_overlays is not self._cache_overlays
            or record.admitted_runtime_preparation is not self._runtime_preparation
            or record.sealed_overlay_digest != self._sealed_overlay_digest
            or record.seal_integrity != self._seal_integrity
            or record.commit_state_digest != self._commit_state_digest
        ):
            return False
        if (
            record is not None
            and self._state == "claimed"
            and not owner._claim_record_matches_current_state(record)
        ):
            return False
        if (
            self._state != "committed"
            and self._current_overlay_digest() != self._sealed_overlay_digest
        ):
            return False
        expected_seal = owner._preparation_seal_integrity(
            self._binding_token,
            self._sealed_overlay_digest,
        )
        if not hmac.compare_digest(self._seal_integrity, expected_seal):
            return False
        if self._state != "committed":
            return True
        receipt = self._committed_receipt
        if (
            record is None
            or receipt is None
            or record.expected_receipt is not receipt
            or receipt.binding_token is not self._binding_token
            or not record.receipt_authority.committed
            or record.receipt_authority.receipt_ref() is not receipt
        ):
            return False
        expected_receipt = owner._preparation_receipt_integrity(
            receipt.binding_token,
            receipt.overlay_digest,
            receipt.committed_state_digest,
        )
        return hmac.compare_digest(receipt._integrity, expected_receipt)


def finalized_endpoint_event_times(
    event: TimingOccurrence,
    format_name: str,
    hostname: str,
    phase: str = "base",
) -> tuple[datetime, datetime] | None:
    """Return a pre-render frozen endpoint native/envelope pair when present."""

    plan = event.source_timing
    if plan is None:
        return None
    native = plan.finalized_times.get(endpoint_event_native_key(format_name, hostname, phase))
    rendered = plan.finalized_times.get(endpoint_event_render_key(format_name, hostname, phase))
    if native is None or rendered is None:
        return None
    return native, rendered


def compatibility_endpoint_event_times(
    event: TimingOccurrence,
    format_name: str,
    hostname: str,
    phase: str = "base",
) -> tuple[datetime, datetime]:
    """Plan one isolated direct-emitter endpoint row without retained global state."""

    finalized = finalized_endpoint_event_times(event, format_name, hostname, phase)
    if finalized is not None:
        return finalized
    if event.source_timing is not None and not event.source_timing.compatibility_mode:
        raise RuntimeError(
            "Endpoint compatibility timing cannot extend an engine-owned incomplete plan: "
            f"format={format_name} host={hostname} phase={phase}"
        )
    canonical_time = ensure_utc(
        event.source_timing.canonical_timestamp
        if event.source_timing is not None
        else event.timestamp
    )
    reference_time = canonical_time.replace(hour=0, minute=0, second=0, microsecond=0)
    runtime = TimingRuntime(reference_time=reference_time, namespace="endpoint-compatibility")
    planner = SourceTimingPlanner(
        event.source_timing.clock_profile_name if event.source_timing is not None else "complete",
        timing_runtime=runtime,
    )
    planned = planner.plan_event(
        event,
        format_name,
        source_instance=f"{_endpoint_format_family(format_name)}:{hostname.casefold()}:compat",
        source_hostname=hostname,
    )
    if planned.source_timing is not None:
        planned.source_timing.compatibility_mode = True
    finalized = finalized_endpoint_event_times(planned, format_name, hostname, phase)
    if finalized is None:
        return canonical_time, canonical_time
    return finalized


def compatibility_sysmon_envelope_time(
    native_time: datetime,
    *,
    hostname: str,
    event_id: int,
    identity_parts: tuple[Any, ...] = (),
) -> datetime:
    """Project a raw direct-emitter Sysmon row through a stateless typed envelope."""

    native_time = ensure_utc(native_time)
    reference_time = native_time.replace(hour=0, minute=0, second=0, microsecond=0)
    runtime = TimingRuntime(
        reference_time=reference_time, namespace="sysmon-envelope-compatibility"
    )
    planner = SourceTimingPlanner(timing_runtime=runtime)
    object_id = "sysmon-compat:" + ":".join(str(part) for part in identity_parts)
    return planner._sysmon_runtime_envelope_time(
        native_time,
        event_id=event_id,
        source_instance=f"sysmon:{hostname.casefold()}:compat",
        hostname=hostname,
        object_id=object_id,
        lifecycle_id=object_id,
    )


def compatibility_process_create_time(
    canonical_start: datetime,
    *,
    format_name: str,
    hostname: str,
    pid: int,
    os_category: str = "windows",
) -> datetime:
    """Return one stateless direct-emitter process-create observation."""

    canonical_start = ensure_utc(canonical_start)
    reference_time = canonical_start.replace(hour=0, minute=0, second=0, microsecond=0)
    runtime = TimingRuntime(reference_time=reference_time, namespace="process-create-compatibility")
    planner = SourceTimingPlanner(timing_runtime=runtime)
    family = _endpoint_format_family(format_name)
    source_instance = f"{family}:{hostname.casefold()}:compat"
    object_id = f"process:{hostname}:{pid}:{canonical_start.isoformat()}"
    native = planner._runtime_endpoint_clock_time(
        canonical_start,
        hostname=hostname,
        os_category=os_category,
    ) + planner._coherent_runtime_latency(
        planner._endpoint_process_source_key(family),
        canonical_time=canonical_start,
        source_instance=source_instance,
        hostname=hostname,
        object_id=object_id,
        lifecycle_id=object_id,
        phase="create",
    )
    if family != "sysmon":
        return native
    return planner._sysmon_runtime_envelope_time(
        native,
        event_id=1,
        source_instance=source_instance,
        hostname=hostname,
        object_id=object_id,
        lifecycle_id=object_id,
    )


def compatibility_relationship_time(
    anchor: datetime,
    *,
    relationship_key: str,
    identity_parts: tuple[Any, ...],
) -> datetime:
    """Return one stateless legacy relationship projection for raw emitter rows.

    Canonical rows are finalized by the engine-owned :class:`TimingRuntime` before
    they reach an emitter.  This adapter only preserves the direct-dictionary API
    used by compatibility tests and callers that do not construct a canonical
    occurrence; keeping the sampler here prevents production emitters from owning
    timing RNG or retaining a planner.
    """

    anchor = ensure_utc(anchor)
    window = get_timing_window(
        relationship_key,
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    minimum_us = window.min_ms * 1_000
    maximum_us = window.max_ms * 1_000
    distribution = (
        ConstantDistribution(float(minimum_us))
        if maximum_us <= minimum_us
        else SourceTimingPlanner._right_skew_distribution(minimum_us, maximum_us + 1)
    )
    runtime = TimingRuntime(
        reference_time=anchor.replace(hour=0, minute=0, second=0, microsecond=0),
        namespace="relationship-compatibility",
    )
    return runtime.sampler.after(
        anchor,
        distribution,
        relationship_key=relationship_key,
        scope=TimingScope(
            stable_id=SourceTimingPlanner._cache_key(
                f"compatibility:{relationship_key}",
                identity_parts,
            ),
            source="compatibility",
        ),
        sample_key="relationship",
    )


def compatibility_ecar_flow_identity_deadline(event: TimingOccurrence) -> datetime:
    """Return the legacy safe-identity bound for isolated SSH compatibility callers."""

    network = event.network
    canonical_start = (
        network.started_at
        if network is not None
        and (network.duration is not None or network.closed_at is not None)
        and getattr(network, "started_at", None) is not None
        else event.source_timing.canonical_timestamp
        if event.source_timing is not None
        else event.timestamp
    )
    window = get_timing_window(
        "source.ecar_flow",
        default_min_ms=40,
        default_max_ms=300,
        default_position="after",
        default_class="source_latency",
    )
    return ensure_utc(canonical_start) + timedelta(milliseconds=window.max_ms + 1)
