#!/usr/bin/env python3
# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Probe the V2 foundation registries under scale, churn, and long-duration load.

The default profile is intentionally a small smoke run.  ``--profile release``
selects the documented 10-to-2-million size ladder and the 24-hour, seven-day,
and 30-day duration points.  Every measured case runs in a fresh interpreter so
RSS and ``PYTHONHASHSEED`` results are not contaminated by an earlier case.
"""

from __future__ import annotations

import argparse
import base64
import gc
import hashlib
import json
import os
import resource
import statistics
import subprocess
import sys
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from itertools import islice
from pathlib import Path
from time import perf_counter, perf_counter_ns
from typing import Any, Literal, TypeVar

import psutil

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationChannelIdentity,
    ApplicationOperationReservation,
    ApplicationTransportBinding,
)
from evidenceforge.events.collection_policy import (
    CollectionCapability,
    CollectionWindow,
    SourceCollectionPolicy,
    SourceInstanceIdentity,
)
from evidenceforge.events.content_identity import (
    BinaryReleaseIdentity,
    LocalArtifactIdentity,
    UserProfileIdentity,
)
from evidenceforge.events.lifecycle import (
    LifecycleCloseBarrier,
    LifecycleRetentionLease,
    SessionLifecycleIdentity,
)
from evidenceforge.events.network import NetworkTrafficLedger, NetworkTransactionPlan
from evidenceforge.events.rdp import (
    RdpLogicalSessionIdentity,
    RdpSessionAffinity,
    RdpTransportPlan,
)
from evidenceforge.generation.application_channels import (
    ApplicationChannelCloseRequest,
    ApplicationChannelRegistry,
)
from evidenceforge.generation.collection_deployment import (
    CompiledCollectionDeployment,
    SourceInstanceDeployment,
)
from evidenceforge.generation.deployment_registry import LocalArtifactVersionRegistry
from evidenceforge.generation.http_channels import (
    HttpApplicationChannelManager,
    HttpChannelAffinity,
)
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.process_runtime_cache import (
    build_production_process_runtime_caches,
)
from evidenceforge.generation.proxy_channels import (
    ExplicitProxyChannelAffinity,
    ExplicitProxyChannelManager,
)
from evidenceforge.generation.rdp_sessions import RdpReconnectStateManager
from evidenceforge.generation.smb_channels import (
    SmbApplicationChannelManager,
    SmbChannelAffinity,
)
from evidenceforge.generation.source_timing import (
    PRODUCTION_SOURCE_TIMING_INDEX_FAMILIES,
    SourceTimingPlanner,
)
from evidenceforge.generation.ssh_channels import (
    SshApplicationChannelManager,
    SshChannelAffinity,
    SshOperationKind,
    SshProcessHold,
    SshSessionBinding,
    SshTransportPlan,
)
from evidenceforge.generation.timing import (
    SourceClockKey,
    SourceClockSpec,
    TimingRuntime,
)
from evidenceforge.generation.workload import RETAINED_STATE_FAMILIES

try:
    from scripts.lifecycle_service_transport_scale_probe import (
        populate_lifecycle_production_shape,
    )
except ModuleNotFoundError as exc:
    if exc.name != "scripts":
        raise
    # Direct ``python scripts/foundation_scale_workload.py`` execution puts the
    # scripts directory, rather than its parent, on ``sys.path``.
    from lifecycle_service_transport_scale_probe import (  # type: ignore[no-redef]
        populate_lifecycle_production_shape,
    )

try:
    from scripts.deployment_population_scale_probe import (
        build_deployment_population,
        deployment_population_family_counts,
    )
except ModuleNotFoundError as exc:
    if exc.name != "scripts":
        raise
    from deployment_population_scale_probe import (  # type: ignore[no-redef]
        build_deployment_population,
        deployment_population_family_counts,
    )

RegistryName = Literal["lifecycle", "channels", "artifacts", "collection", "deployment"]
ProtocolName = Literal["http", "proxy", "smb", "rdp", "ssh"]
ImplementedProtocolName = Literal["http", "proxy", "smb", "rdp", "ssh"]
CaseRegistry = RegistryName | ProtocolName | Literal["mixed"]
GroupMode = Literal["uniform", "skewed"]
WriteMode = Literal["monotonic", "out-of-order"]
CaseKind = Literal["scale", "duration", "mixed", "sidecar"]

_T = TypeVar("_T")
_START = datetime(2026, 1, 1, tzinfo=UTC)
_ONE_MICROSECOND = timedelta(microseconds=1)
_TWO_MICROSECONDS = timedelta(microseconds=2)
_ONE_HOUR = timedelta(hours=1)
_TWO_HOURS = timedelta(hours=2)
_TWO_HOURS_SECONDS = _TWO_HOURS.total_seconds()
_EMPTY_NETWORK_TRAFFIC = NetworkTrafficLedger()
_RELEASE_SIZES = (10, 100, 1_000, 10_000, 100_000, 1_000_000, 2_000_000)
_RELEASE_GROUP_MODES: tuple[GroupMode, ...] = ("uniform", "skewed")
_RELEASE_WRITE_MODES: tuple[WriteMode, ...] = ("monotonic", "out-of-order")
_RELEASE_WORKERS = (1, 4, 8)
_RELEASE_HASH_SEEDS = (0, 271_828)
_RELEASE_DURATIONS = (24, 168, 720)
_RELEASE_QUERIES = 10_000
_RELEASE_RATE_PER_HOUR = 100
_RELEASE_CHURN_ENTRIES = 100_000
_RELEASE_MIXED_ENTRIES = 1_000_000
_RELEASE_SIDECAR_ENTRIES = 1_000_000
_AUTHORITATIVE_RELEASE_CASE_COUNT = 161
_REGISTRIES: tuple[RegistryName, ...] = (
    "lifecycle",
    "channels",
    "artifacts",
    "collection",
    "deployment",
)
_DURATION_REGISTRIES: tuple[RegistryName, ...] = (
    "lifecycle",
    "channels",
    "artifacts",
    "collection",
)
_EXPIRING_REGISTRIES: tuple[RegistryName, ...] = (
    "lifecycle",
    "channels",
    "artifacts",
)
_IMPLEMENTED_PROTOCOLS: tuple[ImplementedProtocolName, ...] = (
    "http",
    "proxy",
    "smb",
    "rdp",
    "ssh",
)
_REQUIRED_PROTOCOLS: tuple[ProtocolName, ...] = _IMPLEMENTED_PROTOCOLS
_MIXED_FAMILIES = RETAINED_STATE_FAMILIES
_EXPLICIT_IMPLEMENTATION_FILES = (
    "pyproject.toml",
    "uv.lock",
    "scripts/foundation_scale_workload.py",
    "scripts/collection_deployment_scale_probe.py",
    "scripts/deployment_path_scale_probe.py",
    "scripts/deployment_population_scale_probe.py",
    "scripts/lifecycle_service_transport_scale_probe.py",
    "scripts/process_runtime_cache_probe.py",
    "scripts/rdp_reconnect_scale_probe.py",
    "scripts/registry_scale_probe.py",
    "scripts/smb_channel_scale_probe.py",
    "scripts/ssh_channel_scale_probe.py",
)


def _implementation_files() -> tuple[str, ...]:
    """Return every tracked production asset plus the scale harness entrypoints."""

    root = Path(__file__).resolve().parents[1]
    package_root = root / "src" / "evidenceforge"
    try:
        tracked = subprocess.run(
            ["git", "ls-files", "-z", "--", "src/evidenceforge"],
            cwd=root,
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        tracked = None
    if tracked is not None and tracked.returncode == 0:
        package_files = {
            os.fsdecode(relative_name)
            for relative_name in tracked.stdout.split(b"\0")
            if relative_name
        }
    else:
        package_files = {
            path.relative_to(root).as_posix()
            for path in package_root.rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
        }
    return tuple(sorted(package_files | set(_EXPLICIT_IMPLEMENTATION_FILES)))


_IMPLEMENTATION_FILES = _implementation_files()


@dataclass(frozen=True, slots=True)
class CaseSpec:
    """Serializable configuration for one isolated workload process."""

    kind: CaseKind
    registry: CaseRegistry
    entries: int = 0
    duration_hours: int = 0
    rate_per_hour: int = 0
    queries: int = 0
    group_mode: GroupMode = "uniform"
    write_mode: WriteMode = "monotonic"
    workers: int = 1
    hash_seed: int = 0
    churn_entries: int = 0


@dataclass(frozen=True, slots=True)
class WorkloadMetrics:
    """Common cardinality and amplification metrics emitted by every registry."""

    logical_entries: int
    live_entries: int
    retained_entries: int
    stale_entries: int
    leased_entries: int
    backing_entries: int
    estimated_bytes: int | None
    maximum_bucket_size: int | None
    lookup_candidates_inspected: int | None
    heap_segment_amplification: float | None
    compaction_work: int | None
    compaction_seconds: float | None
    high_water_mark: int | None
    estimated_index_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class ScaleResult:
    """One isolated cardinality/lookup/churn result."""

    kind: Literal["scale"]
    registry: RegistryName
    entries: int
    queries: int
    group_mode: GroupMode
    write_mode: WriteMode
    workers: int
    hash_seed: int
    load_seconds: float
    primary_cold_lookup_p95_us: float
    primary_lookup_p95_us: float
    secondary_cold_lookup_p95_us: float
    secondary_lookup_p95_us: float
    page_lookup_p95_us: float | None
    churn_entries: int
    churn_seconds: float
    operation_seconds: float | None
    close_prepare_seconds: float | None
    close_seconds: float | None
    expiry_entries: int
    expiry_seconds: float
    rss_delta_bytes: int
    peak_rss_delta_bytes: int
    bytes_per_requested_entry: float
    metrics: WorkloadMetrics
    registry_digest: str
    implementation_digest_start: str
    implementation_digest_end: str
    notes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DurationResult:
    """One fixed-rate duration and plateau result."""

    kind: Literal["duration"]
    registry: RegistryName
    duration_hours: int
    rate_per_hour: int
    group_mode: GroupMode
    workers: int
    hash_seed: int
    mutations: int
    total_seconds: float
    late_hour_seconds: float
    lookup_p95_us: float
    plateau_hour: int | None
    rss_delta_bytes: int
    peak_rss_delta_bytes: int
    metrics: WorkloadMetrics
    registry_digest: str
    implementation_digest_start: str
    implementation_digest_end: str
    notes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MixedFamilyCensus:
    """Public per-family contribution to one shared-process mixed result."""

    requested_logical: int
    physical_records: int
    live_entries: int
    retained_entries: int
    backing_entries: int
    stale_entries: int
    leased_entries: int
    estimated_bytes: int | None
    estimated_index_bytes: int | None
    lookup_candidates_inspected: int | None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MixedResult:
    """One true in-process mixed-registry hot-state memory measurement."""

    kind: Literal["mixed"]
    registry: Literal["mixed"]
    entries: int
    workers: int
    hash_seed: int
    per_registry_entries: dict[str, int]
    per_family_requested_entries: dict[str, int]
    family_censuses: dict[str, MixedFamilyCensus]
    family_coverage_complete: bool
    live_entries: int
    physical_hot_records: int
    load_seconds: float
    rss_delta_bytes: int
    peak_rss_delta_bytes: int
    bytes_per_requested_entry: float
    rss_bytes_per_physical_record: float
    estimated_index_bytes: int | None
    estimated_index_bytes_per_live_entry: float | None
    estimated_index_bytes_per_physical_record: float | None
    per_registry_estimated_index_bytes: dict[str, int | None]
    registry_digest: str
    implementation_digest_start: str
    implementation_digest_end: str
    notes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SidecarResult:
    """One isolated protocol-manager sidecar plus shared-registry measurement."""

    kind: Literal["sidecar"]
    registry: ImplementedProtocolName
    entries: int
    queries: int
    group_mode: GroupMode
    write_mode: WriteMode
    workers: int
    hash_seed: int
    representation: Literal["actual_manager", "structural_equivalent"]
    load_seconds: float
    lookup_p95_us: float
    rss_delta_bytes: int
    peak_rss_delta_bytes: int
    common_live_entries: int
    common_used_operation_ids: int
    common_estimated_bytes: int
    common_estimated_index_bytes: int
    sidecar_live_entries: int
    sidecar_logical_records: int
    sidecar_backing_entries: int
    sidecar_estimated_bytes: int
    sidecar_estimated_index_bytes: int
    sidecar_lookup_candidates_inspected: int
    sidecar_bytes_per_live_entry: float
    sidecar_index_bytes_per_live_entry: float
    physical_hot_records: int
    rss_bytes_per_physical_record: float
    load_seconds_per_million_physical_records: float
    registry_digest: str
    implementation_digest_start: str
    implementation_digest_end: str
    notes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CaseError:
    """An isolated child failure retained in the report instead of being hidden."""

    spec: CaseSpec
    returncode: int
    stderr: str


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    """Git revision and worktree state at one authoritative report boundary."""

    git_sha: str | None
    dirty: bool | None
    status_digest: str | None


def _rss_bytes() -> int:
    """Return current resident memory for this process."""

    return int(psutil.Process().memory_info().rss)


def _implementation_digest() -> str:
    """Hash every production/config asset and scale entrypoint for one child case."""

    root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    for relative_name in _implementation_files():
        path = root / relative_name
        digest.update(relative_name.encode("utf-8"))
        digest.update(b"\0")
        if path.exists():
            digest.update(path.read_bytes())
        else:
            digest.update(b"<missing>")
        digest.update(b"\0")
    return digest.hexdigest()


def _missing_implementation_files() -> tuple[str, ...]:
    """Return manifest entries that cannot participate in a release digest."""

    root = Path(__file__).resolve().parents[1]
    return tuple(
        relative_name
        for relative_name in _EXPLICIT_IMPLEMENTATION_FILES
        if not (root / relative_name).is_file()
    )


def _repository_snapshot() -> RepositorySnapshot:
    """Read the current Git commit and a privacy-preserving dirty-state digest."""

    root = Path(__file__).resolve().parents[1]
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return RepositorySnapshot(git_sha=None, dirty=None, status_digest=None)

    git_sha = revision.stdout.strip() if revision.returncode == 0 else None
    if not git_sha:
        git_sha = None
    if status.returncode != 0:
        return RepositorySnapshot(git_sha=git_sha, dirty=None, status_digest=None)
    status_bytes = status.stdout.encode("utf-8")
    return RepositorySnapshot(
        git_sha=git_sha,
        dirty=bool(status_bytes),
        status_digest=hashlib.sha256(status_bytes).hexdigest(),
    )


def _peak_rss_bytes() -> int:
    """Return peak resident memory using psutil's platform-specific extension."""

    try:
        info = psutil.Process().memory_full_info()
    except (psutil.AccessDenied, PermissionError):
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value if sys.platform == "darwin" else value * 1_024)
    peak = getattr(info, "peak_wset", None)
    if peak is None:
        # Linux exposes only the current RSS through psutil.  The case remains
        # isolated, so current RSS is still an honest lower bound on the peak.
        return int(info.rss)
    return int(peak)


def _p95_us(samples_ns: Sequence[int]) -> float:
    if not samples_ns:
        return 0.0
    ordered = sorted(samples_ns)
    index = min(len(ordered) - 1, max(0, (len(ordered) * 95 + 99) // 100 - 1))
    return ordered[index] / 1_000.0


def _query_ordinals(entries: int, queries: int) -> tuple[int, ...]:
    """Return a deterministic uniform-looking query stream without Python hash()."""

    count = min(max(1, queries), max(1, entries * 4))
    cursor = 0x9E3779B97F4A7C15
    values: list[int] = []
    for _ in range(count):
        cursor = (cursor * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        values.append(cursor % entries)
    return tuple(values)


def _timestamp_ordinal(ordinal: int, write_mode: WriteMode) -> int:
    """Make exactly every tenth append late relative to its predecessor."""

    if write_mode == "out-of-order" and ordinal >= 10 and ordinal % 10 == 0:
        return ordinal - 5
    return ordinal


def _write_ordinal(ordinal: int, entries: int, write_mode: WriteMode) -> int:
    """Return a permutation with one adjacent inversion in each ten writes."""

    if write_mode != "out-of-order":
        return ordinal
    position = ordinal % 10
    if position == 8 and ordinal + 1 < entries:
        return ordinal + 1
    if position == 9:
        return ordinal - 1
    return ordinal


def _partitioned(items: Sequence[_T], workers: int) -> tuple[Sequence[_T], ...]:
    if workers <= 1 or len(items) <= 1:
        return (items,)
    size = max(1, (len(items) + workers - 1) // workers)
    return tuple(items[offset : offset + size] for offset in range(0, len(items), size))


def _parallel_for(items: Sequence[_T], workers: int, function: Callable[[_T], None]) -> None:
    """Apply one mutation function in deterministic input partitions."""

    partitions = _partitioned(items, workers)

    def apply_partition(partition: Sequence[_T]) -> None:
        for item in partition:
            function(item)

    if len(partitions) == 1:
        apply_partition(partitions[0])
        return
    with ThreadPoolExecutor(max_workers=workers) as executor:
        tuple(executor.map(apply_partition, partitions))


def _timed_parallel_queries(
    ordinals: Sequence[int],
    workers: int,
    lookup: Callable[[int], object],
    *,
    warmup_passes: int = 0,
) -> list[int]:
    if warmup_passes < 0:
        raise ValueError("query warmup passes cannot be negative")
    partitions = _partitioned(ordinals, workers)

    def warm_partition(partition: Sequence[int]) -> None:
        for ordinal in partition:
            if lookup(ordinal) is None:
                raise AssertionError(f"lookup for ordinal {ordinal} returned no result")

    for _ in range(warmup_passes):
        if len(partitions) == 1:
            warm_partition(partitions[0])
        else:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                tuple(executor.map(warm_partition, partitions))

    def query_partition(partition: Sequence[int]) -> list[int]:
        samples: list[int] = []
        for ordinal in partition:
            started = perf_counter_ns()
            result = lookup(ordinal)
            elapsed = perf_counter_ns() - started
            if result is None:
                raise AssertionError(f"lookup for ordinal {ordinal} returned no result")
            samples.append(elapsed)
        return samples

    if len(partitions) == 1:
        return query_partition(partitions[0])
    with ThreadPoolExecutor(max_workers=workers) as executor:
        nested = tuple(executor.map(query_partition, partitions))
    return [sample for group in nested for sample in group]


def _digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _artifact(ordinal: int, group_mode: GroupMode) -> LocalArtifactIdentity:
    group = ordinal if group_mode == "uniform" else 0
    version = 1 if group_mode == "uniform" else ordinal + 1
    return LocalArtifactIdentity(
        hostname=f"ws-{group:012d}",
        principal=f"user-{group:012d}",
        platform="windows",
        user_profile_id=f"profile-{group:012d}",
        application_profile_id=f"app-profile-{group:012d}",
        application_id="browser",
        family="cache",
        source_object_id=f"object-{group:012d}",
        native_path=rf"C:\Users\user-{group:012d}\Cache\entry.bin",
        content_id=f"content-{group:012d}",
        version=version,
    )


def _channel_identity(
    ordinal: int,
    group_mode: GroupMode,
    write_mode: WriteMode,
    *,
    start: datetime = _START,
) -> ApplicationChannelIdentity:
    owner = ordinal if group_mode == "uniform" else 0
    # Skew the owner page while keeping each reusable affinity bucket bounded.
    affinity = ordinal if group_mode == "uniform" else ordinal // 8
    opened_at = start + timedelta(microseconds=_timestamp_ordinal(ordinal, write_mode))
    hard_deadline = start + timedelta(hours=2)
    return ApplicationChannelIdentity(
        channel_id=f"channel-{ordinal:012d}",
        protocol="http",
        owner_id=f"owner-{owner:012d}",
        affinity_digest=f"affinity-{affinity:012d}",
        binding=ApplicationTransportBinding(
            transport_id=f"transport-{ordinal:012d}",
            opened_at=start,
            closes_at=start + timedelta(hours=3),
        ),
        opened_at=opened_at,
        idle_timeout=timedelta(hours=1),
        hard_deadline=hard_deadline,
        budget=ApplicationChannelBudget(4_096, 8_192, 2),
    )


def _source(ordinal: int, group_mode: GroupMode) -> SourceInstanceDeployment:
    group = ordinal if group_mode == "uniform" else 0
    return SourceInstanceDeployment(
        identity=SourceInstanceIdentity(
            source_instance=f"source-{ordinal:012d}",
            hostname=f"host-{group:012d}",
            family="ecar",
        ),
        formats=("ecar",),
        policy=SourceCollectionPolicy(
            capabilities=(
                CollectionCapability.PROCESS
                | CollectionCapability.NETWORK
                | CollectionCapability.COHERENT_ACTOR
            ),
            windows=(
                CollectionWindow(_START, _START + timedelta(hours=12)),
                CollectionWindow(_START + timedelta(hours=13), _START + timedelta(days=31)),
            ),
        ),
    )


def _sidecar_started_at(ordinal: int, write_mode: WriteMode) -> datetime:
    """Return a bounded canonical time for one protocol-sidecar insertion."""

    return _START + timedelta(microseconds=_timestamp_ordinal(ordinal, write_mode))


def _sidecar_owner(ordinal: int, group_mode: GroupMode) -> str:
    return f"owner-{ordinal:012d}" if group_mode == "uniform" else "owner-skewed"


def _http_affinity(ordinal: int, group_mode: GroupMode) -> HttpChannelAffinity:
    owner = _sidecar_owner(ordinal, group_mode)
    return HttpChannelAffinity.from_request(
        src_ip=owner,
        dst_ip="198.51.100.20",
        dst_port=443,
        http_host=f"site-{ordinal:012d}.example.test",
        user_agent="EvidenceForge/sidecar-probe",
    )


def _proxy_affinity(ordinal: int, group_mode: GroupMode) -> ExplicitProxyChannelAffinity:
    owner = _sidecar_owner(ordinal, group_mode)
    return ExplicitProxyChannelAffinity(
        client_ip=owner,
        proxy_ip="192.0.2.10",
        proxy_port=8080,
        origin_host=f"origin-{ordinal:012d}.example.test",
        origin_ip="198.51.100.20",
        origin_port=443,
        user_agent="EvidenceForge/sidecar-probe",
        auth_identity="EXAMPLE\\probe",
        policy_id="sidecar-release",
    )


def _rdp_identity(
    ordinal: int, group_mode: GroupMode, write_mode: WriteMode
) -> RdpLogicalSessionIdentity:
    owner = _sidecar_owner(ordinal, group_mode)
    started_at = _sidecar_started_at(ordinal, write_mode)
    return RdpLogicalSessionIdentity(
        logical_session_id=f"rdp-sidecar-{ordinal:012d}",
        affinity=RdpSessionAffinity(
            source_host=owner,
            source_address=owner,
            target_host=f"rdp-target-{ordinal:012d}.example.test",
            target_address="192.0.2.20",
            principal=f"example\\user-{ordinal:012d}",
            logon_id=f"0x{ordinal + 1:016x}",
            session_id=ordinal + 1,
        ),
        started_at=started_at,
        idle_timeout=timedelta(hours=1),
        reconnect_timeout=timedelta(minutes=15),
        hard_deadline=started_at + timedelta(hours=2),
        budget=ApplicationChannelBudget(4_096, 8_192, 2),
    )


def _rdp_transport(
    ordinal: int,
    write_mode: WriteMode,
) -> RdpTransportPlan:
    started_at = _sidecar_started_at(ordinal, write_mode)
    return RdpTransportPlan(
        channel_id=f"rdp-sidecar-channel-{ordinal:012d}",
        binding=ApplicationTransportBinding(
            transport_id=f"rdp-sidecar-transport-{ordinal:012d}",
            opened_at=started_at,
            closes_at=started_at + timedelta(hours=2),
        ),
        connected_at=started_at,
        budget=ApplicationChannelBudget(2_048, 4_096, 1),
    )


def _smb_affinity(
    ordinal: int,
    group_mode: GroupMode,
    *,
    owner: str | None = None,
    client_session: str | None = None,
    server_identity: str | None = None,
    principal: str | None = None,
) -> SmbChannelAffinity:
    owner = owner or _sidecar_owner(ordinal, group_mode)
    return SmbChannelAffinity._from_canonical(
        client_identity=owner,
        client_ip="192.0.2.10",
        client_session=client_session or f"0x{ordinal + 1:016x}",
        server_identity=server_identity or f"file-{ordinal:012d}",
        server_ip="192.0.2.30",
        principal=principal or f"example\\user-{ordinal:012d}",
        auth_protocol="kerberos",
        account_scope="example",
        dialect="3.1.1",
        signing_policy="required",
        encryption_policy="off",
        server_policy="windows:file-server",
        share_policy="disk:standard",
        client_access="windows_native",
    )


def _smb_transport(
    ordinal: int,
    write_mode: WriteMode,
    *,
    started_at: datetime | None = None,
    server_hostname: str | None = None,
) -> NetworkTransactionPlan:
    started_at = started_at or _sidecar_started_at(ordinal, write_mode)
    closed_at = started_at + _TWO_HOURS
    return NetworkTransactionPlan(
        stable_id=f"network-connection-{ordinal:016x}",
        hostname=server_hostname or f"file-{ordinal:012d}",
        outcome="success",
        phase_times=(("attempt", started_at), ("close", closed_at)),
        started_at=started_at,
        closed_at=closed_at,
        src_ip="192.0.2.10",
        src_port=1_024 + ordinal % 60_000,
        dst_ip="192.0.2.30",
        dst_port=445,
        protocol="tcp",
        service="smb",
        zeek_uid=f"Csmb{ordinal:012d}",
        conn_id=f"smb-conn-{ordinal:012d}",
        duration=_TWO_HOURS_SECONDS,
        conn_state="SF",
        history="ShADadfF",
        traffic=_EMPTY_NETWORK_TRAFFIC,
    )


def _ssh_session_values(
    ordinal: int,
    group_mode: GroupMode,
    write_mode: WriteMode,
) -> tuple[SshChannelAffinity, SshTransportPlan, SshSessionBinding]:
    """Return one exact SSH affinity, immutable transport, and lifecycle binding."""

    opened_at = _sidecar_started_at(ordinal, write_mode)
    closes_at = opened_at + timedelta(hours=2)
    client = _sidecar_owner(ordinal, group_mode)
    client_session = (
        f"ssh-client-session-{ordinal:012d}"
        if group_mode == "uniform"
        else "ssh-client-session-skewed"
    )
    server = f"ssh-server-{ordinal:012d}"
    server_session = f"ssh-server-session-{ordinal:012d}"
    principal = f"ssh-user-{ordinal:012d}"
    affinity = SshChannelAffinity(
        client_identity=client,
        client_session_object_id=client_session,
        server_identity=server,
        server_session_object_id=server_session,
        principal=principal,
        auth_method="publickey",
    )
    source_process = SshProcessHold(
        hostname=client,
        pid=1_000_000 + ordinal,
        process_object_id=f"ssh-source-process-{ordinal:012d}",
        session_object_id=client_session,
        principal=f"ssh-local-user-{ordinal:012d}",
        started_at=_START,
        required_until=closes_at,
    )
    receiver_process = SshProcessHold(
        hostname=server,
        pid=3_000_000 + ordinal,
        process_object_id=f"ssh-receiver-process-{ordinal:012d}",
        session_object_id=server_session,
        principal=principal,
        started_at=_START,
        required_until=closes_at,
    )
    transport = SshTransportPlan(
        transport_id=f"ssh-sidecar-transport-{ordinal:012d}",
        zeek_uid=f"Cssh{ordinal:012d}",
        conn_id=f"ssh-conn-{ordinal:012d}",
        source_ip=client,
        server_ip="192.0.2.40",
        source_port=1_024 + ordinal % 60_000,
        server_port=22,
        opened_at=opened_at,
        closes_at=closes_at,
        source_process=source_process,
        receiver_process=receiver_process,
    )
    binding = SshSessionBinding(
        hostname=server,
        logon_id=f"0x{ordinal + 1:016x}",
        session_object_id=server_session,
        lifecycle_group_id=f"ssh-lifecycle-{ordinal:012d}",
        principal=principal,
        ready_at=opened_at + timedelta(microseconds=1),
    )
    return affinity, transport, binding


def _session_identity(
    ordinal: int,
    group_mode: GroupMode,
    write_mode: WriteMode,
    *,
    start: datetime = _START,
) -> SessionLifecycleIdentity:
    host = ordinal if group_mode == "uniform" else 0
    started_at = start + timedelta(microseconds=_timestamp_ordinal(ordinal, write_mode))
    return SessionLifecycleIdentity(
        hostname=f"host-{host:012d}",
        object_id=f"session-{ordinal:012d}",
        logon_id=f"0x{ordinal + 1:016x}",
        principal=f"user-{host:012d}",
        session_kind="interactive",
        started_at=started_at,
        session_id=ordinal + 1,
    )


def _amplification(backing: int, live: int) -> float:
    return backing / max(1, live)


_MIN_PLATEAU_SUFFIX_HOURS = 24


def _final_plateau_hour(
    samples: Sequence[tuple[int, ...]],
    *,
    minimum_suffix_hours: int = _MIN_PLATEAU_SUFFIX_HOURS,
) -> int | None:
    """Return the first hour of a meaningfully long unchanged footprint suffix.

    Every tuple must contain the exact retained-count and backing-capacity
    footprint for one hour. A single final sample is not evidence of a
    plateau: the final unchanged suffix must cover at least one full day.
    """

    if minimum_suffix_hours <= 0:
        raise ValueError("minimum_suffix_hours must be positive")
    if len(samples) < minimum_suffix_hours:
        return None
    final = samples[-1]
    position = len(samples) - 1
    while position > 0 and samples[position - 1] == final:
        position -= 1
    if len(samples) - position < minimum_suffix_hours:
        return None
    return position + 1


def _run_lifecycle_scale(spec: CaseSpec) -> tuple[object, WorkloadMetrics, dict[str, object]]:
    registry = LifecycleRegistry(closed_retention=timedelta(hours=2))
    ordinals = range(spec.entries)

    def register(ordinal: int) -> None:
        identity = _session_identity(ordinal, spec.group_mode, spec.write_mode)
        registry.register_session(
            identity,
            action_id=f"open-{ordinal:012d}",
            transition_id=f"transition-open-{ordinal:012d}",
        )

    load_started = perf_counter()
    _parallel_for(ordinals, spec.workers, register)
    load_seconds = perf_counter() - load_started
    rss_after_load = _rss_bytes()
    peak_after_load = _peak_rss_bytes()
    query_ordinals = _query_ordinals(spec.entries, spec.queries)
    primary_cold = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        lambda ordinal: registry.get_session(f"session-{ordinal:012d}"),
    )
    primary = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        lambda ordinal: registry.get_session(f"session-{ordinal:012d}"),
        warmup_passes=3,
    )

    def temporal_lookup(ordinal: int) -> object:
        identity = _session_identity(ordinal, spec.group_mode, spec.write_mode)
        return registry.session_for_logon_at(
            identity.hostname,
            identity.logon_id,
            identity.started_at,
        )

    secondary_cold = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        temporal_lookup,
    )
    secondary = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        temporal_lookup,
        warmup_passes=3,
    )
    rss_after_load = max(rss_after_load, _rss_bytes())
    peak_after_load = max(peak_after_load, _peak_rss_bytes())

    churn_ordinals = range(min(spec.churn_entries, spec.entries))
    churn_started = perf_counter()

    def close(ordinal: int) -> None:
        identity = _session_identity(ordinal, spec.group_mode, spec.write_mode)
        close_at = _START + timedelta(hours=1, microseconds=ordinal)
        ticket = registry.request_close(
            LifecycleCloseBarrier(
                barrier_id=f"barrier-{ordinal:012d}",
                subject=identity.ref,
                requested_at=close_at,
                authority="generated",
                action_id=f"close-{ordinal:012d}",
            ),
            ticket_id=f"ticket-{ordinal:012d}",
        )
        registry.close(ticket.ticket_id)
        if ordinal % 10 == 0:
            registry.add_retention_lease(
                LifecycleRetentionLease(
                    lease_id=f"lease-{ordinal:012d}",
                    subject=identity.ref,
                    retain_until=_START + timedelta(hours=4),
                    reason="probe-ground-truth",
                )
            )

    _parallel_for(churn_ordinals, spec.workers, close)
    churn_seconds = perf_counter() - churn_started
    expiry_started = perf_counter()
    evicted = registry.advance_watermark(_START + timedelta(hours=4, minutes=30))
    expiry_seconds = perf_counter() - expiry_started
    census = registry.census()
    temporal_live = census.process_temporal_live_entries + census.session_temporal_live_entries
    temporal_backing = (
        census.process_temporal_backing_entries + census.session_temporal_backing_entries
    )
    deadline_live = census.retention_deadline_entries + census.retention_leases
    deadline_backing = (
        census.retention_deadline_backing_entries + census.lease_deadline_backing_entries
    )
    metrics = WorkloadMetrics(
        logical_entries=census.process_entries + census.session_entries,
        live_entries=census.live_processes + census.live_sessions,
        retained_entries=census.retained_processes + census.retained_sessions,
        stale_entries=census.temporal_stale_entries,
        leased_entries=census.retention_leases,
        backing_entries=(
            census.process_index_backing_entries
            + census.session_index_backing_entries
            + temporal_backing
            + deadline_backing
        ),
        estimated_bytes=census.estimated_bytes,
        maximum_bucket_size=None,
        lookup_candidates_inspected=census.lookup_candidates_inspected,
        heap_segment_amplification=max(
            _amplification(temporal_backing, temporal_live),
            _amplification(deadline_backing, deadline_live),
        ),
        compaction_work=None,
        compaction_seconds=None,
        high_water_mark=census.high_water_processes + census.high_water_sessions,
        estimated_index_bytes=census.estimated_index_bytes,
    )
    sampled_state = [
        (
            ordinal,
            (snapshot := registry.get_session(f"session-{ordinal:012d}")) is not None,
            None
            if snapshot is None or snapshot.closed_at is None
            else snapshot.closed_at.isoformat(),
        )
        for ordinal in sorted(set(query_ordinals[: min(128, len(query_ordinals))]))
    ]
    semantic = {
        "sample": sampled_state,
        "live": metrics.live_entries,
        "retained": metrics.retained_entries,
        "leased": metrics.leased_entries,
        "evicted": census.evicted_processes + census.evicted_sessions,
    }
    details = {
        "primary_cold": primary_cold,
        "primary": primary,
        "secondary_cold": secondary_cold,
        "secondary": secondary,
        "page": None,
        "load_seconds": load_seconds,
        "rss_after_load": rss_after_load,
        "peak_after_load": peak_after_load,
        "churn_seconds": churn_seconds,
        "expiry_entries": len(evicted),
        "expiry_seconds": expiry_seconds,
        "semantic": semantic,
        "notes": (
            "Lifecycle out-of-order mode varies canonical start order across exact groups; "
            "overlapping out-of-order reuse within one PID/LogonID group is invalid by contract.",
        ),
    }
    return registry, metrics, details


def _run_channel_scale(spec: CaseSpec) -> tuple[object, WorkloadMetrics, dict[str, object]]:
    registry = ApplicationChannelRegistry(
        window_start=_START,
        window_end=_START + timedelta(hours=4),
        closed_grace=timedelta(seconds=30),
        max_reusable_per_affinity=8,
        shard_count=64,
    )
    ordinals = range(spec.entries)
    load_started = perf_counter()
    _parallel_for(
        ordinals,
        spec.workers,
        lambda ordinal: registry.open_channel(
            _channel_identity(ordinal, spec.group_mode, spec.write_mode)
        ),
    )
    load_seconds = perf_counter() - load_started
    rss_after_load = _rss_bytes()
    peak_after_load = _peak_rss_bytes()
    query_ordinals = _query_ordinals(spec.entries, spec.queries)
    primary_cold = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        lambda ordinal: registry.get(f"channel-{ordinal:012d}"),
    )
    primary = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        lambda ordinal: registry.get(f"channel-{ordinal:012d}"),
        warmup_passes=3,
    )

    def reusable(ordinal: int) -> object:
        owner = ordinal if spec.group_mode == "uniform" else 0
        affinity = ordinal if spec.group_mode == "uniform" else ordinal // 8
        return registry.find_reusable(
            affinity_digest=f"affinity-{affinity:012d}",
            owner_id=f"owner-{owner:012d}",
            at=_START + timedelta(minutes=10),
        )

    secondary_cold = _timed_parallel_queries(query_ordinals, spec.workers, reusable)
    secondary = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        reusable,
        warmup_passes=3,
    )
    page_samples: list[int] = []
    for ordinal in query_ordinals:
        owner = ordinal if spec.group_mode == "uniform" else 0
        started = perf_counter_ns()
        page, _cursor = registry.open_owner_page(f"owner-{owner:012d}", limit=8)
        page_samples.append(perf_counter_ns() - started)
        if not page:
            raise AssertionError("application owner page unexpectedly empty")
    # Include lazily decoded bounded hot views in the memory result.  The load
    # timer remains admission-only, while RSS represents the warmed hot state.
    rss_after_load = max(rss_after_load, _rss_bytes())
    peak_after_load = max(peak_after_load, _peak_rss_bytes())

    churn_ordinals = range(min(spec.churn_entries, spec.entries))

    def operate(ordinal: int) -> None:
        operation_id = f"operation-{ordinal:012d}"
        registry.reserve_operation(
            ApplicationOperationReservation(
                operation_id=operation_id,
                channel_id=f"channel-{ordinal:012d}",
                ordinal=0,
                started_at=_START + timedelta(minutes=10),
                ended_at=_START + timedelta(minutes=11),
                initiator_bytes=128,
                responder_bytes=256,
            )
        )
        if not registry.finalize_operation(operation_id):
            raise AssertionError("application operation did not finalize")

    operation_started = perf_counter()
    _parallel_for(churn_ordinals, spec.workers, operate)
    operation_seconds = perf_counter() - operation_started

    # Protocol managers retain these compact ABA-safe tokens while channels are
    # open.  Build equivalent bounded request pages outside the shared close
    # timer so the reported common-registry mutation cost is not conflated with
    # a manager's sidecar traversal or frozen closure construction.
    close_prepare_started = perf_counter()
    close_pages: list[tuple[ApplicationChannelCloseRequest, ...]] = []
    churn_count = min(spec.churn_entries, spec.entries)
    for page_start in range(0, churn_count, 4_096):
        requests: list[ApplicationChannelCloseRequest] = []
        for ordinal in range(page_start, min(page_start + 4_096, churn_count)):
            channel_id = f"channel-{ordinal:012d}"
            token = registry.channel_close_token(channel_id)
            if token is None:
                raise AssertionError("application channel close token unexpectedly missing")
            requests.append(
                ApplicationChannelCloseRequest(
                    channel_id=channel_id,
                    token=token,
                    closed_at=_START + timedelta(minutes=20),
                    reason="probe-complete",
                )
            )
        close_pages.append(tuple(requests))
    close_prepare_seconds = perf_counter() - close_prepare_started

    def close_page(requests: tuple[ApplicationChannelCloseRequest, ...]) -> None:
        results = registry.close_channels_by_token(requests)
        if len(results) != len(requests) or not all(result.newly_closed for result in results):
            raise AssertionError("application channel batch close was not exact")

    close_started = perf_counter()
    for requests in close_pages:
        close_page(requests)
    close_seconds = perf_counter() - close_started
    churn_seconds = operation_seconds + close_prepare_seconds + close_seconds
    expiry_started = perf_counter()
    before_expiry = registry.census().retained_channels
    census = registry.watermark(_START + timedelta(minutes=21))
    expiry_seconds = perf_counter() - expiry_started
    expired = before_expiry - census.retained_channels
    metrics = WorkloadMetrics(
        logical_entries=census.retained_channels,
        live_entries=census.open_channels,
        retained_entries=census.retained_closed_channels,
        stale_entries=census.stale_expiry_entries,
        leased_entries=0,
        backing_entries=census.expiry_entries + census.route_entries,
        estimated_bytes=census.estimated_bytes,
        maximum_bucket_size=census.maximum_affinity_bucket,
        lookup_candidates_inspected=census.lookup_candidates_inspected,
        heap_segment_amplification=_amplification(
            census.expiry_entries,
            census.retained_channels,
        ),
        compaction_work=(census.route_compaction_work + census.store_primary_compaction_work),
        compaction_seconds=(
            census.route_compaction_seconds + census.store_primary_compaction_seconds
        ),
        high_water_mark=census.high_water_mark,
        estimated_index_bytes=census.estimated_index_bytes,
    )
    sampled = [
        (ordinal, registry.get(f"channel-{ordinal:012d}") is not None)
        for ordinal in sorted(set(query_ordinals[: min(128, len(query_ordinals))]))
    ]
    semantic = {
        "sample": sampled,
        "open": census.open_channels,
        "retained": census.retained_closed_channels,
        "active_operations": census.active_operations,
        "used_operation_ids": census.used_operation_ids,
    }
    details = {
        "primary_cold": primary_cold,
        "primary": primary,
        "secondary_cold": secondary_cold,
        "secondary": secondary,
        "page": page_samples,
        "load_seconds": load_seconds,
        "rss_after_load": rss_after_load,
        "peak_after_load": peak_after_load,
        "churn_seconds": churn_seconds,
        "operation_seconds": operation_seconds,
        "close_prepare_seconds": close_prepare_seconds,
        "close_seconds": close_seconds,
        "expiry_entries": expired,
        "expiry_seconds": expiry_seconds,
        "semantic": semantic,
        "notes": (
            "Application estimates include compact values and all route/store map backing; the "
            "cross-registry index-only overhead gate remains separately open.",
        ),
    }
    return registry, metrics, details


def _run_artifact_scale(spec: CaseSpec) -> tuple[object, WorkloadMetrics, dict[str, object]]:
    registry = LocalArtifactVersionRegistry(
        capacity=max(1, spec.entries + 1),
        retention=timedelta(days=30),
    )
    ordinals = range(spec.entries)

    def publish(ordinal: int) -> None:
        registry.publish(
            _artifact(ordinal, spec.group_mode),
            _START + timedelta(microseconds=_timestamp_ordinal(ordinal, spec.write_mode)),
            retention=(
                timedelta(hours=2)
                if ordinal < min(spec.churn_entries, spec.entries)
                else timedelta(days=30)
            ),
        )

    load_started = perf_counter()
    _parallel_for(ordinals, spec.workers, publish)
    load_seconds = perf_counter() - load_started
    rss_after_load = _rss_bytes()
    peak_after_load = _peak_rss_bytes()
    query_ordinals = _query_ordinals(spec.entries, spec.queries)
    query_artifacts = {
        ordinal: _artifact(ordinal, spec.group_mode) for ordinal in set(query_ordinals)
    }
    primary_cold = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        lambda ordinal: registry.get(query_artifacts[ordinal].artifact_version_id),
    )
    primary = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        lambda ordinal: registry.get(query_artifacts[ordinal].artifact_version_id),
        warmup_passes=3,
    )
    secondary_cold = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        lambda ordinal: registry.get_version(
            query_artifacts[ordinal].artifact_id,
            query_artifacts[ordinal].version,
        ),
    )
    secondary = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        lambda ordinal: registry.get_version(
            query_artifacts[ordinal].artifact_id,
            query_artifacts[ordinal].version,
        ),
        warmup_passes=3,
    )
    page_samples: list[int] = []
    for ordinal in query_ordinals:
        started = perf_counter_ns()
        page, _cursor = registry.page_versions_for_object(
            query_artifacts[ordinal].artifact_id,
            limit=8,
        )
        page_samples.append(perf_counter_ns() - started)
        if not page:
            raise AssertionError("artifact object page unexpectedly empty")
    rss_after_load = max(rss_after_load, _rss_bytes())
    peak_after_load = max(peak_after_load, _peak_rss_bytes())

    churn_ordinals = range(min(spec.churn_entries, spec.entries))
    churn_started = perf_counter()

    def refresh_and_lease(ordinal: int) -> None:
        artifact = _artifact(ordinal, spec.group_mode)
        registry.publish(
            artifact,
            _START + timedelta(minutes=30),
            retention=timedelta(hours=2),
        )
        if ordinal % 10 == 0:
            registry.acquire_lease(
                artifact.artifact_version_id,
                f"owner-{ordinal:012d}",
                _START + timedelta(hours=4),
            )

    _parallel_for(churn_ordinals, spec.workers, refresh_and_lease)
    churn_seconds = perf_counter() - churn_started
    expiry_started = perf_counter()
    evicted = registry.advance_watermark(_START + timedelta(hours=4, minutes=30))
    expiry_seconds = perf_counter() - expiry_started
    census = registry.census(estimate_bytes=True)
    store_index, deadline_index, lease_index = registry.index_metrics(estimate_bytes=True)
    metrics = WorkloadMetrics(
        logical_entries=census.live_versions,
        live_entries=census.live_versions,
        retained_entries=0,
        stale_entries=(
            store_index.stale_entries + deadline_index.stale_entries + lease_index.stale_entries
        ),
        leased_entries=census.leased_versions,
        backing_entries=(
            store_index.backing_entries
            + deadline_index.backing_entries
            + lease_index.backing_entries
        ),
        estimated_bytes=census.estimated_bytes,
        maximum_bucket_size=store_index.max_bucket_size,
        lookup_candidates_inspected=(
            store_index.lookup_candidates_inspected
            + deadline_index.lookup_candidates_inspected
            + lease_index.lookup_candidates_inspected
        ),
        heap_segment_amplification=max(
            _amplification(deadline_index.backing_entries, deadline_index.live_entries),
            _amplification(lease_index.backing_entries, lease_index.live_entries),
        ),
        compaction_work=(
            store_index.compaction_work
            + deadline_index.compaction_work
            + lease_index.compaction_work
        ),
        compaction_seconds=(
            store_index.compaction_seconds
            + deadline_index.compaction_seconds
            + lease_index.compaction_seconds
        ),
        high_water_mark=census.high_water_mark,
        estimated_index_bytes=census.estimated_index_bytes,
    )
    sampled = [
        (
            ordinal,
            registry.get(query_artifacts[ordinal].artifact_version_id) is not None,
        )
        for ordinal in sorted(set(query_ordinals[: min(128, len(query_ordinals))]))
    ]
    semantic = {
        "sample": sampled,
        "live": census.live_versions,
        "leased": census.leased_versions,
        "pending": census.pending_expiry,
    }
    details = {
        "primary_cold": primary_cold,
        "primary": primary,
        "secondary_cold": secondary_cold,
        "secondary": secondary,
        "page": page_samples,
        "load_seconds": load_seconds,
        "rss_after_load": rss_after_load,
        "peak_after_load": peak_after_load,
        "churn_seconds": churn_seconds,
        "expiry_entries": len(evicted),
        "expiry_seconds": expiry_seconds,
        "semantic": semantic,
        "notes": (),
    }
    return registry, metrics, details


def _run_collection_scale(spec: CaseSpec) -> tuple[object, WorkloadMetrics, dict[str, object]]:
    sources = (
        _source(_write_ordinal(ordinal, spec.entries, spec.write_mode), spec.group_mode)
        for ordinal in range(spec.entries)
    )
    load_started = perf_counter()
    registry = CompiledCollectionDeployment(sources)
    load_seconds = perf_counter() - load_started
    rss_after_load = _rss_bytes()
    peak_after_load = _peak_rss_bytes()
    query_ordinals = _query_ordinals(spec.entries, spec.queries)
    primary_cold = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        lambda ordinal: registry.source_by_instance(f"source-{ordinal:012d}"),
    )
    primary = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        lambda ordinal: registry.source_by_instance(f"source-{ordinal:012d}"),
        warmup_passes=3,
    )
    secondary_cold = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        lambda ordinal: registry.collection_window_at(
            f"source-{ordinal:012d}",
            _START + timedelta(hours=1),
        ),
    )
    secondary = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        lambda ordinal: registry.collection_window_at(
            f"source-{ordinal:012d}",
            _START + timedelta(hours=1),
        ),
        warmup_passes=3,
    )
    page_samples: list[int] = []
    for ordinal in query_ordinals:
        group = ordinal if spec.group_mode == "uniform" else 0
        started = perf_counter_ns()
        page = tuple(islice(registry.iter_host_family(f"host-{group:012d}", "ecar"), 8))
        page_samples.append(perf_counter_ns() - started)
        if not page:
            raise AssertionError("collection host/family page unexpectedly empty")
    rss_after_load = max(rss_after_load, _rss_bytes())
    peak_after_load = max(peak_after_load, _peak_rss_bytes())
    census = registry.census
    metrics = WorkloadMetrics(
        logical_entries=census.source_instances,
        live_entries=census.source_instances,
        retained_entries=0,
        stale_entries=0,
        leased_entries=0,
        backing_entries=(
            census.exact_identity_keys + census.collection_windows + census.capability_words
        ),
        estimated_bytes=census.estimated_bytes,
        maximum_bucket_size=census.max_host_family_bucket,
        lookup_candidates_inspected=None,
        heap_segment_amplification=1.0,
        compaction_work=0,
        compaction_seconds=0.0,
        high_water_mark=census.source_instances,
        estimated_index_bytes=census.estimated_index_bytes,
    )
    sampled = [
        registry.source_by_instance(f"source-{ordinal:012d}").identity.canonical_key
        for ordinal in sorted(set(query_ordinals[: min(128, len(query_ordinals))]))
    ]
    semantic = {
        "sample": sampled,
        "sources": census.source_instances,
        "windows": census.collection_windows,
        "buckets": census.host_family_buckets,
    }
    details = {
        "primary_cold": primary_cold,
        "primary": primary,
        "secondary_cold": secondary_cold,
        "secondary": secondary,
        "page": page_samples,
        "load_seconds": load_seconds,
        "rss_after_load": rss_after_load,
        "peak_after_load": peak_after_load,
        "churn_seconds": 0.0,
        "expiry_entries": 0,
        "expiry_seconds": 0.0,
        "semantic": semantic,
        "notes": (
            "Compiled collection deployments are immutable scenario state; worker counts apply "
            "to lock-free reads and write mode applies to compile-input order.",
        ),
    }
    return registry, metrics, details


def _run_deployment_scale(spec: CaseSpec) -> tuple[object, WorkloadMetrics, dict[str, object]]:
    """Load every immutable deployment/content family and exercise exact indexes."""

    # Eleven physical rows are the minimum production-shaped population because
    # the public fixture represents every canonical family at least once. Small
    # ladder points remain requested-size diagnostics and report the exact
    # retained physical denominator through the public census.
    physical_target = max(spec.entries, 11)
    load_started = perf_counter()
    registry = build_deployment_population(
        physical_target,
        profile_shape=spec.group_mode,
    )
    load_seconds = perf_counter() - load_started
    peak_after_load = _peak_rss_bytes()
    gc.collect()
    rss_after_load = _rss_bytes()

    family_counts = deployment_population_family_counts(physical_target)
    host_count = family_counts["host_deployments"]
    profile_count = family_counts["user_profiles"]
    assignment_count = family_counts["user_application_assignments"]
    exact_identity_count = min(
        family_counts["binary_releases"],
        family_counts["installations"],
        profile_count,
    )
    assigned_profile_count = (
        1 if spec.group_mode == "skewed" else min(profile_count, assignment_count)
    )
    exact_ordinals = _query_ordinals(exact_identity_count, spec.queries)
    secondary_ordinals = _query_ordinals(assigned_profile_count, spec.queries)

    def exact_binary(ordinal: int) -> BinaryReleaseIdentity | None:
        profile_ordinal = 0 if spec.group_mode == "skewed" else ordinal
        principal = f"scale-user-{profile_ordinal:012d}"
        product_id = f"scale-product-{ordinal:012d}"
        path = rf"C:\Users\{principal}\Apps\{product_id}\scale-app.exe"
        return registry.resolve_binary(
            f"scale-host-{profile_ordinal % host_count:012d}",
            path,
            "windows",
            principal=principal,
        )

    primary_cold = _timed_parallel_queries(
        exact_ordinals,
        spec.workers,
        exact_binary,
    )
    primary = _timed_parallel_queries(
        exact_ordinals,
        spec.workers,
        exact_binary,
        warmup_passes=3,
    )

    def exact_profile(ordinal: int) -> UserProfileIdentity | None:
        return registry.user_profile_for(
            f"scale-host-{ordinal % host_count:012d}",
            f"scale-user-{ordinal:012d}",
            "windows",
        )

    profile_ids: dict[int, str] = {}
    for ordinal in set(secondary_ordinals):
        profile = exact_profile(ordinal)
        if profile is None:
            raise AssertionError("deployment scale profile unexpectedly missing")
        profile_ids[ordinal] = profile.profile_id

    def select_assignment(ordinal: int) -> object:
        profile_ordinal = 0 if spec.group_mode == "skewed" else ordinal
        return registry.select_user_application_assignment_for_category(
            profile_ids[profile_ordinal],
            "user_app",
            unit_interval=0.5,
        )

    secondary_ordinals = (
        tuple(0 for _ordinal in secondary_ordinals)
        if spec.group_mode == "skewed"
        else secondary_ordinals
    )
    secondary_cold = _timed_parallel_queries(
        secondary_ordinals,
        spec.workers,
        select_assignment,
    )
    secondary = _timed_parallel_queries(
        secondary_ordinals,
        spec.workers,
        select_assignment,
        warmup_passes=3,
    )
    page_samples: list[int] = []
    for ordinal in secondary_ordinals:
        started = perf_counter_ns()
        page, _cursor = registry.page_user_application_assignments_for_category(
            profile_ids[ordinal],
            "user_app",
            limit=8,
        )
        page_samples.append(perf_counter_ns() - started)
        if not page:
            raise AssertionError("deployment assignment page unexpectedly empty")
    rss_after_load = max(rss_after_load, _rss_bytes())
    peak_after_load = max(peak_after_load, _peak_rss_bytes())

    census = registry.scale_census()
    metrics = WorkloadMetrics(
        logical_entries=census.physical_records,
        live_entries=census.live_entries,
        retained_entries=census.retained_entries,
        stale_entries=census.stale_entries,
        leased_entries=census.leased_entries,
        backing_entries=census.backing_entries,
        estimated_bytes=census.estimated_bytes,
        maximum_bucket_size=census.maximum_bucket_size,
        lookup_candidates_inspected=census.lookup_candidates_inspected,
        heap_segment_amplification=None,
        compaction_work=0,
        compaction_seconds=0.0,
        high_water_mark=census.high_water_mark,
        estimated_index_bytes=census.estimated_index_bytes,
    )
    semantic = {
        "physical": census.physical_records,
        "relationships": census.relationship_bindings,
        "families": family_counts,
        "profile_shape": spec.group_mode,
    }
    details = {
        "primary_cold": primary_cold,
        "primary": primary,
        "secondary_cold": secondary_cold,
        "secondary": secondary,
        "page": page_samples,
        "load_seconds": load_seconds,
        "rss_after_load": rss_after_load,
        "peak_after_load": peak_after_load,
        "churn_entries": 0,
        "churn_seconds": 0.0,
        "expiry_entries": 0,
        "expiry_seconds": 0.0,
        "semantic": semantic,
        "notes": (
            "Deployment/content is immutable scenario-scoped state. Primary exact-binary, "
            "secondary exact-category selection, and bounded page reads use public indexes; "
            "write mode does not introduce mutable late writes.",
            f"Requested {spec.entries:,} rows; retained the minimum complete physical "
            f"population of {physical_target:,} rows."
            if physical_target != spec.entries
            else "The public census physical denominator exactly matches the requested rows.",
        ),
    }
    return registry, metrics, details


def _sidecar_registry() -> ApplicationChannelRegistry:
    return ApplicationChannelRegistry(
        window_start=_START,
        window_end=_START + timedelta(hours=4),
        closed_grace=timedelta(seconds=30),
        max_reusable_per_affinity=8,
        shard_count=64,
    )


def _run_http_sidecar(
    spec: CaseSpec,
    *,
    registry: ApplicationChannelRegistry | None = None,
) -> dict[str, object]:
    registry = registry or _sidecar_registry()
    manager = HttpApplicationChannelManager(
        window_start=registry.window_start,
        window_end=registry.window_end,
        registry=registry,
    )
    query_ordinals = _query_ordinals(spec.entries, spec.queries)
    sampled_ordinals = set(query_ordinals)
    query_ids: dict[int, str] = {}

    def register(ordinal: int) -> None:
        started_at = _sidecar_started_at(ordinal, spec.write_mode)
        opened = manager.open_transport(
            _http_affinity(ordinal, spec.group_mode),
            transport_id=f"http-sidecar-transport-{ordinal:012d}",
            zeek_uid=f"Chttp{ordinal:012d}",
            conn_id=f"http-conn-{ordinal:012d}",
            src_port=1_024 + ordinal % 60_000,
            opened_at=started_at,
            closes_at=started_at + timedelta(hours=2),
            initial_request_time=started_at + timedelta(microseconds=1),
            orig_budget=4_096,
            resp_budget=8_192,
            operation_budget=2,
        )
        if opened is None:
            raise AssertionError("HTTP scale transport was unexpectedly non-reusable")
        if ordinal in sampled_ordinals:
            query_ids[ordinal] = opened.channel_id

    load_started = perf_counter()
    _parallel_for(range(spec.entries), spec.workers, register)
    load_seconds = perf_counter() - load_started
    rss_after_load = _rss_bytes()
    peak_after_load = _peak_rss_bytes()
    lookups = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        lambda ordinal: manager.get_transport(query_ids[ordinal]),
        warmup_passes=3,
    )
    rss_after_load = max(rss_after_load, _rss_bytes())
    peak_after_load = max(peak_after_load, _peak_rss_bytes())
    census = manager.census()
    application = census.application
    return {
        "retained_root": manager,
        "load_seconds": load_seconds,
        "rss_after_load": rss_after_load,
        "peak_after_load": peak_after_load,
        "lookup": lookups,
        "common_live_entries": application.retained_channels,
        "common_used_operation_ids": application.used_operation_ids,
        "common_estimated_bytes": application.estimated_bytes,
        "common_estimated_index_bytes": application.estimated_index_bytes,
        "sidecar_live_entries": census.open_transport_views,
        "sidecar_logical_records": census.open_transport_views,
        "sidecar_backing_entries": (census.open_transport_views + census.transport_expiry_entries),
        "sidecar_stale_entries": census.stale_transport_expiry_entries,
        "sidecar_estimated_bytes": census.estimated_bytes,
        "sidecar_estimated_index_bytes": census.sidecar_estimated_index_bytes,
        "sidecar_lookup_candidates_inspected": census.sidecar_lookup_candidates_inspected,
        "semantic": {
            "channels": sorted(query_ids.values()),
            "open": census.open_transport_views,
            "expiry": census.transport_expiry_entries,
        },
        "notes": (
            "Actual HTTP manager entries retain the shared application row and the open-only "
            "HTTP transport view; incremental sidecar estimates exclude the common registry.",
        ),
    }


def _run_proxy_sidecar(
    spec: CaseSpec,
    *,
    registry: ApplicationChannelRegistry | None = None,
) -> dict[str, object]:
    registry = registry or _sidecar_registry()
    manager = ExplicitProxyChannelManager(
        window_start=registry.window_start,
        window_end=registry.window_end,
        registry=registry,
        shard_count=registry.shard_count,
    )
    query_ordinals = _query_ordinals(spec.entries, spec.queries)
    sampled_ordinals = set(query_ordinals)
    query_ids: dict[int, str] = {}

    def register(ordinal: int) -> None:
        started_at = _sidecar_started_at(ordinal, spec.write_mode)
        opened = manager.open_tunnel(
            _proxy_affinity(ordinal, spec.group_mode),
            client_transport_id=f"proxy-client-transport-{ordinal:012d}",
            origin_transport_id=f"proxy-origin-transport-{ordinal:012d}",
            client_zeek_uid=f"Cproxy{ordinal:012d}",
            origin_zeek_uid=f"Corigin{ordinal:012d}",
            tunnel_group_id=f"proxy-group-{ordinal:012d}",
            client_source_port=1_024 + ordinal % 60_000,
            origin_source_port=1_024 + (ordinal + 7_919) % 60_000,
            opened_at=started_at,
            closes_at=started_at + timedelta(hours=2),
            setup_started_at=started_at + timedelta(microseconds=1),
            setup_completed_at=started_at + timedelta(microseconds=2),
            setup_request_wire_bytes=0,
            setup_response_wire_bytes=0,
            planned_request_count=1,
            aggregate_request_wire_bytes=1,
            aggregate_response_wire_bytes=1,
        )
        if opened is None:
            raise AssertionError("proxy scale tunnel was unexpectedly non-reusable")
        if ordinal in sampled_ordinals:
            query_ids[ordinal] = opened.tunnel.channel_id

    load_started = perf_counter()
    _parallel_for(range(spec.entries), spec.workers, register)
    load_seconds = perf_counter() - load_started
    rss_after_load = _rss_bytes()
    peak_after_load = _peak_rss_bytes()
    lookups = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        lambda ordinal: manager.get_tunnel(query_ids[ordinal]),
        warmup_passes=3,
    )
    rss_after_load = max(rss_after_load, _rss_bytes())
    peak_after_load = max(peak_after_load, _peak_rss_bytes())
    census = manager.census()
    application = census.application
    return {
        "retained_root": manager,
        "load_seconds": load_seconds,
        "rss_after_load": rss_after_load,
        "peak_after_load": peak_after_load,
        "lookup": lookups,
        "common_live_entries": application.retained_channels,
        "common_used_operation_ids": application.used_operation_ids,
        "common_estimated_bytes": application.estimated_bytes,
        "common_estimated_index_bytes": application.estimated_index_bytes,
        "sidecar_live_entries": census.open_tunnel_views,
        "sidecar_logical_records": census.open_tunnel_views,
        "sidecar_backing_entries": (census.sidecar_allocated_slots + census.tunnel_expiry_entries),
        "sidecar_stale_entries": census.stale_tunnel_expiry_entries,
        "sidecar_estimated_bytes": census.sidecar_estimated_bytes,
        "sidecar_estimated_index_bytes": census.sidecar_estimated_index_bytes,
        "sidecar_lookup_candidates_inspected": census.sidecar_lookup_candidates_inspected,
        "semantic": {
            "channels": sorted(query_ids.values()),
            "open": census.open_tunnel_views,
            "expiry": census.tunnel_expiry_entries,
        },
        "notes": (
            "Actual proxy manager entries retain one shared application row and one open-only "
            "tunnel view; incremental sidecar estimates exclude the common registry.",
        ),
    }


def _run_rdp_sidecar(
    spec: CaseSpec,
    *,
    registry: ApplicationChannelRegistry | None = None,
) -> dict[str, object]:
    registry = registry or _sidecar_registry()
    manager = RdpReconnectStateManager(
        application_registry=registry,
        window_start=registry.window_start,
        window_end=registry.window_end,
        max_retention_extension=timedelta(hours=1),
    )
    query_ordinals = _query_ordinals(spec.entries, spec.queries)

    def register(ordinal: int) -> None:
        manager.open_session(
            _rdp_identity(ordinal, spec.group_mode, spec.write_mode),
            _rdp_transport(ordinal, spec.write_mode),
        )

    load_started = perf_counter()
    _parallel_for(range(spec.entries), spec.workers, register)
    load_seconds = perf_counter() - load_started
    rss_after_load = _rss_bytes()
    peak_after_load = _peak_rss_bytes()
    lookups = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        lambda ordinal: manager.get(f"rdp-sidecar-{ordinal:012d}"),
        warmup_passes=3,
    )
    rss_after_load = max(rss_after_load, _rss_bytes())
    peak_after_load = max(peak_after_load, _peak_rss_bytes())
    census = manager.census()
    application = census.application
    sidecar_estimated_bytes = census.estimated_bytes
    sidecar_estimated_index_bytes = census.estimated_index_bytes
    return {
        "retained_root": manager,
        "load_seconds": load_seconds,
        "rss_after_load": rss_after_load,
        "peak_after_load": peak_after_load,
        "lookup": lookups,
        "common_live_entries": application.retained_channels,
        "common_used_operation_ids": application.used_operation_ids,
        "common_estimated_bytes": application.estimated_bytes,
        "common_estimated_index_bytes": application.estimated_index_bytes,
        "sidecar_live_entries": census.retained_sessions,
        "sidecar_logical_records": (
            census.retained_sessions + census.active_operations + census.active_leases
        ),
        "sidecar_backing_entries": (
            census.retained_sessions
            + census.session_expiry_entries
            + census.lease_expiry_entries
            + census.blocker_expiry_entries
        ),
        "sidecar_stale_entries": (
            census.stale_session_expiry_entries
            + census.stale_lease_expiry_entries
            + census.stale_blocker_expiry_entries
        ),
        "sidecar_estimated_bytes": sidecar_estimated_bytes,
        "sidecar_estimated_index_bytes": sidecar_estimated_index_bytes,
        "sidecar_lookup_candidates_inspected": census.logical_lookup_candidates_inspected,
        "sidecar_leased_entries": census.active_leases,
        "semantic": {
            "sessions": [f"rdp-sidecar-{ordinal:012d}" for ordinal in query_ordinals],
            "retained": census.retained_sessions,
            "connected": census.connected_sessions,
        },
        "notes": (
            "Actual RDP logical-session entries and shared application channels are loaded "
            "together; the RDP census already reports incremental sidecar estimates separately "
            "from its nested public application census.",
        ),
    }


def _run_smb_sidecar(
    spec: CaseSpec,
    *,
    registry: ApplicationChannelRegistry | None = None,
) -> dict[str, object]:
    registry = registry or _sidecar_registry()
    manager = SmbApplicationChannelManager(
        application_registry=registry,
        window_start=registry.window_start,
        window_end=registry.window_end,
    )
    query_ordinals = _query_ordinals(spec.entries, spec.queries)
    sampled_ordinals = set(query_ordinals)
    query_ids: dict[int, str] = {}

    def register(ordinal: int) -> None:
        started_at = _sidecar_started_at(ordinal, spec.write_mode)
        owner = _sidecar_owner(ordinal, spec.group_mode)
        client_session = f"0x{ordinal + 1:016x}"
        server_hostname = f"file-{ordinal:012d}"
        principal = f"example\\user-{ordinal:012d}"
        transport_plan = _smb_transport(
            ordinal,
            spec.write_mode,
            started_at=started_at,
            server_hostname=server_hostname,
        )
        lease = manager.open_session(
            _smb_affinity(
                ordinal,
                spec.group_mode,
                owner=owner,
                client_session=client_session,
                server_identity=server_hostname,
                principal=principal,
            ),
            transport_plan=transport_plan,
            sensor_observations=(),
            ground_truth_transport_uid=transport_plan.zeek_uid,
            logon_id=client_session,
            auth_session_ref=f"smb-auth-{ordinal:012d}",
            principal=principal,
            auth_protocol="kerberos",
            account_scope="example",
            effective_uid=None,
            effective_gid=None,
            client_access="windows_native",
            server_hostname=server_hostname,
            client_ip=transport_plan.src_ip,
            lifecycle_group_id=transport_plan.stable_id,
            share_ref=f"file-{ordinal:012d}.documents",
            semantic_operation_id=f"smb-operation-{ordinal:012d}",
            operation_started_at=started_at + _ONE_MICROSECOND,
            operation_ended_at=started_at + _TWO_MICROSECONDS,
            operation_initiator_bytes=0,
            operation_responder_bytes=0,
            idle_timeout=_ONE_HOUR,
            initiator_budget=4_096,
            responder_budget=8_192,
            operation_budget=2,
            operation_completes_immediately=True,
            _trusted_canonical_inputs=True,
        )
        if not lease.operation_completed:
            raise AssertionError("SMB scale operation did not reconcile during admission")
        if ordinal in sampled_ordinals:
            query_ids[ordinal] = lease.channel_id

    load_started = perf_counter()
    _parallel_for(range(spec.entries), spec.workers, register)
    load_seconds = perf_counter() - load_started
    rss_after_load = _rss_bytes()
    peak_after_load = _peak_rss_bytes()
    lookups = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        lambda ordinal: manager.session_view(query_ids[ordinal]),
        warmup_passes=3,
    )
    rss_after_load = max(rss_after_load, _rss_bytes())
    peak_after_load = max(peak_after_load, _peak_rss_bytes())
    census = manager.census()
    application = census.application
    return {
        "retained_root": manager,
        "load_seconds": load_seconds,
        "rss_after_load": rss_after_load,
        "peak_after_load": peak_after_load,
        "lookup": lookups,
        "common_live_entries": application.retained_channels,
        "common_used_operation_ids": application.used_operation_ids,
        "common_estimated_bytes": application.estimated_bytes,
        "common_estimated_index_bytes": application.estimated_index_bytes,
        "sidecar_live_entries": census.open_sessions,
        "sidecar_logical_records": (census.open_sessions + census.open_trees + census.open_handles),
        "sidecar_backing_entries": (
            census.session_backing_entries
            + census.tree_backing_entries
            + census.handle_backing_entries
            + census.expiry_entries
        ),
        "sidecar_stale_entries": census.stale_sidecar_entries + census.stale_expiry_entries,
        "sidecar_estimated_bytes": census.sidecar_estimated_bytes,
        "sidecar_estimated_index_bytes": census.sidecar_estimated_index_bytes,
        "sidecar_lookup_candidates_inspected": census.sidecar_lookup_candidates_inspected,
        "semantic": {
            "channels": sorted(query_ids.values()),
            "sessions": census.open_sessions,
            "trees": census.open_trees,
            "handles": census.open_handles,
        },
        "notes": (
            "Actual SMB manager entries include one open session and tree per shared application "
            "channel; incremental sidecar estimates exclude the common registry.",
        ),
    }


def _run_ssh_sidecar(
    spec: CaseSpec,
    *,
    registry: ApplicationChannelRegistry | None = None,
) -> dict[str, object]:
    registry = registry or _sidecar_registry()
    manager = SshApplicationChannelManager(
        application_registry=registry,
        window_start=registry.window_start,
        window_end=registry.window_end,
    )
    query_ordinals = _query_ordinals(spec.entries, spec.queries)
    sampled_ordinals = set(query_ordinals)
    query_ids: dict[int, str] = {}

    def register(ordinal: int) -> None:
        affinity, transport, binding = _ssh_session_values(
            ordinal,
            spec.group_mode,
            spec.write_mode,
        )
        session, _lease = manager.open_session_with_completed_operation(
            affinity,
            transport=transport,
            binding=binding,
            idle_timeout=timedelta(hours=1),
            initiator_budget=4_096,
            responder_budget=8_192,
            operation_budget=2,
            kind=SshOperationKind.EXEC,
            semantic_operation_id=f"ssh-operation-{ordinal:012d}",
            started_at=binding.ready_at + timedelta(microseconds=1),
            ended_at=binding.ready_at + timedelta(microseconds=2),
            initiator_bytes=0,
            responder_bytes=0,
        )
        if ordinal in sampled_ordinals:
            query_ids[ordinal] = session.channel_id

    load_started = perf_counter()
    _parallel_for(range(spec.entries), spec.workers, register)
    load_seconds = perf_counter() - load_started
    rss_after_load = _rss_bytes()
    peak_after_load = _peak_rss_bytes()
    lookups = _timed_parallel_queries(
        query_ordinals,
        spec.workers,
        lambda ordinal: manager.session_view(query_ids[ordinal]),
        warmup_passes=3,
    )
    rss_after_load = max(rss_after_load, _rss_bytes())
    peak_after_load = max(peak_after_load, _peak_rss_bytes())
    census = manager.census()
    application = census.application
    return {
        "retained_root": manager,
        "load_seconds": load_seconds,
        "rss_after_load": rss_after_load,
        "peak_after_load": peak_after_load,
        "lookup": lookups,
        "common_live_entries": application.retained_channels,
        "common_used_operation_ids": application.used_operation_ids,
        "common_estimated_bytes": application.estimated_bytes,
        "common_estimated_index_bytes": application.estimated_index_bytes,
        "sidecar_live_entries": census.open_sessions,
        "sidecar_logical_records": census.open_sessions + census.active_operations,
        "sidecar_backing_entries": (
            census.session_backing_entries
            + census.operation_backing_entries
            + census.expiry_entries
        ),
        "sidecar_stale_entries": census.stale_sidecar_entries + census.stale_expiry_entries,
        "sidecar_estimated_bytes": census.sidecar_estimated_bytes,
        "sidecar_estimated_index_bytes": census.sidecar_estimated_index_bytes,
        "sidecar_lookup_candidates_inspected": census.sidecar_lookup_candidates_inspected,
        "semantic": {
            "channels": sorted(query_ids.values()),
            "sessions": census.open_sessions,
            "operations": census.active_operations,
        },
        "notes": (
            "Actual SSH manager entries retain one completed initial child only as common "
            "aggregate counters and a used-ID marker; incremental sidecar estimates exclude "
            "the common registry.",
        ),
    }


_SIDECAR_RUNNERS: dict[ImplementedProtocolName, Callable[[CaseSpec], dict[str, object]]] = {
    "http": _run_http_sidecar,
    "proxy": _run_proxy_sidecar,
    "smb": _run_smb_sidecar,
    "rdp": _run_rdp_sidecar,
    "ssh": _run_ssh_sidecar,
}


def _run_sidecar_case(spec: CaseSpec) -> SidecarResult:
    implementation_digest_start = _implementation_digest()
    if spec.registry not in _SIDECAR_RUNNERS:
        raise ValueError(f"No implemented protocol-sidecar runner for {spec.registry!r}")
    gc.collect()
    rss_before = _rss_bytes()
    peak_before = _peak_rss_bytes()
    details = _SIDECAR_RUNNERS[spec.registry](spec)
    implementation_digest_end = _implementation_digest()
    live_entries = int(details["sidecar_live_entries"])
    sidecar_estimated_bytes = int(details["sidecar_estimated_bytes"])
    sidecar_estimated_index_bytes = int(details["sidecar_estimated_index_bytes"])
    common_live_entries = int(details["common_live_entries"])
    common_used_operation_ids = int(details["common_used_operation_ids"])
    sidecar_logical_records = int(details["sidecar_logical_records"])
    physical_hot_records = common_live_entries + common_used_operation_ids + sidecar_logical_records
    rss_delta_bytes = max(0, int(details["rss_after_load"]) - rss_before)
    load_seconds = float(details["load_seconds"])
    lookup = details["lookup"]
    assert isinstance(lookup, list)
    return SidecarResult(
        kind="sidecar",
        registry=spec.registry,
        entries=spec.entries,
        queries=min(max(1, spec.queries), max(1, spec.entries * 4)),
        group_mode=spec.group_mode,
        write_mode=spec.write_mode,
        workers=spec.workers,
        hash_seed=spec.hash_seed,
        representation="actual_manager",
        load_seconds=load_seconds,
        lookup_p95_us=_p95_us(lookup),
        rss_delta_bytes=rss_delta_bytes,
        peak_rss_delta_bytes=max(0, int(details["peak_after_load"]) - peak_before),
        common_live_entries=common_live_entries,
        common_used_operation_ids=common_used_operation_ids,
        common_estimated_bytes=int(details["common_estimated_bytes"]),
        common_estimated_index_bytes=int(details["common_estimated_index_bytes"]),
        sidecar_live_entries=live_entries,
        sidecar_logical_records=sidecar_logical_records,
        sidecar_backing_entries=int(details["sidecar_backing_entries"]),
        sidecar_estimated_bytes=sidecar_estimated_bytes,
        sidecar_estimated_index_bytes=sidecar_estimated_index_bytes,
        sidecar_lookup_candidates_inspected=int(details["sidecar_lookup_candidates_inspected"]),
        sidecar_bytes_per_live_entry=sidecar_estimated_bytes / max(1, live_entries),
        sidecar_index_bytes_per_live_entry=(sidecar_estimated_index_bytes / max(1, live_entries)),
        physical_hot_records=physical_hot_records,
        rss_bytes_per_physical_record=rss_delta_bytes / max(1, physical_hot_records),
        load_seconds_per_million_physical_records=(
            load_seconds * 1_000_000 / max(1, physical_hot_records)
        ),
        registry_digest=_digest(details["semantic"]),
        implementation_digest_start=implementation_digest_start,
        implementation_digest_end=implementation_digest_end,
        notes=tuple(details["notes"]),
    )


_SCALE_RUNNERS: dict[
    RegistryName,
    Callable[[CaseSpec], tuple[object, WorkloadMetrics, dict[str, object]]],
] = {
    "lifecycle": _run_lifecycle_scale,
    "channels": _run_channel_scale,
    "artifacts": _run_artifact_scale,
    "collection": _run_collection_scale,
    "deployment": _run_deployment_scale,
}


def _run_scale_case(spec: CaseSpec) -> ScaleResult:
    implementation_digest_start = _implementation_digest()
    gc.collect()
    rss_before = _rss_bytes()
    peak_before = _peak_rss_bytes()
    registry, metrics, details = _SCALE_RUNNERS[spec.registry](spec)
    # The runner sampled the fully loaded hot state before bounded churn while
    # retaining the post-watermark census returned below.
    _ = registry
    churn_seconds = float(details["churn_seconds"])
    operation_seconds_value = details.get("operation_seconds")
    close_prepare_seconds_value = details.get("close_prepare_seconds")
    close_seconds_value = details.get("close_seconds")
    expiry_seconds = float(details["expiry_seconds"])
    primary_cold = details["primary_cold"]
    primary = details["primary"]
    secondary_cold = details["secondary_cold"]
    secondary = details["secondary"]
    page = details["page"]
    assert isinstance(primary_cold, list) and isinstance(primary, list)
    assert isinstance(secondary_cold, list) and isinstance(secondary, list)
    assert page is None or isinstance(page, list)
    rss_after_load = int(details["rss_after_load"])
    peak_after_load = int(details["peak_after_load"])
    implementation_digest_end = _implementation_digest()
    return ScaleResult(
        kind="scale",
        registry=spec.registry,
        entries=spec.entries,
        queries=min(max(1, spec.queries), max(1, spec.entries * 4)),
        group_mode=spec.group_mode,
        write_mode=spec.write_mode,
        workers=spec.workers,
        hash_seed=spec.hash_seed,
        load_seconds=float(details["load_seconds"]),
        primary_cold_lookup_p95_us=_p95_us(primary_cold),
        primary_lookup_p95_us=_p95_us(primary),
        secondary_cold_lookup_p95_us=_p95_us(secondary_cold),
        secondary_lookup_p95_us=_p95_us(secondary),
        page_lookup_p95_us=None if page is None else _p95_us(page),
        churn_entries=int(details.get("churn_entries", min(spec.churn_entries, spec.entries))),
        churn_seconds=churn_seconds,
        operation_seconds=(
            None if operation_seconds_value is None else float(operation_seconds_value)
        ),
        close_prepare_seconds=(
            None if close_prepare_seconds_value is None else float(close_prepare_seconds_value)
        ),
        close_seconds=None if close_seconds_value is None else float(close_seconds_value),
        expiry_entries=int(details["expiry_entries"]),
        expiry_seconds=expiry_seconds,
        rss_delta_bytes=max(0, rss_after_load - rss_before),
        peak_rss_delta_bytes=max(0, peak_after_load - peak_before),
        bytes_per_requested_entry=max(0, rss_after_load - rss_before) / spec.entries,
        metrics=metrics,
        registry_digest=_digest(details["semantic"]),
        implementation_digest_start=implementation_digest_start,
        implementation_digest_end=implementation_digest_end,
        notes=tuple(details["notes"]),
    )


def _mixed_family_from_metrics(
    *,
    requested_logical: int,
    metrics: WorkloadMetrics,
    physical_records: int | None = None,
    notes: tuple[str, ...] = (),
) -> MixedFamilyCensus:
    """Translate one public registry census into the mixed-report schema."""

    physical = metrics.logical_entries if physical_records is None else physical_records
    return MixedFamilyCensus(
        requested_logical=requested_logical,
        physical_records=physical,
        live_entries=metrics.live_entries,
        retained_entries=metrics.retained_entries,
        backing_entries=metrics.backing_entries,
        stale_entries=metrics.stale_entries,
        leased_entries=metrics.leased_entries,
        estimated_bytes=metrics.estimated_bytes,
        estimated_index_bytes=metrics.estimated_index_bytes,
        lookup_candidates_inspected=metrics.lookup_candidates_inspected,
        notes=notes,
    )


def _load_mixed_lifecycle(
    requested_logical: int,
) -> tuple[object, MixedFamilyCensus, object]:
    """Load the production process/session/service/transport lifecycle shape."""

    registry = LifecycleRegistry(closed_retention=timedelta(hours=2))
    production = populate_lifecycle_production_shape(
        registry,
        entries=requested_logical,
        canonical_start=_START,
    )
    metrics = _lifecycle_metrics(registry)
    family = _mixed_family_from_metrics(
        requested_logical=requested_logical,
        metrics=metrics,
        physical_records=production.physical_records,
        notes=(
            "Each logical admission retains packed session, process, service-instance, and "
            "transport rows plus service-process and transport-session binding rows. Logical "
            "service identity is co-packed with the service instance and is not double-counted.",
        ),
    )
    semantic = {
        "physical": production.physical_records,
        "processes": production.process_entries,
        "sessions": production.session_entries,
        "services": production.service_instance_entries,
        "transports": production.transport_entries,
        "service_process_bindings": production.service_process_bindings,
        "transport_session_bindings": production.transport_session_bindings,
    }
    return registry, family, semantic


def _load_mixed_artifacts(
    requested_logical: int,
    *,
    workers: int,
    hash_seed: int,
) -> tuple[object, MixedFamilyCensus, object, float]:
    """Load canonical local-artifact versions plus a representative lease slice."""

    registry_spec = CaseSpec(
        kind="scale",
        registry="artifacts",
        entries=requested_logical,
        queries=min(64, requested_logical),
        group_mode="uniform",
        write_mode="monotonic",
        workers=workers,
        hash_seed=hash_seed,
        churn_entries=0,
    )
    registry_object, _metrics, details = _run_artifact_scale(registry_spec)
    if not isinstance(registry_object, LocalArtifactVersionRegistry):
        raise AssertionError("artifact mixed adapter returned the wrong registry type")
    registry = registry_object
    for ordinal in range(0, requested_logical, 10):
        artifact = _artifact(ordinal, "uniform")
        registry.acquire_lease(
            artifact.artifact_version_id,
            f"mixed-artifact-lease-{ordinal:012d}",
            _START + timedelta(days=31),
        )
    census = registry.census(estimate_bytes=True)
    metrics = _artifact_metrics(registry)
    family = _mixed_family_from_metrics(
        requested_logical=requested_logical,
        metrics=metrics,
        physical_records=census.live_versions + census.active_leases,
        notes=(
            "Physical records are packed canonical artifact versions plus explicit active lease "
            "rows; indexes and deadline heaps are backing entries only.",
        ),
    )
    semantic = {
        "versions": census.live_versions,
        "leases": census.active_leases,
        "leased_versions": census.leased_versions,
    }
    return registry, family, semantic, float(details["load_seconds"])


def _load_mixed_collection(
    requested_logical: int,
    *,
    workers: int,
    hash_seed: int,
) -> tuple[object, MixedFamilyCensus, object, float]:
    """Load immutable source-instance deployment rows through the scale adapter."""

    registry_spec = CaseSpec(
        kind="scale",
        registry="collection",
        entries=requested_logical,
        queries=min(64, requested_logical),
        group_mode="uniform",
        write_mode="monotonic",
        workers=workers,
        hash_seed=hash_seed,
        churn_entries=0,
    )
    registry, metrics, details = _run_collection_scale(registry_spec)
    family = _mixed_family_from_metrics(
        requested_logical=requested_logical,
        metrics=metrics,
        physical_records=metrics.logical_entries,
        notes=(
            "Physical records are immutable compiled source-instance rows; capability words, "
            "windows, and reverse ordinal arrays are structural backing, not extra records.",
        ),
    )
    return registry, family, details["semantic"], float(details["load_seconds"])


def _load_mixed_deployment_content(
    requested_logical: int,
) -> tuple[object, MixedFamilyCensus, object]:
    """Load every immutable deployment/content canonical family without payload bytes."""

    registry = build_deployment_population(requested_logical)
    census = registry.scale_census()
    if census.physical_records != requested_logical:
        raise AssertionError(
            "deployment population factory did not honor its exact physical-row contract"
        )
    family = MixedFamilyCensus(
        requested_logical=requested_logical,
        physical_records=census.physical_records,
        live_entries=census.live_entries,
        retained_entries=census.retained_entries,
        backing_entries=census.backing_entries,
        stale_entries=census.stale_entries,
        leased_entries=census.leased_entries,
        estimated_bytes=census.estimated_bytes,
        estimated_index_bytes=census.estimated_index_bytes,
        lookup_candidates_inspected=census.lookup_candidates_inspected,
        notes=(
            "Physical records are the 11 immutable canonical deployment/content row families. "
            "Relationship bindings are included in backing/byte estimates but not double-counted "
            "as canonical physical rows; no payload bytes are retained.",
        ),
    )
    semantic = {
        "physical": census.physical_records,
        "binary_releases": census.binary_releases,
        "installed_software_releases": census.installed_software_releases,
        "installations": census.installations,
        "user_profiles": census.user_profiles,
        "application_profiles": census.application_profiles,
        "file_versions": census.file_versions,
        "local_artifact_versions": census.local_artifact_versions,
        "host_deployments": census.host_deployments,
        "user_application_assignments": census.user_application_assignments,
        "service_identities": census.service_identities,
        "task_identities": census.task_identities,
        "relationships": census.relationship_bindings,
    }
    return registry, family, semantic


def _load_mixed_process_runtime(
    requested_logical: int,
) -> tuple[object, MixedFamilyCensus, object]:
    """Load every production process-runtime cache family through its public bundle."""

    bundle = build_production_process_runtime_caches(_START + timedelta(days=2))
    family_names = tuple(spec.name for spec in bundle.family_specs)
    load_count = max(requested_logical, len(family_names))
    inserted = 0
    replaced = 0
    for ordinal in range(load_count):
        result = bundle.load_probe_entry(
            family_names[ordinal % len(family_names)],
            ordinal,
            _START + timedelta(hours=1, microseconds=ordinal),
            owner=f"mixed-runtime-owner-{ordinal:012d}",
        )
        inserted += int(result.inserted)
        replaced += int(result.replaced)
    census = bundle.census(watermark=None, estimate_bytes=True)
    family = MixedFamilyCensus(
        requested_logical=load_count,
        physical_records=census.physical_records,
        live_entries=census.live_entries,
        retained_entries=census.live_entries,
        backing_entries=census.backing_entries + census.reverse_backing_entries,
        stale_entries=census.stale_entries + census.reverse_stale_entries,
        leased_entries=0,
        estimated_bytes=census.estimated_bytes,
        estimated_index_bytes=census.estimated_index_bytes,
        lookup_candidates_inspected=(
            census.lookup_candidates_inspected + census.reverse_lookup_candidates_inspected
        ),
        notes=(
            f"Loaded all {len(family_names)} fixed production cache families and the actual "
            f"compact process-route reverse sidecar; inserted={inserted}, replaced={replaced}.",
        ),
    )
    semantic = {
        "families": family_names,
        "physical": census.physical_records,
        "inserted": inserted,
        "replaced": replaced,
    }
    return bundle, family, semantic


def _load_mixed_timing_runtime(
    requested_logical: int,
) -> tuple[object, MixedFamilyCensus, object]:
    """Load every bounded planner index plus its engine-owned timing runtime."""

    planner_family_names = tuple(spec.name for spec in PRODUCTION_SOURCE_TIMING_INDEX_FAMILIES)
    load_count = max(len(planner_family_names) + 2, requested_logical)
    planner_count = max(len(planner_family_names), load_count // 2)
    runtime_count = load_count - planner_count
    clock_count = max(1, runtime_count // 2)
    audit_count = runtime_count - clock_count
    runtime = TimingRuntime(
        reference_time=_START,
        namespace="foundation-mixed-timing-v1",
        max_clock_cache_entries=clock_count,
        max_audit_relationship_keys=max(1, audit_count),
    )
    planner = SourceTimingPlanner(timing_runtime=runtime)
    inserted = 0
    replaced = 0
    for ordinal in range(planner_count):
        result = planner.load_probe_entry(
            planner_family_names[ordinal % len(planner_family_names)],
            ordinal,
            _START + timedelta(hours=1, microseconds=ordinal),
        )
        inserted += int(result.inserted)
        replaced += int(result.replaced)
    clock_spec = SourceClockSpec()
    for ordinal in range(clock_count):
        runtime.clocks.state(
            SourceClockKey(
                kind="mixed-source",
                identity=f"source-{ordinal:012d}",
                profile="foundation-scale",
            ),
            clock_spec,
        )
    for ordinal in range(audit_count):
        runtime.audit.record_sample(
            f"foundation.mixed.relationship.{ordinal:012d}",
            "constant",
        )
    census = planner.census(estimate_bytes=True)
    physical_records = (
        census.live_entries
        + census.runtime.clocks.live_entries
        + census.runtime.audit.relationship_slots_live
        + census.runtime.audit.distribution_keys_live
    )
    estimated_index_bytes = census.estimated_index_bytes + census.runtime.estimated_index_bytes
    family = MixedFamilyCensus(
        requested_logical=load_count,
        physical_records=physical_records,
        live_entries=physical_records,
        retained_entries=physical_records,
        backing_entries=(
            census.backing_entries
            + census.runtime.clocks.backing_entries
            + census.runtime.audit.relationship_slots_live
            + census.runtime.audit.distribution_keys_live
        ),
        stale_entries=census.stale_entries,
        leased_entries=0,
        estimated_bytes=census.estimated_total_bytes,
        estimated_index_bytes=estimated_index_bytes,
        lookup_candidates_inspected=(
            census.lookup_candidates_inspected + census.runtime.clocks.lookup_count
        ),
        notes=(
            f"Loaded all {len(planner_family_names)} bounded production source-timing index "
            f"families plus their engine-owned clocks/audit runtime; inserted={inserted}, "
            f"replaced={replaced}.",
            "Physical timing records are planner-index rows, retained source-clock states, "
            "audit relationship slots, and distribution counter keys. Configured capacities "
            "are structural and are not double-counted as live records.",
        ),
    )
    semantic = {
        "planner_families": planner_family_names,
        "planner_entries": census.live_entries,
        "clocks": census.runtime.clocks.live_entries,
        "audit_slots": census.runtime.audit.relationship_slots_live,
        "distribution_keys": census.runtime.audit.distribution_keys_live,
        "inserted": inserted,
        "replaced": replaced,
    }
    return planner, family, semantic


def _load_mixed_sidecar(
    protocol: ImplementedProtocolName,
    requested_logical: int,
    *,
    registry: ApplicationChannelRegistry,
    workers: int,
    hash_seed: int,
) -> tuple[object, MixedFamilyCensus, object, float]:
    """Load one protocol manager against the shared mixed application registry."""

    sidecar_spec = CaseSpec(
        kind="sidecar",
        registry=protocol,
        entries=requested_logical,
        queries=min(64, requested_logical),
        group_mode="uniform",
        write_mode="monotonic",
        workers=workers,
        hash_seed=hash_seed,
    )
    if protocol == "http":
        details = _run_http_sidecar(sidecar_spec, registry=registry)
    elif protocol == "proxy":
        details = _run_proxy_sidecar(sidecar_spec, registry=registry)
    elif protocol == "smb":
        details = _run_smb_sidecar(sidecar_spec, registry=registry)
    elif protocol == "rdp":
        details = _run_rdp_sidecar(sidecar_spec, registry=registry)
    else:
        details = _run_ssh_sidecar(sidecar_spec, registry=registry)
    physical_records = int(details["sidecar_logical_records"])
    family = MixedFamilyCensus(
        requested_logical=requested_logical,
        physical_records=physical_records,
        live_entries=physical_records,
        retained_entries=physical_records,
        backing_entries=int(details["sidecar_backing_entries"]),
        stale_entries=int(details["sidecar_stale_entries"]),
        leased_entries=int(details.get("sidecar_leased_entries", 0)),
        estimated_bytes=int(details["sidecar_estimated_bytes"]),
        estimated_index_bytes=int(details["sidecar_estimated_index_bytes"]),
        lookup_candidates_inspected=int(details["sidecar_lookup_candidates_inspected"]),
        notes=(
            "Incremental protocol-manager state only; shared application channels and used "
            "operation IDs are counted once in the application_channels family.",
        ),
    )
    return (
        details["retained_root"],
        family,
        details["semantic"],
        float(details["load_seconds"]),
    )


def _mixed_application_family(
    registry: ApplicationChannelRegistry,
    *,
    requested_logical: int,
) -> MixedFamilyCensus:
    """Return the one non-duplicated shared application-registry denominator."""

    census = registry.census()
    physical_records = (
        census.retained_channels + census.active_operations + census.used_operation_ids
    )
    return MixedFamilyCensus(
        requested_logical=requested_logical,
        physical_records=physical_records,
        live_entries=census.open_channels + census.active_operations + census.used_operation_ids,
        retained_entries=physical_records,
        backing_entries=census.expiry_entries + census.route_entries,
        stale_entries=census.stale_expiry_entries,
        leased_entries=0,
        estimated_bytes=census.estimated_bytes,
        estimated_index_bytes=census.estimated_index_bytes,
        lookup_candidates_inspected=census.lookup_candidates_inspected,
        notes=(
            "Counts shared channels, active operations, and bounded used-operation markers "
            "once across direct and all protocol-manager admissions.",
        ),
    )


def _fill_mixed_application_channels(
    registry: ApplicationChannelRegistry,
    entries: int,
    *,
    workers: int,
) -> float:
    """Fill the residual physical-record target with one-row common channels."""

    if entries <= 0:
        return 0.0
    started = perf_counter()
    _parallel_for(
        range(entries),
        workers,
        lambda ordinal: registry.open_channel(_channel_identity(ordinal, "uniform", "monotonic")),
    )
    load_seconds = perf_counter() - started
    # Include the bounded lazy decoded-view cache in the hot RSS footprint.
    for ordinal in _query_ordinals(entries, min(entries, 16_384)):
        if registry.get(f"channel-{ordinal:012d}") is None:
            raise AssertionError("mixed direct application channel unexpectedly missing")
    return load_seconds


def _mixed_requested_logical_entries(target_physical_records: int) -> dict[str, int]:
    """Return bounded representative family loads before residual app-channel fill."""

    representative = max(
        1,
        min(10_000, target_physical_records // (len(_MIXED_FAMILIES) * 4)),
    )
    requested = {family: representative for family in _MIXED_FAMILIES}
    requested["process_runtime"] = max(
        representative,
        17,
    )
    requested["deployment_content"] = max(representative, 11)
    requested["timing_runtime"] = max(
        representative,
        len(PRODUCTION_SOURCE_TIMING_INDEX_FAMILIES) + 2,
    )
    return requested


def _run_mixed_case(spec: CaseSpec) -> MixedResult:
    """Load every retained-state family together and measure one hot process."""

    implementation_digest_start = _implementation_digest()
    if spec.registry != "mixed" or spec.entries < len(_MIXED_FAMILIES):
        raise ValueError("Mixed cases require at least one requested record per retained family")
    gc.collect()
    rss_before = _rss_bytes()
    peak_before = _peak_rss_bytes()
    requested = _mixed_requested_logical_entries(spec.entries)
    retained_roots: list[object] = []
    family_censuses: dict[str, MixedFamilyCensus] = {}
    semantic: dict[str, object] = {}
    load_started = perf_counter()

    lifecycle, lifecycle_family, lifecycle_semantic = _load_mixed_lifecycle(requested["lifecycle"])
    retained_roots.append(lifecycle)
    family_censuses["lifecycle"] = lifecycle_family
    semantic["lifecycle"] = lifecycle_semantic

    artifacts, artifact_family, artifact_semantic, _artifact_load = _load_mixed_artifacts(
        requested["local_artifacts"],
        workers=spec.workers,
        hash_seed=spec.hash_seed,
    )
    retained_roots.append(artifacts)
    family_censuses["local_artifacts"] = artifact_family
    semantic["local_artifacts"] = artifact_semantic

    collection, collection_family, collection_semantic, _collection_load = _load_mixed_collection(
        requested["collection_deployment"],
        workers=spec.workers,
        hash_seed=spec.hash_seed,
    )
    retained_roots.append(collection)
    family_censuses["collection_deployment"] = collection_family
    semantic["collection_deployment"] = collection_semantic

    deployment, deployment_family, deployment_semantic = _load_mixed_deployment_content(
        requested["deployment_content"]
    )
    retained_roots.append(deployment)
    family_censuses["deployment_content"] = deployment_family
    semantic["deployment_content"] = deployment_semantic

    process_runtime, process_family, process_semantic = _load_mixed_process_runtime(
        requested["process_runtime"]
    )
    retained_roots.append(process_runtime)
    family_censuses["process_runtime"] = process_family
    semantic["process_runtime"] = process_semantic

    timing_runtime, timing_family, timing_semantic = _load_mixed_timing_runtime(
        requested["timing_runtime"]
    )
    retained_roots.append(timing_runtime)
    family_censuses["timing_runtime"] = timing_family
    semantic["timing_runtime"] = timing_semantic

    application_registry = _sidecar_registry()
    retained_roots.append(application_registry)
    for protocol in _IMPLEMENTED_PROTOCOLS:
        manager, family, sidecar_semantic, _sidecar_load = _load_mixed_sidecar(
            protocol,
            requested[protocol],
            registry=application_registry,
            workers=spec.workers,
            hash_seed=spec.hash_seed,
        )
        retained_roots.append(manager)
        family_censuses[protocol] = family
        semantic[protocol] = sidecar_semantic

    provisional_application = _mixed_application_family(
        application_registry,
        requested_logical=application_registry.census().retained_channels,
    )
    current_physical = provisional_application.physical_records + sum(
        family.physical_records for family in family_censuses.values()
    )
    residual = max(0, spec.entries - current_physical)
    _fill_mixed_application_channels(
        application_registry,
        residual,
        workers=spec.workers,
    )
    application_family = _mixed_application_family(
        application_registry,
        requested_logical=application_registry.census().retained_channels,
    )
    requested["application_channels"] = application_family.requested_logical
    family_censuses["application_channels"] = application_family
    semantic["application_channels"] = {
        "channels": application_registry.census().retained_channels,
        "physical": application_family.physical_records,
        "direct_residual_fill": residual,
    }
    load_seconds = perf_counter() - load_started

    gc.collect()
    rss_after = _rss_bytes()
    peak_after = _peak_rss_bytes()
    _ = retained_roots
    physical_hot_records = sum(family.physical_records for family in family_censuses.values())
    per_registry_index_bytes = {
        family_name: family.estimated_index_bytes for family_name, family in family_censuses.items()
    }
    estimated_values = tuple(per_registry_index_bytes.values())
    estimated_index_bytes = (
        None
        if any(value is None for value in estimated_values)
        else sum(value for value in estimated_values if value is not None)
    )
    family_coverage_complete = (
        set(family_censuses) == set(_MIXED_FAMILIES)
        and all(family.physical_records > 0 for family in family_censuses.values())
        and all(family.estimated_bytes is not None for family in family_censuses.values())
        and all(family.estimated_index_bytes is not None for family in family_censuses.values())
    )
    implementation_digest_end = _implementation_digest()
    return MixedResult(
        kind="mixed",
        registry="mixed",
        entries=spec.entries,
        workers=spec.workers,
        hash_seed=spec.hash_seed,
        per_registry_entries=requested,
        per_family_requested_entries=requested,
        family_censuses=family_censuses,
        family_coverage_complete=family_coverage_complete,
        live_entries=physical_hot_records,
        physical_hot_records=physical_hot_records,
        load_seconds=load_seconds,
        rss_delta_bytes=max(0, rss_after - rss_before),
        peak_rss_delta_bytes=max(0, peak_after - peak_before),
        bytes_per_requested_entry=max(0, rss_after - rss_before) / spec.entries,
        rss_bytes_per_physical_record=(
            max(0, rss_after - rss_before) / max(1, physical_hot_records)
        ),
        estimated_index_bytes=estimated_index_bytes,
        estimated_index_bytes_per_live_entry=(
            None
            if estimated_index_bytes is None or physical_hot_records == 0
            else estimated_index_bytes / physical_hot_records
        ),
        estimated_index_bytes_per_physical_record=(
            None
            if estimated_index_bytes is None or physical_hot_records == 0
            else estimated_index_bytes / physical_hot_records
        ),
        per_registry_estimated_index_bytes=per_registry_index_bytes,
        registry_digest=_digest(semantic),
        implementation_digest_start=implementation_digest_start,
        implementation_digest_end=implementation_digest_end,
        notes=(
            "Every implemented retained-state family remains live in one isolated interpreter; "
            "RSS is measured once and is not a sum of isolated or extrapolated cases.",
            "Protocol sidecars exclude their shared application rows. The application family "
            "counts common channels, active operations, and used-ID markers exactly once.",
            "The requested entry count is a physical-record floor. Per-family logical loads are "
            "reported separately, and direct common channels fill only the residual.",
        ),
    )


def _lifecycle_metrics(registry: LifecycleRegistry) -> WorkloadMetrics:
    census = registry.census()
    temporal_live = (
        census.process_temporal_live_entries
        + census.session_temporal_live_entries
        + census.service_temporal_live_entries
        + census.transport_temporal_live_entries
    )
    temporal_backing = (
        census.process_temporal_backing_entries
        + census.session_temporal_backing_entries
        + census.service_temporal_backing_entries
        + census.transport_temporal_backing_entries
    )
    deadline_live = (
        census.retention_deadline_entries
        + census.retention_leases
        + census.service_retention_deadline_entries
        + census.transport_retention_deadline_entries
    )
    deadline_backing = (
        census.retention_deadline_backing_entries
        + census.lease_deadline_backing_entries
        + census.service_retention_deadline_entries
        + census.transport_retention_deadline_entries
    )
    return WorkloadMetrics(
        logical_entries=(
            census.process_entries
            + census.session_entries
            + census.logical_service_entries
            + census.service_instance_entries
            + census.transport_entries
            + census.transport_session_bindings
            + census.service_process_bindings
        ),
        live_entries=(
            census.live_processes
            + census.live_sessions
            + census.logical_service_entries
            + census.live_service_instances
            + census.live_transports
            + census.active_transport_session_bindings
            + census.active_service_process_bindings
        ),
        retained_entries=(
            census.retained_processes
            + census.retained_sessions
            + census.retained_service_instances
            + census.retained_transports
        ),
        stale_entries=census.temporal_stale_entries,
        leased_entries=census.retention_leases,
        backing_entries=(
            census.process_index_backing_entries
            + census.session_index_backing_entries
            + census.service_index_backing_entries
            + census.transport_index_backing_entries
            + census.binding_index_backing_entries
            + temporal_backing
            + deadline_backing
        ),
        estimated_bytes=census.estimated_bytes,
        maximum_bucket_size=None,
        lookup_candidates_inspected=census.lookup_candidates_inspected,
        heap_segment_amplification=max(
            _amplification(temporal_backing, temporal_live),
            _amplification(deadline_backing, deadline_live),
        ),
        compaction_work=None,
        compaction_seconds=None,
        high_water_mark=census.high_water_processes + census.high_water_sessions,
        estimated_index_bytes=census.estimated_index_bytes,
    )


def _channel_metrics(registry: ApplicationChannelRegistry) -> WorkloadMetrics:
    census = registry.census()
    return WorkloadMetrics(
        logical_entries=census.retained_channels,
        live_entries=census.open_channels,
        retained_entries=census.retained_closed_channels,
        stale_entries=census.stale_expiry_entries,
        leased_entries=0,
        backing_entries=census.expiry_entries + census.route_entries,
        estimated_bytes=census.estimated_bytes,
        maximum_bucket_size=census.maximum_affinity_bucket,
        lookup_candidates_inspected=census.lookup_candidates_inspected,
        heap_segment_amplification=_amplification(
            census.expiry_entries,
            census.retained_channels,
        ),
        compaction_work=(census.route_compaction_work + census.store_primary_compaction_work),
        compaction_seconds=(
            census.route_compaction_seconds + census.store_primary_compaction_seconds
        ),
        high_water_mark=census.high_water_mark,
        estimated_index_bytes=census.estimated_index_bytes,
    )


def _artifact_metrics(registry: LocalArtifactVersionRegistry) -> WorkloadMetrics:
    census = registry.census(estimate_bytes=True)
    store_index, deadline_index, lease_index = registry.index_metrics(estimate_bytes=True)
    return WorkloadMetrics(
        logical_entries=census.live_versions,
        live_entries=census.live_versions,
        retained_entries=0,
        stale_entries=(
            store_index.stale_entries + deadline_index.stale_entries + lease_index.stale_entries
        ),
        leased_entries=census.leased_versions,
        backing_entries=(
            store_index.backing_entries
            + deadline_index.backing_entries
            + lease_index.backing_entries
        ),
        estimated_bytes=census.estimated_bytes,
        maximum_bucket_size=store_index.max_bucket_size,
        lookup_candidates_inspected=(
            store_index.lookup_candidates_inspected
            + deadline_index.lookup_candidates_inspected
            + lease_index.lookup_candidates_inspected
        ),
        heap_segment_amplification=max(
            _amplification(deadline_index.backing_entries, deadline_index.live_entries),
            _amplification(lease_index.backing_entries, lease_index.live_entries),
        ),
        compaction_work=(
            store_index.compaction_work
            + deadline_index.compaction_work
            + lease_index.compaction_work
        ),
        compaction_seconds=(
            store_index.compaction_seconds
            + deadline_index.compaction_seconds
            + lease_index.compaction_seconds
        ),
        high_water_mark=census.high_water_mark,
        estimated_index_bytes=census.estimated_index_bytes,
    )


def _collection_metrics(registry: CompiledCollectionDeployment) -> WorkloadMetrics:
    census = registry.census
    return WorkloadMetrics(
        logical_entries=census.source_instances,
        live_entries=census.source_instances,
        retained_entries=0,
        stale_entries=0,
        leased_entries=0,
        backing_entries=(
            census.exact_identity_keys + census.collection_windows + census.capability_words
        ),
        estimated_bytes=census.estimated_bytes,
        maximum_bucket_size=census.max_host_family_bucket,
        lookup_candidates_inspected=None,
        heap_segment_amplification=1.0,
        compaction_work=0,
        compaction_seconds=0.0,
        high_water_mark=census.source_instances,
        estimated_index_bytes=census.estimated_index_bytes,
    )


def _measure_optional_lookups(
    ordinals: Sequence[int],
    workers: int,
    lookup: Callable[[int], object],
) -> list[int]:
    """Time lookups whose expected post-watermark result may be absent."""

    partitions = _partitioned(ordinals, workers)

    def run(partition: Sequence[int]) -> list[int]:
        samples: list[int] = []
        for ordinal in partition:
            started = perf_counter_ns()
            lookup(ordinal)
            samples.append(perf_counter_ns() - started)
        return samples

    if len(partitions) == 1:
        return run(partitions[0])
    with ThreadPoolExecutor(max_workers=workers) as executor:
        nested = tuple(executor.map(run, partitions))
    return [sample for group in nested for sample in group]


def _run_lifecycle_duration(
    spec: CaseSpec,
) -> tuple[object, WorkloadMetrics, list[int], float, int, dict[str, object], tuple[str, ...]]:
    registry = LifecycleRegistry(closed_retention=timedelta(hours=6))
    semantic = hashlib.sha256()
    late_hour_seconds = 0.0
    recent: deque[int] = deque(maxlen=max(1, spec.rate_per_hour * 8))
    lookup_samples: list[int] = []
    footprint_samples: list[tuple[int, ...]] = []
    for hour in range(spec.duration_hours):
        hour_started = perf_counter()
        first = hour * spec.rate_per_hour
        batch = range(first, first + spec.rate_per_hour)

        def create_and_close(
            ordinal: int,
            hour_index: int = hour,
            first_ordinal: int = first,
        ) -> None:
            started_at = _START + timedelta(
                hours=hour_index,
                microseconds=ordinal - first_ordinal,
            )
            identity = SessionLifecycleIdentity(
                hostname=(
                    f"host-{ordinal:012d}" if spec.group_mode == "uniform" else "host-000000000000"
                ),
                object_id=f"duration-session-{ordinal:012d}",
                logon_id=f"0x{ordinal + 1:016x}",
                principal=f"user-{ordinal:012d}",
                session_kind="network",
                started_at=started_at,
            )
            registry.register_session(
                identity,
                action_id=f"duration-open-{ordinal:012d}",
                transition_id=f"duration-transition-{ordinal:012d}",
            )
            ticket = registry.request_close(
                LifecycleCloseBarrier(
                    barrier_id=f"duration-barrier-{ordinal:012d}",
                    subject=identity.ref,
                    requested_at=started_at + timedelta(minutes=10),
                    authority="generated",
                    action_id=f"duration-close-{ordinal:012d}",
                ),
                ticket_id=f"duration-ticket-{ordinal:012d}",
            )
            registry.close(ticket.ticket_id)
            if ordinal % 10 == 0:
                registry.add_retention_lease(
                    LifecycleRetentionLease(
                        lease_id=f"duration-lease-{ordinal:012d}",
                        subject=identity.ref,
                        retain_until=started_at + timedelta(hours=8),
                        reason="duration-probe",
                    )
                )

        _parallel_for(batch, spec.workers, create_and_close)
        for ordinal in batch:
            recent.append(ordinal)
            semantic.update(f"duration-session-{ordinal:012d}\n".encode())
        if hour == spec.duration_hours - 1:
            lookup_samples = _measure_optional_lookups(
                tuple(batch),
                spec.workers,
                lambda ordinal: registry.get_session(f"duration-session-{ordinal:012d}"),
            )
        registry.advance_watermark(_START + timedelta(hours=hour + 1))
        census = registry.census()
        footprint_samples.append(
            (
                census.process_entries,
                census.session_entries,
                census.retained_processes,
                census.retained_sessions,
                census.holds,
                census.close_barriers,
                census.closure_tickets,
                census.retention_leases,
                census.process_temporal_backing_entries,
                census.session_temporal_backing_entries,
                census.retention_deadline_backing_entries,
                census.lease_deadline_backing_entries,
                census.ledger_temporal_backing_entries,
                census.ledger_commit_map_backing_bytes,
                census.primary_map_backing_bytes,
                census.route_map_backing_bytes,
            )
        )
        if hour == spec.duration_hours - 1:
            late_hour_seconds = perf_counter() - hour_started
    metrics = _lifecycle_metrics(registry)
    state = {
        "stream": semantic.hexdigest(),
        "recent_retained": sum(
            registry.get_session(f"duration-session-{ordinal:012d}") is not None
            for ordinal in recent
        ),
        "live": metrics.live_entries,
        "retained": metrics.retained_entries,
        "leased": metrics.leased_entries,
        "plateau_hour": _final_plateau_hour(footprint_samples),
    }
    return (
        registry,
        metrics,
        lookup_samples,
        late_hour_seconds,
        spec.duration_hours * spec.rate_per_hour,
        state,
        (),
    )


def _run_channel_duration(
    spec: CaseSpec,
) -> tuple[object, WorkloadMetrics, list[int], float, int, dict[str, object], tuple[str, ...]]:
    window_end = _START + timedelta(hours=spec.duration_hours + 1)
    registry = ApplicationChannelRegistry(
        window_start=_START,
        window_end=window_end,
        closed_grace=timedelta(minutes=30),
        max_reusable_per_affinity=8,
    )
    semantic = hashlib.sha256()
    late_hour_seconds = 0.0
    lookup_samples: list[int] = []
    footprint_samples: list[tuple[int, ...]] = []
    for hour in range(spec.duration_hours):
        hour_started = perf_counter()
        first = hour * spec.rate_per_hour
        batch = range(first, first + spec.rate_per_hour)

        def transact(
            ordinal: int,
            hour_index: int = hour,
            first_ordinal: int = first,
        ) -> None:
            opened_at = _START + timedelta(
                hours=hour_index,
                microseconds=ordinal - first_ordinal,
            )
            owner = ordinal if spec.group_mode == "uniform" else 0
            identity = ApplicationChannelIdentity(
                channel_id=f"duration-channel-{ordinal:012d}",
                protocol="http",
                owner_id=f"duration-owner-{owner:012d}",
                affinity_digest=f"duration-affinity-{ordinal // 8:012d}",
                binding=ApplicationTransportBinding(
                    transport_id=f"duration-transport-{ordinal:012d}",
                    opened_at=opened_at,
                    closes_at=opened_at + timedelta(minutes=25),
                ),
                opened_at=opened_at,
                idle_timeout=timedelta(minutes=5),
                hard_deadline=opened_at + timedelta(minutes=20),
                budget=ApplicationChannelBudget(1_024, 2_048, 1),
            )
            registry.open_channel(identity)
            operation_id = f"duration-operation-{ordinal:012d}"
            registry.reserve_operation(
                ApplicationOperationReservation(
                    operation_id=operation_id,
                    channel_id=identity.channel_id,
                    ordinal=0,
                    started_at=opened_at + timedelta(minutes=1),
                    ended_at=opened_at + timedelta(minutes=2),
                    initiator_bytes=64,
                    responder_bytes=128,
                )
            )
            registry.finalize_operation(operation_id)
            registry.close_channel(
                identity.channel_id,
                closed_at=opened_at + timedelta(minutes=3),
                reason="duration-probe",
            )

        _parallel_for(batch, spec.workers, transact)
        if hour == spec.duration_hours - 1:
            lookup_samples = _measure_optional_lookups(
                tuple(batch),
                spec.workers,
                lambda ordinal: registry.get(f"duration-channel-{ordinal:012d}"),
            )
        for ordinal in batch:
            semantic.update(f"duration-channel-{ordinal:012d}\n".encode())
        registry.watermark(_START + timedelta(hours=hour + 1))
        census = registry.census()
        footprint_samples.append(
            (
                census.retained_channels,
                census.open_channels,
                census.retained_closed_channels,
                census.active_operations,
                census.used_operation_ids,
                census.expiry_entries,
                census.stale_expiry_entries,
                census.route_entries,
                census.route_map_bytes,
                census.store_primary_map_bytes,
            )
        )
        if hour == spec.duration_hours - 1:
            late_hour_seconds = perf_counter() - hour_started
    metrics = _channel_metrics(registry)
    state = {
        "stream": semantic.hexdigest(),
        "live": metrics.live_entries,
        "retained": metrics.retained_entries,
        "stale": metrics.stale_entries,
        "plateau_hour": _final_plateau_hour(footprint_samples),
    }
    return (
        registry,
        metrics,
        lookup_samples,
        late_hour_seconds,
        spec.duration_hours * spec.rate_per_hour,
        state,
        (
            "Application estimates include route-map backing and compact values; RSS remains "
            "measured independently.",
        ),
    )


def _run_artifact_duration(
    spec: CaseSpec,
) -> tuple[object, WorkloadMetrics, list[int], float, int, dict[str, object], tuple[str, ...]]:
    registry = LocalArtifactVersionRegistry(
        capacity=max(1, spec.rate_per_hour * 16),
        retention=timedelta(hours=6),
    )
    semantic = hashlib.sha256()
    late_hour_seconds = 0.0
    lookup_samples: list[int] = []
    recent: deque[str] = deque(maxlen=max(1, spec.rate_per_hour * 8))
    footprint_samples: list[tuple[int, ...]] = []
    for hour in range(spec.duration_hours):
        hour_started = perf_counter()
        first = hour * spec.rate_per_hour
        batch = range(first, first + spec.rate_per_hour)

        def publish(
            ordinal: int,
            hour_index: int = hour,
            first_ordinal: int = first,
        ) -> None:
            group = ordinal if spec.group_mode == "uniform" else 0
            artifact = LocalArtifactIdentity(
                hostname=f"duration-host-{group:012d}",
                principal=f"duration-user-{group:012d}",
                platform="windows",
                user_profile_id=f"duration-profile-{group:012d}",
                application_profile_id=f"duration-app-profile-{group:012d}",
                application_id="browser",
                family="cache",
                source_object_id=f"duration-object-{group:012d}",
                native_path=rf"C:\Duration\{group:012d}\cache.bin",
                content_id=f"duration-content-{group:012d}",
                version=1 if spec.group_mode == "uniform" else ordinal + 1,
            )
            observed_at = _START + timedelta(
                hours=hour_index,
                microseconds=ordinal - first_ordinal,
            )
            registry.publish(artifact, observed_at)
            if ordinal % 10 == 0:
                registry.acquire_lease(
                    artifact.artifact_version_id,
                    f"duration-owner-{ordinal:012d}",
                    observed_at + timedelta(hours=8),
                )

        _parallel_for(batch, spec.workers, publish)
        current_ids: list[str] = []
        for ordinal in batch:
            group = ordinal if spec.group_mode == "uniform" else 0
            artifact = LocalArtifactIdentity(
                hostname=f"duration-host-{group:012d}",
                principal=f"duration-user-{group:012d}",
                platform="windows",
                user_profile_id=f"duration-profile-{group:012d}",
                application_profile_id=f"duration-app-profile-{group:012d}",
                application_id="browser",
                family="cache",
                source_object_id=f"duration-object-{group:012d}",
                native_path=rf"C:\Duration\{group:012d}\cache.bin",
                content_id=f"duration-content-{group:012d}",
                version=1 if spec.group_mode == "uniform" else ordinal + 1,
            )
            current_ids.append(artifact.artifact_version_id)
            recent.append(artifact.artifact_version_id)
            semantic.update(f"{artifact.artifact_version_id}\n".encode())
        if hour == spec.duration_hours - 1:
            frozen_ids = tuple(current_ids)
            lookup_samples = _measure_optional_lookups(
                tuple(range(len(frozen_ids))),
                spec.workers,
                lambda index, ids=frozen_ids: registry.get(ids[index]),
            )
        registry.advance_watermark(_START + timedelta(hours=hour + 1))
        census = registry.census()
        footprint_samples.append(
            (
                census.live_versions,
                census.backing_slots,
                census.leased_versions,
                census.active_leases,
                census.pending_expiry,
                census.route_entries,
                census.route_backing_bytes,
                census.primary_map_entries,
                census.primary_map_backing_bytes,
            )
        )
        if hour == spec.duration_hours - 1:
            late_hour_seconds = perf_counter() - hour_started
    metrics = _artifact_metrics(registry)
    state = {
        "stream": semantic.hexdigest(),
        "recent_retained": sum(registry.get(version_id) is not None for version_id in recent),
        "live": metrics.live_entries,
        "leased": metrics.leased_entries,
        "plateau_hour": _final_plateau_hour(footprint_samples),
    }
    return (
        registry,
        metrics,
        lookup_samples,
        late_hour_seconds,
        spec.duration_hours * spec.rate_per_hour,
        state,
        (),
    )


def _run_collection_duration(
    spec: CaseSpec,
) -> tuple[object, WorkloadMetrics, list[int], float, int, dict[str, object], tuple[str, ...]]:
    source_count = max(10, spec.rate_per_hour * 6)
    registry = CompiledCollectionDeployment(
        _source(ordinal, spec.group_mode) for ordinal in range(source_count)
    )
    semantic = hashlib.sha256()
    late_hour_seconds = 0.0
    lookup_samples: list[int] = []
    for hour in range(spec.duration_hours):
        hour_started = perf_counter()
        ordinals = tuple(
            (hour * spec.rate_per_hour + offset) % source_count
            for offset in range(spec.rate_per_hour)
        )
        samples = _measure_optional_lookups(
            ordinals,
            spec.workers,
            lambda ordinal: registry.source_by_instance(f"source-{ordinal:012d}"),
        )
        for ordinal in ordinals:
            semantic.update(f"{hour}:{ordinal}\n".encode())
        if hour == spec.duration_hours - 1:
            lookup_samples = samples
            late_hour_seconds = perf_counter() - hour_started
    metrics = _collection_metrics(registry)
    state = {
        "stream": semantic.hexdigest(),
        "sources": metrics.live_entries,
        "estimated_bytes": metrics.estimated_bytes,
        "plateau_hour": _final_plateau_hour(
            [(metrics.retained_entries, metrics.backing_entries)] * spec.duration_hours
        ),
    }
    return (
        registry,
        metrics,
        lookup_samples,
        late_hour_seconds,
        spec.duration_hours * spec.rate_per_hour,
        state,
        (
            "Collection deployment is immutable; duration mutations are repeated lock-free "
            "capability/source lookups against one compiled deployment.",
        ),
    )


_DURATION_RUNNERS: dict[
    RegistryName,
    Callable[
        [CaseSpec],
        tuple[
            object,
            WorkloadMetrics,
            list[int],
            float,
            int,
            dict[str, object],
            tuple[str, ...],
        ],
    ],
] = {
    "lifecycle": _run_lifecycle_duration,
    "channels": _run_channel_duration,
    "artifacts": _run_artifact_duration,
    "collection": _run_collection_duration,
}


def _run_duration_case(spec: CaseSpec) -> DurationResult:
    implementation_digest_start = _implementation_digest()
    gc.collect()
    rss_before = _rss_bytes()
    peak_before = _peak_rss_bytes()
    started = perf_counter()
    registry, metrics, samples, late_hour, mutations, semantic, notes = _DURATION_RUNNERS[
        spec.registry
    ](spec)
    total_seconds = perf_counter() - started
    gc.collect()
    rss_after = _rss_bytes()
    peak_after = _peak_rss_bytes()
    _ = registry
    plateau_hour_value = semantic.get("plateau_hour")
    if plateau_hour_value is not None and not isinstance(plateau_hour_value, int):
        raise AssertionError("duration plateau hour must be an integer or null")
    implementation_digest_end = _implementation_digest()
    return DurationResult(
        kind="duration",
        registry=spec.registry,
        duration_hours=spec.duration_hours,
        rate_per_hour=spec.rate_per_hour,
        group_mode=spec.group_mode,
        workers=spec.workers,
        hash_seed=spec.hash_seed,
        mutations=mutations,
        total_seconds=total_seconds,
        late_hour_seconds=late_hour,
        lookup_p95_us=_p95_us(samples),
        plateau_hour=plateau_hour_value,
        rss_delta_bytes=max(0, rss_after - rss_before),
        peak_rss_delta_bytes=max(0, peak_after - peak_before),
        metrics=metrics,
        registry_digest=_digest(semantic),
        implementation_digest_start=implementation_digest_start,
        implementation_digest_end=implementation_digest_end,
        notes=notes,
    )


def _encode_spec(spec: CaseSpec) -> str:
    payload = json.dumps(asdict(spec), sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(payload).decode("ascii")


def _decode_spec(payload: str) -> CaseSpec:
    values = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    return CaseSpec(**values)


def _decode_result(
    values: dict[str, Any],
) -> ScaleResult | DurationResult | MixedResult | SidecarResult:
    if values["kind"] == "mixed":
        values["notes"] = tuple(values["notes"])
        values["family_censuses"] = {
            name: MixedFamilyCensus(
                **{
                    **family,
                    "notes": tuple(family.get("notes", ())),
                }
            )
            for name, family in values["family_censuses"].items()
        }
        return MixedResult(**values)
    if values["kind"] == "sidecar":
        values["notes"] = tuple(values["notes"])
        return SidecarResult(**values)
    metrics = WorkloadMetrics(**values.pop("metrics"))
    values["metrics"] = metrics
    values["notes"] = tuple(values["notes"])
    if values["kind"] == "scale":
        return ScaleResult(**values)
    return DurationResult(**values)


def _run_isolated(
    spec: CaseSpec,
) -> ScaleResult | DurationResult | MixedResult | SidecarResult | CaseError:
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = str(spec.hash_seed)
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--child-case",
        _encode_spec(spec),
    ]
    completed = subprocess.run(
        command,
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return CaseError(
            spec=spec,
            returncode=completed.returncode,
            stderr=completed.stderr[-8_000:],
        )
    try:
        values = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return CaseError(
            spec=spec,
            returncode=2,
            stderr=f"child returned invalid JSON: {exc}: {completed.stdout[-2_000:]}",
        )
    return _decode_result(values)


def _parse_positive_ints(value: str) -> tuple[int, ...]:
    try:
        result = tuple(sorted({int(part.strip()) for part in value.split(",") if part.strip()}))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected comma-separated integers") from exc
    if not result or any(item <= 0 for item in result):
        raise argparse.ArgumentTypeError("values must be positive integers")
    return result


def _parse_nonnegative_ints(value: str) -> tuple[int, ...]:
    try:
        result = tuple(sorted({int(part.strip()) for part in value.split(",") if part.strip()}))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected comma-separated integers") from exc
    if not result or any(item < 0 for item in result):
        raise argparse.ArgumentTypeError("values must be non-negative integers")
    return result


def _parse_registries(value: str) -> tuple[RegistryName, ...]:
    requested = tuple(part.strip() for part in value.split(",") if part.strip())
    unknown = sorted(set(requested) - set(_REGISTRIES))
    if not requested or unknown:
        detail = f"; unknown: {', '.join(unknown)}" if unknown else ""
        raise argparse.ArgumentTypeError(
            f"registries must come from {', '.join(_REGISTRIES)}{detail}"
        )
    return tuple(dict.fromkeys(requested))  # type: ignore[return-value]


def _parse_protocols(value: str) -> tuple[ProtocolName, ...]:
    requested = tuple(part.strip() for part in value.split(",") if part.strip())
    unknown = sorted(set(requested) - set(_REQUIRED_PROTOCOLS))
    if not requested or unknown:
        detail = f"; unknown: {', '.join(unknown)}" if unknown else ""
        raise argparse.ArgumentTypeError(
            f"protocols must come from {', '.join(_REQUIRED_PROTOCOLS)}{detail}"
        )
    return tuple(dict.fromkeys(requested))  # type: ignore[return-value]


def _parse_group_modes(value: str) -> tuple[GroupMode, ...]:
    requested = tuple(part.strip() for part in value.split(",") if part.strip())
    unknown = sorted(set(requested) - {"uniform", "skewed"})
    if not requested or unknown:
        raise argparse.ArgumentTypeError("group modes must be uniform and/or skewed")
    return tuple(dict.fromkeys(requested))  # type: ignore[return-value]


def _parse_write_modes(value: str) -> tuple[WriteMode, ...]:
    requested = tuple(part.strip() for part in value.split(",") if part.strip())
    unknown = sorted(set(requested) - {"monotonic", "out-of-order"})
    if not requested or unknown:
        raise argparse.ArgumentTypeError("write modes must be monotonic and/or out-of-order")
    return tuple(dict.fromkeys(requested))  # type: ignore[return-value]


def _unique_specs(specs: Iterable[CaseSpec]) -> list[CaseSpec]:
    return list(dict.fromkeys(specs))


def _build_scale_specs(
    *,
    profile: str,
    registries: tuple[RegistryName, ...],
    sizes: tuple[int, ...],
    group_modes: tuple[GroupMode, ...],
    write_modes: tuple[WriteMode, ...],
    workers: tuple[int, ...],
    hash_seeds: tuple[int, ...],
    queries: int,
    churn_entries: int,
) -> list[CaseSpec]:
    def make(
        registry: RegistryName,
        entries: int,
        group_mode: GroupMode,
        write_mode: WriteMode,
        worker_count: int,
        hash_seed: int,
    ) -> CaseSpec:
        return CaseSpec(
            kind="scale",
            registry=registry,
            entries=entries,
            queries=queries,
            group_mode=group_mode,
            write_mode=write_mode,
            workers=worker_count,
            hash_seed=hash_seed,
            churn_entries=min(churn_entries, entries),
        )

    if profile in {"smoke", "exhaustive"}:
        return [
            make(registry, size, group_mode, write_mode, worker_count, hash_seed)
            for registry in registries
            for size in sizes
            for group_mode in group_modes
            for write_mode in write_modes
            for worker_count in workers
            for hash_seed in hash_seeds
        ]

    # Release is pairwise rather than a dangerous all-dimensions Cartesian
    # product.  It still covers the full size ladder, both distribution/write
    # modes at the largest point, and identical 100k cases across 1/4/8 workers
    # and two interpreter hash seeds.
    baseline_group = "uniform" if "uniform" in group_modes else group_modes[0]
    baseline_write = "monotonic" if "monotonic" in write_modes else write_modes[0]
    baseline_worker = 1 if 1 in workers else workers[0]
    baseline_seed = hash_seeds[0]
    largest = max(sizes)
    stress_size = max((size for size in sizes if size <= 100_000), default=min(sizes))
    specs: list[CaseSpec] = []
    for registry in registries:
        specs.extend(
            make(
                registry,
                size,
                baseline_group,
                baseline_write,
                baseline_worker,
                baseline_seed,
            )
            for size in sizes
        )
        for group_mode in group_modes:
            for write_mode in write_modes:
                specs.append(
                    make(
                        registry,
                        largest,
                        group_mode,
                        write_mode,
                        baseline_worker,
                        baseline_seed,
                    )
                )
                if registry == "deployment" and 1_000_000 in sizes:
                    # The deployment/content million-point is a mandatory
                    # standalone family gate. Keep every requested population
                    # shape/write-mode pair at the exact contract denominator;
                    # a smaller representative mixed share cannot substitute.
                    specs.append(
                        make(
                            registry,
                            1_000_000,
                            group_mode,
                            write_mode,
                            baseline_worker,
                            baseline_seed,
                        )
                    )
                specs.append(
                    make(
                        registry,
                        stress_size,
                        group_mode,
                        write_mode,
                        baseline_worker,
                        baseline_seed,
                    )
                )
        stress_group = "skewed" if "skewed" in group_modes else group_modes[-1]
        stress_write = "out-of-order" if "out-of-order" in write_modes else write_modes[-1]
        for worker_count in workers:
            for hash_seed in hash_seeds:
                specs.append(
                    make(
                        registry,
                        stress_size,
                        stress_group,
                        stress_write,
                        worker_count,
                        hash_seed,
                    )
                )
    return _unique_specs(specs)


def _build_duration_specs(
    *,
    profile: str,
    registries: tuple[RegistryName, ...],
    durations: tuple[int, ...],
    workers: tuple[int, ...],
    hash_seeds: tuple[int, ...],
    rate_per_hour: int,
    group_modes: tuple[GroupMode, ...],
) -> list[CaseSpec]:
    def make(
        registry: RegistryName,
        duration: int,
        worker_count: int,
        hash_seed: int,
        group_mode: GroupMode,
    ) -> CaseSpec:
        return CaseSpec(
            kind="duration",
            registry=registry,
            duration_hours=duration,
            rate_per_hour=rate_per_hour,
            group_mode=group_mode,
            workers=worker_count,
            hash_seed=hash_seed,
        )

    if profile in {"smoke", "exhaustive"}:
        return [
            make(registry, duration, worker_count, hash_seed, group_mode)
            for registry in registries
            for duration in durations
            for worker_count in workers
            for hash_seed in hash_seeds
            for group_mode in group_modes
        ]

    baseline_worker = 1 if 1 in workers else workers[0]
    baseline_seed = hash_seeds[0]
    baseline_group = "skewed" if "skewed" in group_modes else group_modes[0]
    determinism_duration = min(durations)
    specs = []
    for registry in registries:
        specs.extend(
            make(registry, duration, baseline_worker, baseline_seed, baseline_group)
            for duration in durations
        )
        for worker_count in workers:
            for hash_seed in hash_seeds:
                specs.append(
                    make(
                        registry,
                        determinism_duration,
                        worker_count,
                        hash_seed,
                        baseline_group,
                    )
                )
    return _unique_specs(specs)


def _build_sidecar_specs(
    *,
    profile: str,
    protocols: tuple[ProtocolName, ...],
    entries: int,
    workers: tuple[int, ...],
    hash_seeds: tuple[int, ...],
    queries: int,
) -> list[CaseSpec]:
    """Build isolated actual-manager sidecar cases.

    Release runs one actual-million baseline for every implemented requested
    manager, plus a 100K worker/hash-seed matrix. Missing planned managers stay
    visible as an explicit completeness gate instead of synthetic stand-ins.
    """

    implemented = tuple(protocol for protocol in protocols if protocol in _IMPLEMENTED_PROTOCOLS)
    if not implemented or entries <= 0:
        return []

    def make(
        protocol: ProtocolName,
        case_entries: int,
        group_mode: GroupMode,
        write_mode: WriteMode,
        worker_count: int,
        hash_seed: int,
    ) -> CaseSpec:
        return CaseSpec(
            kind="sidecar",
            registry=protocol,
            entries=case_entries,
            queries=queries,
            group_mode=group_mode,
            write_mode=write_mode,
            workers=worker_count,
            hash_seed=hash_seed,
        )

    baseline_worker = 1 if 1 in workers else workers[0]
    baseline_seed = hash_seeds[0]
    if profile == "smoke":
        return [
            make(protocol, entries, "uniform", "monotonic", baseline_worker, baseline_seed)
            for protocol in implemented
        ]
    if profile == "exhaustive":
        return [
            make(protocol, entries, group_mode, write_mode, worker_count, hash_seed)
            for protocol in implemented
            for group_mode in ("uniform", "skewed")
            for write_mode in ("monotonic", "out-of-order")
            for worker_count in workers
            for hash_seed in hash_seeds
        ]

    stress_entries = min(entries, 100_000)
    specs: list[CaseSpec] = []
    for protocol in implemented:
        specs.append(
            make(
                protocol,
                entries,
                "uniform",
                "monotonic",
                baseline_worker,
                baseline_seed,
            )
        )
        for worker_count in workers:
            for hash_seed in hash_seeds:
                specs.append(
                    make(
                        protocol,
                        stress_entries,
                        "skewed",
                        "out-of-order",
                        worker_count,
                        hash_seed,
                    )
                )
    return _unique_specs(specs)


def _same_digest(
    results: Sequence[ScaleResult | DurationResult | SidecarResult],
) -> bool | None:
    if len(results) < 2:
        return None
    return len({result.registry_digest for result in results}) == 1


def _result_gates(
    scale_results: list[ScaleResult],
    duration_results: list[DurationResult],
    mixed_results: list[MixedResult],
    sidecar_results: list[SidecarResult],
    errors: list[CaseError],
    *,
    expected_registries: tuple[RegistryName, ...],
    expected_sizes: tuple[int, ...],
    expected_group_modes: tuple[GroupMode, ...],
    expected_write_modes: tuple[WriteMode, ...],
    expected_workers: tuple[int, ...],
    expected_hash_seeds: tuple[int, ...],
    expected_durations: tuple[int, ...],
    expected_protocols: tuple[ProtocolName, ...],
    expected_sidecar_entries: int,
    reference_host: bool,
) -> tuple[dict[str, bool | None], dict[str, dict[str, float | None]]]:
    ratios: dict[str, dict[str, float | None]] = {}
    exact_ratios: list[float] = []
    secondary_ratios: list[float] = []
    temporal_candidate_normalized_ratios: list[float] = []
    for registry in expected_registries:
        baseline = {
            result.entries: result
            for result in scale_results
            if result.registry == registry
            and result.group_mode == "uniform"
            and result.write_mode == "monotonic"
            and result.workers == 1
            and result.hash_seed == min((item.hash_seed for item in scale_results), default=0)
        }
        small = baseline.get(1_000)
        million = baseline.get(1_000_000)
        exact = (
            None
            if small is None or million is None
            else million.primary_lookup_p95_us / max(small.primary_lookup_p95_us, 0.001)
        )
        exact_cold = (
            None
            if small is None or million is None
            else million.primary_cold_lookup_p95_us / max(small.primary_cold_lookup_p95_us, 0.001)
        )
        secondary = (
            None
            if small is None or million is None
            else million.secondary_lookup_p95_us
            / max(
                small.secondary_lookup_p95_us,
                0.001,
            )
        )
        secondary_cold = (
            None
            if small is None or million is None
            else million.secondary_cold_lookup_p95_us
            / max(small.secondary_cold_lookup_p95_us, 0.001)
        )
        # Cold/random ratios remain visible diagnostics, but are deliberately
        # not gates: the 1K working set is cache-resident while the first-touch
        # 1M stream is not.  The stated relative contracts compare symmetric
        # three-pass warmed measurements below.
        ratios[registry] = {
            "primary_1m_over_1k": exact,
            "primary_cold_1m_over_1k": exact_cold,
            "secondary_1m_over_1k": secondary,
            "secondary_cold_1m_over_1k": secondary_cold,
            # The lifecycle point lookup returns exactly one session, so k=1
            # and the candidate-normalized temporal ratio is the measured
            # warmed point-lookup ratio itself.
            "temporal_candidate_normalized_1m_over_1k": (
                secondary if registry == "lifecycle" else None
            ),
            "temporal_returned_results_per_query": (
                1.0 if registry == "lifecycle" and secondary is not None else None
            ),
        }
        if exact is not None:
            exact_ratios.append(exact)
        if secondary is not None:
            secondary_ratios.append(secondary)
            if registry == "lifecycle":
                temporal_candidate_normalized_ratios.append(secondary)

    all_results: list[ScaleResult | DurationResult | MixedResult | SidecarResult] = [
        *scale_results,
        *duration_results,
        *mixed_results,
        *sidecar_results,
    ]
    implementation_stable_within_cases = all(
        result.implementation_digest_start == result.implementation_digest_end
        for result in all_results
    )
    implementation_digests = {result.implementation_digest_start for result in all_results}
    single_implementation_revision = (
        None
        if not all_results
        else implementation_stable_within_cases and len(implementation_digests) == 1
    )

    worker_groups: dict[tuple[object, ...], list[ScaleResult | DurationResult | SidecarResult]] = {}
    hash_groups: dict[tuple[object, ...], list[ScaleResult | DurationResult | SidecarResult]] = {}
    combined_groups: dict[
        tuple[object, ...], list[ScaleResult | DurationResult | SidecarResult]
    ] = {}
    for result in [*scale_results, *duration_results, *sidecar_results]:
        if isinstance(result, ScaleResult):
            semantic = (
                "scale",
                result.registry,
                result.entries,
                result.group_mode,
                result.write_mode,
                result.churn_entries,
            )
        elif isinstance(result, DurationResult):
            semantic = (
                "duration",
                result.registry,
                result.duration_hours,
                result.rate_per_hour,
                result.group_mode,
            )
        else:
            semantic = (
                "sidecar",
                result.registry,
                result.entries,
                result.group_mode,
                result.write_mode,
                result.representation,
            )
        worker_groups.setdefault((*semantic, result.hash_seed), []).append(result)
        hash_groups.setdefault((*semantic, result.workers), []).append(result)
        combined_groups.setdefault(semantic, []).append(result)

    worker_checks = [
        _same_digest(group)
        for group in worker_groups.values()
        if len({item.workers for item in group}) > 1
    ]
    hash_checks = [
        _same_digest(group)
        for group in hash_groups.values()
        if len({item.hash_seed for item in group}) > 1
    ]
    combined_checks = [
        _same_digest(group)
        for group in combined_groups.values()
        if len({(item.workers, item.hash_seed) for item in group}) > 1
    ]

    plateau_memory: list[float] = []
    plateau_index_memory: list[float] = []
    seven_day_plateau_hours: list[int | None] = []
    seven_day_plateau_coverage = 0
    late_hour_ratios: list[float] = []
    duration_lookup_ratios: list[float] = []
    expected_duration_registries = tuple(
        registry for registry in expected_registries if registry in _DURATION_REGISTRIES
    )
    for registry in expected_duration_registries:
        baseline = {
            result.duration_hours: result
            for result in duration_results
            if result.registry == registry and result.workers == 1 and result.hash_seed == 0
        }
        day = baseline.get(24)
        week = baseline.get(168)
        month = baseline.get(720)
        if week is not None and month is not None:
            plateau_memory.append(month.rss_delta_bytes / max(1, week.rss_delta_bytes))
            if (
                week.metrics.estimated_index_bytes is not None
                and month.metrics.estimated_index_bytes is not None
            ):
                plateau_index_memory.append(
                    month.metrics.estimated_index_bytes / max(1, week.metrics.estimated_index_bytes)
                )
        if week is not None:
            seven_day_plateau_coverage += 1
            seven_day_plateau_hours.append(week.plateau_hour)
        if day is not None and month is not None:
            late_hour_ratios.append(month.late_hour_seconds / max(day.late_hour_seconds, 0.000_001))
            duration_lookup_ratios.append(month.lookup_p95_us / max(day.lookup_p95_us, 0.001))

    million_results = [result for result in scale_results if result.entries == 1_000_000]
    million_deployment_results = [
        result
        for result in million_results
        if result.registry == "deployment"
        and result.metrics.logical_entries >= 1_000_000
        and result.metrics.estimated_index_bytes is not None
    ]
    required_deployment_million_shapes = {
        (group_mode, write_mode)
        for group_mode in expected_group_modes
        for write_mode in expected_write_modes
    }
    measured_deployment_million_shapes = {
        (result.group_mode, result.write_mode) for result in million_deployment_results
    }
    million_sidecar_results = [result for result in sidecar_results if result.entries == 1_000_000]
    million_mixed_results = [result for result in mixed_results if result.entries == 1_000_000]
    mixed_family_coverage = [
        result.family_coverage_complete and set(result.family_censuses) == set(_MIXED_FAMILIES)
        for result in mixed_results
    ]
    mixed_physical_denominators = [
        result.physical_hot_records >= result.entries
        and result.physical_hot_records
        == sum(family.physical_records for family in result.family_censuses.values())
        for result in mixed_results
    ]
    expiry_results = [
        result
        for result in scale_results
        if result.expiry_entries >= 100_000 and result.registry != "collection"
    ]
    required_expiry_registries = set(expected_registries).intersection(_EXPIRING_REGISTRIES)
    expiry_registry_coverage = {
        result.registry for result in expiry_results
    } >= required_expiry_registries
    estimated_index_results = [
        result
        for result in scale_results
        if result.registry == "artifacts"
        and result.entries == 1_000_000
        and result.metrics.estimated_index_bytes is not None
        and result.metrics.logical_entries > 0
    ]
    expected_scale_coverage = all(
        any(result.registry == registry and result.entries == size for result in scale_results)
        for registry in expected_registries
        for size in expected_sizes
    )
    expected_group_coverage = all(
        any(
            result.registry == registry and result.group_mode == group_mode
            for result in scale_results
        )
        for registry in expected_registries
        for group_mode in expected_group_modes
    )
    expected_write_coverage = all(
        any(
            result.registry == registry and result.write_mode == write_mode
            for result in scale_results
        )
        for registry in expected_registries
        for write_mode in expected_write_modes
    )
    expected_worker_coverage = all(
        (
            not expected_sizes
            or all(
                any(
                    result.registry == registry and result.workers == worker
                    for result in scale_results
                )
                for registry in expected_registries
            )
        )
        and (
            not expected_durations
            or all(
                any(
                    result.registry == registry and result.workers == worker
                    for result in duration_results
                )
                for registry in expected_duration_registries
            )
        )
        and (
            not expected_protocols
            or all(
                any(
                    result.registry == protocol and result.workers == worker
                    for result in sidecar_results
                )
                for protocol in expected_protocols
            )
        )
        for worker in expected_workers
    )
    expected_duration_coverage = all(
        any(
            result.registry == registry and result.duration_hours == duration
            for result in duration_results
        )
        for registry in expected_duration_registries
        for duration in expected_durations
    )
    expected_hash_seed_coverage = all(
        (
            not expected_sizes
            or all(
                any(
                    result.registry == registry and result.hash_seed == seed
                    for result in scale_results
                )
                for registry in expected_registries
            )
        )
        and (
            not expected_durations
            or all(
                any(
                    result.registry == registry and result.hash_seed == seed
                    for result in duration_results
                )
                for registry in expected_duration_registries
            )
        )
        and (
            not expected_protocols
            or all(
                any(
                    result.registry == protocol and result.hash_seed == seed
                    for result in sidecar_results
                )
                for protocol in expected_protocols
            )
        )
        for seed in expected_hash_seeds
    )
    expected_sidecar_coverage = all(
        any(
            result.registry == protocol
            and result.entries >= expected_sidecar_entries
            and result.representation in {"actual_manager", "structural_equivalent"}
            for result in sidecar_results
        )
        for protocol in expected_protocols
    )
    sidecar_estimates_complete = all(
        result.common_estimated_bytes > 0
        and result.common_estimated_index_bytes > 0
        and result.sidecar_estimated_bytes > 0
        and result.sidecar_estimated_index_bytes > 0
        and result.sidecar_live_entries == result.entries
        and result.common_live_entries == result.entries
        for result in sidecar_results
    )
    sidecar_denominators_complete = all(
        result.physical_hot_records
        == (
            result.common_live_entries
            + result.common_used_operation_ids
            + result.sidecar_logical_records
        )
        and result.physical_hot_records > 0
        for result in sidecar_results
    )
    gates: dict[str, bool | None] = {
        "all_isolated_cases_completed": not errors,
        "single_implementation_revision": single_implementation_revision,
        "requested_size_ladder_covered": expected_scale_coverage,
        "requested_group_modes_covered": expected_group_coverage,
        "requested_write_modes_covered": expected_write_coverage,
        "requested_worker_counts_covered": expected_worker_coverage,
        "requested_pythonhashseeds_covered": expected_hash_seed_coverage,
        "requested_durations_covered": expected_duration_coverage,
        "required_protocol_managers_available": (
            None
            if not expected_protocols
            else set(expected_protocols).issubset(_IMPLEMENTED_PROTOCOLS)
        ),
        "protocol_sidecar_actual_or_structural_scale_covered": (
            None
            if not expected_protocols or expected_sidecar_entries <= 0
            else expected_sidecar_coverage
        ),
        "protocol_sidecar_common_and_incremental_bytes_exposed": (
            None if not sidecar_results else sidecar_estimates_complete
        ),
        "protocol_sidecar_physical_denominator_exposed": (
            None if not sidecar_results else sidecar_denominators_complete
        ),
        "mixed_retained_state_families_complete": (
            None if not mixed_results else all(mixed_family_coverage)
        ),
        "mixed_physical_denominator_at_least_requested": (
            None if not mixed_results else all(mixed_physical_denominators)
        ),
        "deployment_content_actual_million_covered": (
            None
            if not million_deployment_results
            else measured_deployment_million_shapes >= required_deployment_million_shapes
        ),
        "deployment_content_million_rss_lte_512_mib": (
            None
            if not million_deployment_results
            else all(
                result.rss_delta_bytes <= 512 * 1_024 * 1_024
                for result in million_deployment_results
            )
        ),
        "deployment_content_million_load_lte_60_seconds": (
            None
            if not million_deployment_results
            else all(result.load_seconds <= 60.0 for result in million_deployment_results)
        ),
        "deployment_content_index_overhead_lte_256_bytes_per_physical_record": (
            None
            if not million_deployment_results
            else all(
                result.metrics.estimated_index_bytes / result.metrics.logical_entries <= 256
                for result in million_deployment_results
                if result.metrics.estimated_index_bytes is not None
            )
        ),
        "primary_1m_over_1k_lte_2": (
            None if not exact_ratios else all(ratio <= 2.0 for ratio in exact_ratios)
        ),
        "secondary_1m_over_1k_lte_3": (
            None if not secondary_ratios else all(ratio <= 3.0 for ratio in secondary_ratios)
        ),
        "temporal_candidate_normalized_1m_over_1k_lte_3": (
            None
            if not temporal_candidate_normalized_ratios
            else all(ratio <= 3.0 for ratio in temporal_candidate_normalized_ratios)
        ),
        "million_load_lte_60_seconds": (
            None
            if not million_results and not million_sidecar_results
            else all(
                result.load_seconds <= 60.0
                for result in [*million_results, *million_sidecar_results]
            )
        ),
        "million_mixed_rss_lte_512_mib": (
            None
            if not million_mixed_results
            else all(
                result.physical_hot_records >= 1_000_000
                and result.rss_delta_bytes <= 512 * 1_024 * 1_024
                for result in million_mixed_results
            )
        ),
        "artifact_index_overhead_lte_256_bytes_per_live_entry": (
            None
            if not estimated_index_results
            else all(
                result.metrics.estimated_index_bytes / result.metrics.logical_entries <= 256
                for result in estimated_index_results
                if result.metrics.estimated_index_bytes is not None
            )
        ),
        "all_registry_index_overhead_lte_256_bytes_per_physical_record": (
            None
            if not million_mixed_results
            or any(
                result.estimated_index_bytes_per_physical_record is None
                for result in million_mixed_results
            )
            else all(
                result.estimated_index_bytes_per_physical_record <= 256
                for result in million_mixed_results
                if result.estimated_index_bytes_per_physical_record is not None
            )
        ),
        "protocol_sidecar_index_overhead_lte_256_bytes_per_live_entry": (
            None
            if not million_sidecar_results
            else all(
                result.sidecar_index_bytes_per_live_entry <= 256
                for result in million_sidecar_results
            )
        ),
        "expire_100k_lte_2_seconds": (
            None
            if not expiry_results or not expiry_registry_coverage
            else all(result.expiry_seconds <= 2.0 for result in expiry_results)
        ),
        # `expiry_seconds` deliberately surrounds each registry's complete
        # watermark call, including its bounded heap/map/segment compaction.
        # Therefore the same <=2s measurement is a conservative upper bound on
        # compaction alone, not a second empty-watermark microbenchmark.
        "compact_100k_lte_2_seconds": (
            None
            if not expiry_results or not expiry_registry_coverage
            else all(result.expiry_seconds <= 2.0 for result in expiry_results)
        ),
        "heap_segment_amplification_below_2": all(
            result.metrics.heap_segment_amplification is None
            or result.metrics.heap_segment_amplification < 2.0
            for result in [*scale_results, *duration_results]
        ),
        "deterministic_across_workers": (
            None if not worker_checks else all(check is True for check in worker_checks)
        ),
        "deterministic_across_pythonhashseed": (
            None if not hash_checks else all(check is True for check in hash_checks)
        ),
        "deterministic_across_workers_and_pythonhashseed": (
            None if not combined_checks else all(check is True for check in combined_checks)
        ),
        "thirty_day_late_hour_lte_1_25x_day": (
            None if not late_hour_ratios else all(ratio <= 1.25 for ratio in late_hour_ratios)
        ),
        "thirty_day_lookup_lte_2x_day": (
            None
            if not duration_lookup_ratios
            else all(ratio <= 2.0 for ratio in duration_lookup_ratios)
        ),
        "seven_to_thirty_day_plateau_rss_within_10_percent": (
            None if not plateau_memory else all(ratio <= 1.10 for ratio in plateau_memory)
        ),
        "seven_to_thirty_day_plateau_index_bytes_within_10_percent": (
            None
            if not plateau_index_memory
            else all(ratio <= 1.10 for ratio in plateau_index_memory)
        ),
        "retained_counts_plateau_by_seven_days": (
            None
            if not expected_duration_registries
            or seven_day_plateau_coverage != len(expected_duration_registries)
            else all(hour is not None and hour <= 168 for hour in seven_day_plateau_hours)
        ),
    }
    if reference_host:
        gates["reference_primary_p95_lte_10_us"] = (
            None
            if not million_results
            else all(result.primary_lookup_p95_us <= 10.0 for result in million_results)
        )
        gates["reference_secondary_p95_lte_50_us"] = (
            None
            if not million_results
            else all(result.secondary_lookup_p95_us <= 50.0 for result in million_results)
        )
        gates["reference_protocol_sidecar_exact_p95_lte_10_us"] = (
            None
            if not million_sidecar_results
            else all(result.lookup_p95_us <= 10.0 for result in million_sidecar_results)
        )
    return gates, ratios


def _resolve_defaults(args: argparse.Namespace) -> dict[str, object]:
    release_like = args.profile in {"release", "exhaustive"}
    sidecar_entries = (
        args.sidecar_entries
        if args.sidecar_entries is not None
        else (_RELEASE_SIDECAR_ENTRIES if release_like else 0)
    )
    return {
        "registries": args.registries or _REGISTRIES,
        "sizes": args.sizes or (_RELEASE_SIZES if release_like else (10, 100)),
        "group_modes": args.group_modes or (_RELEASE_GROUP_MODES if release_like else ("uniform",)),
        "write_modes": args.write_modes
        or (_RELEASE_WRITE_MODES if release_like else ("monotonic",)),
        "workers": args.workers or (_RELEASE_WORKERS if release_like else (1,)),
        "hash_seeds": args.hash_seeds or (_RELEASE_HASH_SEEDS if release_like else (0,)),
        "durations": args.duration_hours or (_RELEASE_DURATIONS if release_like else (24,)),
        "queries": (
            args.queries if args.queries is not None else (_RELEASE_QUERIES if release_like else 50)
        ),
        "rate_per_hour": (
            args.rate_per_hour
            if args.rate_per_hour is not None
            else (_RELEASE_RATE_PER_HOUR if release_like else 2)
        ),
        "churn_entries": (
            args.churn_entries
            if args.churn_entries is not None
            else (_RELEASE_CHURN_ENTRIES if release_like else 5)
        ),
        "mixed_entries": (
            args.mixed_entries
            if args.mixed_entries is not None
            else (_RELEASE_MIXED_ENTRIES if release_like else 0)
        ),
        "sidecar_protocols": (
            args.sidecar_protocols
            or (_IMPLEMENTED_PROTOCOLS if release_like or sidecar_entries else ())
        ),
        "sidecar_entries": sidecar_entries,
    }


def _authoritative_release_requested(args: argparse.Namespace) -> bool:
    """Return whether this invocation claims final release evidence authority."""

    return args.profile == "release" and args.enforce and args.require_complete


def _canonical_release_configuration(config: dict[str, object]) -> bool:
    """Return whether resolved inputs preserve the frozen 161-case release matrix."""

    return config == {
        "registries": _REGISTRIES,
        "sizes": _RELEASE_SIZES,
        "group_modes": _RELEASE_GROUP_MODES,
        "write_modes": _RELEASE_WRITE_MODES,
        "workers": _RELEASE_WORKERS,
        "hash_seeds": _RELEASE_HASH_SEEDS,
        "durations": _RELEASE_DURATIONS,
        "queries": _RELEASE_QUERIES,
        "rate_per_hour": _RELEASE_RATE_PER_HOUR,
        "churn_entries": _RELEASE_CHURN_ENTRIES,
        "mixed_entries": _RELEASE_MIXED_ENTRIES,
        "sidecar_protocols": _IMPLEMENTED_PROTOCOLS,
        "sidecar_entries": _RELEASE_SIDECAR_ENTRIES,
    }


def _authoritative_release_preflight_errors(
    config: dict[str, object],
    specs: Sequence[CaseSpec],
    snapshot: RepositorySnapshot,
) -> tuple[str, ...]:
    """Return allocation-free reasons an authoritative release must not launch."""

    errors: list[str] = []
    if (
        not _canonical_release_configuration(config)
        or len(specs) != _AUTHORITATIVE_RELEASE_CASE_COUNT
    ):
        errors.append(
            "the authoritative release must use the unchanged canonical 161-case configuration"
        )
    if len(set(_IMPLEMENTATION_FILES)) != len(_IMPLEMENTATION_FILES):
        errors.append("the implementation provenance manifest contains duplicate paths")
    missing = _missing_implementation_files()
    if missing:
        errors.append("implementation provenance files are missing: " + ", ".join(missing))
    if snapshot.git_sha is None:
        errors.append("the Git HEAD revision is unavailable")
    if snapshot.dirty is not False:
        errors.append("the Git worktree must be clean before authoritative release measurement")
    return tuple(errors)


def _release_provenance_gates(
    *,
    authoritative: bool,
    case_count: int,
    implementation_revision_gate: bool | None,
    start: RepositorySnapshot,
    end: RepositorySnapshot,
) -> dict[str, bool | None]:
    """Build final revision gates without making dirty development runs unusable."""

    manifest_complete = (
        len(set(_IMPLEMENTATION_FILES)) == len(_IMPLEMENTATION_FILES)
        and not _missing_implementation_files()
    )
    if not authoritative:
        return {
            "implementation_manifest_complete": manifest_complete,
            "repository_revision_stable": None,
            "repository_worktree_clean": None,
            "authoritative_release_case_count_preserved": None,
            "release_result_revision_bound": None,
        }

    revision_stable = (
        start.git_sha is not None and end.git_sha is not None and start.git_sha == end.git_sha
    )
    worktree_clean = start.dirty is False and end.dirty is False
    case_count_preserved = case_count == _AUTHORITATIVE_RELEASE_CASE_COUNT
    return {
        "implementation_manifest_complete": manifest_complete,
        "repository_revision_stable": revision_stable,
        "repository_worktree_clean": worktree_clean,
        "authoritative_release_case_count_preserved": case_count_preserved,
        "release_result_revision_bound": (
            manifest_complete
            and revision_stable
            and worktree_clean
            and case_count_preserved
            and implementation_revision_gate is True
        ),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        choices=("smoke", "release", "exhaustive"),
        default="smoke",
        help=(
            "Smoke is tiny. Release uses the full size/duration ladder with a pairwise stress "
            "matrix. Exhaustive takes the full Cartesian product and is intentionally expensive."
        ),
    )
    parser.add_argument("--registries", type=_parse_registries)
    parser.add_argument(
        "--sidecar-protocols",
        type=_parse_protocols,
        help="Protocol managers to measure with their shared ApplicationChannelRegistry.",
    )
    parser.add_argument(
        "--sidecar-entries",
        type=int,
        help=(
            "Actual manager entries per protocol-sidecar case. Release defaults to 1,000,000; "
            "smoke skips sidecars unless this is explicit."
        ),
    )
    parser.add_argument("--sizes", type=_parse_positive_ints)
    parser.add_argument("--group-modes", type=_parse_group_modes)
    parser.add_argument("--write-modes", type=_parse_write_modes)
    parser.add_argument("--workers", type=_parse_positive_ints)
    parser.add_argument("--hash-seeds", type=_parse_nonnegative_ints)
    parser.add_argument("--duration-hours", type=_parse_positive_ints)
    parser.add_argument("--queries", type=int)
    parser.add_argument("--rate-per-hour", type=int)
    parser.add_argument("--churn-entries", type=int)
    parser.add_argument(
        "--mixed-entries",
        type=int,
        help=(
            "Load at least this many physical hot records across every retained-state family in "
            "one process. Release defaults to 1,000,000; smoke skips unless explicit."
        ),
    )
    parser.add_argument("--skip-scale", action="store_true")
    parser.add_argument("--skip-duration", action="store_true")
    parser.add_argument("--skip-mixed", action="store_true")
    parser.add_argument("--skip-sidecars", action="store_true")
    parser.add_argument("--reference-host", action="store_true")
    parser.add_argument("--json-output", type=Path)
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Exit nonzero for a measured false gate; open/null gates remain visible.",
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="Also exit nonzero while any gate is open/null (release-readiness behavior).",
    )
    parser.add_argument("--child-case", help=argparse.SUPPRESS)
    return parser


def main() -> int:
    parser = _parser()
    args = parser.parse_args()
    if args.child_case is not None:
        spec = _decode_spec(args.child_case)
        actual_seed = os.environ.get("PYTHONHASHSEED")
        if actual_seed != str(spec.hash_seed):
            parser.error(
                f"child PYTHONHASHSEED {actual_seed!r} does not match case {spec.hash_seed}"
            )
        if spec.kind == "scale":
            result = _run_scale_case(spec)
        elif spec.kind == "duration":
            result = _run_duration_case(spec)
        elif spec.kind == "sidecar":
            result = _run_sidecar_case(spec)
        else:
            result = _run_mixed_case(spec)
        print(json.dumps(asdict(result), sort_keys=True, separators=(",", ":")))
        return 0

    if args.skip_scale and args.skip_duration and args.skip_sidecars:
        parser.error("all workload families cannot be skipped")
    if args.queries is not None and args.queries <= 0:
        parser.error("--queries must be positive")
    if args.rate_per_hour is not None and args.rate_per_hour <= 0:
        parser.error("--rate-per-hour must be positive")
    if args.churn_entries is not None and args.churn_entries < 0:
        parser.error("--churn-entries cannot be negative")
    if args.mixed_entries is not None and args.mixed_entries < len(_MIXED_FAMILIES):
        parser.error(f"--mixed-entries must be at least {len(_MIXED_FAMILIES)}")
    if args.sidecar_entries is not None and args.sidecar_entries <= 0:
        parser.error("--sidecar-entries must be positive")

    config = _resolve_defaults(args)
    registries = config["registries"]
    sizes = config["sizes"]
    group_modes = config["group_modes"]
    write_modes = config["write_modes"]
    workers = config["workers"]
    hash_seeds = config["hash_seeds"]
    durations = config["durations"]
    queries = config["queries"]
    rate_per_hour = config["rate_per_hour"]
    churn_entries = config["churn_entries"]
    mixed_entries = config["mixed_entries"]
    sidecar_protocols = config["sidecar_protocols"]
    sidecar_entries = config["sidecar_entries"]
    assert isinstance(registries, tuple)
    assert isinstance(sizes, tuple)
    assert isinstance(group_modes, tuple)
    assert isinstance(write_modes, tuple)
    assert isinstance(workers, tuple)
    assert isinstance(hash_seeds, tuple)
    assert isinstance(durations, tuple)
    assert isinstance(queries, int)
    assert isinstance(rate_per_hour, int)
    assert isinstance(churn_entries, int)
    assert isinstance(mixed_entries, int)
    assert isinstance(sidecar_protocols, tuple)
    assert isinstance(sidecar_entries, int)

    specs: list[CaseSpec] = []
    if not args.skip_scale:
        specs.extend(
            _build_scale_specs(
                profile=args.profile,
                registries=registries,
                sizes=sizes,
                group_modes=group_modes,
                write_modes=write_modes,
                workers=workers,
                hash_seeds=hash_seeds,
                queries=queries,
                churn_entries=churn_entries,
            )
        )
    if not args.skip_duration:
        duration_registries = tuple(
            registry for registry in registries if registry in _DURATION_REGISTRIES
        )
        specs.extend(
            _build_duration_specs(
                profile=args.profile,
                registries=duration_registries,
                durations=durations,
                workers=workers,
                hash_seeds=hash_seeds,
                rate_per_hour=rate_per_hour,
                group_modes=group_modes,
            )
        )
    if (
        not args.skip_scale
        and not args.skip_mixed
        and mixed_entries
        and (args.mixed_entries is not None or set(registries) == set(_REGISTRIES))
    ):
        specs.append(
            CaseSpec(
                kind="mixed",
                registry="mixed",
                entries=mixed_entries,
                queries=queries,
                group_mode="uniform",
                write_mode="monotonic",
                workers=1 if 1 in workers else workers[0],
                hash_seed=hash_seeds[0],
            )
        )
    if not args.skip_sidecars and sidecar_entries:
        specs.extend(
            _build_sidecar_specs(
                profile=args.profile,
                protocols=sidecar_protocols,
                entries=sidecar_entries,
                workers=workers,
                hash_seeds=hash_seeds,
                queries=queries,
            )
        )
    if not specs:
        parser.error("the selected options produced no workload cases")

    authoritative_release = _authoritative_release_requested(args)
    repository_start = _repository_snapshot()
    if authoritative_release:
        preflight_errors = _authoritative_release_preflight_errors(
            config,
            specs,
            repository_start,
        )
        if preflight_errors:
            parser.error("authoritative release preflight failed: " + "; ".join(preflight_errors))

    completed: list[ScaleResult | DurationResult | MixedResult | SidecarResult] = []
    errors: list[CaseError] = []
    for index, spec in enumerate(specs, start=1):
        print(
            f"foundation scale probe case {index}/{len(specs)}: {spec.kind}/{spec.registry}",
            file=sys.stderr,
        )
        result = _run_isolated(spec)
        if isinstance(result, CaseError):
            errors.append(result)
        else:
            completed.append(result)
    # Capture final repository provenance before writing the requested JSON
    # artifact, which may itself be a tracked or untracked repository path.
    repository_end = _repository_snapshot()
    scale_results = [result for result in completed if isinstance(result, ScaleResult)]
    duration_results = [result for result in completed if isinstance(result, DurationResult)]
    mixed_results = [result for result in completed if isinstance(result, MixedResult)]
    sidecar_results = [result for result in completed if isinstance(result, SidecarResult)]
    expected_protocols: tuple[ProtocolName, ...] = (
        _REQUIRED_PROTOCOLS
        if args.profile in {"release", "exhaustive"} and not args.skip_sidecars
        else sidecar_protocols
    )
    gates, ratios = _result_gates(
        scale_results,
        duration_results,
        mixed_results,
        sidecar_results,
        errors,
        expected_registries=registries,
        expected_sizes=() if args.skip_scale else sizes,
        expected_group_modes=() if args.skip_scale else group_modes,
        expected_write_modes=() if args.skip_scale else write_modes,
        expected_workers=workers,
        expected_hash_seeds=hash_seeds,
        expected_durations=() if args.skip_duration else durations,
        expected_protocols=() if args.skip_sidecars else expected_protocols,
        expected_sidecar_entries=0 if args.skip_sidecars else sidecar_entries,
        reference_host=args.reference_host,
    )
    gates.update(
        _release_provenance_gates(
            authoritative=authoritative_release,
            case_count=len(specs),
            implementation_revision_gate=gates["single_implementation_revision"],
            start=repository_start,
            end=repository_end,
        )
    )
    open_gates = sorted(name for name, value in gates.items() if value is None)
    failed_gates = sorted(name for name, value in gates.items() if value is False)
    million_deployment_results = [
        result
        for result in scale_results
        if result.registry == "deployment"
        and result.entries == 1_000_000
        and result.metrics.logical_entries >= 1_000_000
    ]
    observability_gaps: list[str] = []
    if gates["million_mixed_rss_lte_512_mib"] is None:
        observability_gaps.append(
            "The mixed RSS gate requires an explicit one-million-entry mixed case; release "
            "mode includes it and smoke mode does not."
        )
    if gates["all_registry_index_overhead_lte_256_bytes_per_physical_record"] is None:
        observability_gaps.append(
            "The all-registry index-overhead gate requires that same mixed case and a public "
            "index-only estimate from every registry."
        )
    if gates["mixed_retained_state_families_complete"] is not True:
        observability_gaps.append(
            "The mixed result must retain and expose public total/index byte censuses for every "
            f"implemented family: {', '.join(_MIXED_FAMILIES)}."
        )
    if gates["mixed_physical_denominator_at_least_requested"] is not True:
        observability_gaps.append(
            "The mixed result must reach its requested actual physical-record floor, and the "
            "reported total must exactly equal the sum of non-overlapping family denominators."
        )
    if gates["deployment_content_actual_million_covered"] is not True:
        observability_gaps.append(
            "Deployment/content requires its own actual one-million-physical-row scale case; "
            "its smaller representative share in the mixed workload is not a substitute."
        )
    if gates["required_protocol_managers_available"] is False:
        missing_protocols = sorted(set(expected_protocols) - set(_IMPLEMENTED_PROTOCOLS))
        observability_gaps.append(
            "Required protocol managers are not implemented and therefore cannot have an "
            f"actual-million sidecar result: {', '.join(missing_protocols)}."
        )
    if gates["protocol_sidecar_actual_or_structural_scale_covered"] is False:
        observability_gaps.append(
            "At least one required protocol lacks an actual or structurally equivalent "
            f"{sidecar_entries:,}-entry sidecar run."
        )
    payload: dict[str, object] = {
        "schema_version": 1,
        "profile": args.profile,
        "python": sys.version,
        "release_authority": {
            "requested": authoritative_release,
            "required_flags": ("--profile release", "--enforce", "--require-complete"),
            "canonical_case_count": _AUTHORITATIVE_RELEASE_CASE_COUNT,
        },
        "repository": {
            "git_sha_start": repository_start.git_sha,
            "git_sha_end": repository_end.git_sha,
            "dirty_start": repository_start.dirty,
            "dirty_end": repository_end.dirty,
            "status_digest_start": repository_start.status_digest,
            "status_digest_end": repository_end.status_digest,
            "snapshot_boundary": "before_json_output",
        },
        "configuration": {
            "registries": registries,
            "sizes": sizes,
            "group_modes": group_modes,
            "write_modes": write_modes,
            "workers": workers,
            "hash_seeds": hash_seeds,
            "duration_hours": durations,
            "queries": queries,
            "rate_per_hour": rate_per_hour,
            "churn_entries": churn_entries,
            "mixed_entries": mixed_entries,
            "mixed_families": _MIXED_FAMILIES,
            "sidecar_protocols": sidecar_protocols,
            "required_protocols": expected_protocols,
            "sidecar_entries": sidecar_entries,
        },
        "case_count": len(specs),
        "results": [asdict(result) for result in completed],
        "errors": [asdict(error) for error in errors],
        "ratios": ratios,
        "gate_evidence": {
            "expire_and_compact_100k": [
                {
                    "registry": result.registry,
                    "entries": result.expiry_entries,
                    "close_prepare_seconds": result.close_prepare_seconds,
                    "close_seconds": result.close_seconds,
                    "watermark_seconds": result.expiry_seconds,
                    "includes_bounded_compaction": True,
                }
                for result in scale_results
                if result.expiry_entries >= 100_000 and result.registry != "collection"
            ],
            "temporal_candidate_normalization": {
                "registry": "lifecycle",
                "returned_results_per_query": 1,
                "ratio": ratios.get("lifecycle", {}).get(
                    "temporal_candidate_normalized_1m_over_1k"
                ),
            },
            "duration_plateaus": [
                {
                    "registry": result.registry,
                    "duration_hours": result.duration_hours,
                    "plateau_hour": result.plateau_hour,
                    "retained_entries": result.metrics.retained_entries,
                    "estimated_index_bytes": result.metrics.estimated_index_bytes,
                    "rss_delta_bytes": result.rss_delta_bytes,
                }
                for result in duration_results
                if result.duration_hours in {168, 720}
                and result.workers == 1
                and result.hash_seed == min(hash_seeds, default=0)
            ],
            "duration_plateau_contract": {
                "minimum_unchanged_suffix_hours": _MIN_PLATEAU_SUFFIX_HOURS,
                "exact_footprint": "retained counts and backing capacity",
                "no_stable_suffix_result": None,
            },
            "protocol_sidecars": [
                {
                    "protocol": result.registry,
                    "entries": result.entries,
                    "representation": result.representation,
                    "common_estimated_bytes": result.common_estimated_bytes,
                    "common_estimated_index_bytes": result.common_estimated_index_bytes,
                    "sidecar_estimated_bytes": result.sidecar_estimated_bytes,
                    "sidecar_estimated_index_bytes": result.sidecar_estimated_index_bytes,
                    "lookup_p95_us": result.lookup_p95_us,
                    "physical_hot_records": result.physical_hot_records,
                    "rss_bytes_per_physical_record": result.rss_bytes_per_physical_record,
                    "load_seconds_per_million_physical_records": (
                        result.load_seconds_per_million_physical_records
                    ),
                }
                for result in sidecar_results
                if result.entries == sidecar_entries
            ],
            "mixed_retained_state_families": [
                {
                    "requested_physical_floor": result.entries,
                    "physical_hot_records": result.physical_hot_records,
                    "rss_delta_bytes": result.rss_delta_bytes,
                    "rss_bytes_per_physical_record": result.rss_bytes_per_physical_record,
                    "family_coverage_complete": result.family_coverage_complete,
                    "families": {
                        name: asdict(family) for name, family in result.family_censuses.items()
                    },
                }
                for result in mixed_results
            ],
            "deployment_content_actual_million": [
                {
                    "group_mode": result.group_mode,
                    "write_mode": result.write_mode,
                    "physical_records": result.metrics.logical_entries,
                    "load_seconds": result.load_seconds,
                    "rss_delta_bytes": result.rss_delta_bytes,
                    "rss_bytes_per_physical_record": (
                        result.rss_delta_bytes / max(1, result.metrics.logical_entries)
                    ),
                    "estimated_index_bytes": result.metrics.estimated_index_bytes,
                    "estimated_index_bytes_per_physical_record": (
                        None
                        if result.metrics.estimated_index_bytes is None
                        else result.metrics.estimated_index_bytes
                        / max(1, result.metrics.logical_entries)
                    ),
                }
                for result in million_deployment_results
            ],
        },
        "gates": gates,
        "open_gates": open_gates,
        "failed_gates": failed_gates,
        "summary": {
            "median_primary_lookup_p95_us": (
                statistics.median(result.primary_lookup_p95_us for result in scale_results)
                if scale_results
                else None
            ),
            "median_secondary_lookup_p95_us": (
                statistics.median(result.secondary_lookup_p95_us for result in scale_results)
                if scale_results
                else None
            ),
            "maximum_rss_delta_bytes": max(
                (result.rss_delta_bytes for result in completed),
                default=0,
            ),
            "implementation_digests": sorted(
                {
                    result.implementation_digest_start
                    for result in completed
                    if result.implementation_digest_start
                }
            ),
            "git_sha": (
                repository_end.git_sha
                if repository_start.git_sha == repository_end.git_sha
                else None
            ),
        },
        "known_observability_gaps": observability_gaps,
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.json_output is not None:
        args.json_output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if args.require_complete and (open_gates or failed_gates):
        return 1
    if args.enforce and failed_gates:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
