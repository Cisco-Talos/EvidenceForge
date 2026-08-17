#!/usr/bin/env python3
"""Fresh-child scale and duration probe for lifecycle service/transport authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter, perf_counter_ns
from typing import Any, Literal

import psutil

from evidenceforge.events.lifecycle import (
    LifecycleCloseBarrier,
    LifecycleMembership,
    LifecycleRetentionLease,
    LogicalServiceIdentity,
    ProcessLifecycleIdentity,
    ProcessTokenIdentity,
    ServiceInstanceLifecycleIdentity,
    ServiceProcessBindingIdentity,
    SessionLifecycleIdentity,
    TransportLifecycleIdentity,
    TransportSessionBindingIdentity,
)
from evidenceforge.events.network import NetworkTuple
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry

_Kind = Literal["service", "transport"]
_GroupMode = Literal["uniform", "skewed"]
_WriteMode = Literal["monotonic", "out-of-order"]

_START = datetime(2026, 1, 5, 9, tzinfo=UTC)
_MIB = 1024 * 1024
_DEFAULT_SCALE_LADDER = "10,100,1000,10000,100000,1000000,2000000"
_SOURCE_FILES = (
    Path("src/evidenceforge/events/lifecycle.py"),
    Path("src/evidenceforge/generation/indexes.py"),
    Path("src/evidenceforge/generation/lifecycle_registry.py"),
    Path("scripts/lifecycle_service_transport_scale_probe.py"),
)


@dataclass(frozen=True, slots=True)
class LifecycleProductionShapeCensus:
    """Public physical and semantic denominators for mixed lifecycle scale.

    Logical-service identity is semantically distinct but co-packed into its
    service-instance value row. ``physical_records`` therefore counts that row
    once, while ``semantic_records`` also reports the logical identity count.
    """

    process_entries: int
    session_entries: int
    logical_service_entries: int
    service_instance_entries: int
    transport_entries: int
    service_process_bindings: int
    transport_session_bindings: int
    physical_records: int
    semantic_records: int
    route_entries: int
    estimated_bytes: int
    estimated_index_bytes: int
    candidates_inspected: int


def lifecycle_production_shape_census(
    registry: LifecycleRegistry,
) -> LifecycleProductionShapeCensus:
    """Return a public-census-only physical denominator for a mixed registry."""

    census = registry.census()
    physical_records = (
        census.process_entries
        + census.session_entries
        + census.service_instance_entries
        + census.transport_entries
        + census.service_process_bindings
        + census.transport_session_bindings
    )
    semantic_records = physical_records + census.logical_service_entries
    return LifecycleProductionShapeCensus(
        process_entries=census.process_entries,
        session_entries=census.session_entries,
        logical_service_entries=census.logical_service_entries,
        service_instance_entries=census.service_instance_entries,
        transport_entries=census.transport_entries,
        service_process_bindings=census.service_process_bindings,
        transport_session_bindings=census.transport_session_bindings,
        physical_records=physical_records,
        semantic_records=semantic_records,
        route_entries=census.route_entries,
        estimated_bytes=census.estimated_bytes,
        estimated_index_bytes=census.estimated_index_bytes,
        candidates_inspected=census.candidates_inspected,
    )


def populate_lifecycle_production_shape(
    registry: LifecycleRegistry,
    *,
    entries: int,
    start_ordinal: int = 0,
    canonical_start: datetime = _START,
) -> LifecycleProductionShapeCensus:
    """Populate representative session/process/service/transport ownership rows.

    Each ordinal contributes four canonical entity rows and the two ownership
    relations required by production service and remote-session activity. The
    transport consumes a prebuilt canonical tuple and UID; it never allocates
    observation-local identity inside the lifecycle registry.
    """

    if entries < 0 or start_ordinal < 0:
        raise ValueError("Lifecycle production-shape counts must be non-negative")
    for ordinal in range(start_ordinal, start_ordinal + entries):
        target_host = f"shape-target-{ordinal}"
        source_host = f"shape-source-{ordinal}"
        session = SessionLifecycleIdentity(
            hostname=target_host,
            object_id=f"shape-session-{ordinal}",
            logon_id=f"0x{ordinal + 0x100000:016x}",
            principal=f"shape-user-{ordinal}",
            session_kind="remote_interactive",
            started_at=canonical_start,
            session_id=2,
        )
        registry.register_session(
            session,
            action_id=f"shape-session-{ordinal}",
            transition_id=f"shape-session-start-{ordinal}",
        )
        process = ProcessLifecycleIdentity(
            hostname=target_host,
            object_id=f"shape-process-{ordinal}",
            pid=4_000 + ordinal % 50_000,
            started_at=canonical_start + timedelta(microseconds=1),
            image=r"C:\Windows\System32\svchost.exe",
            role="service_host",
        )
        registry.register_process(
            process,
            token=ProcessTokenIdentity(
                principal=session.principal,
                logon_id=session.logon_id,
                session_id=session.session_id,
                logon_type=10,
            ),
            membership=LifecycleMembership(
                owner_kind="session",
                owner_object_id=session.object_id,
                session_object_id=session.object_id,
            ),
            action_id=f"shape-process-{ordinal}",
            transition_id=f"shape-process-start-{ordinal}",
        )
        logical = LogicalServiceIdentity(
            hostname=target_host,
            logical_service_id=f"shape-service-{ordinal}",
            canonical_name=f"ShapeService{ordinal}",
            service_kind="builtin",
        )
        service = ServiceInstanceLifecycleIdentity(
            hostname=target_host,
            object_id=f"shape-service-object-{ordinal}",
            logical_service_id=logical.logical_service_id,
            boot_id=f"shape-boot-{ordinal}",
            instance_id="builtin",
            started_at=canonical_start + timedelta(microseconds=1),
        )
        registry.register_service_instance(
            logical,
            service,
            action_id=f"shape-service-{ordinal}",
            transition_id=f"shape-service-start-{ordinal}",
        )
        transport = TransportLifecycleIdentity(
            hostname=source_host,
            object_id=f"shape-transport-object-{ordinal}",
            transport_id=f"shape-network-plan-{ordinal}",
            src_hostname=source_host,
            dst_hostname=target_host,
            network_tuple=_tuple_for(ordinal),
            opened_at=canonical_start + timedelta(microseconds=1),
            close_deadline=canonical_start + timedelta(hours=1),
            zeek_uid=f"C-shape-{ordinal}",
            conn_id=f"shape-conn-{ordinal}",
        )
        registry.register_transport(
            transport,
            action_id=f"shape-transport-{ordinal}",
            transition_id=f"shape-transport-start-{ordinal}",
        )
        bound_at = canonical_start + timedelta(microseconds=2)
        registry.bind_service_process(
            ServiceProcessBindingIdentity(
                binding_id=f"shape-service-process-{ordinal}",
                service_object_id=service.object_id,
                process_object_id=process.object_id,
                bound_at=bound_at,
                role="shared_host_process",
                action_id=f"shape-service-process-{ordinal}",
            )
        )
        registry.bind_transport_session(
            TransportSessionBindingIdentity(
                binding_id=f"shape-transport-session-{ordinal}",
                transport_object_id=transport.object_id,
                session_object_id=session.object_id,
                bound_at=bound_at,
                role="session",
                action_id=f"shape-transport-session-{ordinal}",
            )
        )
    return lifecycle_production_shape_census(registry)


def _rss_bytes() -> int:
    return psutil.Process().memory_info().rss


def _peak_rss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == "darwin" else value * 1024)


def _p95_us(samples_ns: list[int]) -> float:
    if not samples_ns:
        return 0.0
    ordered = sorted(samples_ns)
    index = min(len(ordered) - 1, max(0, round(len(ordered) * 0.95) - 1))
    return ordered[index] / 1_000.0


def _query_keys(entries: int, queries: int) -> list[int]:
    cursor = 0x9E3779B97F4A7C15
    keys: list[int] = []
    for _ in range(min(queries, entries * 4)):
        cursor = (cursor * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        keys.append(cursor % entries)
    return keys


def _timestamp_ordinal(ordinal: int, write_mode: _WriteMode) -> int:
    if write_mode == "out-of-order" and ordinal >= 10 and ordinal % 10 == 0:
        return ordinal - 9
    return ordinal


def _host(ordinal: int, group_mode: _GroupMode) -> str:
    return f"h{ordinal}" if group_mode == "uniform" else "skew-owner"


def _logical_service(ordinal: int, group_mode: _GroupMode) -> LogicalServiceIdentity:
    hostname = _host(ordinal, group_mode)
    return LogicalServiceIdentity(
        hostname=hostname,
        logical_service_id=f"svc{ordinal}",
        canonical_name=f"Service{ordinal}",
        service_kind="builtin",
    )


def _service_identity(
    ordinal: int,
    group_mode: _GroupMode,
    write_mode: _WriteMode,
) -> ServiceInstanceLifecycleIdentity:
    logical = _logical_service(ordinal, group_mode)
    return ServiceInstanceLifecycleIdentity(
        hostname=logical.hostname,
        object_id=f"so{ordinal}",
        logical_service_id=logical.logical_service_id,
        boot_id="b0",
        instance_id="builtin",
        started_at=_START + timedelta(microseconds=_timestamp_ordinal(ordinal, write_mode)),
    )


def _tuple_for(ordinal: int) -> NetworkTuple:
    return NetworkTuple(
        src_ip=f"10.{(ordinal >> 16) & 255}.{(ordinal >> 8) & 255}.{ordinal & 255}",
        src_port=10_000 + ordinal % 50_000,
        dst_ip=f"198.18.{(ordinal >> 8) & 255}.{ordinal & 255}",
        dst_port=22 + ordinal % 4,
        protocol="tcp",
    )


def _transport_identity(
    ordinal: int,
    group_mode: _GroupMode,
    write_mode: _WriteMode,
) -> TransportLifecycleIdentity:
    opened_at = _START + timedelta(microseconds=_timestamp_ordinal(ordinal, write_mode))
    hostname = _host(ordinal, group_mode)
    return TransportLifecycleIdentity(
        hostname=hostname,
        object_id=f"to{ordinal}",
        transport_id=f"tp{ordinal}",
        src_hostname=hostname,
        dst_hostname=f"d{ordinal % 257}",
        network_tuple=_tuple_for(ordinal),
        opened_at=opened_at,
        close_deadline=opened_at + timedelta(hours=1),
        zeek_uid=f"C{ordinal}",
    )


def _register(
    registry: LifecycleRegistry,
    kind: _Kind,
    ordinal: int,
    group_mode: _GroupMode,
    write_mode: _WriteMode,
) -> None:
    if kind == "service":
        logical = _logical_service(ordinal, group_mode)
        registry.register_service_instance(
            logical,
            _service_identity(ordinal, group_mode, write_mode),
            action_id=f"a{ordinal}",
            transition_id=f"st{ordinal}",
        )
        return
    registry.register_transport(
        _transport_identity(ordinal, group_mode, write_mode),
        action_id=f"a{ordinal}",
        transition_id=f"tt{ordinal}",
    )


def _exact_lookup(
    registry: LifecycleRegistry,
    kind: _Kind,
    ordinal: int,
) -> object | None:
    if kind == "service":
        return registry.get_service_instance(f"so{ordinal}")
    return registry.get_transport(f"to{ordinal}")


def _temporal_lookup(
    registry: LifecycleRegistry,
    kind: _Kind,
    ordinal: int,
    group_mode: _GroupMode,
    write_mode: _WriteMode,
) -> object | None:
    if kind == "service":
        identity = _service_identity(ordinal, group_mode, write_mode)
        return registry.service_for_logical_at(
            identity.hostname,
            identity.logical_service_id,
            identity.started_at,
        )
    identity = _transport_identity(ordinal, group_mode, write_mode)
    return registry.transport_for_tuple_at(
        identity.hostname,
        identity.tuple_key,
        identity.opened_at,
    )


def _assert_snapshot(kind: _Kind, ordinal: int, snapshot: Any | None) -> None:
    if snapshot is None:
        raise AssertionError(f"Lifecycle {kind} lookup missed ordinal {ordinal}")
    expected = f"so{ordinal}" if kind == "service" else f"to{ordinal}"
    identity = snapshot.identity
    if identity.object_id != expected:
        raise AssertionError(
            f"Lifecycle {kind} lookup returned {identity.object_id}, not {expected}"
        )


def _public_digest(census: object, *, kind: _Kind, entries: int) -> str:
    payload = asdict(census)  # public frozen census only
    payload["watermark"] = str(payload["watermark"])
    encoded = json.dumps(
        {"kind": kind, "entries": entries, "census": payload},
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _scale_child(payload: dict[str, Any]) -> dict[str, Any]:
    entries = int(payload["entries"])
    queries = int(payload["queries"])
    kind: _Kind = payload["entity_kind"]
    group_mode: _GroupMode = payload["group_mode"]
    write_mode: _WriteMode = payload["write_mode"]
    workers = int(payload["workers"])
    registry = LifecycleRegistry(shard_count=64)
    rss_before = _rss_bytes()
    peak_before = _peak_rss_bytes()
    load_started = perf_counter()
    if workers == 1:
        for ordinal in range(entries):
            _register(registry, kind, ordinal, group_mode, write_mode)
    else:

        def publish(ordinal: int) -> None:
            _register(registry, kind, ordinal, group_mode, write_mode)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            tuple(executor.map(publish, range(entries), chunksize=256))
    load_seconds = perf_counter() - load_started
    rss_loaded = _rss_bytes()
    peak_loaded = _peak_rss_bytes()

    keys = _query_keys(entries, queries)

    def exact_pass(*, measure: bool) -> list[int]:
        samples: list[int] = []
        for ordinal in keys:
            started = perf_counter_ns()
            snapshot = _exact_lookup(registry, kind, ordinal)
            elapsed = perf_counter_ns() - started
            _assert_snapshot(kind, ordinal, snapshot)
            if measure:
                samples.append(elapsed)
        return samples

    def temporal_pass(*, measure: bool) -> list[int]:
        samples: list[int] = []
        for ordinal in keys:
            started = perf_counter_ns()
            snapshot = _temporal_lookup(registry, kind, ordinal, group_mode, write_mode)
            elapsed = perf_counter_ns() - started
            _assert_snapshot(kind, ordinal, snapshot)
            if measure:
                samples.append(elapsed)
        return samples

    exact_cold = exact_pass(measure=True)
    for _ in range(3):
        exact_pass(measure=False)
    exact_candidates_before = registry.census().lookup_candidates_inspected
    exact_warm = exact_pass(measure=True)
    exact_candidates_after = registry.census().lookup_candidates_inspected

    missing_before = registry.census().lookup_candidates_inspected
    for ordinal in range(min(1_000, len(keys))):
        missing = (
            registry.get_service_instance(f"missing-service-{ordinal}")
            if kind == "service"
            else registry.get_transport(f"missing-transport-{ordinal}")
        )
        if missing is not None:
            raise AssertionError("Lifecycle missing exact lookup returned state")
    missing_after = registry.census().lookup_candidates_inspected

    temporal_cold = temporal_pass(measure=True)
    for _ in range(3):
        temporal_pass(measure=False)
    temporal_candidates_before = registry.census().lookup_candidates_inspected
    temporal_warm = temporal_pass(measure=True)
    temporal_candidates_after = registry.census().lookup_candidates_inspected

    census = registry.census()
    rss_hot = _rss_bytes()
    peak_hot = _peak_rss_bytes()
    live_entries = (
        census.service_instance_entries if kind == "service" else census.transport_entries
    )
    temporal_live = (
        census.service_temporal_live_entries
        if kind == "service"
        else census.transport_temporal_live_entries
    )
    temporal_backing = (
        census.service_temporal_backing_entries
        if kind == "service"
        else census.transport_temporal_backing_entries
    )
    primary_backing = (
        census.service_index_backing_entries
        if kind == "service"
        else census.transport_index_backing_entries
    )
    return {
        "kind": "scale",
        "entity_kind": kind,
        "entries": entries,
        "queries": len(keys),
        "group_mode": group_mode,
        "write_mode": write_mode,
        "workers": workers,
        "load_seconds": load_seconds,
        "exact_cold_lookup_p95_us": _p95_us(exact_cold),
        "exact_lookup_p95_us": _p95_us(exact_warm),
        "temporal_cold_lookup_p95_us": _p95_us(temporal_cold),
        "temporal_lookup_p95_us": _p95_us(temporal_warm),
        "exact_candidates_inspected": exact_candidates_after - exact_candidates_before,
        "temporal_candidates_inspected": temporal_candidates_after - temporal_candidates_before,
        "missing_candidates_inspected": missing_after - missing_before,
        "rss_loaded_delta_bytes": max(0, rss_loaded - rss_before),
        "rss_hot_delta_bytes": max(0, rss_hot - rss_before),
        "rss_delta_bytes": max(0, max(rss_loaded, rss_hot) - rss_before),
        "peak_rss_delta_bytes": max(0, max(peak_loaded, peak_hot) - peak_before),
        "estimated_bytes": census.estimated_bytes,
        "estimated_index_bytes": census.estimated_index_bytes,
        "estimated_index_bytes_per_live": census.estimated_index_bytes / max(1, live_entries),
        "live_entries": live_entries,
        "retained_entries": live_entries,
        "stale_entries": census.temporal_stale_entries,
        "primary_backing_entries": primary_backing,
        "temporal_live_entries": temporal_live,
        "temporal_backing_entries": temporal_backing,
        "route_entries": census.route_entries,
        "route_map_backing_bytes": census.route_map_backing_bytes,
        "retention_deadline_entries": census.retention_deadline_entries,
        "lease_deadline_backing_entries": census.lease_deadline_backing_entries,
        "public_census_digest": _public_digest(census, kind=kind, entries=entries),
    }


def _close_one(
    registry: LifecycleRegistry,
    kind: _Kind,
    ordinal: int,
    started_at: datetime,
) -> None:
    if kind == "service":
        logical = LogicalServiceIdentity(
            hostname="expiry-owner",
            logical_service_id=f"expiry-svc-{ordinal}",
            canonical_name=f"ExpiryService{ordinal}",
            service_kind="builtin",
        )
        identity: ServiceInstanceLifecycleIdentity | TransportLifecycleIdentity = (
            ServiceInstanceLifecycleIdentity(
                hostname=logical.hostname,
                object_id=f"expiry-so-{ordinal}",
                logical_service_id=logical.logical_service_id,
                boot_id="expiry-boot",
                instance_id="builtin",
                started_at=started_at,
            )
        )
        registry.register_service_instance(
            logical,
            identity,
            action_id=f"expiry-start-{ordinal}",
            transition_id=f"expiry-start-{ordinal}",
        )
        close_at = started_at + timedelta(microseconds=1)
        authority = "generated"
    else:
        close_at = started_at + timedelta(microseconds=1)
        identity = TransportLifecycleIdentity(
            hostname="expiry-owner",
            object_id=f"expiry-to-{ordinal}",
            transport_id=f"expiry-plan-{ordinal}",
            src_hostname="expiry-owner",
            dst_hostname="expiry-target",
            network_tuple=_tuple_for(ordinal),
            opened_at=started_at,
            close_deadline=close_at,
            zeek_uid=f"C-expiry-{ordinal}",
        )
        registry.register_transport(
            identity,
            action_id=f"expiry-start-{ordinal}",
            transition_id=f"expiry-start-{ordinal}",
        )
        authority = "authoritative"
    barrier = LifecycleCloseBarrier(
        barrier_id=f"expiry-barrier-{ordinal}",
        subject=identity.ref,
        requested_at=close_at,
        authority=authority,
        action_id=f"expiry-close-{ordinal}",
    )
    ticket = registry.request_close(barrier, ticket_id=f"expiry-ticket-{ordinal}")
    registry.close(ticket.ticket_id)


def _expiry_child(payload: dict[str, Any]) -> dict[str, Any]:
    entries = int(payload["entries"])
    kind: _Kind = payload["entity_kind"]
    registry = LifecycleRegistry(
        shard_count=64,
        closed_retention=timedelta(seconds=1),
        ledger_detail_retention=timedelta(0),
    )
    load_started = perf_counter()
    for ordinal in range(entries):
        _close_one(registry, kind, ordinal, _START + timedelta(microseconds=ordinal * 3))
    close_seconds = perf_counter() - load_started
    before = registry.census()
    cutoff = _START + timedelta(seconds=entries + 2)
    expiry_started = perf_counter()
    evicted = registry.advance_watermark(cutoff)
    expiry_seconds = perf_counter() - expiry_started
    after = registry.census()
    live_after = after.service_instance_entries if kind == "service" else after.transport_entries
    return {
        "kind": "expiry",
        "entity_kind": kind,
        "entries": entries,
        "close_seconds": close_seconds,
        "expiry_seconds": expiry_seconds,
        "evicted_entries": len(evicted),
        "entries_before": (
            before.service_instance_entries if kind == "service" else before.transport_entries
        ),
        "entries_after": live_after,
        "routes_after": after.route_entries,
        "temporal_backing_after": (
            after.service_temporal_backing_entries
            if kind == "service"
            else after.transport_temporal_backing_entries
        ),
        "deadline_backing_after": after.retention_deadline_backing_entries,
        "primary_compaction_pending": after.primary_compaction_pending,
        "route_compaction_pending": after.route_compaction_pending,
        "public_census_digest": _public_digest(after, kind=kind, entries=0),
    }


def _retention_lease_skew_child(payload: dict[str, Any]) -> dict[str, Any]:
    entries = int(payload["entries"])
    registry = LifecycleRegistry(
        shard_count=1,
        closed_retention=timedelta(seconds=1),
    )
    logical = LogicalServiceIdentity(
        hostname="lease-skew-owner",
        logical_service_id="lease-skew-service",
        canonical_name="LeaseSkewService",
        service_kind="builtin",
    )
    identity = ServiceInstanceLifecycleIdentity(
        hostname=logical.hostname,
        object_id="lease-skew-object",
        logical_service_id=logical.logical_service_id,
        boot_id="lease-skew-boot",
        instance_id="builtin",
        started_at=_START,
    )
    registry.register_service_instance(
        logical,
        identity,
        action_id="lease-skew-start",
        transition_id="lease-skew-start",
    )
    rss_before = _rss_bytes()
    peak_before = _peak_rss_bytes()
    load_started = perf_counter()
    for ordinal in range(entries):
        registry.add_retention_lease(
            LifecycleRetentionLease(
                lease_id=f"lease-skew-{ordinal}",
                subject=identity.ref,
                retain_until=_START + timedelta(hours=2, microseconds=ordinal),
                reason="single_subject_scale",
            )
        )
    load_seconds = perf_counter() - load_started
    before = registry.census()
    close_started = perf_counter()
    ticket = registry.request_close(
        LifecycleCloseBarrier(
            barrier_id="lease-skew-close",
            subject=identity.ref,
            requested_at=_START + timedelta(minutes=1),
            authority="generated",
            action_id="lease-skew-close",
        ),
        ticket_id="lease-skew-ticket",
    )
    registry.close(ticket.ticket_id)
    close_seconds = perf_counter() - close_started
    after = registry.census()
    expected_deadline = _START + timedelta(hours=2, microseconds=entries - 1)
    lookup_samples: list[int] = []
    for _ in range(10_000):
        started = perf_counter_ns()
        actual_deadline = registry.retention_deadline(identity.ref)
        lookup_samples.append(perf_counter_ns() - started)
    return {
        "kind": "retention_lease_skew",
        "entries": entries,
        "load_seconds": load_seconds,
        "close_seconds": close_seconds,
        "deadline_matches": actual_deadline == expected_deadline,
        "lookup_p95_us": _p95_us(lookup_samples),
        "deadline_candidates_inspected": (
            after.retention_lease_deadline_candidates_inspected
            - before.retention_lease_deadline_candidates_inspected
        ),
        "retention_lease_subjects": after.retention_lease_subjects,
        "retention_lease_subject_bindings": after.retention_lease_subject_bindings,
        "retention_lease_max_subject_bindings": after.retention_lease_max_subject_bindings,
        "rss_delta_bytes": max(0, _rss_bytes() - rss_before),
        "peak_rss_delta_bytes": max(0, _peak_rss_bytes() - peak_before),
        "estimated_bytes": after.estimated_bytes,
        "estimated_index_bytes": after.estimated_index_bytes,
        "route_entries": after.route_entries,
        "public_census_digest": _public_digest(after, kind="service", entries=1),
    }


def _duration_anchor(registry: LifecycleRegistry, kind: _Kind) -> str:
    if kind == "service":
        logical = LogicalServiceIdentity(
            hostname="duration-anchor",
            logical_service_id="duration-anchor",
            canonical_name="DurationAnchor",
            service_kind="builtin",
        )
        identity = ServiceInstanceLifecycleIdentity(
            hostname=logical.hostname,
            object_id="duration-anchor-service",
            logical_service_id=logical.logical_service_id,
            boot_id="duration-boot",
            instance_id="builtin",
            started_at=_START,
        )
        registry.register_service_instance(
            logical,
            identity,
            action_id="duration-anchor",
            transition_id="duration-anchor",
        )
        return identity.object_id
    identity = TransportLifecycleIdentity(
        hostname="duration-anchor",
        object_id="duration-anchor-transport",
        transport_id="duration-anchor-plan",
        src_hostname="duration-anchor",
        dst_hostname="duration-target",
        network_tuple=NetworkTuple("203.0.113.1", 55_000, "203.0.113.2", 22, "tcp"),
        opened_at=_START,
        close_deadline=_START + timedelta(days=365),
        zeek_uid="C-duration-anchor",
    )
    registry.register_transport(
        identity,
        action_id="duration-anchor",
        transition_id="duration-anchor",
    )
    return identity.object_id


def _duration_child(payload: dict[str, Any]) -> dict[str, Any]:
    hours = int(payload["duration_hours"])
    rate = int(payload["rate_per_hour"])
    kind: _Kind = payload["entity_kind"]
    registry = LifecycleRegistry(
        shard_count=64,
        closed_retention=timedelta(minutes=1),
        ledger_detail_retention=timedelta(minutes=1),
    )
    anchor = _duration_anchor(registry, kind)
    rss_before = _rss_bytes()
    peak_before = _peak_rss_bytes()
    started = perf_counter()
    ordinal = 0
    late_hour_seconds = 0.0
    lookup_samples: list[int] = []
    for hour in range(hours):
        hour_started = perf_counter()
        hour_start = _START + timedelta(hours=hour)
        for within_hour in range(rate):
            event_at = hour_start + timedelta(seconds=within_hour + 1)
            _close_one(registry, kind, ordinal, event_at)
            ordinal += 1
        registry.advance_watermark(hour_start + timedelta(minutes=59))
        lookup_started = perf_counter_ns()
        snapshot = (
            registry.get_service_instance(anchor)
            if kind == "service"
            else registry.get_transport(anchor)
        )
        lookup_samples.append(perf_counter_ns() - lookup_started)
        if snapshot is None:
            raise AssertionError("Duration anchor was evicted")
        late_hour_seconds = perf_counter() - hour_started
    census = registry.census()
    current_rss = _rss_bytes()
    return {
        "kind": "duration",
        "entity_kind": kind,
        "duration_hours": hours,
        "rate_per_hour": rate,
        "mutations": ordinal,
        "total_seconds": perf_counter() - started,
        "late_hour_seconds": late_hour_seconds,
        "lookup_p95_us": _p95_us(lookup_samples[-min(24, len(lookup_samples)) :]),
        "rss_delta_bytes": max(0, current_rss - rss_before),
        "peak_rss_delta_bytes": max(0, _peak_rss_bytes() - peak_before),
        "estimated_bytes": census.estimated_bytes,
        "estimated_index_bytes": census.estimated_index_bytes,
        "primary_map_backing_bytes": census.primary_map_backing_bytes,
        "route_map_backing_bytes": census.route_map_backing_bytes,
        "live_entries": (
            census.service_instance_entries if kind == "service" else census.transport_entries
        ),
        "route_entries": census.route_entries,
        "temporal_backing_entries": (
            census.service_temporal_backing_entries
            if kind == "service"
            else census.transport_temporal_backing_entries
        ),
        "retention_deadline_backing_entries": census.retention_deadline_backing_entries,
        "primary_compaction_pending": census.primary_compaction_pending,
        "route_compaction_pending": census.route_compaction_pending,
        "public_census_digest": _public_digest(census, kind=kind, entries=1),
    }


def _source_hashes() -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in _SOURCE_FILES:
        hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def _run_child(payload: dict[str, Any], *, hash_seed: int) -> dict[str, Any]:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--child",
        json.dumps(payload, separators=(",", ":")),
    ]
    environment = os.environ.copy()
    environment["PYTHONHASHSEED"] = str(hash_seed)
    started = perf_counter()
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    if completed.returncode:
        return {
            "kind": payload["kind"],
            "entity_kind": payload.get("entity_kind"),
            "entries": payload.get("entries"),
            "duration_hours": payload.get("duration_hours"),
            "hash_seed": hash_seed,
            "child_seconds": perf_counter() - started,
            "error": completed.stderr[-4_000:] or completed.stdout[-4_000:],
            "returncode": completed.returncode,
        }
    result = json.loads(completed.stdout)
    result["hash_seed"] = hash_seed
    result["child_seconds"] = perf_counter() - started
    return result


def _ratio_groups(results: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    ratios: dict[str, dict[str, float]] = {}
    groups: dict[tuple[object, ...], dict[int, dict[str, Any]]] = {}
    for result in results:
        if result.get("kind") != "scale" or "error" in result:
            continue
        key = (
            result["entity_kind"],
            result["group_mode"],
            result["write_mode"],
            result["workers"],
            result["hash_seed"],
        )
        groups.setdefault(key, {})[result["entries"]] = result
    for key, by_size in groups.items():
        if 1_000 not in by_size:
            continue
        baseline = by_size[1_000]
        label = "/".join(str(value) for value in key)
        for size, result in by_size.items():
            if size == 1_000:
                continue
            ratios[f"{label}/{size}"] = {
                "exact": result["exact_lookup_p95_us"]
                / max(0.001, baseline["exact_lookup_p95_us"]),
                "temporal": result["temporal_lookup_p95_us"]
                / max(0.001, baseline["temporal_lookup_p95_us"]),
                "exact_cold_diagnostic": result["exact_cold_lookup_p95_us"]
                / max(0.001, baseline["exact_cold_lookup_p95_us"]),
                "temporal_cold_diagnostic": result["temporal_cold_lookup_p95_us"]
                / max(0.001, baseline["temporal_cold_lookup_p95_us"]),
            }
    return ratios


def _gate_failures(
    results: list[dict[str, Any]],
    ratios: dict[str, dict[str, float]],
    *,
    requested_scale_cases: int,
    require_complete: bool,
) -> list[str]:
    failures: list[str] = []
    completed_scale = 0
    for result in results:
        label = "/".join(
            str(result.get(key, ""))
            for key in ("kind", "entity_kind", "entries", "duration_hours", "hash_seed")
        )
        if "error" in result:
            failures.append(f"{label}: child failed ({result['returncode']})")
            continue
        if result["kind"] == "scale":
            completed_scale += 1
            entries = result["entries"]
            if result["live_entries"] != entries:
                failures.append(f"{label}: live cardinality mismatch")
            if result["exact_candidates_inspected"] != result["queries"]:
                failures.append(f"{label}: exact lookup did not inspect exactly one candidate")
            if result["temporal_candidates_inspected"] != result["queries"]:
                failures.append(f"{label}: temporal lookup did not inspect exactly one candidate")
            if result["missing_candidates_inspected"] != 0:
                failures.append(f"{label}: exact misses inspected candidates")
            if result["exact_lookup_p95_us"] > 10.0:
                failures.append(f"{label}: warmed exact p95 exceeds 10us")
            if result["temporal_lookup_p95_us"] > 50.0:
                failures.append(f"{label}: warmed temporal p95 exceeds 50us")
            if result["temporal_backing_entries"] > max(1, result["temporal_live_entries"] * 2):
                failures.append(f"{label}: temporal backing exceeds 2x live")
            if entries >= 100_000 and result["estimated_index_bytes_per_live"] > 256.0:
                failures.append(f"{label}: index estimate exceeds 256B/live")
            if entries >= 1_000_000:
                if result["rss_delta_bytes"] > 512 * _MIB * (entries / 1_000_000):
                    failures.append(f"{label}: RSS exceeds 512MiB/1M live")
                if result["load_seconds"] > 60.0 * (entries / 1_000_000):
                    failures.append(f"{label}: load exceeds 60s/1M")
        elif result["kind"] == "expiry":
            if result["entries_before"] != result["entries"]:
                failures.append(f"{label}: expiry admission cardinality mismatch")
            if result["evicted_entries"] != result["entries"] or result["entries_after"]:
                failures.append(f"{label}: expiry did not remove every due entry")
            if result["entries"] >= 100_000 and result["expiry_seconds"] > (
                2.0 * result["entries"] / 100_000
            ):
                failures.append(f"{label}: complete expiry exceeds 2s/100K")
            if result["temporal_backing_after"]:
                failures.append(f"{label}: expiry retained temporal backing")
        elif result["kind"] == "retention_lease_skew":
            entries = result["entries"]
            if result["retention_lease_subjects"] != 1:
                failures.append(f"{label}: retention leases did not retain one subject")
            if result["retention_lease_subject_bindings"] != entries:
                failures.append(f"{label}: retention lease binding cardinality mismatch")
            if result["retention_lease_max_subject_bindings"] != entries:
                failures.append(f"{label}: retention lease max-subject telemetry mismatch")
            if result["deadline_candidates_inspected"] != 1:
                failures.append(f"{label}: retention deadline did not inspect one candidate")
            if not result["deadline_matches"]:
                failures.append(f"{label}: retention deadline did not resolve exact maximum")
            if result["lookup_p95_us"] > 10.0:
                failures.append(f"{label}: retention deadline lookup p95 exceeds 10us")
        elif result["kind"] == "duration":
            if result["live_entries"] != 1:
                failures.append(f"{label}: duration registry did not plateau at anchor")
    if require_complete and completed_scale != requested_scale_cases:
        failures.append(
            f"scale matrix incomplete: completed {completed_scale}/{requested_scale_cases} cases"
        )
    for label, values in ratios.items():
        if label.endswith("/1000000") or label.endswith("/2000000"):
            if values["exact"] > 2.0:
                failures.append(f"{label}: warmed exact 1K ratio exceeds 2x")
            if values["temporal"] > 3.0:
                failures.append(f"{label}: warmed temporal 1K ratio exceeds 3x")

    for kind in ("service", "transport"):
        durations = {
            (result["duration_hours"], result["hash_seed"]): result
            for result in results
            if result.get("kind") == "duration"
            and result.get("entity_kind") == kind
            and "error" not in result
        }
        for seed in {seed for _hours, seed in durations}:
            day = durations.get((24, seed))
            week = durations.get((168, seed))
            month = durations.get((720, seed))
            if day is not None and month is not None:
                if month["late_hour_seconds"] > day["late_hour_seconds"] * 1.25:
                    failures.append(f"duration/{kind}/{seed}: late-hour ratio exceeds 1.25x")
                if month["lookup_p95_us"] > day["lookup_p95_us"] * 1.25:
                    failures.append(f"duration/{kind}/{seed}: lookup ratio exceeds 1.25x")
            if week is not None and month is not None:
                for metric in (
                    "estimated_bytes",
                    "estimated_index_bytes",
                    "primary_map_backing_bytes",
                    "route_map_backing_bytes",
                    "rss_delta_bytes",
                ):
                    if month[metric] > max(1, week[metric]) * 1.10:
                        failures.append(f"duration/{kind}/{seed}: 7d->30d {metric} exceeds 10%")
    return failures


def _parse_ints(value: str) -> tuple[int, ...]:
    return tuple(int(item) for item in value.split(",") if item)


def _parse_text(value: str) -> tuple[str, ...]:
    return tuple(item for item in value.split(",") if item)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("smoke", "release"), default="smoke")
    parser.add_argument("--sizes")
    parser.add_argument("--kinds", default="service,transport")
    parser.add_argument("--group-modes")
    parser.add_argument("--write-modes")
    parser.add_argument("--workers")
    parser.add_argument("--hash-seeds")
    parser.add_argument("--queries", type=int)
    parser.add_argument("--expiry-entries", type=int)
    parser.add_argument("--retention-lease-entries")
    parser.add_argument("--duration-hours")
    parser.add_argument("--rate-per-hour", type=int)
    parser.add_argument("--skip-scale", action="store_true")
    parser.add_argument("--skip-expiry", action="store_true")
    parser.add_argument("--skip-duration", action="store_true")
    parser.add_argument("--reference-host", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--child")
    args = parser.parse_args()
    if args.child:
        payload = json.loads(args.child)
        if payload["kind"] == "scale":
            result = _scale_child(payload)
        elif payload["kind"] == "expiry":
            result = _expiry_child(payload)
        elif payload["kind"] == "retention_lease_skew":
            result = _retention_lease_skew_child(payload)
        else:
            result = _duration_child(payload)
        print(json.dumps(result, sort_keys=True))
        return 0

    release = args.profile == "release"
    sizes = _parse_ints(args.sizes or (_DEFAULT_SCALE_LADDER if release else "10,1000"))
    kinds = _parse_text(args.kinds)
    group_modes = _parse_text(args.group_modes or ("uniform,skewed" if release else "uniform"))
    write_modes = _parse_text(
        args.write_modes or ("monotonic,out-of-order" if release else "monotonic")
    )
    workers = _parse_ints(args.workers or ("1,4,8" if release else "1"))
    hash_seeds = _parse_ints(args.hash_seeds or ("0,271828" if release else "0"))
    queries = args.queries if args.queries is not None else (10_000 if release else 20)
    expiry_entries = (
        args.expiry_entries if args.expiry_entries is not None else (100_000 if release else 100)
    )
    retention_lease_entries = _parse_ints(args.retention_lease_entries or "")
    duration_hours = _parse_ints(args.duration_hours or "24,168,720")
    rate_per_hour = (
        args.rate_per_hour if args.rate_per_hour is not None else (100 if release else 2)
    )
    if not args.reference_host and release and args.enforce:
        raise SystemExit("Release enforcement requires --reference-host")

    source_hashes_start = _source_hashes()
    results: list[dict[str, Any]] = []
    requested_scale_cases = 0
    if not args.skip_scale:
        for kind in kinds:
            for group_mode in group_modes:
                for write_mode in write_modes:
                    for worker_count in workers:
                        for seed in hash_seeds:
                            for entries in sizes:
                                requested_scale_cases += 1
                                results.append(
                                    _run_child(
                                        {
                                            "kind": "scale",
                                            "entity_kind": kind,
                                            "entries": entries,
                                            "queries": queries,
                                            "group_mode": group_mode,
                                            "write_mode": write_mode,
                                            "workers": worker_count,
                                        },
                                        hash_seed=seed,
                                    )
                                )
    if not args.skip_expiry:
        for kind in kinds:
            for seed in hash_seeds:
                results.append(
                    _run_child(
                        {
                            "kind": "expiry",
                            "entity_kind": kind,
                            "entries": expiry_entries,
                        },
                        hash_seed=seed,
                    )
                )
    if not args.skip_duration:
        for kind in kinds:
            for seed in hash_seeds:
                for hours in duration_hours:
                    results.append(
                        _run_child(
                            {
                                "kind": "duration",
                                "entity_kind": kind,
                                "duration_hours": hours,
                                "rate_per_hour": rate_per_hour,
                            },
                            hash_seed=seed,
                        )
                    )
    for entries in retention_lease_entries:
        if entries <= 0:
            raise SystemExit("--retention-lease-entries values must be positive")
        for seed in hash_seeds:
            results.append(
                _run_child(
                    {
                        "kind": "retention_lease_skew",
                        "entries": entries,
                    },
                    hash_seed=seed,
                )
            )

    source_hashes_end = _source_hashes()
    ratios = _ratio_groups(results)
    failures = _gate_failures(
        results,
        ratios,
        requested_scale_cases=requested_scale_cases,
        require_complete=args.require_complete,
    )
    if source_hashes_start != source_hashes_end:
        failures.append("source revision changed during probe")
    digest_groups: dict[str, set[str]] = {}
    for result in results:
        digest = result.get("public_census_digest")
        if not digest:
            continue
        key = "/".join(
            str(result.get(field, ""))
            for field in (
                "kind",
                "entity_kind",
                "entries",
                "duration_hours",
                "group_mode",
                "write_mode",
                "workers",
            )
        )
        digest_groups.setdefault(key, set()).add(digest)
    nondeterministic = sorted(key for key, values in digest_groups.items() if len(values) > 1)
    failures.extend(f"{key}: public census digest changed by hash seed" for key in nondeterministic)
    worker_digest_groups: dict[str, set[str]] = {}
    for result in results:
        digest = result.get("public_census_digest")
        if not digest or result.get("kind") != "scale":
            continue
        key = "/".join(
            str(result.get(field, ""))
            for field in (
                "kind",
                "entity_kind",
                "entries",
                "group_mode",
                "write_mode",
                "hash_seed",
            )
        )
        worker_digest_groups.setdefault(key, set()).add(digest)
    worker_nondeterministic = sorted(
        key for key, values in worker_digest_groups.items() if len(values) > 1
    )
    failures.extend(
        f"{key}: public census digest changed by worker count" for key in worker_nondeterministic
    )

    report: dict[str, Any] = {
        "schema_version": 1,
        "profile": args.profile,
        "reference_host": args.reference_host,
        "source_hashes_start": source_hashes_start,
        "source_hashes_end": source_hashes_end,
        "lookup_contract": {
            "gated": "three symmetric untimed passes followed by one independent measured pass",
            "diagnostic": "first-touch cold/random p95 is retained but not ratio-gated",
        },
        "results": results,
        "lookup_ratios_vs_1k": ratios,
        "failures": failures,
    }
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    report["canonical_report_sha256"] = hashlib.sha256(canonical).hexdigest()
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if args.json_output is not None:
        args.json_output.write_text(rendered + "\n", encoding="utf-8")
    return int(args.enforce and bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
