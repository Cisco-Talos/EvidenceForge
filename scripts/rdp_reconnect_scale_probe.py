#!/usr/bin/env python3
"""Fresh-child scale and duration probe for reconnectable RDP state."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter, perf_counter_ns
from typing import Any

import psutil

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationChannelIdentity,
    ApplicationTransportBinding,
)
from evidenceforge.events.rdp import (
    RdpLogicalSessionIdentity,
    RdpSessionAffinity,
    RdpSessionSnapshot,
    RdpSessionState,
    RdpTransportGeneration,
    RdpTransportPlan,
)
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.rdp_sessions import RdpReconnectStateManager

_START = datetime(2026, 1, 5, 9, tzinfo=UTC)
_MIB = 1024 * 1024


def _rss_bytes() -> int:
    return psutil.Process().memory_info().rss


def _peak_rss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == "darwin" else value * 1024)


def _p95_us(samples: list[int]) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    position = min(len(ordered) - 1, max(0, round(len(ordered) * 0.95) - 1))
    return ordered[position] / 1_000.0


def _drain_manager_watermark(
    manager: RdpReconnectStateManager,
    cutoff: datetime,
) -> None:
    """Consume bounded manager pages before the one shared app watermark."""

    while manager.watermark(cutoff).has_more:
        pass


def _affinity(index: int) -> RdpSessionAffinity:
    return RdpSessionAffinity(
        source_host=f"c{index}",
        source_address=f"198.18.{(index // 256) % 256}.{index % 256}",
        target_host=f"r{index % 257}",
        target_address=f"198.19.{(index // 257) % 256}.{index % 257 % 256}",
        principal=f"d\\u{index}",
        logon_id=f"0x{index + 1:x}",
        session_id=index + 1,
    )


def _identity(
    index: int, started_at: datetime, hard_deadline: datetime
) -> RdpLogicalSessionIdentity:
    return RdpLogicalSessionIdentity(
        logical_session_id=f"s{index}",
        affinity=_affinity(index),
        started_at=started_at,
        idle_timeout=timedelta(minutes=30),
        reconnect_timeout=timedelta(minutes=15),
        hard_deadline=hard_deadline,
        budget=ApplicationChannelBudget(1, 1, 1),
    )


def _transport(index: int, started_at: datetime, closes_at: datetime) -> RdpTransportPlan:
    return RdpTransportPlan(
        channel_id=f"c{index}",
        binding=ApplicationTransportBinding(
            transport_id=f"t{index}",
            opened_at=started_at - timedelta(microseconds=1),
            closes_at=closes_at,
        ),
        connected_at=started_at,
        budget=ApplicationChannelBudget(1, 1, 1),
    )


def _application_identity(
    identity: RdpLogicalSessionIdentity,
    transport: RdpTransportPlan,
    window_end: datetime,
) -> ApplicationChannelIdentity:
    affinity_digest = hashlib.sha256(
        (f"rdp-transport-affinity-v1\0{identity.affinity.digest}\0{transport.channel_id}").encode()
    ).hexdigest()
    return ApplicationChannelIdentity(
        channel_id=transport.channel_id,
        protocol="rdp",
        owner_id=identity.owner_id,
        affinity_digest=affinity_digest,
        binding=transport.binding,
        opened_at=transport.connected_at,
        idle_timeout=identity.idle_timeout,
        hard_deadline=min(identity.hard_deadline, transport.binding.closes_at, window_end),
        budget=transport.budget,
    )


def _manager(
    *,
    window_end: datetime,
    grace: timedelta,
) -> tuple[RdpReconnectStateManager, ApplicationChannelRegistry]:
    application = ApplicationChannelRegistry(
        window_start=_START,
        window_end=window_end,
        closed_grace=grace,
    )
    manager = RdpReconnectStateManager(
        application_registry=application,
        window_start=_START,
        window_end=window_end,
        post_logout_grace=grace,
        max_retention_extension=max(grace, timedelta(hours=1)),
    )
    return manager, application


def _query_keys(entries: int, queries: int) -> list[int]:
    cursor = 0x9E3779B97F4A7C15
    keys: list[int] = []
    for _ in range(queries):
        cursor = (cursor * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        keys.append(cursor % entries)
    return keys


def _scale_child(entries: int, queries: int) -> dict[str, Any]:
    window_end = _START + timedelta(hours=4)
    grace = timedelta(hours=2)
    manager, application = _manager(window_end=window_end, grace=grace)
    rss_before = _rss_bytes()
    peak_before = _peak_rss_bytes()
    started = perf_counter()
    logout_at = _START + timedelta(seconds=1)
    for index in range(entries):
        identity = _identity(index, _START, _START + timedelta(hours=1))
        manager.open_session(
            identity,
            _transport(index, _START, _START + timedelta(hours=1)),
        )
        manager.logout(identity.logical_session_id, logged_out_at=logout_at)
    load_seconds = perf_counter() - started
    loaded_census = manager.census()
    rss_loaded = _rss_bytes()
    peak_loaded = _peak_rss_bytes()

    keys = _query_keys(entries, min(queries, entries * 4))
    affinities = [_affinity(key) for key in keys]
    for _ in range(3):
        for key in keys:
            manager.get(f"s{key}")
        for affinity in affinities:
            manager.find_by_affinity(affinity)
    exact_samples: list[int] = []
    affinity_samples: list[int] = []
    candidates_before = manager.census()
    for key in keys:
        tick = perf_counter_ns()
        snapshot = manager.get(f"s{key}")
        exact_samples.append(perf_counter_ns() - tick)
        if snapshot is None or snapshot.logical_session_id != f"s{key}":
            raise AssertionError("RDP exact lookup returned the wrong logical session")
    for affinity in affinities:
        tick = perf_counter_ns()
        snapshot = manager.find_by_affinity(affinity)
        affinity_samples.append(perf_counter_ns() - tick)
        if snapshot is None or snapshot.identity.affinity != affinity:
            raise AssertionError("RDP affinity lookup returned the wrong logical session")
    candidates_after = manager.census()
    hot_census = manager.census()
    rss_hot = _rss_bytes()
    peak_hot = _peak_rss_bytes()

    manager_expiry_started = perf_counter()
    cutoff = _START + timedelta(hours=3)
    _drain_manager_watermark(manager, cutoff)
    manager_expiry_seconds = perf_counter() - manager_expiry_started
    application_expiry_started = perf_counter()
    application.watermark(cutoff)
    application_expiry_seconds = perf_counter() - application_expiry_started
    expiry_seconds = manager_expiry_seconds + application_expiry_seconds
    expired = manager.census()
    return {
        "kind": "scale",
        "entries": entries,
        "queries": len(keys),
        "load_seconds": load_seconds,
        "exact_lookup_p95_us": _p95_us(exact_samples),
        "affinity_lookup_p95_us": _p95_us(affinity_samples),
        "logical_candidates_inspected": (
            candidates_after.logical_lookup_candidates_inspected
            - candidates_before.logical_lookup_candidates_inspected
        ),
        "affinity_candidates_inspected": (
            candidates_after.affinity_lookup_candidates_inspected
            - candidates_before.affinity_lookup_candidates_inspected
        ),
        "rss_loaded_delta_bytes": max(0, rss_loaded - rss_before),
        "rss_hot_delta_bytes": max(0, rss_hot - rss_before),
        "rss_delta_bytes": max(0, max(rss_loaded, rss_hot) - rss_before),
        "peak_rss_delta_bytes": max(0, max(peak_loaded, peak_hot) - peak_before),
        "rdp_estimated_bytes": hot_census.estimated_bytes,
        "rdp_estimated_index_bytes": hot_census.estimated_index_bytes,
        "rdp_decoded_cache_entries": hot_census.decoded_cache_entries,
        "rdp_decoded_cache_capacity": hot_census.decoded_cache_capacity,
        "rdp_decoded_cache_estimated_bytes": hot_census.decoded_cache_estimated_bytes,
        "application_estimated_bytes": hot_census.application.estimated_bytes,
        "application_estimated_index_bytes": hot_census.application.estimated_index_bytes,
        "rdp_index_bytes_per_entry": hot_census.estimated_index_bytes / entries,
        "application_index_bytes_per_channel": (
            hot_census.application.estimated_index_bytes / entries
        ),
        "combined_index_bytes_per_logical_pair": (
            hot_census.estimated_index_bytes + hot_census.application.estimated_index_bytes
        )
        / entries,
        "combined_index_bytes_per_record": (
            hot_census.estimated_index_bytes + hot_census.application.estimated_index_bytes
        )
        / (entries * 2),
        "combined_estimated_bytes_per_record": (
            hot_census.estimated_bytes + hot_census.application.estimated_bytes
        )
        / (entries * 2),
        "retained_sessions": loaded_census.retained_sessions,
        "application_channels": loaded_census.application.retained_channels,
        "application_open_channels": loaded_census.application.open_channels,
        "application_closed_channels": loaded_census.application.retained_closed_channels,
        "application_active_operations": loaded_census.application.active_operations,
        "application_used_operation_ids": loaded_census.application.used_operation_ids,
        "application_route_entries": loaded_census.application.route_entries,
        "application_expiry_entries": loaded_census.application.expiry_entries,
        "expiry_seconds": expiry_seconds,
        "manager_expiry_seconds": manager_expiry_seconds,
        "application_expiry_seconds": application_expiry_seconds,
        "retained_after_expiry": expired.retained_sessions,
        "application_after_expiry": expired.application.retained_channels,
    }


def _application_baseline_child(entries: int) -> dict[str, Any]:
    """Measure the shared registry cost of the exact same closed channels."""

    window_end = _START + timedelta(hours=4)
    grace = timedelta(hours=2)
    application = ApplicationChannelRegistry(
        window_start=_START,
        window_end=window_end,
        closed_grace=grace,
    )
    rss_before = _rss_bytes()
    peak_before = _peak_rss_bytes()
    started = perf_counter()
    logout_at = _START + timedelta(seconds=1)
    for index in range(entries):
        identity = _identity(index, _START, _START + timedelta(hours=1))
        transport = _transport(index, _START, _START + timedelta(hours=1))
        application.open_channel(_application_identity(identity, transport, window_end))
        application.close_channel(
            transport.channel_id,
            closed_at=logout_at,
            reason="rdp_logoff",
        )
    census = application.census()
    return {
        "kind": "application_baseline",
        "entries": entries,
        "load_seconds": perf_counter() - started,
        "rss_delta_bytes": max(0, _rss_bytes() - rss_before),
        "peak_rss_delta_bytes": max(0, _peak_rss_bytes() - peak_before),
        "estimated_bytes": census.estimated_bytes,
        "estimated_index_bytes": census.estimated_index_bytes,
        "retained_channels": census.retained_channels,
        "open_channels": census.open_channels,
        "closed_channels": census.retained_closed_channels,
        "active_operations": census.active_operations,
        "used_operation_ids": census.used_operation_ids,
        "route_entries": census.route_entries,
        "expiry_entries": census.expiry_entries,
    }


def _sidecar_scale_child(entries: int, queries: int) -> dict[str, Any]:
    """Load the exact RDP sidecar structures without duplicating common channels."""

    window_end = _START + timedelta(hours=4)
    grace = timedelta(hours=2)
    manager, _application = _manager(window_end=window_end, grace=grace)
    rss_before = _rss_bytes()
    peak_before = _peak_rss_bytes()
    load_started = perf_counter()
    logout_at = _START + timedelta(seconds=1)
    retention_deadline = logout_at + grace
    for index in range(entries):
        identity = _identity(index, _START, _START + timedelta(hours=1))
        transport = _transport(index, _START, _START + timedelta(hours=1))
        generation = RdpTransportGeneration(
            ordinal=0,
            channel_id=transport.channel_id,
            binding=transport.binding,
            connected_at=_START,
            idle_deadline=_START + identity.idle_timeout,
            disconnected_at=logout_at,
        )
        snapshot = RdpSessionSnapshot(
            identity=identity,
            state=RdpSessionState.LOGGED_OUT,
            generation=generation,
            last_transition_at=logout_at,
            logged_out_at=logout_at,
            retention_deadline=retention_deadline,
        )
        shard = manager._shard(identity.logical_session_id, create=True)
        route = manager._affinity_partition(identity.affinity, create=True)
        assert shard is not None and route is not None
        with route.lock, shard.lock:
            handle = shard.sessions.insert(snapshot)
            logical_route_key = manager._logical_route_key(identity.logical_session_id)
            affinity_route_key = manager._affinity_route_key(identity.affinity)
            shard.sessions.set_route_metadata(
                handle,
                logical_route_key=logical_route_key,
                affinity_route_key=affinity_route_key,
                affinity_partition_id=route.partition_id,
            )
            shard.session_routes.set_digest(logical_route_key, handle)
            locator = manager._pack_locator(shard.shard_id, handle)
            route.routes.set_digest(affinity_route_key, locator)
            shard.session_expiry.set(handle, retention_deadline.timestamp())
            shard.logged_out_sessions += 1
            shard.generation_high_water_mark = max(shard.generation_high_water_mark, 1)
    load_seconds = perf_counter() - load_started
    rss_loaded = _rss_bytes()
    peak_loaded = _peak_rss_bytes()

    keys = _query_keys(entries, min(queries, entries * 4))
    for _ in range(3):
        for key in keys:
            manager.get(f"s{key}")
    exact_samples: list[int] = []
    candidates_before = manager.census().logical_lookup_candidates_inspected
    for key in keys:
        tick = perf_counter_ns()
        snapshot = manager.get(f"s{key}")
        exact_samples.append(perf_counter_ns() - tick)
        if snapshot is None or snapshot.logical_session_id != f"s{key}":
            raise AssertionError("RDP sidecar exact lookup returned the wrong session")
    hot_census = manager.census()
    shards = tuple(manager._shards.values())
    affinity_partitions = tuple(
        route for route in manager._affinity_partitions if route is not None
    )
    session_store_index_bytes = sum(
        shard.sessions.metrics(estimate_bytes=True).estimated_bytes for shard in shards
    )
    session_store_value_bytes = sum(shard.sessions.estimated_value_bytes for shard in shards)
    session_route_bytes = sum(
        shard.session_routes.metrics(estimate_bytes=True).estimated_bytes for shard in shards
    )
    affinity_route_bytes = sum(
        route.routes.metrics(estimate_bytes=True).estimated_bytes for route in affinity_partitions
    )
    session_expiry_bytes = sum(
        shard.session_expiry.metrics(estimate_bytes=True).estimated_bytes for shard in shards
    )
    empty_sidecar_index_bytes = sum(
        shard.operations.metrics(estimate_bytes=True).estimated_bytes
        + shard.leases.metrics(estimate_bytes=True).estimated_bytes
        + shard.lease_routes.metrics(estimate_bytes=True).estimated_bytes
        + shard.lease_expiry.metrics(estimate_bytes=True).estimated_bytes
        + shard.blocker_expiry.metrics(estimate_bytes=True).estimated_bytes
        for shard in shards
    )
    rss_hot = _rss_bytes()
    peak_hot = _peak_rss_bytes()

    expiry_started = perf_counter()
    _drain_manager_watermark(manager, _START + timedelta(hours=3))
    expiry_seconds = perf_counter() - expiry_started
    expired = manager.census()
    return {
        "kind": "sidecar_scale",
        "entries": entries,
        "queries": len(keys),
        "load_seconds": load_seconds,
        "exact_lookup_p95_us": _p95_us(exact_samples),
        "logical_candidates_inspected": (
            hot_census.logical_lookup_candidates_inspected - candidates_before
        ),
        "rss_loaded_delta_bytes": max(0, rss_loaded - rss_before),
        "rss_hot_delta_bytes": max(0, rss_hot - rss_before),
        "rss_delta_bytes": max(0, max(rss_loaded, rss_hot) - rss_before),
        "peak_rss_delta_bytes": max(0, max(peak_loaded, peak_hot) - peak_before),
        "rdp_estimated_bytes": hot_census.estimated_bytes,
        "rdp_estimated_index_bytes": hot_census.estimated_index_bytes,
        "rdp_index_bytes_per_entry": hot_census.estimated_index_bytes / entries,
        "rdp_decoded_cache_entries": hot_census.decoded_cache_entries,
        "rdp_decoded_cache_estimated_bytes": hot_census.decoded_cache_estimated_bytes,
        "session_store_index_bytes": session_store_index_bytes,
        "session_store_value_bytes": session_store_value_bytes,
        "session_route_bytes": session_route_bytes,
        "affinity_route_bytes": affinity_route_bytes,
        "session_expiry_bytes": session_expiry_bytes,
        "empty_sidecar_index_bytes": empty_sidecar_index_bytes,
        "retained_sessions": hot_census.retained_sessions,
        "expiry_seconds": expiry_seconds,
        "retained_after_expiry": expired.retained_sessions,
    }


def _duration_child(duration_hours: int, rate_per_hour: int) -> dict[str, Any]:
    window_end = _START + timedelta(hours=duration_hours + 2)
    manager, application = _manager(window_end=window_end, grace=timedelta(seconds=1))
    rss_before = _rss_bytes()
    peak_before = _peak_rss_bytes()
    started = perf_counter()
    index = 0
    late_hour_seconds = 0.0
    for hour in range(duration_hours):
        hour_started = perf_counter()
        hour_start = _START + timedelta(hours=hour)
        for ordinal in range(rate_per_hour):
            event_at = hour_start + timedelta(seconds=1 + ordinal)
            identity = _identity(index, event_at, event_at + timedelta(minutes=10))
            manager.open_session(
                identity,
                _transport(index, event_at, event_at + timedelta(minutes=5)),
            )
            manager.logout(
                identity.logical_session_id,
                logged_out_at=event_at + timedelta(microseconds=1),
            )
            index += 1
        cutoff = hour_start + timedelta(minutes=59)
        _drain_manager_watermark(manager, cutoff)
        application.watermark(cutoff)
        late_hour_seconds = perf_counter() - hour_started
    total_seconds = perf_counter() - started
    census = manager.census()
    return {
        "kind": "duration",
        "duration_hours": duration_hours,
        "rate_per_hour": rate_per_hour,
        "mutations": index,
        "total_seconds": total_seconds,
        "late_hour_seconds": late_hour_seconds,
        "rss_delta_bytes": max(0, _rss_bytes() - rss_before),
        "peak_rss_delta_bytes": max(0, _peak_rss_bytes() - peak_before),
        "estimated_bytes": census.estimated_bytes,
        "estimated_index_bytes": census.estimated_index_bytes,
        "primary_map_bytes": census.primary_map_bytes,
        "retained_sessions": census.retained_sessions,
        "compaction_pending": census.compaction_pending,
    }


def _run_child(payload: dict[str, int]) -> dict[str, Any]:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--child",
        json.dumps(payload, separators=(",", ":")),
    ]
    environment = os.environ.copy()
    environment["PYTHONHASHSEED"] = "0"
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    return json.loads(completed.stdout)


def _ratios(results: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    ratios: dict[str, dict[str, float]] = {}
    for kind in ("scale", "sidecar_scale"):
        by_size = {result["entries"]: result for result in results if result["kind"] == kind}
        baseline = by_size.get(1_000)
        if baseline is None:
            continue
        ratios[kind] = {
            str(size): result["exact_lookup_p95_us"] / baseline["exact_lookup_p95_us"]
            for size, result in by_size.items()
            if size != 1_000
        }
    return ratios


def _gate_failures(
    results: list[dict[str, Any]],
    ratios: dict[str, dict[str, float]],
) -> list[str]:
    failures: list[str] = []
    for result in results:
        if result["kind"] not in {"scale", "sidecar_scale"}:
            continue
        entries = result["entries"]
        if result["retained_sessions"] != entries:
            failures.append(f"{entries}: retained cardinality mismatch")
        if result["kind"] == "scale":
            if result["application_channels"] != entries:
                failures.append(f"{entries}: application cardinality mismatch")
            if result["affinity_candidates_inspected"] != result["queries"]:
                failures.append(f"{entries}: affinity lookup inspected more than one candidate")
        if result["logical_candidates_inspected"] != result["queries"]:
            failures.append(f"{result['kind']} {entries}: exact lookup inspected !=1 candidate")
        if result["exact_lookup_p95_us"] > 10.0:
            failures.append(f"{result['kind']} {entries}: exact p95 exceeds 10us")
        if entries >= 100_000:
            manager_expiry_seconds = result.get(
                "manager_expiry_seconds",
                result["expiry_seconds"],
            )
            if manager_expiry_seconds / (entries / 100_000) > 2.0:
                failures.append(
                    f"{result['kind']} {entries}: normalized RDP expiry exceeds 2s/100K"
                )
            if (
                result["kind"] == "scale"
                and result["application_expiry_seconds"] / (entries / 100_000) > 2.0
            ):
                failures.append(f"{entries}: normalized application expiry exceeds 2s/100K")
        if entries >= 100_000 and result["rdp_index_bytes_per_entry"] > 256.0:
            failures.append(f"{result['kind']} {entries}: RDP sidecar index exceeds 256B/live")
        if entries >= 1_000_000:
            physical_records = result["retained_sessions"]
            if result["kind"] == "scale":
                physical_records += (
                    result["application_channels"] + result["application_used_operation_ids"]
                )
            normalized_rss = result["rss_delta_bytes"] / (physical_records / 1_000_000)
            if normalized_rss > 512 * _MIB:
                failures.append(
                    f"{result['kind']} {entries}: normalized RSS exceeds 512MiB/1M records"
                )
            if result["kind"] == "scale":
                common_records = result["common_application_physical_records"]
                common_normalized_rss = result["common_application_rss_delta_bytes"] / (
                    common_records / 1_000_000
                )
                if common_normalized_rss > 512 * _MIB:
                    failures.append(f"{entries}: common application RSS exceeds 512MiB/1M records")
        if result["retained_after_expiry"]:
            failures.append(f"{result['kind']} {entries}: expiry retained RDP state")
        if result["kind"] == "scale" and result["application_after_expiry"]:
            failures.append(f"{entries}: expiry retained application channels")
    for kind, kind_ratios in ratios.items():
        for size, ratio in kind_ratios.items():
            if int(size) >= 1_000_000 and ratio > 2.0:
                failures.append(f"{kind} {size}: warmed exact 1K ratio exceeds 2x")
    durations = {
        result["duration_hours"]: result for result in results if result["kind"] == "duration"
    }
    if 168 in durations and 720 in durations:
        seven = durations[168]
        thirty = durations[720]
        if thirty["estimated_bytes"] > seven["estimated_bytes"] * 1.10:
            failures.append("duration: 7d->30d estimated bytes exceeds 10%")
        if thirty["primary_map_bytes"] > seven["primary_map_bytes"] * 1.10:
            failures.append("duration: 7d->30d primary-map bytes exceeds 10%")
        if thirty["rss_delta_bytes"] > seven["rss_delta_bytes"] * 1.10:
            failures.append("duration: 7d->30d raw RSS delta exceeds 10%")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", default="1000,100000")
    parser.add_argument(
        "--sidecar-sizes",
        default="",
        help="Actual retained RDP-sidecar cardinalities to load without common channels",
    )
    parser.add_argument("--queries", type=int, default=10_000)
    parser.add_argument("--duration-hours", default="24,168,720")
    parser.add_argument("--rate-per-hour", type=int, default=20)
    parser.add_argument("--skip-scale", action="store_true")
    parser.add_argument("--skip-duration", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--child")
    args = parser.parse_args()
    if args.child:
        payload = json.loads(args.child)
        if payload["kind"] == "scale":
            result = _scale_child(payload["entries"], payload["queries"])
        elif payload["kind"] == "sidecar_scale":
            result = _sidecar_scale_child(payload["entries"], payload["queries"])
        elif payload["kind"] == "application_baseline":
            result = _application_baseline_child(payload["entries"])
        else:
            result = _duration_child(payload["duration_hours"], payload["rate_per_hour"])
        print(json.dumps(result, sort_keys=True))
        return 0

    results: list[dict[str, Any]] = []
    if not args.skip_scale:
        for entries in (int(value) for value in args.sizes.split(",") if value):
            baseline = _run_child({"kind": "application_baseline", "entries": entries})
            scale = _run_child({"kind": "scale", "entries": entries, "queries": args.queries})
            scale["common_application_rss_delta_bytes"] = baseline["rss_delta_bytes"]
            scale["common_application_peak_rss_delta_bytes"] = baseline["peak_rss_delta_bytes"]
            scale["common_application_channels"] = baseline["retained_channels"]
            scale["common_application_open_channels"] = baseline["open_channels"]
            scale["common_application_closed_channels"] = baseline["closed_channels"]
            scale["common_application_active_operations"] = baseline["active_operations"]
            scale["common_application_used_operation_ids"] = baseline["used_operation_ids"]
            scale["common_application_route_entries"] = baseline["route_entries"]
            scale["common_application_expiry_entries"] = baseline["expiry_entries"]
            scale["common_application_physical_records"] = (
                baseline["retained_channels"] + baseline["used_operation_ids"]
            )
            scale["combined_physical_records"] = (
                scale["retained_sessions"]
                + scale["application_channels"]
                + scale["application_used_operation_ids"]
            )
            scale["combined_rss_per_million_records"] = scale["rss_delta_bytes"] / (
                scale["combined_physical_records"] / 1_000_000
            )
            scale["common_application_rss_per_million_records"] = baseline["rss_delta_bytes"] / (
                scale["common_application_physical_records"] / 1_000_000
            )
            scale["rdp_incremental_rss_estimate_bytes"] = max(
                0,
                scale["rss_delta_bytes"] - baseline["rss_delta_bytes"],
            )
            scale["rdp_incremental_peak_rss_estimate_bytes"] = max(
                0,
                scale["peak_rss_delta_bytes"] - baseline["peak_rss_delta_bytes"],
            )
            results.append(scale)
        for entries in (int(value) for value in args.sidecar_sizes.split(",") if value):
            results.append(
                _run_child({"kind": "sidecar_scale", "entries": entries, "queries": args.queries})
            )
    if not args.skip_duration:
        for hours in (int(value) for value in args.duration_hours.split(",") if value):
            results.append(
                _run_child(
                    {
                        "kind": "duration",
                        "duration_hours": hours,
                        "rate_per_hour": args.rate_per_hour,
                    }
                )
            )
    ratios = _ratios(results)
    failures = _gate_failures(results, ratios)
    report = {"results": results, "exact_lookup_ratios_vs_1k": ratios, "failures": failures}
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if args.json_output is not None:
        args.json_output.write_text(rendered + "\n", encoding="utf-8")
    return int(args.enforce and bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
