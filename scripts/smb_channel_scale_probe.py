#!/usr/bin/env python3
"""Measure retained SMB session/tree/handle sidecars in fresh processes."""

from __future__ import annotations

import argparse
import gc
import json
import multiprocessing
import resource
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from time import perf_counter, perf_counter_ns

from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
)
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.smb_channels import (
    SmbApplicationChannelManager,
    SmbChannelAffinity,
)

_START = datetime(2026, 8, 16, tzinfo=UTC)
_TRAFFIC = NetworkTrafficLedger(
    orig=DirectionalTrafficLedger(payload_bytes=128, packets=1, ip_bytes=168),
    resp=DirectionalTrafficLedger(payload_bytes=512, packets=1, ip_bytes=552),
)


@dataclass(frozen=True, slots=True)
class _ScaleResult:
    """One fresh-process retained-state measurement."""

    entries: int
    workload: str
    load_seconds: float
    rss_delta_bytes: int
    rss_bytes_per_entry: float
    rss_bytes_per_retained_record: float
    sidecar_estimated_bytes: int
    sidecar_estimated_bytes_per_entry: float
    sidecar_estimated_bytes_per_smb_record: float
    sidecar_estimated_index_bytes: int
    sidecar_estimated_index_bytes_per_entry: float
    shared_application_estimated_bytes: int
    shared_application_estimated_index_bytes: int
    estimated_bytes_per_retained_record: float
    common_retained_channels: int
    common_active_operations: int
    common_used_operation_ids: int
    total_retained_records: int
    exact_cold_lookup_p95_us: float
    exact_warmed_lookup_p95_us: float
    exact_lookup_p95_us: float
    affinity_lookup_p95_us: float
    exact_candidates_p95: int
    exact_candidates_max: int
    open_sessions: int
    open_trees: int
    open_handles: int
    expiry_entries: int
    expiry_seconds: float
    sidecar_expiry_seconds: float
    closure_decode_seconds: float
    sidecar_expiry_with_closure_decode_seconds: float
    shared_expiry_seconds: float
    expiry_with_closure_decode_seconds: float
    expired_sessions: int
    closure_pages: int
    maximum_closure_page: int


def _peak_rss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == "darwin" else value * 1024)


def _p95(values: list[int]) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, round(len(ordered) * 0.95) - 1))]


def _affinity(index: int) -> SmbChannelAffinity:
    return SmbChannelAffinity(
        client_identity=f"client-{index}",
        client_ip=f"10.{(index >> 16) & 255}.{(index >> 8) & 255}.{index & 255}",
        client_session=f"session-{index}",
        server_identity=f"file-{index % 256}",
        server_ip=f"172.20.{(index >> 8) & 255}.{index & 255}",
        principal=f"example\\user-{index % 4096}",
        auth_protocol="kerberos",
        account_scope="example",
        dialect="3.1.1",
        signing_policy="required",
        encryption_policy="off",
        server_policy="windows:file-server",
        share_policy="disk:standard",
        client_access="windows_native",
    )


def _plan(index: int, closes_at: datetime) -> NetworkTransactionPlan:
    started_at = _START + timedelta(microseconds=index)
    return NetworkTransactionPlan(
        stable_id=f"smb-transport-{index}",
        hostname=f"file-{index % 256}",
        outcome="success",
        phase_times=(("attempt", started_at), ("close", closes_at)),
        started_at=started_at,
        closed_at=closes_at,
        src_ip=f"10.{(index >> 16) & 255}.{(index >> 8) & 255}.{index & 255}",
        src_port=49_152 + (index % 16_384),
        dst_ip=f"172.20.{(index >> 8) & 255}.{index & 255}",
        dst_port=445,
        protocol="tcp",
        service="smb",
        zeek_uid=f"C{index:016x}",
        conn_id=f"conn-{index}",
        duration=(closes_at - started_at).total_seconds(),
        conn_state="SF",
        history="ShADadfF",
        traffic=_TRAFFIC,
    )


def _query_indices(entries: int, queries: int) -> list[int]:
    cursor = 0x9E3779B97F4A7C15
    values: list[int] = []
    for _ in range(min(queries, entries * 4)):
        cursor = (cursor * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        values.append(cursor % entries)
    return values


def _measure_one(entries: int, queries: int, workload: str) -> _ScaleResult:
    window_end = _START + timedelta(days=2)
    registry = ApplicationChannelRegistry(window_start=_START, window_end=window_end)
    manager = SmbApplicationChannelManager(
        application_registry=registry,
        window_start=_START,
        window_end=window_end,
    )
    closes_at = _START + timedelta(hours=1)
    gc.collect()
    rss_before = _peak_rss_bytes()
    started = perf_counter()
    for index in range(entries):
        plan = _plan(index, closes_at)
        lease = manager.open_session(
            _affinity(index),
            transport_plan=plan,
            sensor_observations=(),
            ground_truth_transport_uid=plan.zeek_uid,
            logon_id=f"0x{index:016X}",
            auth_session_ref=f"auth-{index}",
            principal=f"example\\user-{index % 4096}",
            auth_protocol="kerberos",
            account_scope="example",
            effective_uid=None,
            effective_gid=None,
            client_access="windows_native",
            server_hostname=plan.hostname,
            client_ip=plan.src_ip,
            lifecycle_group_id=plan.stable_id,
            share_ref=f"{plan.hostname}.documents",
            semantic_operation_id=f"operation-{index}",
            operation_started_at=plan.started_at + timedelta(microseconds=1),
            operation_ended_at=plan.started_at + timedelta(milliseconds=1),
            operation_initiator_bytes=128,
            operation_responder_bytes=512,
            idle_timeout=timedelta(minutes=10),
            initiator_budget=1_024,
            responder_budget=4_096,
            operation_budget=8,
        )
        handle = manager.open_handle(
            lease,
            file_id=f"content-{index}",
            content_version=1,
            access="read",
            opened_at=lease.started_at,
        )
        if workload == "expiry":
            manager.close_handle(handle, lease, closed_at=lease.ended_at)
            manager.finalize_operation(lease)
    load_seconds = perf_counter() - started
    rss_after = _peak_rss_bytes()

    indices = _query_indices(entries, queries)
    lookup_pairs = [
        (
            affinity := _affinity(index),
            manager.channel_id_for(affinity, f"smb-transport-{index}"),
        )
        for index in indices
    ]
    gc.collect()
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        exact_cold_ns: list[int] = []
        for _affinity_value, channel_id in lookup_pairs:
            started_ns = perf_counter_ns()
            exact = manager.session_view(channel_id)
            exact_cold_ns.append(perf_counter_ns() - started_ns)
            if exact is None or exact.channel_id != channel_id:
                raise AssertionError("exact SMB session lookup returned the wrong channel")
        exact_warmed_ns: list[int] = []
        affinity_ns: list[int] = []
        candidate_before = manager.census().lookup_candidates_inspected
        for affinity, channel_id in lookup_pairs:
            started_ns = perf_counter_ns()
            exact = manager.session_view(channel_id)
            exact_warmed_ns.append(perf_counter_ns() - started_ns)
            if exact is None or exact.channel_id != channel_id:
                raise AssertionError("exact SMB session lookup returned the wrong channel")
            started_ns = perf_counter_ns()
            reusable = manager.find_reusable_session(
                affinity,
                at=_START + timedelta(seconds=1),
            )
            affinity_ns.append(perf_counter_ns() - started_ns)
            if reusable is None or reusable.channel_id != channel_id:
                raise AssertionError("exact SMB affinity lookup returned the wrong channel")
        candidate_delta = manager.census().lookup_candidates_inspected - candidate_before
        if candidate_delta % max(1, len(lookup_pairs)):
            raise AssertionError("SMB affinity candidate accounting is not per-lookup stable")
        candidates = [candidate_delta // max(1, len(lookup_pairs))]
    finally:
        if gc_was_enabled:
            gc.enable()

    census = manager.census()
    expiry_seconds = 0.0
    sidecar_expiry_seconds = 0.0
    closure_decode_seconds = 0.0
    sidecar_expiry_with_closure_decode_seconds = 0.0
    shared_expiry_seconds = 0.0
    expiry_with_closure_decode_seconds = 0.0
    expired_sessions = 0
    closure_pages = 0
    maximum_closure_page = 0
    if workload == "expiry":
        while True:
            page_started = perf_counter()
            page = manager.watermark(_START + timedelta(hours=2))
            sidecar_expiry_seconds += perf_counter() - page_started
            closure_pages += 1
            maximum_closure_page = max(maximum_closure_page, len(page.closures))
            decode_started = perf_counter()
            for closure in page.closures:
                if not closure.channel_id:  # pragma: no cover - internal invariant
                    raise AssertionError("SMB closure page decoded an empty channel ID")
                expired_sessions += 1
            closure_decode_seconds += perf_counter() - decode_started
            if not page.has_more:
                break
        shared_expiry_started = perf_counter()
        registry.watermark(_START + timedelta(hours=2))
        shared_expiry_seconds = perf_counter() - shared_expiry_started
        sidecar_expiry_with_closure_decode_seconds = sidecar_expiry_seconds + closure_decode_seconds
        expiry_seconds = sidecar_expiry_seconds + shared_expiry_seconds
        expiry_with_closure_decode_seconds = expiry_seconds + closure_decode_seconds

    application = census.application
    smb_records = census.open_sessions + census.open_trees + census.open_handles
    total_retained_records = (
        smb_records
        + application.retained_channels
        + application.active_operations
        + application.used_operation_ids
    )
    estimated_total_bytes = census.sidecar_estimated_bytes + application.estimated_bytes
    rss_delta = max(0, rss_after - rss_before)
    return _ScaleResult(
        entries=entries,
        workload=workload,
        load_seconds=load_seconds,
        rss_delta_bytes=rss_delta,
        rss_bytes_per_entry=rss_delta / entries,
        rss_bytes_per_retained_record=rss_delta / max(1, total_retained_records),
        sidecar_estimated_bytes=census.sidecar_estimated_bytes,
        sidecar_estimated_bytes_per_entry=census.sidecar_estimated_bytes / entries,
        sidecar_estimated_bytes_per_smb_record=(
            census.sidecar_estimated_bytes / max(1, smb_records)
        ),
        sidecar_estimated_index_bytes=census.sidecar_estimated_index_bytes,
        sidecar_estimated_index_bytes_per_entry=(census.sidecar_estimated_index_bytes / entries),
        shared_application_estimated_bytes=application.estimated_bytes,
        shared_application_estimated_index_bytes=application.estimated_index_bytes,
        estimated_bytes_per_retained_record=(
            estimated_total_bytes / max(1, total_retained_records)
        ),
        common_retained_channels=application.retained_channels,
        common_active_operations=application.active_operations,
        common_used_operation_ids=application.used_operation_ids,
        total_retained_records=total_retained_records,
        exact_cold_lookup_p95_us=_p95(exact_cold_ns) / 1_000,
        exact_warmed_lookup_p95_us=_p95(exact_warmed_ns) / 1_000,
        exact_lookup_p95_us=_p95(exact_warmed_ns) / 1_000,
        affinity_lookup_p95_us=_p95(affinity_ns) / 1_000,
        exact_candidates_p95=_p95(candidates),
        exact_candidates_max=max(candidates, default=0),
        open_sessions=census.open_sessions,
        open_trees=census.open_trees,
        open_handles=census.open_handles,
        expiry_entries=census.expiry_entries,
        expiry_seconds=expiry_seconds,
        sidecar_expiry_seconds=sidecar_expiry_seconds,
        closure_decode_seconds=closure_decode_seconds,
        sidecar_expiry_with_closure_decode_seconds=(sidecar_expiry_with_closure_decode_seconds),
        shared_expiry_seconds=shared_expiry_seconds,
        expiry_with_closure_decode_seconds=expiry_with_closure_decode_seconds,
        expired_sessions=expired_sessions,
        closure_pages=closure_pages,
        maximum_closure_page=maximum_closure_page,
    )


def _child(args: tuple[int, int, str]) -> _ScaleResult:
    return _measure_one(*args)


def _sizes(value: str) -> list[int]:
    result = sorted({int(item.strip()) for item in value.split(",") if item.strip()})
    if not result or any(item <= 0 for item in result):
        raise argparse.ArgumentTypeError("sizes must be comma-separated positive integers")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=_sizes, default=_sizes("10,1000,100000,1000000"))
    parser.add_argument("--queries", type=int, default=2_000)
    parser.add_argument("--workload", choices=("open", "expiry"), default="open")
    args = parser.parse_args()
    context = multiprocessing.get_context("spawn")
    results: list[_ScaleResult] = []
    for entries in args.sizes:
        with context.Pool(1) as pool:
            result = pool.apply(_child, ((entries, args.queries, args.workload),))
        results.append(result)
    warmed_1k = next((item for item in results if item.entries == 1_000), None)
    payload = {
        "results": [asdict(result) for result in results],
        "warmed_1k_exact_p95_us": (
            warmed_1k.exact_lookup_p95_us if warmed_1k is not None else None
        ),
        "million_to_warmed_1k_ratio": (
            next(
                (
                    item.exact_lookup_p95_us / max(warmed_1k.exact_lookup_p95_us, 0.001)
                    for item in results
                    if item.entries == 1_000_000 and warmed_1k is not None
                ),
                None,
            )
        ),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
