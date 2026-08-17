#!/usr/bin/env python3
"""Fresh-process scale probe for packed SSH application child channels."""

from __future__ import annotations

import argparse
import json
import resource
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter, perf_counter_ns

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from evidenceforge.generation.application_channels import ApplicationChannelRegistry  # noqa: E402
from evidenceforge.generation.ssh_channels import (  # noqa: E402
    SshApplicationChannelManager,
    SshChannelAffinity,
    SshOperationKind,
    SshProcessHold,
    SshSessionBinding,
    SshTransportPlan,
)

_START = datetime(2026, 8, 1, tzinfo=UTC)


def _rss_bytes() -> int:
    retained = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return retained if sys.platform == "darwin" else retained * 1024


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = max(0, min(len(ordered) - 1, int(len(ordered) * percentile) - 1))
    return ordered[position]


def _session_values(
    index: int,
) -> tuple[SshChannelAffinity, SshTransportPlan, SshSessionBinding]:
    opened_at = _START + timedelta(seconds=1)
    closes_at = opened_at + timedelta(hours=1)
    client = f"ssh-client-{index}"
    server = f"ssh-server-{index}"
    client_session = f"ssh-client-session-{index}"
    server_session = f"ssh-server-session-{index}"
    principal = f"ssh-user-{index}"
    affinity = SshChannelAffinity(
        client_identity=client,
        client_session_object_id=client_session,
        server_identity=server,
        server_session_object_id=server_session,
        principal=principal,
        auth_method="publickey",
    )
    source = SshProcessHold(
        hostname=client,
        pid=1_000_000 + index,
        process_object_id=f"ssh-source-process-{index}",
        session_object_id=client_session,
        principal=f"ssh-local-user-{index}",
        started_at=_START,
        required_until=closes_at,
    )
    receiver = SshProcessHold(
        hostname=server,
        pid=2_000_000 + index,
        process_object_id=f"ssh-receiver-process-{index}",
        session_object_id=server_session,
        principal=principal,
        started_at=_START,
        required_until=closes_at,
    )
    transport = SshTransportPlan(
        transport_id=f"ssh-transport-{index}",
        zeek_uid=f"C{index:016x}",
        conn_id=f"ssh-conn-{index}",
        source_ip=f"10.{index // 62_500}.{(index // 250) % 250}.{index % 250 + 1}",
        server_ip=f"172.{16 + index // 1_000_000}.{(index // 250) % 250}.{index % 250 + 1}",
        source_port=32_768 + index % 28_000,
        server_port=22,
        opened_at=opened_at,
        closes_at=closes_at,
        source_process=source,
        receiver_process=receiver,
    )
    binding = SshSessionBinding(
        hostname=server,
        logon_id=f"0x{index + 1:016x}",
        session_object_id=server_session,
        lifecycle_group_id=f"ssh-lifecycle-{index}",
        principal=principal,
        ready_at=opened_at + timedelta(seconds=1),
    )
    return affinity, transport, binding


def _project(measured: int, baseline: int, actual: int, target: int) -> int:
    variable = max(0, measured - baseline)
    return baseline + round(variable * target / max(1, actual))


def run_probe(entries: int, lookup_samples: int, structural_target: int) -> dict[str, object]:
    """Load one actual cohort and return measured plus layout-equivalent results."""

    window_end = _START + timedelta(days=2)
    application = ApplicationChannelRegistry(window_start=_START, window_end=window_end)
    manager = SshApplicationChannelManager(
        application_registry=application,
        window_start=_START,
        window_end=window_end,
    )
    empty = manager.census()
    rss_before = _rss_bytes()
    started = perf_counter()
    channel_ids: list[str] = []
    for index in range(entries):
        affinity, transport, binding = _session_values(index)
        session, _lease = manager.open_session_with_completed_operation(
            affinity,
            transport=transport,
            binding=binding,
            idle_timeout=timedelta(hours=1),
            initiator_budget=1_000,
            responder_budget=1_000,
            operation_budget=2,
            kind=SshOperationKind.EXEC,
            semantic_operation_id=f"ssh-exec-{index}",
            started_at=binding.ready_at + timedelta(seconds=1),
            ended_at=binding.ready_at + timedelta(seconds=2),
            initiator_bytes=32,
            responder_bytes=64,
        )
        channel_ids.append(session.channel_id)
    insert_seconds = perf_counter() - started
    # Exercise the same sidecar-first/shared-once frontier as production.  The
    # frontier follows every child operation but precedes the one-hour channel
    # deadline, so it compacts empty active-operation routes without closing a
    # measured session.
    stable_frontier = _START + timedelta(seconds=10)
    sidecar_page = manager.watermark(stable_frontier)
    if sidecar_page.closures or sidecar_page.has_more:  # pragma: no cover
        raise RuntimeError("SSH scale frontier unexpectedly closed a live session")
    application.watermark(stable_frontier)
    frontier_seconds = perf_counter() - started - insert_seconds
    rss_after = _rss_bytes()
    rss_increment = max(0, rss_after - rss_before)
    census = manager.census()

    sample_count = min(entries, max(1, lookup_samples))
    stride = max(1, entries // sample_count)
    sample = channel_ids[::stride][:sample_count]
    cold: list[float] = []
    for channel_id in sample:
        before = perf_counter_ns()
        if manager.session_view(channel_id) is None:  # pragma: no cover
            raise RuntimeError("SSH probe exact lookup missed a live session")
        cold.append((perf_counter_ns() - before) / 1_000)
    for _round in range(4):
        for channel_id in sample:
            manager.session_view(channel_id)
    candidates_before = manager.census().lookup_candidates_inspected
    warm: list[float] = []
    for _round in range(8):
        for channel_id in sample:
            before = perf_counter_ns()
            manager.session_view(channel_id)
            warm.append((perf_counter_ns() - before) / 1_000)
    candidates_after = manager.census().lookup_candidates_inspected
    queries = len(warm)
    sidecar_live_records = census.open_sessions + census.active_operations
    common_live_records = (
        census.application.retained_channels
        + census.application.active_operations
        + census.application.used_operation_ids
    )
    total_live_records = sidecar_live_records + common_live_records

    projected_sidecar_bytes = _project(
        census.sidecar_estimated_bytes,
        empty.sidecar_estimated_bytes,
        entries,
        structural_target,
    )
    projected_sidecar_index = _project(
        census.sidecar_estimated_index_bytes,
        empty.sidecar_estimated_index_bytes,
        entries,
        structural_target,
    )
    projected_common_bytes = _project(
        census.application.estimated_bytes,
        empty.application.estimated_bytes,
        entries,
        structural_target,
    )
    projected_common_index = _project(
        census.application.estimated_index_bytes,
        empty.application.estimated_index_bytes,
        entries,
        structural_target,
    )
    projected_total_index = projected_sidecar_index + projected_common_index
    projected_sidecar_live = round(sidecar_live_records * structural_target / entries)
    projected_common_live = round(common_live_records * structural_target / entries)
    projected_total_live = projected_sidecar_live + projected_common_live
    return {
        "schema_version": 2,
        "actual": {
            "sessions": entries,
            "finalized_operations": entries,
            "retained_completed_operation_rows": census.active_operations,
            "load_seconds": insert_seconds,
            "frontier_seconds": frontier_seconds,
            "rss_before_bytes": rss_before,
            "rss_after_bytes": rss_after,
            "rss_increment_bytes": rss_increment,
            "rss_bytes_per_session": rss_increment / max(1, entries),
            "cold_exact_p95_us": _percentile(cold, 0.95),
            "warmed_exact_p95_us": _percentile(warm, 0.95),
            "lookup_queries": queries,
            "lookup_candidates": candidates_after - candidates_before,
            "lookup_candidates_per_query": (candidates_after - candidates_before) / max(1, queries),
            "common_estimated_bytes": census.application.estimated_bytes,
            "common_estimated_index_bytes": census.application.estimated_index_bytes,
            "common_live_records": common_live_records,
            "common_index_bytes_per_live_record": census.application.estimated_index_bytes
            / max(1, common_live_records),
            "common_index_bytes_per_session": census.application.estimated_index_bytes
            / max(1, entries),
            "sidecar_estimated_bytes": census.sidecar_estimated_bytes,
            "sidecar_estimated_index_bytes": census.sidecar_estimated_index_bytes,
            "sidecar_live_records": sidecar_live_records,
            "sidecar_index_bytes_per_live_record": census.sidecar_estimated_index_bytes
            / max(1, sidecar_live_records),
            "sidecar_index_bytes_per_session": census.sidecar_estimated_index_bytes
            / max(1, entries),
            "total_estimated_bytes": census.estimated_bytes,
            "total_estimated_index_bytes": census.estimated_index_bytes,
            "total_live_records": total_live_records,
            "total_index_bytes_per_live_record": census.estimated_index_bytes
            / max(1, total_live_records),
            "total_index_bytes_per_session": census.estimated_index_bytes / max(1, entries),
            "session_backing_entries": census.session_backing_entries,
            "operation_backing_entries": census.operation_backing_entries,
            "expiry_entries": census.expiry_entries,
            "stale_expiry_entries": census.stale_expiry_entries,
            "common_route_amplification": census.application.route_map_amplification,
            "decoded_cache_entries": census.decoded_cache_entries,
        },
        "structural_equivalent": {
            "sessions": structural_target,
            "basis": f"actual_{entries}_retained_layout",
            "common_estimated_bytes": projected_common_bytes,
            "common_estimated_index_bytes": projected_common_index,
            "common_live_records": projected_common_live,
            "common_index_bytes_per_live_record": projected_common_index
            / max(1, projected_common_live),
            "sidecar_estimated_bytes": projected_sidecar_bytes,
            "sidecar_estimated_index_bytes": projected_sidecar_index,
            "sidecar_live_records": projected_sidecar_live,
            "sidecar_index_bytes_per_live_record": projected_sidecar_index
            / max(1, projected_sidecar_live),
            "total_estimated_bytes": projected_common_bytes + projected_sidecar_bytes,
            "total_estimated_index_bytes": projected_total_index,
            "total_live_records": projected_total_live,
            "total_index_bytes_per_live_record": projected_total_index
            / max(1, projected_total_live),
            "total_index_bytes_per_session": projected_total_index / max(1, structural_target),
        },
        "gates": {
            "warmed_exact_p95_at_most_10us": _percentile(warm, 0.95) <= 10.0,
            "sidecar_index_at_most_256_bytes_per_live": (
                census.sidecar_estimated_index_bytes / max(1, sidecar_live_records) <= 256.0
            ),
            "common_index_at_most_256_bytes_per_live": (
                census.application.estimated_index_bytes / max(1, common_live_records) <= 256.0
            ),
            "total_index_at_most_256_bytes_per_live": (
                census.estimated_index_bytes / max(1, total_live_records) <= 256.0
            ),
            "no_completed_operation_history": census.active_operations == 0
            and census.operation_backing_entries == 0,
            "exact_candidate_bound": candidates_after - candidates_before <= queries,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entries", type=int, default=100_000)
    parser.add_argument("--lookup-samples", type=int, default=512)
    parser.add_argument("--structural-target", type=int, default=1_000_000)
    args = parser.parse_args()
    if args.entries <= 0 or args.lookup_samples <= 0 or args.structural_target <= 0:
        parser.error("scale counts must be positive")
    print(
        json.dumps(
            run_probe(args.entries, args.lookup_samples, args.structural_target),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
