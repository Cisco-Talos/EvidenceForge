# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Reproducible duration-scaling probe for canonical identity state.

The probe drives the same process identity, primary-thread, termination, expiry,
and lookup paths used during generation. It compares fixed 24-hour, seven-day,
and 30-day workloads and fails when retained late-reference state grows beyond
the explicit 48-hour lifetime or when late-run hourly cost materially diverges.
"""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from evidenceforge.generation.state_manager import StateManager
from evidenceforge.utils.paths import safe_write_text

_DURATIONS_HOURS = (24, 7 * 24, 30 * 24)
_RETENTION_HOURS_WITH_BOUNDARY = 49


@dataclass(frozen=True, slots=True)
class DurationResult:
    """Measured state cost and retained counts for one fixed duration."""

    duration_hours: int
    processes_per_hour: int
    total_processes: int
    total_seconds: float
    median_hour_ms: float
    final_24h_median_ms: float
    lookup_ns_per_operation: float
    retained_process_object_ids: int
    retained_process_keys: int
    retained_threads: int
    maximum_expected_retained: int
    allocator_open_allocations: int
    allocator_open_ordinals: int
    allocator_transient_reservations: int
    allocator_candidate_probes: int
    allocator_allocations: int
    allocator_retained_bytes: int


def _deep_size(value: object, seen: set[int] | None = None) -> int:
    """Return a deterministic recursive size estimate for allocator-owned state."""
    visited = seen if seen is not None else set()
    identity = id(value)
    if identity in visited:
        return 0
    visited.add(identity)
    size = sys.getsizeof(value)
    if isinstance(value, dict):
        return size + sum(
            _deep_size(key, visited) + _deep_size(item, visited) for key, item in value.items()
        )
    if isinstance(value, list | tuple | set):
        return size + sum(_deep_size(item, visited) for item in value)
    if hasattr(value, "__dict__"):
        return size + _deep_size(vars(value), visited)
    return size


def _allocator_retained_bytes(state: StateManager) -> int:
    """Measure only bounded PID allocator policy and open-window containers."""
    fields = (
        state._pid_counters,
        state._pid_os,
        state._pid_rngs,
        state._pid_time_epochs,
        state._pid_bucket_offsets,
        state._linux_pid_weekly_churn_prefixes,
        state._linux_pid_allocations,
        state._pid_sealed_logical_positions,
        state._fixed_pid_reservations,
        state._active_pid_reservation_counts,
        state._transient_pid_reservations,
        state._transient_pid_reservation_counts,
    )
    return _deep_size(fields)


def _run_duration(duration_hours: int, processes_per_hour: int) -> DurationResult:
    """Run one deterministic process-identity workload and return its metrics."""

    state = StateManager()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    hour_costs: list[float] = []
    latest_object_ids: list[str] = []
    first_object_id = ""
    started = time.perf_counter()

    for hour in range(duration_hours):
        hour_start = time.perf_counter()
        event_time = start + timedelta(hours=hour)
        state.set_current_time(event_time)
        latest_object_ids.clear()
        for ordinal in range(processes_per_hour):
            hostname = f"WS-{ordinal % 8:02d}"
            pid = state.create_process(
                system=hostname,
                parent_pid=0,
                image=r"C:\Windows\System32\cmd.exe",
                command_line=f"cmd.exe /c echo {hour}-{ordinal}",
                username=f"analyst{ordinal % 16}",
                integrity_level="Medium",
            )
            identity = state.get_process_identity(hostname, pid)
            if identity is None:
                raise RuntimeError("Live process identity lookup failed")
            first_object_id = first_object_id or identity.object_id
            latest_object_ids.append(identity.object_id)
            if not state.end_process(
                hostname,
                pid,
                event_time + timedelta(seconds=1, microseconds=ordinal),
            ):
                raise RuntimeError("Process termination failed")
            if state.get_process_identity_by_object_id(identity.object_id) is None:
                raise RuntimeError("Retained process identity lookup failed")
            linux_event_time = event_time + timedelta(
                seconds=(ordinal * 3_600) / processes_per_hour
            )
            state.allocate_transient_linux_pid(
                f"LINUX-{ordinal % 8:02d}",
                linux_event_time,
                release_time=linux_event_time + timedelta(seconds=1),
            )
        state.advance_pid_allocation_watermark(event_time + timedelta(hours=1))
        hour_costs.append(time.perf_counter() - hour_start)

    total_seconds = time.perf_counter() - started
    lookup_iterations = max(100_000, processes_per_hour * 1_000)
    lookup_started = time.perf_counter_ns()
    for ordinal in range(lookup_iterations):
        object_id = latest_object_ids[ordinal % len(latest_object_ids)]
        if state.get_process_identity_by_object_id(object_id) is None:
            raise RuntimeError("Hot retained identity lookup failed")
    lookup_elapsed_ns = time.perf_counter_ns() - lookup_started

    if duration_hours > _RETENTION_HOURS_WITH_BOUNDARY:
        state.set_current_time(start + timedelta(hours=duration_hours))
        if state.get_process_identity_by_object_id(first_object_id) is not None:
            raise RuntimeError("Expired identity survived the 48-hour retention window")

    maximum_expected = _RETENTION_HOURS_WITH_BOUNDARY * processes_per_hour
    retained_counts = (
        len(state._ended_processes_by_object_id),
        len(state._ended_processes_by_key),
        len(state._ended_threads),
    )
    if any(count > maximum_expected for count in retained_counts):
        raise RuntimeError(
            "Retained identity state exceeded its duration-stable bound: "
            f"counts={retained_counts}, maximum={maximum_expected}"
        )

    allocator_census = state.pid_allocator_census()
    if any(
        allocator_census[key] != 0
        for key in ("open_allocations", "open_ordinals", "transient_reservations")
    ):
        raise RuntimeError(f"Allocator open-window state did not seal: {allocator_census}")
    if allocator_census["candidate_probes"] != allocator_census["allocations"]:
        raise RuntimeError(
            f"Allocator probe work grew despite no live collisions: {allocator_census}"
        )

    final_window = hour_costs[-min(24, len(hour_costs)) :]
    gc.collect()
    return DurationResult(
        duration_hours=duration_hours,
        processes_per_hour=processes_per_hour,
        total_processes=duration_hours * processes_per_hour,
        total_seconds=round(total_seconds, 6),
        median_hour_ms=round(statistics.median(hour_costs) * 1_000, 6),
        final_24h_median_ms=round(statistics.median(final_window) * 1_000, 6),
        lookup_ns_per_operation=round(lookup_elapsed_ns / lookup_iterations, 3),
        retained_process_object_ids=retained_counts[0],
        retained_process_keys=retained_counts[1],
        retained_threads=retained_counts[2],
        maximum_expected_retained=maximum_expected,
        allocator_open_allocations=allocator_census["open_allocations"],
        allocator_open_ordinals=allocator_census["open_ordinals"],
        allocator_transient_reservations=allocator_census["transient_reservations"],
        allocator_candidate_probes=allocator_census["candidate_probes"],
        allocator_allocations=allocator_census["allocations"],
        allocator_retained_bytes=_allocator_retained_bytes(state),
    )


def run_probe(processes_per_hour: int) -> dict[str, object]:
    """Run all fixed durations and validate late-run cost stability."""

    results = [
        _run_duration(duration_hours, processes_per_hour) for duration_hours in _DURATIONS_HOURS
    ]
    baseline_cost = max(results[0].final_24h_median_ms, 0.001)
    cost_ratios = {
        str(result.duration_hours): round(result.final_24h_median_ms / baseline_cost, 4)
        for result in results
    }
    lookup_baseline = max(results[0].lookup_ns_per_operation, 1.0)
    lookup_ratios = {
        str(result.duration_hours): round(result.lookup_ns_per_operation / lookup_baseline, 4)
        for result in results
    }
    if cost_ratios[str(_DURATIONS_HOURS[-1])] > 1.25:
        raise RuntimeError(f"30-day late-hour cost ratio exceeded 1.25: {cost_ratios}")
    if lookup_ratios[str(_DURATIONS_HOURS[-1])] > 2.0:
        raise RuntimeError(f"30-day lookup-cost ratio exceeded 2.0: {lookup_ratios}")
    memory_ratio = results[-1].allocator_retained_bytes / max(
        results[1].allocator_retained_bytes,
        1,
    )
    if not 0.9 <= memory_ratio <= 1.1:
        raise RuntimeError(
            "Seven-day and 30-day retained allocator memory differed by more than 10%: "
            f"ratio={memory_ratio:.4f}"
        )
    return {
        "schema_version": 2,
        "probe": "batch7b_identity_state_duration_scaling",
        "processes_per_hour": processes_per_hour,
        "retention_hours": 48,
        "results": [asdict(result) for result in results],
        "late_hour_cost_ratio_vs_24h": cost_ratios,
        "lookup_cost_ratio_vs_24h": lookup_ratios,
        "allocator_memory_ratio_30d_vs_7d": round(memory_ratio, 4),
        "status": "passed",
    }


def main() -> int:
    """Run the command-line probe."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--processes-per-hour",
        type=int,
        default=64,
        help="Fixed process creation/termination rate for every duration (default: 64)",
    )
    parser.add_argument("--output", type=Path, help="Optional JSON result path")
    args = parser.parse_args()
    if args.processes_per_hour <= 0:
        parser.error("--processes-per-hour must be positive")

    result = run_probe(args.processes_per_hour)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        safe_write_text(args.output.resolve(), rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
