#!/usr/bin/env python3
# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Measure duration-stable registry behavior from tiny to million-entry pools."""

from __future__ import annotations

import argparse
import gc
import json
import multiprocessing
import resource
import statistics
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter, perf_counter_ns
from typing import Any

from evidenceforge.generation.indexes import (
    CompactIndexedStore,
    ExpiringIndex,
    SegmentedTemporalIndex,
)


@dataclass(frozen=True, slots=True)
class _ProbeRecord:
    host: int
    owner: int
    ordinal: int


@dataclass(frozen=True, slots=True)
class _ScaleResult:
    entries: int
    queries: int
    group_mode: str
    write_mode: str
    workload: str
    load_seconds: float
    compact_load_seconds: float
    temporal_load_seconds: float
    exact_cold_lookup_p95_us: float
    exact_lookup_p95_us: float
    temporal_cold_lookup_p95_us: float
    temporal_lookup_p95_us: float
    rss_delta_bytes: int
    compact_rss_delta_bytes: int
    temporal_rss_delta_bytes: int
    compact_backing_entries: int
    temporal_backing_entries: int
    temporal_stale_entries: int
    temporal_block_size_limit: int
    compact_estimated_bytes: int
    temporal_estimated_bytes: int
    churn_entries: int = 0
    replacement_seconds: float = 0.0
    expiry_seconds: float = 0.0
    temporal_compaction_seconds: float = 0.0
    expiry_backing_entries: int = 0


def _peak_rss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == "darwin" else value * 1024)


def _p95_us(samples_ns: list[int]) -> float:
    if not samples_ns:
        return 0.0
    ordered = sorted(samples_ns)
    index = min(len(ordered) - 1, max(0, round(len(ordered) * 0.95) - 1))
    return ordered[index] / 1_000.0


def _probe_one(
    entries: int,
    queries: int,
    out_of_order_rate: float,
    group_mode: str,
    write_mode: str,
    workload: str,
) -> _ScaleResult:
    gc.collect()
    rss_before = _peak_rss_bytes()
    compact: CompactIndexedStore[int, _ProbeRecord] = CompactIndexedStore(
        host=lambda record: record.host,
        owner=lambda record: record.owner,
    )
    temporal: SegmentedTemporalIndex[int] = SegmentedTemporalIndex()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    effective_out_of_order_rate = out_of_order_rate if write_mode == "out-of-order" else 0.0
    out_of_order_every = (
        max(1, round(1.0 / effective_out_of_order_rate)) if effective_out_of_order_rate else 0
    )

    load_started = perf_counter()
    for ordinal in range(entries):
        host = ordinal if group_mode == "uniform" else ordinal % 512
        owner = ordinal if group_mode == "uniform" else 0
        compact[ordinal] = _ProbeRecord(host=host, owner=owner, ordinal=ordinal)
    compact_loaded_at = perf_counter()
    rss_after_compact = _peak_rss_bytes()
    for ordinal in range(entries):
        timestamp_ordinal = ordinal
        if out_of_order_every and ordinal >= 512 and ordinal % out_of_order_every == 0:
            timestamp_ordinal -= 511
        temporal.add(
            ordinal,
            ordinal if group_mode == "uniform" else 0,
            start + timedelta(microseconds=timestamp_ordinal),
        )
    load_seconds = perf_counter() - load_started
    rss_after = _peak_rss_bytes()

    query_count = min(max(1, queries), max(1, entries * 4))
    query_keys: list[int] = []
    cursor = 0x9E3779B97F4A7C15
    for _ in range(query_count):
        cursor = (cursor * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        query_keys.append(cursor % entries)

    def run_exact_queries(*, measure: bool) -> list[int]:
        samples: list[int] = []
        for key in query_keys:
            started = perf_counter_ns()
            record = compact[key]
            elapsed = perf_counter_ns() - started
            if measure:
                samples.append(elapsed)
            if record.ordinal != key:
                raise AssertionError("compact primary lookup returned the wrong record")
        return samples

    def run_temporal_queries(*, measure: bool) -> list[int]:
        samples: list[int] = []
        for key in query_keys:
            cutoff = start + timedelta(microseconds=max(0, key - 1))
            started = perf_counter_ns()
            next(
                iter(
                    temporal.iter_after(
                        key if group_mode == "uniform" else 0,
                        cutoff,
                        limit=1,
                    )
                ),
                None,
            )
            elapsed = perf_counter_ns() - started
            if measure:
                samples.append(elapsed)
        return samples

    # First-touch timings remain useful diagnostics, but cross-size release
    # ratios compare three symmetrically warmed passes followed by one measured
    # pass for each operation independently. This keeps a cache-resident 1K
    # working set from being compared to a first-touch 1M working set, and
    # avoids making exact lookup latency depend on an interleaved temporal
    # query's unrelated cache footprint.
    exact_cold_samples = run_exact_queries(measure=True)
    for _ in range(3):
        run_exact_queries(measure=False)
    exact_samples = run_exact_queries(measure=True)
    temporal_cold_samples = run_temporal_queries(measure=True)
    for _ in range(3):
        run_temporal_queries(measure=False)
    temporal_samples = run_temporal_queries(measure=True)

    churn_entries = 0
    replacement_seconds = 0.0
    expiry_seconds = 0.0
    temporal_compaction_seconds = 0.0
    expiry_backing_entries = 0
    if workload == "churn":
        churn_entries = max(1, entries // 2)
        replacement_started = perf_counter()
        for ordinal in range(churn_entries):
            record = compact[ordinal]
            compact[ordinal] = _ProbeRecord(
                host=record.host,
                owner=record.owner,
                ordinal=record.ordinal,
            )
            temporal.add(
                ordinal,
                ordinal if group_mode == "uniform" else 0,
                start + timedelta(microseconds=entries + ordinal),
            )
        replacement_seconds = perf_counter() - replacement_started

        compaction_started = perf_counter()
        temporal.compact()
        temporal_compaction_seconds = perf_counter() - compaction_started

        expiry: ExpiringIndex[int, int] = ExpiringIndex()
        due_entries = min(entries, 100_000)
        for ordinal in range(due_entries):
            expiry.set(ordinal, ordinal, 1.0)
            expiry.set(ordinal, ordinal, 2.0)
        expiry_started = perf_counter()
        expired_count = 0
        while page := expiry.expire_before_page(2.0, inclusive=True, limit=4_096):
            expired_count += len(page)
        if expired_count != due_entries:
            raise AssertionError("expiry churn did not return every current due entry")
        expiry.compact()
        # One authoritative timer covers bounded page expiry plus the backing
        # map/heap compaction required to reach the post-watermark census.
        expiry_seconds = perf_counter() - expiry_started
        expiry_backing_entries = expiry.metrics().backing_entries

    compact_metrics = compact.metrics(estimate_bytes=True)
    temporal_metrics = temporal.metrics(estimate_bytes=True)
    return _ScaleResult(
        entries=entries,
        queries=query_count,
        group_mode=group_mode,
        write_mode=write_mode,
        workload=workload,
        load_seconds=load_seconds,
        compact_load_seconds=compact_loaded_at - load_started,
        temporal_load_seconds=load_seconds - (compact_loaded_at - load_started),
        exact_cold_lookup_p95_us=_p95_us(exact_cold_samples),
        exact_lookup_p95_us=_p95_us(exact_samples),
        temporal_cold_lookup_p95_us=_p95_us(temporal_cold_samples),
        temporal_lookup_p95_us=_p95_us(temporal_samples),
        rss_delta_bytes=max(0, rss_after - rss_before),
        compact_rss_delta_bytes=max(0, rss_after_compact - rss_before),
        temporal_rss_delta_bytes=max(0, rss_after - rss_after_compact),
        compact_backing_entries=compact_metrics.backing_entries,
        temporal_backing_entries=temporal_metrics.backing_entries,
        temporal_stale_entries=temporal_metrics.stale_entries,
        temporal_block_size_limit=SegmentedTemporalIndex.MAX_BLOCK_SIZE,
        compact_estimated_bytes=compact_metrics.estimated_bytes,
        temporal_estimated_bytes=temporal_metrics.estimated_bytes,
        churn_entries=churn_entries,
        replacement_seconds=replacement_seconds,
        expiry_seconds=expiry_seconds,
        temporal_compaction_seconds=temporal_compaction_seconds,
        expiry_backing_entries=expiry_backing_entries,
    )


def _child_probe(args: tuple[int, int, float, str, str, str]) -> _ScaleResult:
    return _probe_one(*args)


def _ratios(results: list[_ScaleResult]) -> dict[str, float | None]:
    by_size = {result.entries: result for result in results}
    if 1_000 not in by_size or 1_000_000 not in by_size:
        return {
            "exact_1m_over_1k": None,
            "temporal_1m_over_1k": None,
            "exact_cold_1m_over_1k": None,
            "temporal_cold_1m_over_1k": None,
        }
    small = by_size[1_000]
    large = by_size[1_000_000]
    return {
        "exact_1m_over_1k": large.exact_lookup_p95_us / max(small.exact_lookup_p95_us, 0.001),
        "temporal_1m_over_1k": large.temporal_lookup_p95_us
        / max(small.temporal_lookup_p95_us, 0.001),
        "exact_cold_1m_over_1k": large.exact_cold_lookup_p95_us
        / max(small.exact_cold_lookup_p95_us, 0.001),
        "temporal_cold_1m_over_1k": large.temporal_cold_lookup_p95_us
        / max(small.temporal_cold_lookup_p95_us, 0.001),
    }


def _gates(
    results: list[_ScaleResult],
    *,
    reference_host: bool,
) -> dict[str, bool | None]:
    ratios = _ratios(results)
    by_size = {result.entries: result for result in results}
    million = by_size.get(1_000_000)
    gates: dict[str, bool | None] = {
        "exact_lookup_ratio_lte_2": (
            None if ratios["exact_1m_over_1k"] is None else ratios["exact_1m_over_1k"] <= 2.0
        ),
        "temporal_lookup_ratio_lte_3": (
            None if ratios["temporal_1m_over_1k"] is None else ratios["temporal_1m_over_1k"] <= 3.0
        ),
        "million_rss_lte_512_mib": (
            None if million is None else million.rss_delta_bytes <= 512 * 1024 * 1024
        ),
        "million_load_lte_60_seconds": (None if million is None else million.load_seconds <= 60.0),
        "temporal_block_contract_bounded": all(
            result.temporal_block_size_limit <= SegmentedTemporalIndex.MAX_BLOCK_SIZE
            for result in results
        ),
        "watermark_amplification_below_2": all(
            result.temporal_backing_entries < result.entries * 2
            and result.expiry_backing_entries < max(1, result.entries * 2)
            for result in results
        ),
        "expire_100k_lte_2_seconds": (
            None
            if not any(
                result.workload == "churn" and result.entries >= 100_000 for result in results
            )
            else all(
                result.expiry_seconds <= 2.0
                for result in results
                if result.workload == "churn" and result.entries >= 100_000
            )
        ),
        "compact_100k_lte_2_seconds": (
            None
            if not any(
                result.workload == "churn" and result.entries >= 100_000 for result in results
            )
            else all(
                result.expiry_seconds <= 2.0
                for result in results
                if result.workload == "churn" and result.entries >= 100_000
            )
        ),
    }
    if reference_host:
        gates["reference_exact_p95_lte_10_us"] = (
            None if million is None else million.exact_lookup_p95_us <= 10.0
        )
        gates["reference_temporal_p95_lte_50_us"] = (
            None if million is None else million.temporal_lookup_p95_us <= 50.0
        )
    return gates


def _parse_sizes(value: str) -> list[int]:
    sizes = sorted({int(part.strip()) for part in value.split(",") if part.strip()})
    if not sizes or any(size <= 0 for size in sizes):
        raise argparse.ArgumentTypeError("sizes must be comma-separated positive integers")
    return sizes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sizes",
        type=_parse_sizes,
        default=_parse_sizes("10,100,1000,10000,100000,1000000,2000000"),
    )
    parser.add_argument("--queries", type=int, default=10_000)
    parser.add_argument("--out-of-order-rate", type=float, default=0.10)
    parser.add_argument(
        "--group-mode",
        choices=("skewed", "uniform"),
        default="skewed",
        help="Use one hot owner/group or one sparse equality/temporal group per record.",
    )
    parser.add_argument(
        "--write-mode",
        choices=("monotonic", "out-of-order"),
        default="out-of-order",
    )
    parser.add_argument(
        "--workload",
        choices=("lookup", "churn"),
        default="lookup",
        help="Optionally add replacement, expiry, and watermark compaction churn.",
    )
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help=(
            "Fail for false gates and for open/null gates caused by missing 1K, 1M, or "
            "100K churn cases. Ordinary smoke runs may omit this flag."
        ),
    )
    parser.add_argument("--reference-host", action="store_true")
    args = parser.parse_args()
    if args.queries <= 0:
        parser.error("--queries must be positive")
    if not 0.0 <= args.out_of_order_rate <= 1.0:
        parser.error("--out-of-order-rate must be between 0 and 1")

    context = multiprocessing.get_context("spawn")
    # A fresh child per size keeps ``ru_maxrss`` and allocator retention from a
    # preceding scale point from contaminating the next measurement.
    with context.Pool(processes=1, maxtasksperchild=1) as pool:
        results = [
            pool.apply(
                _child_probe,
                (
                    (
                        size,
                        args.queries,
                        args.out_of_order_rate,
                        args.group_mode,
                        args.write_mode,
                        args.workload,
                    ),
                ),
            )
            for size in args.sizes
        ]
    ratios = _ratios(results)
    gates = _gates(results, reference_host=args.reference_host)
    open_gates = sorted(name for name, passed in gates.items() if passed is None)
    failed_gates = sorted(name for name, passed in gates.items() if passed is False)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "python": sys.version,
        "sizes": args.sizes,
        "out_of_order_rate": args.out_of_order_rate,
        "group_mode": args.group_mode,
        "write_mode": args.write_mode,
        "workload": args.workload,
        "results": [asdict(result) for result in results],
        "ratios": ratios,
        "lookup_ratio_contract": {
            "gated": (
                "each operation receives three symmetric untimed passes followed by one "
                "independent measured pass"
            ),
            "diagnostic_only": "first-touch cold/random p95 and cold cross-size ratios",
        },
        "expiry_compaction_contract": {
            "measurement": (
                "expiry_seconds includes every bounded due page and the final backing "
                "map/heap compaction"
            ),
            "expire_gate": "expire_100k_lte_2_seconds",
            "compaction_gate": "compact_100k_lte_2_seconds",
        },
        "gates": gates,
        "open_gates": open_gates,
        "failed_gates": failed_gates,
        "summary": {
            "median_exact_lookup_p95_us": statistics.median(
                result.exact_lookup_p95_us for result in results
            ),
            "median_temporal_lookup_p95_us": statistics.median(
                result.temporal_lookup_p95_us for result in results
            ),
        },
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.json_output is not None:
        args.json_output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if args.require_complete and (open_gates or failed_gates):
        return 1
    return 1 if args.enforce and failed_gates else 0


if __name__ == "__main__":
    raise SystemExit(main())
