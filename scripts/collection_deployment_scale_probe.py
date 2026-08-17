#!/usr/bin/env python3
"""Measure packed collection-deployment scale from 10 to two million sources."""

from __future__ import annotations

import argparse
import gc
import json
import multiprocessing
import resource
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from time import perf_counter, perf_counter_ns

from evidenceforge.events.collection_policy import (
    CollectionCapability,
    SourceCollectionPolicy,
    SourceInstanceIdentity,
)
from evidenceforge.generation.collection_deployment import (
    CompiledCollectionDeployment,
    SourceInstanceDeployment,
)


@dataclass(frozen=True, slots=True)
class _ScaleResult:
    """One fresh-process collection deployment measurement."""

    entries: int
    shape: str
    queries: int
    load_seconds: float
    rss_delta_bytes: int
    estimated_bytes: int
    estimated_bytes_per_source: float
    estimated_index_bytes: int
    estimated_index_bytes_per_source: float
    warmed_exact_lookup_p95_us: float
    cold_exact_lookup_p95_us: float
    warmed_host_family_lookup_p95_us: float
    cold_host_family_lookup_p95_us: float
    cold_format_count_lookup_p95_us: float
    warmed_format_count_lookup_p95_us: float
    cold_format_find_one_lookup_p95_us: float
    warmed_format_find_one_lookup_p95_us: float
    exact_candidates_p95: int
    exact_candidates_max: int
    host_family_candidates_p95: int
    host_family_candidates_max: int
    unique_hostnames: int
    unique_families: int
    unique_format_sets: int
    unique_policies: int
    exact_index_capacity: int
    host_index_capacity: int
    host_family_index_capacity: int
    packed_index_bytes: int
    content_digest: str


_FORMATS = ("zeek_conn", "zeek_dns", "zeek_http", "zeek_ssl")
_POLICIES = tuple(
    SourceCollectionPolicy(
        capabilities=(
            CollectionCapability.NETWORK
            | CollectionCapability.SOURCE_ENDPOINT
            | CollectionCapability.DESTINATION_ENDPOINT
            | capability
        ),
        missingness=index / 1_000,
    )
    for index, capability in enumerate(
        (
            CollectionCapability.DNS,
            CollectionCapability.HTTP,
            CollectionCapability.TLS,
            CollectionCapability.FILE,
        )
    )
)


def _peak_rss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == "darwin" else value * 1024)


def _p95(samples: list[int]) -> int:
    if not samples:
        return 0
    ordered = sorted(samples)
    return ordered[min(len(ordered) - 1, max(0, round(len(ordered) * 0.95) - 1))]


def _p95_us(samples_ns: list[int]) -> float:
    return _p95(samples_ns) / 1_000.0


def _hostname(index: int, shape: str) -> str:
    return f"edge-{index}" if shape == "uniform" else f"edge-{index % 512}"


def _source(index: int, shape: str) -> SourceInstanceDeployment:
    format_name = _FORMATS[index % len(_FORMATS)]
    return SourceInstanceDeployment(
        identity=SourceInstanceIdentity(
            source_instance=f"sensor-{index}",
            hostname=_hostname(index, shape),
            family="zeek",
        ),
        formats=(format_name,),
        policy=_POLICIES[index % len(_POLICIES)],
    )


def _query_indices(entries: int, queries: int) -> list[int]:
    count = min(max(1, queries), max(1, entries * 4))
    cursor = 0x9E3779B97F4A7C15
    values: list[int] = []
    for _ in range(count):
        cursor = (cursor * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        values.append(cursor % entries)
    return values


def _measure_exact(
    deployment: CompiledCollectionDeployment,
    indices: list[int],
) -> tuple[list[int], list[int]]:
    timings: list[int] = []
    candidates: list[int] = []
    for index in indices:
        source_id = f"sensor-{index}"
        started = perf_counter_ns()
        source = deployment.source_by_instance(source_id)
        timings.append(perf_counter_ns() - started)
        if source is None or source.identity.source_instance != source_id:
            raise AssertionError("exact source lookup returned the wrong deployment")
        candidates.append(deployment.exact_lookup_candidates(source_id))
    return timings, candidates


def _measure_host_family(
    deployment: CompiledCollectionDeployment,
    indices: list[int],
    shape: str,
) -> tuple[list[int], list[int]]:
    timings: list[int] = []
    candidates: list[int] = []
    for index in indices:
        hostname = _hostname(index, shape)
        started = perf_counter_ns()
        count = deployment.count_host_family(hostname, "zeek")
        timings.append(perf_counter_ns() - started)
        expected = (
            1
            if shape == "uniform"
            else 1 + ((deployment.census.source_instances - 1 - (index % 512)) // 512)
        )
        if count != expected:
            raise AssertionError(
                f"host/family lookup returned {count} sources; expected {expected}"
            )
        candidates.append(deployment.host_family_lookup_candidates(hostname, "zeek"))
    return timings, candidates


def _measure_formats(
    deployment: CompiledCollectionDeployment,
    names: list[str],
) -> tuple[list[int], list[int]]:
    count_timings: list[int] = []
    find_one_timings: list[int] = []
    for format_name in names:
        started_ns = perf_counter_ns()
        count = deployment.count_format(format_name)
        count_timings.append(perf_counter_ns() - started_ns)
        if count < 1:
            raise AssertionError("format count lookup lost a deployed format")
        started_ns = perf_counter_ns()
        source = next(deployment.iter_format(format_name), None)
        find_one_timings.append(perf_counter_ns() - started_ns)
        if source is None or format_name not in source.formats:
            raise AssertionError("format iterator returned the wrong source")
    return count_timings, find_one_timings


def _probe_one(entries: int, queries: int, shape: str) -> _ScaleResult:
    gc.collect()
    rss_before = _peak_rss_bytes()
    started = perf_counter()
    deployment = CompiledCollectionDeployment(_source(index, shape) for index in range(entries))
    load_seconds = perf_counter() - started
    rss_after_load = _peak_rss_bytes()

    cold_format_count, cold_format_find_one = _measure_formats(deployment, list(_FORMATS))
    cold_indices = _query_indices(entries, queries)
    cold_exact, exact_candidates = _measure_exact(deployment, cold_indices)
    cold_host, host_candidates = _measure_host_family(deployment, cold_indices, shape)

    hot_width = min(entries, 1_024)
    hot_indices = [index % hot_width for index in range(len(cold_indices))]
    _measure_exact(deployment, hot_indices[:hot_width])
    _measure_host_family(deployment, hot_indices[:hot_width], shape)
    warmed_exact, _ = _measure_exact(deployment, hot_indices)
    warmed_host, _ = _measure_host_family(deployment, hot_indices, shape)
    warmed_format_names = [_FORMATS[query % len(_FORMATS)] for query in range(len(cold_indices))]
    warmed_format_count, warmed_format_find_one = _measure_formats(
        deployment,
        warmed_format_names,
    )

    census = deployment.census
    return _ScaleResult(
        entries=entries,
        shape=shape,
        queries=len(cold_indices),
        load_seconds=load_seconds,
        rss_delta_bytes=max(0, rss_after_load - rss_before),
        estimated_bytes=census.estimated_bytes,
        estimated_bytes_per_source=census.estimated_bytes / entries,
        estimated_index_bytes=census.estimated_index_bytes,
        estimated_index_bytes_per_source=census.estimated_index_bytes / entries,
        warmed_exact_lookup_p95_us=_p95_us(warmed_exact),
        cold_exact_lookup_p95_us=_p95_us(cold_exact),
        warmed_host_family_lookup_p95_us=_p95_us(warmed_host),
        cold_host_family_lookup_p95_us=_p95_us(cold_host),
        cold_format_count_lookup_p95_us=_p95_us(cold_format_count),
        warmed_format_count_lookup_p95_us=_p95_us(warmed_format_count),
        cold_format_find_one_lookup_p95_us=_p95_us(cold_format_find_one),
        warmed_format_find_one_lookup_p95_us=_p95_us(warmed_format_find_one),
        exact_candidates_p95=_p95(exact_candidates),
        exact_candidates_max=max(exact_candidates, default=0),
        host_family_candidates_p95=_p95(host_candidates),
        host_family_candidates_max=max(host_candidates, default=0),
        unique_hostnames=census.unique_hostnames,
        unique_families=census.unique_families,
        unique_format_sets=census.unique_format_sets,
        unique_policies=census.unique_policies,
        exact_index_capacity=census.exact_index_capacity,
        host_index_capacity=census.host_index_capacity,
        host_family_index_capacity=census.host_family_index_capacity,
        packed_index_bytes=census.packed_index_bytes,
        content_digest=deployment.content_digest,
    )


def _child_probe(args: tuple[int, int, str]) -> _ScaleResult:
    return _probe_one(*args)


def _parse_sizes(value: str) -> list[int]:
    sizes = sorted({int(part.strip()) for part in value.split(",") if part.strip()})
    if not sizes or any(size <= 0 for size in sizes):
        raise argparse.ArgumentTypeError("sizes must be comma-separated positive integers")
    return sizes


def _ratios(results: list[_ScaleResult]) -> dict[str, float | None]:
    ratios: dict[str, float | None] = {}
    for shape in sorted({result.shape for result in results}):
        by_size = {result.entries: result for result in results if result.shape == shape}
        small = by_size.get(1_000)
        million = by_size.get(1_000_000)
        metric_names = (
            "warmed_exact_lookup_p95_us",
            "cold_exact_lookup_p95_us",
            "warmed_host_family_lookup_p95_us",
            "cold_host_family_lookup_p95_us",
            "warmed_format_count_lookup_p95_us",
            "cold_format_count_lookup_p95_us",
            "warmed_format_find_one_lookup_p95_us",
            "cold_format_find_one_lookup_p95_us",
        )
        for metric_name in metric_names:
            label = metric_name.removesuffix("_lookup_p95_us")
            ratios[f"{shape}_{label}_1m_over_1k"] = (
                None
                if small is None or million is None
                else getattr(million, metric_name) / max(getattr(small, metric_name), 0.001)
            )
    return ratios


def _gates(results: list[_ScaleResult]) -> dict[str, bool | None]:
    million_results = [result for result in results if result.entries == 1_000_000]
    ratios = _ratios(results)
    warmed_ratio_values = [
        value for name, value in ratios.items() if "warmed_exact" in name and value is not None
    ]
    warmed_host_ratio_values = [
        value
        for name, value in ratios.items()
        if "warmed_host_family" in name and value is not None
    ]
    warmed_format_ratio_values = [
        value for name, value in ratios.items() if "warmed_format" in name and value is not None
    ]
    return {
        "million_rss_lte_512_mib": (
            None
            if not million_results
            else all(result.rss_delta_bytes <= 512 * 1024 * 1024 for result in million_results)
        ),
        "million_estimated_bytes_per_source_lte_256": (
            None
            if not million_results
            else all(result.estimated_bytes_per_source <= 256 for result in million_results)
        ),
        "million_estimated_index_bytes_per_source_lte_256": (
            None
            if not million_results
            else all(result.estimated_index_bytes_per_source <= 256 for result in million_results)
        ),
        "million_load_lte_60_seconds": (
            None
            if not million_results
            else all(result.load_seconds <= 60 for result in million_results)
        ),
        "million_warmed_exact_p95_lte_10_us": (
            None
            if not million_results
            else all(result.warmed_exact_lookup_p95_us <= 10 for result in million_results)
        ),
        "million_cold_exact_p95_lte_10_us": (
            None
            if not million_results
            else all(result.cold_exact_lookup_p95_us <= 10 for result in million_results)
        ),
        "million_cold_host_family_p95_lte_50_us": (
            None
            if not million_results
            else all(result.cold_host_family_lookup_p95_us <= 50 for result in million_results)
        ),
        "exact_lookup_1m_over_1k_lte_2": (
            None if not warmed_ratio_values else all(value <= 2 for value in warmed_ratio_values)
        ),
        "host_family_lookup_1m_over_1k_lte_2": (
            None
            if not warmed_host_ratio_values
            else all(value <= 2 for value in warmed_host_ratio_values)
        ),
        "format_lookup_1m_over_1k_lte_2": (
            None
            if not warmed_format_ratio_values
            else all(value <= 2 for value in warmed_format_ratio_values)
        ),
        "exact_candidates_p95_lte_16": all(result.exact_candidates_p95 <= 16 for result in results),
        "host_family_candidates_p95_lte_24": all(
            result.host_family_candidates_p95 <= 24 for result in results
        ),
        "packed_capacities_below_2x_entries": all(
            result.exact_index_capacity < max(8, result.entries * 2)
            and result.host_index_capacity < max(8, result.unique_hostnames * 2)
            and result.host_family_index_capacity < max(8, result.unique_hostnames * 2)
            for result in results
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sizes",
        type=_parse_sizes,
        default=_parse_sizes("10,100,1000,10000,100000,1000000,2000000"),
    )
    parser.add_argument("--queries", type=int, default=5_000)
    parser.add_argument(
        "--shape",
        choices=("uniform", "skewed", "both"),
        default="both",
    )
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--enforce", action="store_true")
    args = parser.parse_args()
    if args.queries < 1:
        parser.error("queries must be positive")

    shapes = ("uniform", "skewed") if args.shape == "both" else (args.shape,)
    work = [(size, args.queries, shape) for shape in shapes for size in args.sizes]
    context = multiprocessing.get_context("spawn")
    with context.Pool(processes=1, maxtasksperchild=1) as pool:
        results = pool.map(_child_probe, work, chunksize=1)

    payload = {
        "schema_version": 1,
        "rss_measurement": "fresh-child peak RSS minus post-import baseline",
        "sizes": args.sizes,
        "shapes": list(shapes),
        "results": [asdict(result) for result in results],
        "ratios": _ratios(results),
        "gates": _gates(results),
    }
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.json_output is not None:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")
    if args.enforce and any(value is False for value in payload["gates"].values()):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
