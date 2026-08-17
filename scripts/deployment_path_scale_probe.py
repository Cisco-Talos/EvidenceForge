#!/usr/bin/env python3
"""Probe compact deployment path bindings in a fresh process per scale point."""

from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import resource
import sys
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from time import perf_counter, perf_counter_ns

from evidenceforge.events.content_identity import (
    BinaryReleaseIdentity,
    BinaryReleaseKey,
    SoftwareInstallationIdentity,
)
from evidenceforge.generation.deployment_registry import DeploymentContentRegistry

_PATHS = (
    ("agent", r"C:\Program Files\Evidence Agent\agent.exe", "agent.exe"),
    ("updater", r"C:\Program Files\Evidence Updater\updater.exe", "updater.exe"),
)


@dataclass(frozen=True, slots=True)
class PathScaleResult:
    """Structural and lookup metrics for one deployment-path scale point."""

    hosts: int
    bindings: int
    interned_hosts: int
    interned_principals: int
    interned_native_paths: int
    packed_integer_keys: int
    packed_integer_targets: int
    process_id: int
    load_seconds: float
    cold_lookup_p95_us: float
    warm_lookup_p95_us: float
    peak_rss_bytes: int
    rss_growth_bytes: int
    estimated_index_bytes: int
    estimated_bytes_per_binding: float


def _release(product_id: str, artifact_name: str) -> BinaryReleaseIdentity:
    return BinaryReleaseIdentity(
        key=BinaryReleaseKey(
            product_id=product_id,
            version="1.0.0",
            build="1",
            architecture="x64",
            platform="windows",
            artifact_name=artifact_name,
        )
    )


def _installations(
    hosts: int,
    releases: tuple[BinaryReleaseIdentity, ...],
) -> Iterator[SoftwareInstallationIdentity]:
    for host_ordinal in range(hosts):
        hostname = f"ws-{host_ordinal:07d}"
        for (application_id, native_path, _artifact_name), release in zip(
            _PATHS,
            releases,
            strict=True,
        ):
            yield SoftwareInstallationIdentity(
                hostname=hostname,
                application_id=application_id,
                release_id=release.release_id,
                platform="windows",
                scope="machine",
                install_root=native_path.rsplit("\\", 1)[0],
                image_paths=(native_path,),
            )


def _p95_us(samples_ns: list[int]) -> float:
    ordered = sorted(samples_ns)
    index = min(len(ordered) - 1, max(0, (len(ordered) * 95 + 99) // 100 - 1))
    return ordered[index] / 1_000.0


def _peak_rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak if sys.platform == "darwin" else peak * 1024


def probe(hosts: int, queries: int) -> PathScaleResult:
    """Build and query one isolated-size compact deployment registry."""

    releases = tuple(_release(product_id, artifact_name) for product_id, _, artifact_name in _PATHS)
    rss_before = _peak_rss_bytes()
    started = perf_counter()
    registry = DeploymentContentRegistry(
        binary_releases=releases,
        installations=_installations(hosts, releases),
    )
    load_seconds = perf_counter() - started
    rss_after = _peak_rss_bytes()
    census = registry.binary_path_index_census(estimate_bytes=True)

    query_count = min(max(1, queries), hosts * len(_PATHS))
    cursor = 0x9E3779B97F4A7C15
    query_specs: list[tuple[int, int]] = []
    for query_ordinal in range(query_count):
        cursor = (cursor * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        host_ordinal = cursor % hosts
        path_ordinal = query_ordinal % len(_PATHS)
        query_specs.append((host_ordinal, path_ordinal))

    passes: list[list[int]] = []
    for _pass in range(2):
        samples_ns: list[int] = []
        for host_ordinal, path_ordinal in query_specs:
            started_ns = perf_counter_ns()
            resolved = registry.resolve_binary(
                f"WS-{host_ordinal:07d}",
                _PATHS[path_ordinal][1],
                "windows",
            )
            samples_ns.append(perf_counter_ns() - started_ns)
            if resolved is not releases[path_ordinal]:
                raise AssertionError("compact deployment path lookup returned the wrong release")
        passes.append(samples_ns)

    expected_bindings = hosts * len(_PATHS)
    if (
        census.bindings != expected_bindings
        or census.packed_integer_keys != expected_bindings
        or census.packed_integer_targets != expected_bindings
    ):
        raise AssertionError("deployment path bindings are not represented by packed keys")
    if census.interned_hosts != hosts:
        raise AssertionError("host interning cardinality disagrees with the workload")
    if census.interned_principals != 0 or census.interned_native_paths != len(_PATHS):
        raise AssertionError("shared machine paths were not interned exactly once")

    return PathScaleResult(
        hosts=hosts,
        bindings=census.bindings,
        interned_hosts=census.interned_hosts,
        interned_principals=census.interned_principals,
        interned_native_paths=census.interned_native_paths,
        packed_integer_keys=census.packed_integer_keys,
        packed_integer_targets=census.packed_integer_targets,
        process_id=os.getpid(),
        load_seconds=load_seconds,
        cold_lookup_p95_us=_p95_us(passes[0]),
        warm_lookup_p95_us=_p95_us(passes[1]),
        peak_rss_bytes=rss_after,
        rss_growth_bytes=max(0, rss_after - rss_before),
        estimated_index_bytes=census.estimated_bytes,
        estimated_bytes_per_binding=census.estimated_bytes / census.bindings,
    )


def _fresh_probe(hosts: int, queries: int) -> PathScaleResult:
    context = multiprocessing.get_context("spawn")
    with context.Pool(processes=1) as pool:
        return pool.starmap(probe, ((hosts, queries),))[0]


def _sizes(value: str) -> tuple[int, ...]:
    parsed = tuple(sorted({int(part.strip()) for part in value.split(",") if part.strip()}))
    if not parsed or any(size <= 0 for size in parsed):
        raise argparse.ArgumentTypeError("host sizes must be comma-separated positive integers")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hosts", type=_sizes, default=_sizes("10,100000"))
    parser.add_argument("--queries", type=int, default=1_000)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--require-release-scale", action="store_true")
    args = parser.parse_args()
    if args.queries <= 0:
        parser.error("--queries must be positive")

    results = tuple(_fresh_probe(hosts, args.queries) for hosts in args.hosts)
    largest = results[-1]
    lookup_growth = largest.warm_lookup_p95_us / max(results[0].warm_lookup_p95_us, 0.001)
    gates = {
        "all_binding_keys_packed": all(
            result.bindings == result.packed_integer_keys for result in results
        ),
        "all_binding_targets_packed": all(
            result.bindings == result.packed_integer_targets for result in results
        ),
        "two_bindings_per_host": all(result.bindings == result.hosts * 2 for result in results),
        "shared_paths_intern_once": all(result.interned_native_paths == 2 for result in results),
        "machine_scope_uses_no_principal_handles": all(
            result.interned_principals == 0 for result in results
        ),
        "fresh_process_per_scale": len({result.process_id for result in results}) == len(results),
        "warm_lookup_p95_growth_lte_10x": lookup_growth <= 10.0,
    }
    if args.require_release_scale:
        host_sizes = {result.hosts for result in results}
        gates["actual_one_million_bindings"] = (
            500_000 in host_sizes
            and next(result.bindings for result in results if result.hosts == 500_000) == 1_000_000
        )
        gates["actual_two_million_bindings"] = (
            1_000_000 in host_sizes
            and next(result.bindings for result in results if result.hosts == 1_000_000)
            == 2_000_000
        )
    payload = {
        "schema_version": 2,
        "host_sizes": list(args.hosts),
        "results": [asdict(result) for result in results],
        "warm_lookup_p95_growth": lookup_growth,
        "gates": gates,
    }
    encoded = json.dumps(payload, indent=2, sort_keys=True)
    if args.json_output is not None:
        args.json_output.write_text(f"{encoded}\n", encoding="utf-8")
    else:
        print(encoded)
    return 1 if args.enforce and not all(gates.values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
