"""Measure fixed cleanup workloads without imposing a performance threshold.

Run in a fresh process with the same interpreter for each source checkout. Keep
timing observations separate from deterministic controls and generated evidence.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import os
import resource
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def workload(name: str, source: Path) -> tuple[Callable[[], object], int]:
    """Bind one fixed workload to the selected checkout's existing owners."""
    if name == "cli-failure":
        from types import SimpleNamespace
        from unittest.mock import patch

        from typer.testing import CliRunner

        from evidenceforge.cli import commands

        fixture = Path(__file__).resolve().parents[1] / "tests/fixtures/scenarios/minimal.yaml"

        def failing_cli() -> object:
            results: list[dict[str, object]] = []
            for checkpoint_hours in (0, 24):
                for interrupted in (False, True):
                    with tempfile.TemporaryDirectory(prefix="eforge-cleanup-failure-") as temporary:
                        output = Path(temporary)
                        (output / "data").mkdir()
                        (output / "data/old.log").write_bytes(b"original evidence\n")
                        (output / "GROUND_TRUTH.md").write_bytes(b"original ground truth\n")

                        def fail(was_interrupted: bool = interrupted) -> None:
                            if was_interrupted:
                                raise KeyboardInterrupt()
                            raise OSError("cleanup benchmark fault")

                        with patch.object(
                            commands,
                            "GenerationEngine",
                            return_value=SimpleNamespace(generate=fail),
                        ):
                            result = CliRunner().invoke(
                                commands.app,
                                [
                                    "generate",
                                    str(fixture),
                                    "--output",
                                    str(output),
                                    "--overwrite",
                                    "--checkpoint-hours",
                                    str(checkpoint_hours),
                                ],
                            )
                        results.append(
                            {
                                "exit_code": result.exit_code,
                                "old_evidence_sha256": hashlib.sha256(
                                    (output / "data/old.log").read_bytes()
                                ).hexdigest(),
                                "old_truth_sha256": hashlib.sha256(
                                    (output / "GROUND_TRUTH.md").read_bytes()
                                ).hexdigest(),
                                "temporary_staging_count": len(
                                    list(output.glob(".eforge_staging_*"))
                                ),
                                "persistent_staging": (
                                    output / ".eforge-generation/staged"
                                ).exists(),
                                "cleanup_message": "Cleaned up staging directory" in result.stdout,
                                "preservation_message": "Previous output preserved"
                                in result.stdout,
                            }
                        )
            return results

        return failing_cli, 4
    if name == "generation-cli":
        from compare_cleanup_output import snapshot

        fixture = Path(__file__).resolve().parents[1] / "tests/fixtures/scenarios/minimal.yaml"
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(source / "src")

        def generate_cli() -> object:
            with tempfile.TemporaryDirectory(prefix="eforge-cleanup-cli-measure-") as temporary:
                output = Path(temporary) / "bundle"
                subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "evidenceforge",
                        "generate",
                        str(fixture),
                        "--output",
                        str(output),
                        "--seed",
                        "42",
                        "--checkpoint-hours",
                        "0",
                    ],
                    env=environment,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    check=True,
                )
                return snapshot(output)

        return generate_cli, 1
    if name == "generation":
        from compare_cleanup_output import snapshot

        from evidenceforge.generation.engine import GenerationEngine
        from evidenceforge.models.scenario import Scenario
        from evidenceforge.utils.files import load_yaml

        document = load_yaml(source / "tests/fixtures/scenarios/minimal.yaml")

        def generate() -> object:
            with tempfile.TemporaryDirectory(prefix="eforge-cleanup-measure-") as temporary:
                output = Path(temporary)
                GenerationEngine(Scenario(**document), output, generation_seed=42).generate()
                return snapshot(output)

        return generate, 1
    if name == "fingerprint":
        from evidenceforge.composition import compile_scenario
        from evidenceforge.generation.checkpoints import fingerprint

        compiled = compile_scenario(source / "tests/fixtures/scenarios/checkpoint-all-formats.yaml")
        options = {"output_target": "default", "formats": ["zeek"], "oob_hosts": ()}

        def fingerprints() -> object:
            combined = getattr(fingerprint, "run_fingerprint_details", None)
            if combined is not None:
                return combined(compiled, **options)
            return (
                fingerprint.run_fingerprint(compiled, **options),
                fingerprint.run_fingerprint_components(compiled, **options),
            )

        return fingerprints, 1
    if name == "prepared-clocks":
        from evidenceforge.generation.timing import (
            ClockWanderSpec,
            SourceClockKey,
            SourceClockSpec,
            TimingRuntime,
            TriangularDistribution,
        )

        epoch = datetime(2024, 1, 15, tzinfo=UTC)
        spec = SourceClockSpec(
            wander=ClockWanderSpec(
                knot_distribution_microseconds=TriangularDistribution(
                    minimum=-10_000, mode=20, maximum=10_000
                ),
                knot_interval=timedelta(seconds=30),
            )
        )
        keys = tuple(SourceClockKey(kind="endpoint", identity=f"HOST-{i}") for i in range(8))
        times = tuple(epoch + timedelta(milliseconds=i * 137 - 500) for i in range(2048))

        def prepared_clocks() -> object:
            runtime = TimingRuntime(
                reference_time=epoch,
                namespace="cleanup-prepared-clock-control",
                generation_seed=137,
                max_clock_cache_entries=4,
            )
            digest = hashlib.sha256()
            for batch in range(16):
                preparation = runtime.prepared()
                for index in range(batch * 128, (batch + 1) * 128):
                    projected = preparation.clocks.project(
                        times[index], key=keys[index % len(keys)], spec=spec
                    )
                    digest.update(projected.isoformat().encode())
                if batch % 4 == 3:
                    preparation.cancel()
                else:
                    preparation._acquire_claim()
                    try:
                        preparation._commit_no_fail()
                    finally:
                        preparation._release_claim()
            return {"values_sha256": digest.hexdigest(), "census": asdict(runtime.census())}

        return prepared_clocks, len(times)
    if name == "clocks":
        from evidenceforge.generation.timing import (
            SourceClockKey,
            SourceClockRegistry,
            SourceClockSpec,
            TimingSampler,
        )

        epoch = datetime(2024, 1, 15, tzinfo=UTC)
        spec = SourceClockSpec()
        keys = tuple(SourceClockKey(kind="endpoint", identity=f"HOST-{i}") for i in range(8))
        times = tuple(epoch + timedelta(milliseconds=i * 137 - 500) for i in range(2048))

        def clocks() -> object:
            registry = SourceClockRegistry(
                reference_time=epoch,
                sampler=TimingSampler(namespace="cleanup-clock-control", generation_seed=42),
                max_cache_entries=4,
            )
            digest = hashlib.sha256()
            for i, timestamp in enumerate(times):
                projected = registry.project(timestamp, key=keys[i % len(keys)], spec=spec)
                digest.update(projected.isoformat().encode())
            return {"values_sha256": digest.hexdigest(), "census": asdict(registry.census())}

        return clocks, len(times)
    if name == "gates-context":
        from evidenceforge.generation.lifecycle_registry import _MutationGate

        def context_gates() -> object:
            gate = _MutationGate()
            for i in range(10_000):
                if i % 100 == 0:
                    with gate.watermark():
                        pass
                else:
                    with gate.mutation():
                        pass
            return {"readers": gate._readers, "writer": gate._writer}

        return context_gates, 10_000
    if name == "gates":
        from evidenceforge.generation.application_channels import _MutationGate

        def gates() -> object:
            gate = _MutationGate()
            for i in range(10_000):
                if i % 100 == 0:
                    with gate.watermark():
                        pass
                else:
                    gate.enter_mutation()
                    gate.exit_mutation()
            return {"readers": gate._readers, "writer": gate._writer}

        return gates, 10_000
    raise ValueError(f"Unknown workload: {name}")


def main() -> None:
    """Record warmups, individual timing samples and a separate allocation sample."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument(
        "--workload",
        choices=(
            "fingerprint",
            "clocks",
            "prepared-clocks",
            "gates",
            "gates-context",
            "generation",
            "generation-cli",
            "cli-failure",
        ),
        required=True,
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=7)
    args = parser.parse_args()
    sys.path.insert(0, str(args.source.resolve() / "src"))
    operation, count = workload(args.workload, args.source.resolve())
    for _ in range(2):
        operation()
    seconds: list[float] = []
    result: Any = None
    for _ in range(args.samples):
        started = time.perf_counter()
        result = operation()
        seconds.append(time.perf_counter() - started)
    gc.collect()
    tracemalloc.start()
    operation()
    retained, peak = tracemalloc.get_traced_memory()
    retained_blocks = sum(item.count for item in tracemalloc.take_snapshot().statistics("filename"))
    tracemalloc.stop()
    report = {
        "source": str(args.source.resolve()),
        "workload": args.workload,
        "warmups": 2,
        "operations_per_sample": count,
        "seconds": seconds,
        "median_seconds": statistics.median(seconds),
        "operations_per_second": count / statistics.median(seconds),
        "allocation_sample_retained_bytes": retained,
        "allocation_sample_peak_bytes": peak,
        "allocation_sample_retained_blocks": retained_blocks,
        "process_max_rss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "child_process_max_rss": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
        "allocation_scope": "parent harness only; child RSS recorded separately"
        if args.workload == "generation-cli"
        else "in-process workload",
        "result": result,
    }
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(f"{args.workload}: {report['median_seconds']:.6f}s; {peak} peak traced bytes")


if __name__ == "__main__":
    main()
