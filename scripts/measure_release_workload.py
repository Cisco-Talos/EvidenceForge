# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Measure one fresh CLI workload across a verified suspension and exact resume."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import psutil
from pydantic import BaseModel, ConfigDict
from scripts.calibrate_generation_resources import (
    _directory_allocated_bytes,
    _directory_bytes,
    _tree_rss,
)

from evidenceforge.composition.artifacts import verify_generation_bundle
from evidenceforge.generation.checkpoints.control import request_suspension
from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore


class Measurement(BaseModel):
    """Observed bounds for this workload, rather than a scalability guarantee."""

    model_config = ConfigDict(extra="forbid")
    scenario_sha256: str
    generation_seconds: float = 0
    verification_seconds: float = 0
    peak_process_tree_rss_bytes: int = 0
    sampled_peak_working_disk_bytes: int = 0
    retained_checkpoint_logical_bytes: int = 0
    retained_checkpoint_allocated_bytes: int = 0
    checkpoint_completed_simulated_hours: int = 0
    final_logical_bytes: int = 0
    final_owned_temporary_allocated_bytes: int = 0
    bundle_relative_path: str = "working/bundle"
    disk_scope: str = "bundle plus owned worker temporary files; excludes backup and reports"
    rss_sample_seconds: float = 0.05
    disk_sample_seconds: float = 0.2
    bundle_verified: bool = False


def main() -> None:
    """Validate, measure generation, verify a committed checkpoint and resume exactly."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--checkpoint-hours", type=int, default=6)
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    args = parser.parse_args()
    if args.checkpoint_hours < 1 or args.timeout_seconds < 1:
        parser.error("checkpoint cadence and timeout must be positive")
    scenario = args.scenario.resolve(strict=True)
    destination = args.destination.resolve()
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    working = destination / "working"
    temporary = working / "temporary"
    temporary.mkdir(mode=0o700, parents=True)
    bundle = working / "bundle"
    environment = os.environ | {
        "TMPDIR": str(temporary),
        "TMP": str(temporary),
        "TEMP": str(temporary),
    }
    report = Measurement(scenario_sha256=hashlib.sha256(scenario.read_bytes()).hexdigest())
    prefix = [sys.executable, "-m", "evidenceforge"]
    with (destination / "validation.json").open("w") as output:
        subprocess.run(
            [
                *prefix,
                "validate",
                str(scenario),
                "--json",
                "--checkpoint-hours",
                str(args.checkpoint_hours),
            ],
            stdout=output,
            env=environment,
            check=True,
            timeout=120,
        )
    store = IncrementalCheckpointStore(bundle)
    deadline = time.monotonic() + args.timeout_seconds

    def run(
        arguments: list[str], label: str, *, suspend: bool = False, verification: bool = False
    ) -> None:
        started = time.monotonic()
        phase_deadline = min(deadline, started + 300) if verification else deadline
        requested = False
        next_disk = 0.0
        suffix = "json" if verification else "log"
        with (destination / f"{label}.{suffix}").open("w") as log:
            child = subprocess.Popen(
                [*prefix, *arguments], stdout=log, stderr=subprocess.STDOUT, env=environment
            )
            process = psutil.Process(child.pid)
            try:
                while child.poll() is None:
                    if time.monotonic() > phase_deadline:
                        raise TimeoutError("workload exceeded its fixed wall-time budget")
                    try:
                        report.peak_process_tree_rss_bytes = max(
                            report.peak_process_tree_rss_bytes, _tree_rss(process)
                        )
                    except psutil.NoSuchProcess:
                        pass
                    now = time.monotonic()
                    if now >= next_disk:
                        report.sampled_peak_working_disk_bytes = max(
                            report.sampled_peak_working_disk_bytes,
                            _directory_allocated_bytes(working),
                        )
                        next_disk = now + report.disk_sample_seconds
                    if suspend and not requested and store.index_path.exists():
                        # Immediate suspension forces an hour-one checkpoint.
                        # Wait for the first cadence checkpoint before measuring
                        # the retained state of this longer workload.
                        request_suspension(store)
                        requested = True
                    time.sleep(report.rss_sample_seconds)
                if child.returncode != 0:
                    raise RuntimeError(
                        f"{label} failed with exit {child.returncode}; see {log.name}"
                    )
                if suspend and not requested:
                    raise RuntimeError("generation never exposed suspension control")
            finally:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=10)
                if verification:
                    report.verification_seconds += time.monotonic() - started
                else:
                    report.generation_seconds += time.monotonic() - started
                (destination / "measurement.json").write_text(
                    report.model_dump_json(indent=2) + "\n"
                )

    run(
        [
            "generate",
            str(scenario),
            "--output",
            str(bundle),
            "--seed",
            "42",
            "--checkpoint-hours",
            str(args.checkpoint_hours),
        ],
        "generate",
        suspend=True,
    )
    recovery = store.recover(read_only=True)
    if recovery.used_fallback:
        raise RuntimeError("measurement requires the newest committed checkpoint")
    report.checkpoint_completed_simulated_hours = recovery.manifest.cursor.completed_simulated_hours
    report.retained_checkpoint_logical_bytes = _directory_bytes(store.workspace)
    report.retained_checkpoint_allocated_bytes = _directory_allocated_bytes(store.workspace)
    (destination / "checkpoint-manifest.json").write_text(
        recovery.manifest.model_dump_json(indent=2) + "\n"
    )
    # Preserve the stopped valid recovery before hydration/resume. Reflinks/hardlinks
    # are deliberately avoided so this copy cannot mutate the original checkpoint.
    shutil.copytree(store.workspace, destination / "checkpoint-backup")
    run(
        ["checkpoint", "verify", str(bundle), "--json"],
        "checkpoint-verification",
        verification=True,
    )
    run(["generate", "--output", str(bundle), "--resume", "--resume-policy", "exact"], "resume")
    verify_generation_bundle(bundle)
    report.bundle_verified = True
    report.final_logical_bytes = _directory_bytes(bundle)
    report.final_owned_temporary_allocated_bytes = _directory_allocated_bytes(temporary)
    report.sampled_peak_working_disk_bytes = max(
        report.sampled_peak_working_disk_bytes, _directory_allocated_bytes(working)
    )
    (destination / "measurement.json").write_text(report.model_dump_json(indent=2) + "\n")
    manifest = json.loads((bundle / "GENERATION_MANIFEST.json").read_text())
    print(report.model_dump_json(indent=2))
    print(
        json.dumps(
            {
                "formats": manifest["formats"],
                "seed": manifest["generation_seed"],
                "target": manifest["output_target"],
            }
        )
    )


if __name__ == "__main__":
    main()
