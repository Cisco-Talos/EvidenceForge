#!/usr/bin/env python3
# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Measure forecast accuracy across scaled EvidenceForge generation workloads."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import psutil


def _tree_rss(process: psutil.Process) -> int:
    """Return RSS for a process and its live children."""
    processes = [process, *process.children(recursive=True)]
    total = 0
    for candidate in processes:
        try:
            total += int(candidate.memory_info().rss)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return total


def _directory_bytes(path: Path) -> int:
    """Return bytes occupied by regular generated files below a directory."""
    total = 0
    for candidate in path.rglob("*"):
        if candidate.is_file() and not candidate.is_symlink():
            total += candidate.stat().st_size
    return total


def _parse_profiles(values: list[str] | None) -> list[tuple[str, str | None]]:
    """Parse repeatable NAME=FORMATS calibration profiles."""
    if not values:
        return [("full", None)]
    profiles: list[tuple[str, str | None]] = []
    names: set[str] = set()
    for value in values:
        name, separator, formats = value.partition("=")
        name = name.strip()
        formats = formats.strip()
        if not separator or not name or not formats:
            raise ValueError("profiles must use NAME=FORMATS (use NAME=all for full output)")
        if name in names:
            raise ValueError(f"duplicate profile name: {name}")
        names.add(name)
        profiles.append((name, None if formats == "all" else formats))
    return profiles


def _worker(
    scenario_path: Path,
    output: Path,
    result_path: Path,
    formats: str | None,
    duration_scale: float,
) -> int:
    """Generate one scaled scenario in this isolated child process."""
    from evidenceforge.events.dispatcher import expand_formats
    from evidenceforge.generation.engine import GenerationEngine
    from evidenceforge.models.scenario import Scenario
    from evidenceforge.utils.files import load_scenario_yaml
    from evidenceforge.utils.personas import merge_builtin_personas
    from evidenceforge.utils.time import resolve_time_window

    scenario_data = merge_builtin_personas(load_scenario_yaml(scenario_path))
    scenario = Scenario(**scenario_data)
    start, end = resolve_time_window(scenario.time_window)
    scaled_seconds = max(1, round((end - start).total_seconds() * duration_scale))
    scenario = scenario.model_copy(
        update={
            "time_window": scenario.time_window.model_copy(
                update={"duration": f"{scaled_seconds}s", "end": None}
            )
        }
    )
    if formats:
        requested = expand_formats(part.strip() for part in formats.split(","))
        available = expand_formats(
            {entry["format"] for entry in scenario.output.logs if "format" in entry}
        )
        selected = requested & available
        if not selected:
            raise ValueError(f"profile formats do not intersect scenario output: {formats}")
        scenario = scenario.model_copy(
            update={
                "storyline": [],
                "red_herrings": [],
                "output": scenario.output.model_copy(
                    update={"logs": [{"format": name} for name in sorted(selected)]}
                ),
            }
        )

    engine = GenerationEngine(
        scenario,
        output / "data",
        ground_truth_dir=output,
        artifact_dir=output / "artifacts",
        scenario_root=scenario_path.parent,
    )
    engine.generate()
    result_path.write_text(
        json.dumps(
            {
                "scenario_name": scenario.name,
                "effective_duration_seconds": scaled_seconds,
                "baseline_only": formats is not None,
                "workload_estimate": engine.workload_estimate.model_dump(mode="json"),
                "resource_forecast": engine.resource_forecast.model_dump(mode="json"),
            }
        ),
        encoding="utf-8",
    )
    return 0


def _measure(
    scenario: Path,
    profile_name: str,
    formats: str | None,
    duration_scale: float,
) -> dict[str, Any]:
    """Generate one scenario in a child process and return calibration measurements."""
    with tempfile.TemporaryDirectory(prefix="eforge-resource-calibration-") as temporary:
        temporary_path = Path(temporary)
        output = temporary_path / "output"
        worker_result = temporary_path / "worker-result.json"
        command = [
            sys.executable,
            str(Path(__file__).resolve()),
            str(scenario),
            "--worker",
            "--worker-output",
            str(output),
            "--worker-result",
            str(worker_result),
            "--worker-duration-scale",
            str(duration_scale),
        ]
        if formats:
            command.extend(("--worker-formats", formats))
        started = time.monotonic()
        child = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        process = psutil.Process(child.pid)
        peak_rss = 0
        while child.poll() is None:
            peak_rss = max(peak_rss, _tree_rss(process))
            time.sleep(0.05)
        stdout, stderr = child.communicate()
        elapsed = time.monotonic() - started
        if child.returncode != 0:
            raise RuntimeError(
                f"generation failed for {scenario} profile={profile_name} "
                f"scale={duration_scale:g} with exit code {child.returncode}:\n"
                f"{stderr or stdout}"
            )
        worker_data = json.loads(worker_result.read_text(encoding="utf-8"))
        forecast = worker_data["resource_forecast"]
        return {
            "scenario": worker_data["scenario_name"],
            "profile": profile_name,
            "formats": formats,
            "duration_scale": duration_scale,
            "effective_duration_seconds": worker_data["effective_duration_seconds"],
            "baseline_only": worker_data["baseline_only"],
            "elapsed_seconds": round(elapsed, 3),
            "peak_rss_bytes": peak_rss,
            "output_bytes": _directory_bytes(output),
            "workload_estimate": worker_data["workload_estimate"],
            "forecast_memory": forecast["memory"],
            "forecast_disk": forecast["disk"],
        }


def _parser() -> argparse.ArgumentParser:
    """Build the parent/worker command parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", nargs="+", type=Path)
    parser.add_argument(
        "--profile",
        action="append",
        help="Repeatable NAME=FORMATS profile; use NAME=all for full scenario output.",
    )
    parser.add_argument(
        "--duration-scale",
        nargs="+",
        type=float,
        default=[1.0],
        help="Positive duration multipliers to measure (default: 1).",
    )
    parser.add_argument("--output-json", type=Path, help="Write the result document to this path.")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--worker-output", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--worker-result", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--worker-formats", help=argparse.SUPPRESS)
    parser.add_argument("--worker-duration-scale", type=float, help=argparse.SUPPRESS)
    return parser


def _write_document(
    output_path: Path | None,
    measurements: list[dict[str, Any]],
    failures: list[dict[str, Any]],
) -> None:
    """Persist a resumable calibration checkpoint or print the final document."""
    document = {
        "schema_version": 2,
        "python": sys.version,
        "platform": sys.platform,
        "measurements": measurements,
        "failures": failures,
    }
    rendered = json.dumps(document, indent=2) + "\n"
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


def main() -> int:
    """Measure requested scenarios or execute one isolated worker generation."""
    parser = _parser()
    args = parser.parse_args()
    scenarios = [path.resolve() for path in args.scenario]
    missing = [path for path in scenarios if not path.is_file()]
    if missing:
        parser.error(f"scenario file not found: {missing[0]}")

    if args.worker:
        if args.worker_output is None or args.worker_result is None:
            parser.error("worker output and result paths are required")
        if args.worker_duration_scale is None or args.worker_duration_scale <= 0:
            parser.error("worker duration scale must be positive")
        if len(scenarios) != 1:
            parser.error("worker mode accepts exactly one scenario")
        return _worker(
            scenarios[0],
            args.worker_output,
            args.worker_result,
            args.worker_formats,
            args.worker_duration_scale,
        )

    if any(scale <= 0 for scale in args.duration_scale):
        parser.error("duration scales must be positive")
    try:
        profiles = _parse_profiles(args.profile)
    except ValueError as exc:
        parser.error(str(exc))
    measurements: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for scenario in scenarios:
        for profile_name, formats in profiles:
            for scale in args.duration_scale:
                try:
                    measurements.append(_measure(scenario, profile_name, formats, scale))
                except RuntimeError as exc:
                    failures.append(
                        {
                            "scenario": scenario.name,
                            "profile": profile_name,
                            "formats": formats,
                            "duration_scale": scale,
                            "error": str(exc),
                        }
                    )
                    if args.output_json:
                        _write_document(args.output_json, measurements, failures)
                    raise
                if args.output_json:
                    _write_document(args.output_json, measurements, failures)
    if args.output_json is None:
        _write_document(None, measurements, failures)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
