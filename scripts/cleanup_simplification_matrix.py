"""Run selected frozen comparison groups against baseline and preceding captures."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

from compare_cleanup_output import snapshot

GROUPS = {
    "core": ("cleanup_output_matrix.py", None, 32),
    "typed": ("cleanup_supplement_matrix.py", "cleanup-typed-handlers.yaml", 6),
    "periodic": ("cleanup_supplement_matrix.py", "cleanup-periodic-content.yaml", 6),
    "shell": ("cleanup_supplement_matrix.py", "cleanup-foreground-ownership.yaml", 6),
    "foreground": ("cleanup_foreground_matrix.py", None, 36),
    "process": ("cleanup_process_matrix.py", None, 36),
    "parent-preflight": ("cleanup_parent_preflight_matrix.py", None, 72),
    "system": ("cleanup_supplement_matrix.py", "cleanup-system-families.yaml", 6),
    "cli": ("cleanup_cli_matrix.py", None, 6),
    "network": ("cleanup_network_matrix.py", None, 32),
    "smb": ("cleanup_supplement_matrix.py", "cleanup-smb-phases.yaml", 6),
    "companions": ("cleanup_supplement_matrix.py", "cleanup-process-companions.yaml", 6),
}

ADDITIONAL_BASELINES = {
    "system": "pass4-baseline-system",
    "network": "pass4-baseline-network",
    "smb": "pass4-baseline-smb-v2",
    "cli": "pass4-baseline-cli",
    "companions": "pass4-baseline-companions-v2",
}


def main() -> None:
    """Capture new evidence, checking raw bytes and manifest-listed actual hashes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--previous-prefix")
    parser.add_argument("--groups", nargs="+", choices=tuple(GROUPS), default=list(GROUPS))
    args = parser.parse_args()
    scripts = Path(__file__).resolve().parent
    comparisons: list[dict[str, object]] = []
    measurements: dict[str, float] = {}
    for group in args.groups:
        driver, fixture, expected_count = GROUPS[group]
        reference = args.root / ADDITIONAL_BASELINES.get(group, f"pass3-final-{group}")
        output = args.root / f"{args.prefix}-{group}"
        if output.exists():
            raise ValueError(f"Refusing to overwrite capture: {output}")
        command = [
            sys.executable,
            str(scripts / driver),
            "--source",
            str(args.source.resolve()),
            "--output",
            str(output),
            "--baseline",
            str(reference),
        ]
        if group == "core":
            command.extend(["--fixtures", str(scripts.parent / "tests/fixtures/scenarios")])
        if group == "cli":
            command.extend(
                [
                    "--fixture",
                    str(scripts.parent / "tests/fixtures/scenarios/checkpoint-all-formats.yaml"),
                ]
            )
        if fixture:
            command.extend(["--fixture", str(scripts / "fixtures" / fixture)])
        started = time.perf_counter()
        with (args.root / f"{args.prefix}-{group}.log").open("x") as stream:
            subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, check=True)
        measurements[group] = time.perf_counter() - started
        cases = sorted(path.name for path in output.iterdir() if path.is_dir())
        if len(cases) != expected_count:
            raise ValueError(f"Incomplete {group}: expected {expected_count}, found {len(cases)}")
        for case in cases:
            actual = snapshot(output / case)
            if not actual or actual != snapshot(reference / case):
                raise ValueError(f"Baseline difference: {group}/{case}")
            if args.previous_prefix:
                previous = args.root / f"{args.previous_prefix}-{group}" / case
                if actual != snapshot(previous):
                    raise ValueError(f"Previous-item difference: {group}/{case}")
            comparisons.append({"group": group, "case": case, "file_hashes": actual})
        print(f"PASS {group}: {len(cases)} raw-byte cases", flush=True)
    report = {
        "baseline_commit": "26a150ac4d807b1b00e6d7c02019837132447dc1",
        "prefix": args.prefix,
        "previous_prefix": args.previous_prefix,
        "comparison_policy": "Raw evidence bytes; established diagnostic/provenance exceptions only",
        "comparisons": comparisons,
        "group_elapsed_seconds_including_comparison": measurements,
        "input_index_sha256": hashlib.sha256(
            (scripts / "fixtures/cleanup-inputs.json").read_bytes()
        ).hexdigest(),
    }
    with (args.root / f"{args.prefix}-report.json").open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
