"""Run the fixed cross-build cleanup evidence matrix in fresh Python processes."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def cases() -> list[tuple[str, int, str, bool, bool]]:
    """Return fixed coverage cases; both baseline and candidates use this inventory."""
    result = [
        (fixture, seed, "default", False, False)
        for fixture in (
            "minimal",
            "full-coverage-apt",
            "smb-resource-calibration",
            "smb-linux-matrix",
        )
        for seed in (42, 137)
    ]
    result.extend(
        ("checkpoint-all-formats", seed, target, serial, filtered)
        for seed in (42, 137)
        for target in ("default", "sof-elk", "splunk")
        for serial in (False, True)
        for filtered in (False, True)
    )
    return result


def main() -> None:
    """Capture every case, optionally checking an immutable baseline immediately."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--case", help="Run only the exact named case")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    harness = Path(__file__).with_name("compare_cleanup_output.py")
    for fixture, seed, target, serial, filtered in cases():
        name = f"{fixture}-{seed}-{target}-{'serial' if serial else 'threaded'}"
        name += "-filtered" if filtered else "-full"
        if args.case and name != args.case:
            continue
        destination = args.output / name
        command = [
            sys.executable,
            str(harness),
            "capture",
            "--source",
            str(args.source),
            "--fixture",
            str(args.fixtures / f"{fixture}.yaml"),
            "--seed",
            str(seed),
            "--target",
            target,
            "--output",
            str(destination),
        ]
        if serial:
            command.append("--serial")
        if filtered:
            command.append("--filtered")
        print(f"START {name}", flush=True)
        with (args.output / f"{name}.log").open("w") as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
        if args.baseline:
            subprocess.run(
                [
                    sys.executable,
                    str(harness),
                    "compare",
                    str(args.baseline / name),
                    str(destination),
                ],
                check=True,
            )
        print(f"PASS {name}", flush=True)


if __name__ == "__main__":
    main()
