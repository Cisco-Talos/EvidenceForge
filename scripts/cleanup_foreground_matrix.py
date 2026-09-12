"""Capture native foreground contract cases in fresh processes and compare raw bytes."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from cleanup_foreground_contract import CASES
from compare_cleanup_output import snapshot


def main() -> None:
    """Run all fixed cases without modifying prior captures."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    driver = Path(__file__).with_name("cleanup_foreground_contract.py")
    for seed in (42, 137):
        for case in CASES:
            for threaded in (False, True):
                name = f"{case}-{seed}-{'threaded' if threaded else 'serial'}"
                output = args.output / name
                command = [
                    sys.executable,
                    str(driver),
                    "--source",
                    str(args.source),
                    "--output",
                    str(output),
                    "--seed",
                    str(seed),
                    "--case",
                    case,
                ]
                if threaded:
                    command.append("--threaded")
                with (args.output / f"{name}.log").open("w") as log:
                    subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
                if args.baseline and snapshot(args.baseline / name) != snapshot(output):
                    raise ValueError(f"Foreground evidence differs: {name}")
                print(f"PASS {name}", flush=True)


if __name__ == "__main__":
    main()
