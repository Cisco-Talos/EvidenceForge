"""Shared fresh-process runner for fixed native evidence and lifecycle contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from compare_cleanup_output import snapshot


def run_matrix(*, driver: Path, cases: tuple[str, ...], description: str) -> None:
    """Run all fixed cases without modifying prior captures."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    inputs = json.loads(
        (Path(__file__).parent / "fixtures" / "cleanup-native-inputs.json").read_text()
    )
    if hashlib.sha256(driver.read_bytes()).hexdigest() != inputs[driver.name]:
        raise ValueError(f"Frozen native input changed: {driver.name}")
    args.output.mkdir(parents=True, exist_ok=False)
    for seed in (42, 137):
        for case in cases:
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
                    raise ValueError(f"Native evidence differs: {name}")
                print(f"PASS {name}", flush=True)
