"""Compare public CLI generation with full and narrowed frozen format selections."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from compare_cleanup_output import snapshot


def main() -> None:
    """Capture CLI bundles without replacing inputs or accepting evidence differences."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    inputs = json.loads((Path(__file__).parent / "fixtures/cleanup-inputs.json").read_text())
    if hashlib.sha256(args.fixture.read_bytes()).hexdigest() != inputs.get(args.fixture.name):
        raise ValueError("CLI input is not frozen")
    args.output.mkdir(parents=True, exist_ok=False)
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(args.source.resolve() / "src")
    for seed in (42, 137):
        for target in ("default", "sof-elk", "splunk"):
            name = f"cli-{seed}-{target}"
            output = args.output / name
            command = [
                sys.executable,
                "-m",
                "evidenceforge",
                "generate",
                str(args.fixture.resolve()),
                "--output",
                str(output.resolve()),
                "--seed",
                str(seed),
                "--target",
                target,
                "--checkpoint-hours",
                "0",
            ]
            if seed == 137:
                command.extend(["--formats", "zeek"])
            with (args.output / f"{name}.log").open("x") as log:
                subprocess.run(
                    command, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True
                )
            actual = snapshot(output)
            if not actual or (args.baseline and actual != snapshot(args.baseline / name)):
                raise ValueError(f"CLI evidence differs: {name}")
            (args.output / f"{name}.hashes.json").write_text(
                json.dumps(actual, indent=2, sort_keys=True) + "\n"
            )
            print(f"PASS {name}: {len(actual)} artifacts", flush=True)


if __name__ == "__main__":
    main()
