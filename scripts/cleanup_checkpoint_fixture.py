"""Preserve an original-build checkpoint using the public suspension protocol."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

from evidenceforge.generation.checkpoints.control import request_suspension
from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore


def main() -> None:
    """Suspend a selected build at its first durable completed-hour boundary."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", choices=("default", "sof-elk", "splunk"), required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Checkpoint destination must be new")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(args.source.resolve() / "src")
    command = [
        sys.executable,
        "-m",
        "evidenceforge",
        "generate",
        str(args.fixture.resolve()),
        "--output",
        str(args.output.resolve()),
        "--target",
        args.target,
        "--seed",
        str(args.seed),
        "--checkpoint-hours",
        "1",
    ]
    with args.output.with_suffix(".log").open("w") as log:
        process = subprocess.Popen(
            command,
            cwd=args.output.parent,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            controller = args.output / ".eforge-generation" / "controller.json"
            deadline = time.monotonic() + 120
            while not controller.exists() and process.poll() is None:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Generation did not expose checkpoint control")
                time.sleep(0.05)
            if not controller.exists():
                raise RuntimeError(f"Generation exited before suspension: {process.poll()}")
            request_suspension(IncrementalCheckpointStore(args.output))
            if process.wait(timeout=300) != 0:
                raise RuntimeError("Generation failed while suspending; inspect fixture log")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=30)
    if not (args.output / ".eforge-generation" / "CURRENT.json").is_file():
        raise RuntimeError("Generation did not retain a durable checkpoint")
    print(f"Preserved {args.target} seed {args.seed} checkpoint at {args.output}")


if __name__ == "__main__":
    main()
