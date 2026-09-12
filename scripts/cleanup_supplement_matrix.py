"""Compare the frozen bounded typed-handler fixture across seeds and output targets."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main() -> None:
    """Capture immutable cases and optionally compare their raw evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    harness = Path(__file__).with_name("compare_cleanup_output.py")
    fixture = Path(__file__).parent / "fixtures" / "cleanup-typed-handlers.yaml"
    for seed in (42, 137):
        for target in ("default", "sof-elk", "splunk"):
            name = f"typed-handlers-{seed}-{target}"
            destination = args.output / name
            with (args.output / f"{name}.log").open("w") as log:
                subprocess.run(
                    [
                        sys.executable,
                        str(harness),
                        "capture",
                        "--source",
                        str(args.source),
                        "--fixture",
                        str(fixture.resolve()),
                        "--output",
                        str(destination),
                        "--seed",
                        str(seed),
                        "--target",
                        target,
                    ],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    check=True,
                )
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
