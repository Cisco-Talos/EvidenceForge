"""Exercise original-build and exact same-build resume across the frozen checkpoint matrix."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def run(arguments: list[str], log: Path, *, environment: dict[str, str] | None = None) -> None:
    """Run one gate with its complete diagnostic output retained outside evidence."""
    with log.open("w") as stream:
        subprocess.run(
            arguments,
            env=environment,
            cwd=log.parent,
            stdout=stream,
            stderr=subprocess.STDOUT,
            check=True,
        )


def main() -> None:
    """Keep originals intact and exercise each resume policy on a fresh copy."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--baseline-source", type=Path, required=True)
    parser.add_argument(
        "--control-source",
        type=Path,
        help="Uninterrupted reference build; defaults to baseline-source. Use the accepted correction for semantic fixes.",
    )
    parser.add_argument("--original-checkpoints", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    scripts = Path(__file__).resolve().parent
    fixture = args.baseline_source / "tests/fixtures/scenarios/checkpoint-all-formats.yaml"
    environment = os.environ.copy()
    control_source = args.control_source or args.baseline_source
    environment["PYTHONPATH"] = str(control_source.resolve() / "src")
    environment["TMPDIR"] = str(args.output.resolve())
    for target in ("default", "sof-elk", "splunk"):
        for seed in (42, 137):
            name = f"{target}-{seed}"
            control = args.output / f"control-{name}"
            run(
                [
                    sys.executable,
                    "-m",
                    "evidenceforge",
                    "generate",
                    str(fixture),
                    "--output",
                    str(control),
                    "--seed",
                    str(seed),
                    "--target",
                    target,
                    "--checkpoint-hours",
                    "0",
                ],
                args.output / f"control-{name}.log",
                environment=environment,
            )
            run(
                [
                    sys.executable,
                    str(scripts / "verify_cleanup_resume.py"),
                    "--source",
                    str(args.source),
                    "--checkpoint",
                    str(args.original_checkpoints / name),
                    "--control",
                    str(control),
                    "--output",
                    str(args.output / f"compatible-{name}"),
                ],
                args.output / f"compatible-{name}.log",
            )
            print(
                f"PASS original checkpoint / exact rejection / compatible resume: {name}",
                flush=True,
            )
            checkpoint = args.output / f"same-build-checkpoint-{name}"
            run(
                [
                    sys.executable,
                    str(scripts / "cleanup_checkpoint_fixture.py"),
                    "--source",
                    str(args.source),
                    "--fixture",
                    str(fixture),
                    "--output",
                    str(checkpoint),
                    "--target",
                    target,
                    "--seed",
                    str(seed),
                ],
                args.output / f"same-build-capture-{name}.log",
            )
            run(
                [
                    sys.executable,
                    str(scripts / "verify_cleanup_resume.py"),
                    "--source",
                    str(args.source),
                    "--checkpoint",
                    str(checkpoint),
                    "--control",
                    str(control),
                    "--output",
                    str(args.output / f"exact-{name}"),
                    "--same-build",
                ],
                args.output / f"exact-{name}.log",
            )
            print(f"PASS same-build exact resume: {name}", flush=True)


if __name__ == "__main__":
    main()
