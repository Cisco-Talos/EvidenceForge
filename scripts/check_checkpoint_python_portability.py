"""Release-slow checkpoint portability check across Python 3.12 and 3.13."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from evidenceforge.composition.artifacts import verify_generation_bundle
from evidenceforge.generation.checkpoints.control import request_suspension
from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore


def _run_resuming_side(bundle: Path) -> None:
    verified = subprocess.run(
        [sys.executable, "-m", "evidenceforge", "checkpoint", "verify", str(bundle), "--json"],
        check=False,
        capture_output=True,
        text=True,
        timeout=90,
    )
    if verified.returncode != 0:
        raise SystemExit(verified.stdout + verified.stderr)
    report = json.loads(verified.stdout)
    if report["loadability"] != "verified" or "python" not in report["runtime_differences"]:
        raise SystemExit(f"Python drift did not reach full hydration: {report}")
    resumed = subprocess.run(
        [sys.executable, "-m", "evidenceforge", "generate", "--output", str(bundle), "--resume"],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if resumed.returncode != 0:
        raise SystemExit(resumed.stdout + resumed.stderr)
    manifest = json.loads((bundle / "GENERATION_MANIFEST.json").read_text(encoding="utf-8"))
    verify_generation_bundle(bundle)
    if manifest["resume_provenance"]["migration_count"] != 1:
        raise SystemExit("final manifest omitted the same-cursor migration lineage")
    transition = manifest["resume_provenance"]["transitions"][-1]
    if "python" not in transition["runtime_differences"]:
        raise SystemExit("final manifest omitted Python runtime drift provenance")


def _create_under_python_312(repository: Path, bundle: Path, scenario: Path) -> None:
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            str(scenario),
            "--output",
            str(bundle),
            "--checkpoint-hours",
            "1",
            "--overwrite",
        ],
        cwd=repository,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    controller = bundle / ".eforge-generation" / "controller.json"
    deadline = time.monotonic() + 30
    while not controller.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    if not controller.exists():
        output, _ = process.communicate(timeout=30)
        raise SystemExit(f"Python 3.12 generation did not expose checkpoint control:\n{output}")
    request_suspension(IncrementalCheckpointStore(bundle))
    output, _ = process.communicate(timeout=90)
    if process.returncode != 0 or not (bundle / ".eforge-generation" / "CURRENT.json").is_file():
        raise SystemExit(f"Python 3.12 generation did not suspend recoverably:\n{output}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume", type=Path)
    arguments = parser.parse_args()
    if arguments.resume is not None:
        _run_resuming_side(arguments.resume)
        return
    if sys.version_info[:2] != (3, 12):
        raise SystemExit("portability fixture creation must run under Python 3.12")
    repository = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="eforge-python-portability-") as temporary:
        root = Path(temporary).resolve()
        scenario = root / "scenario.yaml"
        scenario.write_text(
            (repository / "tests/fixtures/scenarios/minimal.yaml")
            .read_text(encoding="utf-8")
            .replace('duration: "1h"', 'duration: "3h"'),
            encoding="utf-8",
        )
        bundle = root / "bundle"
        _create_under_python_312(repository, bundle, scenario)
        resumed = subprocess.run(
            [
                "uv",
                "run",
                "--python",
                "3.13",
                "--isolated",
                "python",
                str(Path(__file__).resolve()),
                "--resume",
                str(bundle),
            ],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
            timeout=240,
        )
        if resumed.returncode != 0:
            raise SystemExit(resumed.stdout + resumed.stderr)
    print("Python 3.12 -> 3.13 checkpoint verify/resume portability passed")


if __name__ == "__main__":
    main()
