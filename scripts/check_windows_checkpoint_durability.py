"""Run the focused native durability gate and retain reproducible CI diagnostics."""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path


def main() -> None:
    """Fail on errors, timeouts, empty collection, or skipped Windows durability tests."""
    if os.name != "nt":
        raise SystemExit("The Windows durability gate requires native Windows Python")
    from evidenceforge.utils import windows_filesystem as filesystem

    artifacts = Path(".artifacts/windows-checkpoint-durability").resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    descriptor = filesystem.open_directory(artifacts)
    os.close(descriptor)  # also validates that CI storage is fixed, local NTFS
    (artifacts / "host.json").write_text(
        json.dumps(
            {
                "platform": platform.platform(),
                "python": sys.version,
                "filesystem": "fixed local NTFS (validated through native handle)",
                "artifact_root": str(artifacts),
                "runner_os": os.environ.get("RUNNER_OS"),
                "image_os": os.environ.get("ImageOS"),
                "image_version": os.environ.get("ImageVersion"),
                "commit": os.environ.get("GITHUB_SHA"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    report = artifacts / "results.xml"
    started = time.monotonic()
    command = [
        sys.executable,
        "-m",
        "pytest",
        "tests/integration/test_windows_checkpoint_durability.py",
        "-m",
        "slow",
        "--no-cov",
        "--durations=20",
        "--basetemp",
        str(artifacts / "cases"),
        "--junitxml",
        str(report),
    ]
    with (artifacts / "pytest.log").open("w+b") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        try:
            process.wait(timeout=1000)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=30)
            log.seek(0)
            print(log.read().decode("utf-8", errors="replace"))
    if process.returncode:
        raise SystemExit(process.returncode)
    cases = ET.parse(report).getroot().findall(".//testcase")
    if len(cases) < 4 or any(case.find("skipped") is not None for case in cases):
        raise SystemExit("Windows durability gate did not execute every required test")
    print(
        f"Windows checkpoint durability passed: {len(cases)} tests in {time.monotonic() - started:.2f}s"
    )


if __name__ == "__main__":
    main()
