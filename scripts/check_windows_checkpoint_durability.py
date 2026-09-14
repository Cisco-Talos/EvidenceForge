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

import psutil


def _stop_process_tree(process: subprocess.Popen) -> None:
    """Bound cleanup of pytest and any CLI children if the overall gate times out."""
    try:
        children = psutil.Process(process.pid).children(recursive=True)
    except psutil.NoSuchProcess:
        children = []
    if process.poll() is None:
        process.kill()
    for child in children:
        try:
            child.kill()
        except psutil.NoSuchProcess:
            pass
    process.wait(timeout=30)
    _gone, alive = psutil.wait_procs(children, timeout=30)
    if alive:
        raise RuntimeError(
            f"Durability test children did not exit: {[child.pid for child in alive]}"
        )


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
    print((artifacts / "host.json").read_text(encoding="utf-8"), flush=True)
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
                _stop_process_tree(process)
            process.wait(timeout=30)
            log.seek(0)
            print(log.read().decode("utf-8", errors="replace"))
    if process.returncode:
        raise SystemExit(process.returncode)
    cases = ET.parse(report).getroot().findall(".//testcase")
    if len(cases) < 4 or any(case.find("skipped") is not None for case in cases):
        raise SystemExit("Windows durability gate did not execute every required test")
    for summary in sorted((artifacts / "cases").rglob("matrix-summary.json")):
        print(f"Crash matrix: {summary.read_text(encoding='utf-8')}")
    for trace in sorted((artifacts / "cases").rglob("cli-trace.jsonl")):
        for line in trace.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            if event["operation"] == "ack":
                print(
                    f"CLI checkpoint {event['sequence']}: "
                    f"{event['elapsed_seconds']:.3f}s publication"
                )
    print(
        f"Windows checkpoint durability passed: {len(cases)} tests in {time.monotonic() - started:.2f}s"
    )


if __name__ == "__main__":
    main()
