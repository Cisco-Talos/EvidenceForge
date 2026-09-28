"""Detached local CLI jobs for the desktop prototype."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import psutil

from evidenceforge.desktop.state import GenerationJob


def _eforge_command() -> list[str]:
    """Use the installed interpreter during development or an explicit packaged CLI."""
    configured = os.environ.get("EFORGE_DESKTOP_EFORGE_BIN")
    if configured:
        return [str(Path(configured).expanduser().resolve())]
    if getattr(sys, "frozen", False):
        executable = shutil.which("eforge")
        if executable is None:
            raise FileNotFoundError("Set EFORGE_DESKTOP_EFORGE_BIN to a packaged eforge CLI")
        return [executable]
    return [sys.executable, "-m", "evidenceforge"]


def _start_process(command: list[str], *, cwd: Path, log_file: Path) -> tuple[int, float]:
    """Start a job that remains alive when the desktop window closes."""
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("ab") as log_stream:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=log_stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    try:
        created_at = psutil.Process(process.pid).create_time()
    except psutil.NoSuchProcess:
        created_at = time.time()
    return process.pid, created_at


def start_generation(
    scenario: Path,
    workspace: Path,
    state_directory: Path,
    output_parent: Path | None = None,
) -> GenerationJob:
    """Start a new output bundle beneath the selected destination."""
    scenario = scenario.resolve()
    workspace = workspace.resolve()
    if not scenario.is_file():
        raise FileNotFoundError(f"Scenario file does not exist: {scenario}")
    job_id = uuid4().hex
    label = datetime.now().strftime("%Y%m%d-%H%M%S")
    destination = (output_parent or workspace / "runs").expanduser().resolve()
    output_root = destination / scenario.stem / f"{label}-{job_id[:8]}"
    output_root.mkdir(parents=True, exist_ok=False)
    job_files = state_directory / "jobs"
    job_files.mkdir(parents=True, exist_ok=True)
    progress_file = job_files / f"{job_id}.jsonl"
    log_file = job_files / f"{job_id}.log"
    command = [
        *_eforge_command(),
        "generate",
        str(scenario),
        "--project-root",
        str(workspace),
        "--output",
        str(output_root),
        "--progress-jsonl",
        str(progress_file),
    ]
    pid, created_at = _start_process(command, cwd=workspace, log_file=log_file)
    return GenerationJob(
        id=job_id,
        scenario=scenario,
        output_root=output_root,
        progress_file=progress_file,
        log_file=log_file,
        pid=pid,
        process_created_at=created_at,
        started_at=time.time(),
    )


def resume_generation(job: GenerationJob, workspace: Path, state_directory: Path) -> None:
    """Resume a checkpointed run while retaining its bundle and library identity."""
    if process_running(job):
        raise RuntimeError("Generation is still running")
    progress_file = state_directory / "jobs" / f"{job.id}-resume-{uuid4().hex[:8]}.jsonl"
    command = [
        *_eforge_command(),
        "generate",
        "--project-root",
        str(workspace.resolve()),
        "--output",
        str(job.output_root),
        "--resume",
        "--progress-jsonl",
        str(progress_file),
    ]
    pid, created_at = _start_process(command, cwd=workspace.resolve(), log_file=job.log_file)
    job.pid = pid
    job.process_created_at = created_at
    job.progress_file = progress_file
    job.started_at = time.time()
    job.status = "running"


def process_running(job: GenerationJob) -> bool:
    """Check both PID and creation time so a recycled PID cannot claim a job."""
    try:
        process = psutil.Process(job.pid)
        return (
            abs(process.create_time() - job.process_created_at) < 2
            and process.is_running()
            and process.status() != psutil.STATUS_ZOMBIE
        )
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def refresh_status(job: GenerationJob) -> bool:
    """Reconcile a detached job after a desktop restart."""
    if job.status != "running" or process_running(job):
        return False
    manifest = job.output_root / "GENERATION_MANIFEST.json"
    job.status = "completed" if manifest.is_file() else "stopped"
    return True


def request_suspension(job: GenerationJob, workspace: Path) -> subprocess.CompletedProcess[str]:
    """Ask the CLI to stop after its current simulated hour and checkpoint."""
    return subprocess.run(
        [*_eforge_command(), "checkpoint", "suspend", str(job.output_root)],
        cwd=workspace.resolve(),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
