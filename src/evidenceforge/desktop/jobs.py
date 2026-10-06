"""Detached local CLI workers shared by EvidenceForge Studio."""

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

from evidenceforge.desktop.state import AppSettings, EvaluationJob, GenerationJob
from evidenceforge.studio.runtime import command_environment, runtime_root

_detached_processes: list[subprocess.Popen[bytes]] = []


def _eforge_command(settings: AppSettings | None = None) -> list[str]:
    """Use the installed interpreter during development or an explicit packaged CLI."""
    configured = os.environ.get("EFORGE_DESKTOP_EFORGE_BIN")
    if configured:
        return [str(Path(configured).expanduser().resolve())]
    if settings is not None and settings.eforge_path is not None:
        return [str(settings.eforge_path.expanduser().resolve())]
    if getattr(sys, "frozen", False):
        executable = shutil.which("eforge")
        if executable is None:
            raise FileNotFoundError("Set EFORGE_DESKTOP_EFORGE_BIN to a packaged eforge CLI")
        return [executable]
    options = ["-I", "-B"] if runtime_root() is not None else []
    return [sys.executable, *options, "-m", "evidenceforge"]


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
            env=command_environment(),
        )
    _detached_processes[:] = [running for running in _detached_processes if running.poll() is None]
    _detached_processes.append(process)
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
        submitted_at=time.time(),
        workspace=workspace,
        command=command,
        owned_output=True,
    )


def queue_generation(
    scenario: Path,
    workspace: Path,
    state_directory: Path,
    output_parent: Path | None = None,
    *,
    settings: AppSettings | None = None,
    checkpoint_hours: int = 24,
) -> GenerationJob:
    """Record a generation that the detached controller will launch."""
    scenario = scenario.resolve()
    workspace = workspace.resolve()
    if not scenario.is_file():
        raise FileNotFoundError(f"Scenario file does not exist: {scenario}")
    if settings is not None and settings.close_action == "pause" and checkpoint_hours == 0:
        raise ValueError("Checkpoint and pause requires checkpointing to be enabled")
    job_id = uuid4().hex
    label = datetime.now().strftime("%Y%m%d-%H%M%S")
    destination = (output_parent or workspace / "runs").expanduser().resolve()
    output_root = destination / scenario.stem / f"{label}-{job_id[:8]}"
    output_root.mkdir(parents=True, exist_ok=False)
    (output_root / ".eforge-desktop-job.json").write_text(
        f'{{"job_id":"{job_id}"}}\n', encoding="utf-8"
    )
    job_files = state_directory / "jobs"
    command = [
        *_eforge_command(settings),
        "generate",
        str(scenario),
        "--project-root",
        str(workspace),
        "--output",
        str(output_root),
        "--checkpoint-hours",
        str(checkpoint_hours),
        "--progress-jsonl",
        str(job_files / f"{job_id}.jsonl"),
    ]
    return GenerationJob(
        id=job_id,
        scenario=scenario,
        output_root=output_root,
        progress_file=job_files / f"{job_id}.jsonl",
        log_file=job_files / f"{job_id}.log",
        started_at=time.time(),
        submitted_at=time.time(),
        status="queued",
        workspace=workspace,
        command=command,
        checkpoint_hours=checkpoint_hours,
        owned_output=True,
    )


def queue_evaluation(
    generation: GenerationJob, state_directory: Path, *, settings: AppSettings | None = None
) -> EvaluationJob:
    """Record an evaluation of a completed app-owned run."""
    job_id = uuid4().hex
    workspace = generation.workspace or generation.scenario.parent
    return EvaluationJob(
        id=job_id,
        generation_id=generation.id,
        workspace=workspace,
        output_root=generation.output_root,
        result_file=state_directory / "jobs" / f"{job_id}.json",
        log_file=state_directory / "jobs" / f"{job_id}.log",
        command=[
            *_eforge_command(settings),
            "eval",
            str(generation.output_root),
            "--format",
            "json",
        ],
        created_at=time.time(),
    )


def resume_generation(job: GenerationJob, workspace: Path, state_directory: Path) -> None:
    """Resume a checkpointed run while retaining its bundle and library identity."""
    if process_running(job):
        raise RuntimeError("Generation is still running")
    from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore

    checkpoint = IncrementalCheckpointStore(job.output_root)
    if not checkpoint.recovery_index_entries(read_only=True):
        raise RuntimeError("No recovery checkpoint exists for this run; inspect its partial files")
    progress_file = state_directory / "jobs" / f"{job.id}-resume-{uuid4().hex[:8]}.jsonl"
    command_prefix = (
        job.command[: job.command.index("generate")]
        if "generate" in job.command
        else _eforge_command()
    )
    command = [
        *command_prefix,
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
    job.progress_history.append(job.progress_file)
    job.progress_file = progress_file
    job.started_at = time.time()
    job.status = "running"
    job.status_message = ""


def process_running(job: GenerationJob) -> bool:
    """Check both PID and creation time so a recycled PID cannot claim a job."""
    if job.pid <= 0:
        return False
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
    command_prefix = (
        job.command[: job.command.index("generate")]
        if "generate" in job.command
        else _eforge_command()
    )
    return subprocess.run(
        [*command_prefix, "checkpoint", "suspend", str(job.output_root)],
        cwd=workspace.resolve(),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
