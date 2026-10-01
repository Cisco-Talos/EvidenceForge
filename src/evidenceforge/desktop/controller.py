"""Detached, local controller for desktop-owned generation and evaluation jobs."""

from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Protocol

import psutil

from evidenceforge.desktop.job_store import ControlIntent, JobStore
from evidenceforge.desktop.jobs import _start_process, request_suspension, resume_generation
from evidenceforge.desktop.state import EvaluationJob, GenerationJob
from evidenceforge.evaluation.models import QualityReport
from evidenceforge.generation.checkpoints.control import read_suspension_record
from evidenceforge.generation.checkpoints.errors import CheckpointError
from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore

logger = logging.getLogger(__name__)
_controller_processes: list[subprocess.Popen[bytes]] = []
_evaluation_processes: list[subprocess.Popen[bytes]] = []
_PROCESS_START_TOLERANCE_SECONDS = 0.01


class ProcessRecord(Protocol):
    """Fields required to verify ownership of a local process."""

    pid: int
    process_created_at: float


def _running(job: ProcessRecord) -> bool:
    if job.pid <= 0:
        return False
    try:
        process = psutil.Process(job.pid)
        return (
            abs(process.create_time() - job.process_created_at) < _PROCESS_START_TOLERANCE_SECONDS
            and process.is_running()
            and process.status() != psutil.STATUS_ZOMBIE
        )
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def _terminate_owned(job: ProcessRecord) -> None:
    """Terminate a verified app-owned process group or standalone process."""
    if not _running(job):
        return
    try:
        parent = psutil.Process(job.pid)
        owns_group = os.name == "posix" and os.getpgid(job.pid) == job.pid
    except (OSError, psutil.NoSuchProcess, psutil.AccessDenied):
        return
    if not _running(job):
        return
    try:
        if owns_group:
            os.killpg(job.pid, signal.SIGTERM)
        else:
            parent.terminate()
    except (OSError, psutil.NoSuchProcess, psutil.AccessDenied):
        return
    if owns_group:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.killpg(job.pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.05)
        try:
            os.killpg(job.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return
    try:
        parent.wait(timeout=2)
    except psutil.TimeoutExpired:
        if _running(job):
            try:
                parent.kill()
            except (OSError, psutil.NoSuchProcess, psutil.AccessDenied):
                pass


def _delete_owned_incomplete(job: GenerationJob) -> bool:
    """Delete only a marked incomplete bundle owned by this exact GUI job."""
    root = job.output_root
    marker = root / ".eforge-desktop-job.json"
    if not job.owned_output or root.is_symlink() or not root.is_dir():
        return False
    if (root / "GENERATION_MANIFEST.json").exists() or marker.is_symlink() or not marker.is_file():
        return False
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if payload.get("job_id") != job.id or _running(job):
        return False
    shutil.rmtree(root)
    return True


def _delete_owned_complete(job: GenerationJob) -> bool:
    """Delete a finished bundle only when its marker proves this GUI job owns it."""
    root = job.output_root
    marker = root / ".eforge-desktop-job.json"
    manifest = root / "GENERATION_MANIFEST.json"
    if not job.owned_output or root.is_symlink() or not root.is_dir():
        return False
    if (
        marker.is_symlink()
        or manifest.is_symlink()
        or not marker.is_file()
        or not manifest.is_file()
    ):
        return False
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if payload.get("job_id") != job.id or _running(job):
        return False
    shutil.rmtree(root)
    return True


def _start_evaluation(job: EvaluationJob) -> None:
    job.result_file.parent.mkdir(parents=True, exist_ok=True)
    with job.result_file.open("wb") as output, job.log_file.open("ab") as errors:
        process = subprocess.Popen(
            job.command,
            cwd=job.workspace,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=errors,
            start_new_session=True,
        )
    _evaluation_processes[:] = [
        running for running in _evaluation_processes if running.poll() is None
    ]
    _evaluation_processes.append(process)
    job.pid = process.pid
    try:
        job.process_created_at = psutil.Process(process.pid).create_time()
    except psutil.NoSuchProcess:
        job.process_created_at = time.time()
    job.status = "running"
    job.status_message = ""


def _finish_evaluation(job: EvaluationJob, store: JobStore) -> None:
    try:
        report = QualityReport.model_validate_json(job.result_file.read_text(encoding="utf-8"))
        destination = store.directory / "evaluations" / f"{job.generation_id}.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(".json.tmp")
        temporary.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        os.replace(temporary, destination)
        job.status = "completed"
        job.status_message = ""
    except (OSError, UnicodeError, ValueError) as error:
        job.status = "failed"
        job.status_message = str(error)[:500]


def _worker_tick(store: JobStore, intent: ControlIntent) -> bool:
    """Apply one durable control intent and reconcile every owned job."""
    changed = False
    generations = store.load_generations()
    evaluations = store.load_evaluations()
    running_generations = sum(job.status == "running" and _running(job) for job in generations)
    action = intent.action
    for job in generations:
        previous = job.model_dump()
        if job.status == "running" and not _running(job):
            if (job.output_root / "GENERATION_MANIFEST.json").is_file():
                job.status = "completed"
            elif job.status_message == "Pause requested":
                checkpoint = IncrementalCheckpointStore(job.output_root)
                try:
                    suspended = read_suspension_record(checkpoint)
                    recoveries = checkpoint.recovery_index_entries(read_only=True)
                except CheckpointError:
                    suspended = None
                    recoveries = ()
                if suspended is not None and recoveries:
                    job.status = "paused"
                    job.status_message = ""
                else:
                    job.status = "stopped"
                    job.status_message = (
                        "Generation stopped before a resumable checkpoint was saved"
                    )
            else:
                job.status = "stopped"
        if action == "kill":
            if job.status == "running":
                _terminate_owned(job)
                job.status = "stopped"
            elif job.status in {"queued", "paused"}:
                job.status = "cancelled"
            if intent.settings.kill_incomplete_bundles == "delete":
                try:
                    _delete_owned_incomplete(job)
                except OSError as error:
                    job.status_message = f"Could not remove incomplete bundle: {error}"
        elif action == "pause":
            exception = intent.generation_exceptions.get(job.id)
            if exception == "continue":
                pass
            elif exception == "stop":
                if job.status == "running":
                    _terminate_owned(job)
                    job.status = "stopped"
                elif job.status == "queued":
                    job.status = "cancelled"
            elif job.status == "queued":
                job.status = "paused"
            elif (
                job.status == "running"
                and job.status_message != "Pause requested"
                and not job.status_message.startswith("Pause request failed")
            ):
                if job.checkpoint_hours == 0:
                    job.status_message = "Cannot checkpoint: this job has checkpointing disabled"
                else:
                    try:
                        result = request_suspension(job, job.workspace or job.scenario.parent)
                        job.status_message = (
                            "Pause requested"
                            if result.returncode == 0
                            else f"Pause request failed: {(result.stderr or result.stdout)[-350:]}"
                        )
                    except (OSError, subprocess.TimeoutExpired) as error:
                        job.status_message = f"Pause request failed: {error}"
        elif action in {"open", "resume", "continue"}:
            selected = intent.resume_generation_id is None or job.id == intent.resume_generation_id
            can_start = action != "continue" or intent.settings.continue_queued_generations
            if (
                job.status == "queued"
                and can_start
                and running_generations < intent.settings.max_concurrent_generations
            ):
                try:
                    job.pid, job.process_created_at = _start_process(
                        job.command,
                        cwd=job.workspace or job.scenario.parent,
                        log_file=job.log_file,
                    )
                    job.status = "running"
                    job.status_message = ""
                    running_generations += 1
                except (OSError, ValueError) as error:
                    job.status = "failed"
                    job.status_message = str(error)[:500]
            elif job.status in {"paused", "stopped"} and action == "resume" and selected:
                if job.pid == 0 and not (job.output_root / ".eforge-generation").exists():
                    job.status = "queued"
                else:
                    try:
                        resume_generation(
                            job, job.workspace or job.scenario.parent, store.directory
                        )
                    except (OSError, RuntimeError, ValueError, CheckpointError) as error:
                        job.status_message = f"Resume failed: {error}"
        if job.model_dump() != previous:
            store.save_generation(job)
            changed = True
    for job in evaluations:
        previous = job.model_dump()
        if job.status == "running" and not _running(job):
            _finish_evaluation(job, store)
        if action == "kill":
            if job.status == "running":
                _terminate_owned(job)
            if job.status in {"running", "queued", "paused"}:
                job.status = "cancelled"
        elif action == "pause":
            if job.status == "running" and intent.settings.pause_evaluations == "restart":
                _terminate_owned(job)
                job.status = "paused"
            elif job.status == "queued":
                job.status = "paused"
        elif action == "continue":
            policy = intent.settings.continue_evaluations
            if policy != "continue" and job.status == "running":
                _terminate_owned(job)
                job.status = "paused" if policy == "hold" else "cancelled"
            elif policy != "continue" and job.status == "queued":
                job.status = "paused" if policy == "hold" else "cancelled"
            elif job.status == "queued":
                try:
                    _start_evaluation(job)
                except OSError as error:
                    job.status = "failed"
                    job.status_message = str(error)[:500]
        elif action in {"open", "resume"}:
            if job.status == "paused" and (action == "open" or intent.resume_generation_id is None):
                job.status = "queued"
            if job.status == "queued":
                try:
                    _start_evaluation(job)
                except OSError as error:
                    job.status = "failed"
                    job.status_message = str(error)[:500]
        if job.model_dump() != previous:
            store.save_evaluation(job)
            changed = True
    return changed


def _lock_is_live(path: Path) -> bool:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        process = psutil.Process(int(payload["pid"]))
        return (
            abs(process.create_time() - float(payload["created_at"]))
            < _PROCESS_START_TOLERANCE_SECONDS
        )
    except (OSError, ValueError, KeyError, psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def ensure_controller(directory: Path) -> None:
    """Start a single detached controller when no valid one exists."""
    lock = directory / "job-records" / "controller.lock"
    if lock.is_file() and _lock_is_live(lock):
        return
    directory.mkdir(parents=True, exist_ok=True)
    log = directory / "controller.log"
    with log.open("ab") as output:
        process = subprocess.Popen(
            [sys.executable, "-m", "evidenceforge.desktop.controller", str(directory)],
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    _controller_processes[:] = [
        running for running in _controller_processes if running.poll() is None
    ]
    _controller_processes.append(process)


def run_controller(directory: Path) -> None:
    """Poll durable records without depending on the GUI process lifetime."""
    store = JobStore(directory)
    lock = directory / "job-records" / "controller.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    if lock.is_file():
        if _lock_is_live(lock):
            return
        lock.unlink(missing_ok=True)
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(json.dumps({"pid": os.getpid(), "created_at": psutil.Process().create_time()}))
    last_intent = ""
    idle_since: float | None = None
    try:
        while True:
            try:
                intent = store.read_control()
                if intent.id != last_intent:
                    store.acknowledge(intent)
                    last_intent = intent.id
                _worker_tick(store, intent)
                if intent.action == "kill":
                    return
                active = any(
                    job.status == "running"
                    or (job.status == "queued" and intent.action in {"open", "resume"})
                    for job in store.load_generations()
                ) or any(
                    job.status == "running"
                    or (job.status == "queued" and intent.action in {"open", "resume"})
                    for job in store.load_evaluations()
                )
                idle_since = None if active else (idle_since or time.monotonic())
                if idle_since is not None and time.monotonic() - idle_since > 8:
                    return
            except (OSError, ValueError) as error:
                logger.error("Desktop controller error: %s", error)
            time.sleep(0.5)
    finally:
        lock.unlink(missing_ok=True)


def main() -> None:
    """Run the local controller from a detached Python process."""
    logging.basicConfig(level=logging.INFO)
    run_controller(Path(sys.argv[1]))


if __name__ == "__main__":
    main()
