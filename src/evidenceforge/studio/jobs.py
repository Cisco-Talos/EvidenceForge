"""Bridge durable Studio jobs to the existing CLI lifecycle contract."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from glob import escape
from pathlib import Path
from typing import Any

from evidenceforge.composition.artifacts import write_resolved_scenario
from evidenceforge.composition.compiler import compile_scenario
from evidenceforge.desktop.controller import _worker_tick
from evidenceforge.desktop.job_store import ControlIntent
from evidenceforge.desktop.jobs import queue_evaluation, queue_generation, request_suspension
from evidenceforge.desktop.progress import GenerationProgress, parse_progress_line
from evidenceforge.desktop.state import EvaluationJob, GenerationJob
from evidenceforge.evaluation.models import QualityReport
from evidenceforge.generation.checkpoints.errors import CheckpointError
from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore
from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.studio.contexts import context_path
from evidenceforge.studio.imports import dependency_health
from evidenceforge.studio.settings import StudioSettings, controller_settings
from evidenceforge.studio.store import StudioStore


class StudioJobStore:
    """SQLite-backed job repository accepted by the existing controller logic."""

    def __init__(self, store: StudioStore, directory: Path) -> None:
        self.store = store
        self.directory = directory

    def load_generations(self) -> list[GenerationJob]:
        """Load every app-owned generation for reconciliation."""
        return [
            GenerationJob.model_validate(payload)
            for payload in self.store.job_payloads(kind="generation")
        ]

    def load_evaluations(self) -> list[EvaluationJob]:
        """Load every app-owned evaluation for reconciliation."""
        return [
            EvaluationJob.model_validate(payload)
            for payload in self.store.job_payloads(kind="evaluation")
        ]

    def save_generation(self, job: GenerationJob) -> None:
        """Save a generation before the service announces its change."""
        self.store.save_job(job.id, job.workspace or job.scenario.parent, "generation", job)

    def save_evaluation(self, job: EvaluationJob) -> None:
        """Save an evaluation before the service announces its change."""
        self.store.save_job(job.id, job.workspace, "evaluation", job)


def queue_studio_generation(
    job_store: StudioJobStore,
    scenario: Path,
    workspace: Path,
    settings: StudioSettings,
    output_parent: Path | None = None,
    checkpoint_hours: int = 24,
) -> GenerationJob:
    """Freeze all deterministic inputs before publishing a queued generation."""
    scenario = scenario.resolve()
    workspace = workspace.resolve()
    source_sha256 = hashlib.sha256(scenario.read_bytes()).hexdigest()
    before = dependency_health(scenario, workspace)
    if not before.ready:
        raise ValueError("Resolve the scenario's missing or conflicting dependencies first")
    compiled = compile_scenario(
        scenario, project_root=workspace, context=context_path(scenario, workspace)
    )
    after = dependency_health(scenario, workspace)
    if (
        not after.ready
        or before.fingerprint != after.fingerprint
        or source_sha256 != hashlib.sha256(scenario.read_bytes()).hexdigest()
    ):
        raise ValueError("Scenario inputs changed while queuing. Refresh and try again")
    job = queue_generation(
        scenario,
        workspace,
        job_store.directory,
        output_parent or settings.output_parents.get(str(workspace.resolve())),
        settings=controller_settings(settings),
        checkpoint_hours=checkpoint_hours,
    )
    snapshot_directory = job_store.directory / "inputs" / job.id
    try:
        job.input_snapshot = write_resolved_scenario(compiled, snapshot_directory)
        job.input_sha256 = hashlib.sha256(job.input_snapshot.read_bytes()).hexdigest()
        job.compiled_sha256 = compiled.digests["compiled_sha256"]
        job.source_sha256 = source_sha256
        job.dependency_sha256 = before.fingerprint
        # Preserve the authored path for associations; only the worker reads the snapshot.
        job.command[job.command.index("generate") + 1] = str(job.input_snapshot)
        job_store.save_generation(job)
    except (OSError, ValueError, EvidenceForgeError, sqlite3.Error):
        # These directories have just been reserved and have never been published to a worker.
        if snapshot_directory.is_dir():
            shutil.rmtree(snapshot_directory)
        (job.output_root / ".eforge-desktop-job.json").unlink(missing_ok=True)
        job.output_root.rmdir()
        raise
    return job


def queue_studio_evaluation(
    job_store: StudioJobStore, generation: GenerationJob, settings: StudioSettings
) -> EvaluationJob:
    """Persist an evaluation linked to its generation."""
    if any(
        job.generation_id == generation.id and job.status in {"queued", "running", "paused"}
        for job in job_store.load_evaluations()
    ):
        raise ValueError("An evaluation for this run is already queued, running, or paused")
    job = queue_evaluation(generation, job_store.directory, settings=controller_settings(settings))
    job_store.save_evaluation(job)
    return job


def retain_latest_evaluations(job_store: StudioJobStore) -> list[str]:
    """Replace older terminal evaluations only after a newer valid report is durable.

    A crashed or interrupted retry leaves the previous score available. A completed
    report replaces it even when required quality checks fail. Cleanup is limited
    to verified Studio report/log paths; generated and imported data are never
    removed here. Active evaluations remain owned by the controller.
    """
    evaluations = job_store.load_evaluations()
    terminal = {"completed", "failed", "stopped", "cancelled"}
    by_run: dict[str, list[EvaluationJob]] = {}
    for job in evaluations:
        by_run.setdefault(job.generation_id, []).append(job)
    newest: dict[str, EvaluationJob] = {}
    for job in sorted(evaluations, key=lambda entry: (entry.created_at, entry.id), reverse=True):
        if job.generation_id in newest or job.status != "completed":
            continue
        if not any(
            older.generation_id == job.generation_id
            and older.workspace == job.workspace
            and older.status in terminal
            and (older.created_at, older.id) < (job.created_at, job.id)
            for older in by_run[job.generation_id]
        ):
            continue
        expected = job_store.directory / "jobs" / f"{job.id}.json"
        if (
            job.result_file != expected
            or expected.is_symlink()
            or expected.parent.is_symlink()
            or not expected.resolve().is_relative_to(job_store.directory.resolve())
            or not expected.is_file()
        ):
            continue
        try:
            if expected.stat().st_size > 32 * 1024 * 1024:
                continue
            QualityReport.model_validate_json(expected.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            continue
        newest[job.generation_id] = job
    removed: list[str] = []
    for job in evaluations:
        latest = newest.get(job.generation_id)
        if (
            latest is None
            or latest.workspace != job.workspace
            or (job.created_at, job.id) >= (latest.created_at, latest.id)
            or job.status not in terminal
        ):
            continue
        try:
            for path, suffix in ((job.result_file, "json"), (job.log_file, "log")):
                expected = job_store.directory / "jobs" / f"{job.id}.{suffix}"
                if (
                    path == expected
                    and not path.is_symlink()
                    and not path.parent.is_symlink()
                    and path.resolve().is_relative_to(job_store.directory.resolve())
                ):
                    path.unlink(missing_ok=True)
        except OSError:
            # Retry cleanup on the next controller tick without losing its record.
            continue
        job_store.store.delete_job(job.id)
        removed.append(job.id)
    return removed


def reconcile_jobs(job_store: StudioJobStore, intent: ControlIntent) -> list[dict[str, Any]]:
    """Apply one controller tick and return records that changed."""
    before = {payload["id"]: payload for payload in job_store.store.job_payloads()}
    _worker_tick(job_store, intent)
    after = job_store.store.job_payloads()
    return [payload for payload in after if payload != before.get(payload["id"])]


def progress_for(job: GenerationJob) -> GenerationProgress:
    """Restore a progress card from the durable CLI JSONL stream."""
    progress = GenerationProgress()
    for path in progress_files(job):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            with path.open(encoding="utf-8", errors="replace") as stream:
                for line in stream:
                    event = parse_progress_line(line)
                    if event is not None:
                        progress.apply(event)
        except OSError:
            continue
    return progress


def progress_files(job: GenerationJob) -> list[Path]:
    """List each attempt's progress, including runs saved before history was tracked."""
    directory = job.progress_file.parent
    original = directory / f"{job.id}.jsonl"
    if job.progress_history:
        return list(dict.fromkeys([original, *job.progress_history, job.progress_file]))
    resumes = (
        sorted(directory.glob(f"{escape(job.id)}-resume-*.jsonl"), key=_modified_ns)
        if directory.is_dir()
        else []
    )
    return list(dict.fromkeys([original, *resumes, job.progress_file]))


def _modified_ns(path: Path) -> int:
    try:
        return 0 if path.is_symlink() else path.stat().st_mtime_ns
    except OSError:
        return 0


def progress_signature(job: GenerationJob) -> tuple[tuple[str, int, int], ...]:
    """Cheaply detect appended progress without reparsing every file on each poll."""
    signature: list[tuple[str, int, int]] = []
    for path in progress_files(job):
        try:
            info = path.stat() if not path.is_symlink() else None
        except OSError:
            info = None
        signature.append(
            (
                str(path),
                0 if info is None else info.st_mtime_ns,
                0 if info is None else info.st_size,
            )
        )
    return tuple(signature)


def can_resume(job: GenerationJob) -> bool:
    """Report whether Resume has a queued input or durable recovery point to use."""
    if job.status not in {"paused", "stopped"}:
        return False
    checkpoint = IncrementalCheckpointStore(job.output_root)
    if job.pid == 0 and not checkpoint.workspace.exists():
        return True
    try:
        return bool(checkpoint.recovery_index_entries(read_only=True))
    except CheckpointError:
        return False


def job_summary(payload: dict[str, Any]) -> dict[str, Any]:
    """Attach restored progress and the saved evaluation score when available."""
    summary = dict(payload)
    if "scenario" in payload:
        summary["kind"] = "generation"
        generation = GenerationJob.model_validate(payload)
        summary["progress"] = json.loads(progress_for(generation).model_dump_json())
        summary["can_resume"] = can_resume(generation)
    else:
        summary["kind"] = "evaluation"
        result_file = Path(payload["result_file"])
        if result_file.is_file():
            try:
                report = QualityReport.model_validate_json(result_file.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError):
                summary["scorecard"] = {"error": "Saved evaluation could not be read"}
            else:
                summary["scorecard"] = {
                    "overall_score": report.overall_score,
                    "acceptance_passed": report.acceptance_passed,
                    "total_records": report.total_records,
                    "evaluated_at": report.evaluated_at.isoformat(),
                }
    return summary


def suspend_generation(job_store: StudioJobStore, job_id: str) -> str:
    """Request a safe checkpoint for one active app-owned generation."""
    job = next((entry for entry in job_store.load_generations() if entry.id == job_id), None)
    if job is None:
        raise KeyError(job_id)
    if job.status != "running":
        raise ValueError("Only a running generation can be suspended")
    if job.checkpoint_hours == 0:
        raise ValueError("This generation has checkpointing disabled")
    result = request_suspension(job, job.workspace or job.scenario.parent)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout)[-500:])
    job.status_message = "Pause requested"
    job_store.save_generation(job)
    return job.status_message
