"""Bridge durable Studio jobs to the existing CLI lifecycle contract."""

from __future__ import annotations

import hashlib
import json
from glob import escape
from pathlib import Path
from typing import Any

from evidenceforge.desktop.controller import _worker_tick
from evidenceforge.desktop.job_store import ControlIntent
from evidenceforge.desktop.jobs import queue_evaluation, queue_generation, request_suspension
from evidenceforge.desktop.progress import GenerationProgress, parse_progress_line
from evidenceforge.desktop.state import AppSettings, EvaluationJob, GenerationJob
from evidenceforge.evaluation.models import QualityReport
from evidenceforge.generation.checkpoints.errors import CheckpointError
from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore
from evidenceforge.studio.settings import QuitSettings, StudioSettings
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


def controller_settings(settings: StudioSettings) -> AppSettings:
    """Translate shared quit preferences into the CLI controller model."""
    quit_settings: QuitSettings = settings.quit
    return AppSettings(
        close_action=quit_settings.action,
        continue_queued_generations=quit_settings.continue_queued_generations,
        continue_evaluations=quit_settings.continue_evaluations,
        pause_close_timing=quit_settings.pause_close_timing,
        pause_evaluations=quit_settings.pause_evaluations,
        kill_incomplete_bundles=quit_settings.kill_incomplete_bundles,
        skill_install_scope=settings.skill_install_scope,
        skill_install_agent=settings.skill_install_agent,
        codex_path=settings.codex_path,
        eforge_path=settings.eforge_path,
        max_concurrent_generations=settings.max_concurrent_generations,
    )


def queue_studio_generation(
    job_store: StudioJobStore,
    scenario: Path,
    workspace: Path,
    settings: StudioSettings,
    output_parent: Path | None = None,
    checkpoint_hours: int = 24,
) -> GenerationJob:
    """Persist a new GUI-owned generation before launching it."""
    job = queue_generation(
        scenario,
        workspace,
        job_store.directory,
        output_parent,
        settings=controller_settings(settings),
        checkpoint_hours=checkpoint_hours,
    )
    job.source_sha256 = hashlib.sha256(scenario.read_bytes()).hexdigest()
    job_store.save_generation(job)
    return job


def queue_studio_evaluation(
    job_store: StudioJobStore, generation: GenerationJob, settings: StudioSettings
) -> EvaluationJob:
    """Persist an evaluation linked to its generation."""
    job = queue_evaluation(generation, job_store.directory, settings=controller_settings(settings))
    job_store.save_evaluation(job)
    return job


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
