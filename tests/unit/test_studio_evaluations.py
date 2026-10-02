"""Latest-score retention is a Studio policy, separate from the CLI evaluator."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from evidenceforge.desktop.state import EvaluationJob, GenerationJob
from evidenceforge.studio.jobs import (
    StudioJobStore,
    queue_studio_evaluation,
    retain_latest_evaluations,
)
from evidenceforge.studio.settings import StudioSettings
from evidenceforge.studio.store import StudioStore


@pytest.fixture
def job_store(tmp_path: Path) -> Iterator[StudioJobStore]:
    store = StudioStore(tmp_path / "studio.sqlite")
    yield StudioJobStore(store, tmp_path / "state")
    store.close()


def _evaluation(
    job_store: StudioJobStore,
    name: str,
    created: float,
    *,
    generation: str = "run",
    status: str = "completed",
    valid: bool = True,
    acceptance_passed: bool = True,
) -> EvaluationJob:
    job = EvaluationJob(
        id=name,
        generation_id=generation,
        workspace=job_store.directory.parent / "workspace",
        output_root=job_store.directory.parent / "bundle",
        result_file=job_store.directory / "jobs" / f"{name}.json",
        log_file=job_store.directory / "jobs" / f"{name}.log",
        command=[],
        created_at=created,
        status=status,
    )
    job.result_file.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "scenario_name": "example",
        "evaluated_at": "2026-10-02T16:00:00Z",
        "overall_score": created,
        "acceptance_passed": acceptance_passed,
        "total_records": 10,
    }
    job.result_file.write_text(json.dumps(report) if valid else "incomplete report")
    job.log_file.write_text("evaluation log")
    job_store.save_evaluation(job)
    return job


def test_completed_report_failing_standards_replaces_passing_scores_without_touching_bundles(
    job_store: StudioJobStore,
) -> None:
    first = _evaluation(job_store, "first", 1)
    latest = _evaluation(job_store, "latest", 2, acceptance_passed=False)
    other = _evaluation(job_store, "other", 3, generation="different-run")
    latest.output_root.mkdir()
    evidence = latest.output_root / "windows.jsonl"
    evidence.write_text("unchanged evidence")
    job_store.store.remove_job_history([first.id])
    assert retain_latest_evaluations(job_store) == [first.id]
    assert not first.result_file.exists()
    assert not first.log_file.exists()
    assert latest.result_file.is_file()
    assert json.loads(latest.result_file.read_text())["acceptance_passed"] is False
    assert {job.id for job in job_store.load_evaluations()} == {latest.id, other.id}
    assert job_store.store.removed_job_ids(latest.workspace) == []
    assert evidence.read_text() == "unchanged evidence"
    assert retain_latest_evaluations(job_store) == []


@pytest.mark.parametrize("status", ["queued", "running", "paused", "failed", "cancelled"])
def test_unfinished_or_crashed_retry_does_not_remove_previous_scores(
    job_store: StudioJobStore, status: str
) -> None:
    first = _evaluation(job_store, "first", 1)
    _evaluation(job_store, "retry", 2, status=status, valid=False)
    assert retain_latest_evaluations(job_store) == []
    assert first.result_file.is_file()
    assert len(job_store.load_evaluations()) == 2


def test_invalid_completed_report_does_not_replace_valid_predecessor(
    job_store: StudioJobStore,
) -> None:
    first = _evaluation(job_store, "first", 1)
    _evaluation(job_store, "invalid", 2, valid=False)
    assert retain_latest_evaluations(job_store) == []
    assert first.result_file.is_file()


def test_older_active_evaluation_remains_owned_by_controller(job_store: StudioJobStore) -> None:
    active = _evaluation(job_store, "active", 1, status="paused")
    _evaluation(job_store, "latest", 2)
    assert retain_latest_evaluations(job_store) == []
    assert active.result_file.is_file()


def test_cleanup_preserves_external_paths_and_symlink_targets(job_store: StudioJobStore) -> None:
    first = _evaluation(job_store, "first", 1)
    latest = _evaluation(job_store, "latest", 2)
    external = job_store.directory.parent / "external.json"
    external.write_text("external data")
    first.result_file.unlink()
    first.result_file.symlink_to(external)
    first.log_file = external
    job_store.save_evaluation(first)
    assert retain_latest_evaluations(job_store) == [first.id]
    assert external.read_text() == "external data"
    assert first.result_file.is_symlink()
    assert latest.result_file.is_file()


def test_symlinked_new_report_cannot_authorize_score_replacement(job_store: StudioJobStore) -> None:
    first = _evaluation(job_store, "first", 1)
    latest = _evaluation(job_store, "latest", 2)
    latest.result_file.unlink()
    latest.result_file.symlink_to(first.result_file)
    assert retain_latest_evaluations(job_store) == []
    assert first.result_file.is_file()


def test_cleanup_retries_file_failure_before_removing_the_record(
    job_store: StudioJobStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _evaluation(job_store, "first", 1)
    _evaluation(job_store, "latest", 2)
    original = Path.unlink

    def fail(path: Path, missing_ok: bool = False) -> None:
        if path == first.result_file:
            raise PermissionError("locked")
        original(path, missing_ok=missing_ok)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", fail)
        assert retain_latest_evaluations(job_store) == []
        assert len(job_store.load_evaluations()) == 2
    assert retain_latest_evaluations(job_store) == [first.id]


@pytest.mark.parametrize("status", ["queued", "running", "paused"])
def test_duplicate_evaluation_is_rejected_at_the_service_boundary(
    job_store: StudioJobStore, status: str
) -> None:
    _evaluation(job_store, "active", 1, status=status)
    generation = GenerationJob(
        id="run",
        scenario=job_store.directory.parent / "scenario.yaml",
        output_root=job_store.directory.parent / "bundle",
        workspace=job_store.directory.parent / "workspace",
        progress_file=job_store.directory / "jobs/run.jsonl",
        log_file=job_store.directory / "jobs/run.log",
        command=[],
        started_at=1,
        status="completed",
    )
    with pytest.raises(ValueError, match="already queued, running, or paused"):
        queue_studio_evaluation(
            job_store, generation, StudioSettings(workspace=generation.workspace)
        )
    assert len(job_store.load_evaluations()) == 1
