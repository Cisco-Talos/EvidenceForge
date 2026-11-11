"""Individual job controls preserve files, ownership and other queued work."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from evidenceforge.desktop.job_store import ControlIntent
from evidenceforge.desktop.state import EvaluationJob, GenerationJob
from evidenceforge.studio.jobs import StudioJobStore, job_summary, stop_studio_job
from evidenceforge.studio.paths import StudioPaths
from evidenceforge.studio.service import create_app
from evidenceforge.studio.store import StudioStore


@pytest.fixture
def jobs(tmp_path: Path) -> Iterator[StudioJobStore]:
    store = StudioStore(tmp_path / "studio.sqlite")
    yield StudioJobStore(store, tmp_path / "state")
    store.close()


def _job(
    jobs: StudioJobStore, kind: str, status: str, *, foreign: bool = False
) -> GenerationJob | EvaluationJob:
    workspace = jobs.directory.parent / ("foreign" if foreign else "workspace")
    output = workspace / "runs" / f"{kind}-{status}"
    output.mkdir(parents=True, exist_ok=True)
    (output / "evidence.log").write_text("keep this evidence")
    shared = {
        "id": f"{kind}-{status}",
        "workspace": workspace,
        "output_root": output,
        "log_file": output / "job.log",
        "status": status,
    }
    if kind == "generation":
        generation = GenerationJob(
            **shared,
            scenario=workspace / "scenario.yaml",
            progress_file=output / "progress.jsonl",
            started_at=100,
        )
        jobs.save_generation(generation)
        return generation
    evaluation = EvaluationJob(
        **shared,
        generation_id="source",
        result_file=output / "score.json",
        command=[],
        created_at=100,
    )
    jobs.save_evaluation(evaluation)
    return evaluation


@pytest.mark.parametrize("kind", ["generation", "evaluation"])
@pytest.mark.parametrize("status", ["queued", "paused", "running"])
def test_stop_targets_one_job_and_keeps_files_and_control_intent(
    jobs: StudioJobStore, monkeypatch: pytest.MonkeyPatch, kind: str, status: str
) -> None:
    target = _job(jobs, kind, status)
    other = _job(jobs, kind, "completed")
    terminated: list[str] = []
    monkeypatch.setattr(
        "evidenceforge.studio.jobs._terminate_owned", lambda job: terminated.append(job.id)
    )
    monkeypatch.setattr("evidenceforge.studio.jobs._running", lambda _job: False)
    jobs.store.save_control(ControlIntent(action="continue"))
    before = jobs.store.load_control()
    stopped = stop_studio_job(jobs, target.workspace, target.id)
    assert stopped.status == (
        "stopped" if kind == "generation" and status == "running" else "cancelled"
    )
    assert terminated == ([target.id] if status == "running" else [])
    assert (target.output_root / "evidence.log").read_text() == "keep this evidence"
    assert jobs.store.load_control() == before
    assert (
        next(payload for payload in jobs.store.job_payloads() if payload["id"] == other.id)[
            "status"
        ]
        == "completed"
    )


def test_stop_rejects_foreign_terminal_and_still_running_jobs(
    jobs: StudioJobStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    foreign = _job(jobs, "generation", "paused", foreign=True)
    terminal = _job(jobs, "evaluation", "completed")
    running = _job(jobs, "generation", "running")
    terminate: list[str] = []
    monkeypatch.setattr(
        "evidenceforge.studio.jobs._terminate_owned", lambda job: terminate.append(job.id)
    )
    monkeypatch.setattr("evidenceforge.studio.jobs._running", lambda _job: True)
    with pytest.raises(KeyError):
        stop_studio_job(jobs, terminal.workspace, foreign.id)
    with pytest.raises(ValueError, match="Only queued"):
        stop_studio_job(jobs, terminal.workspace, terminal.id)
    with pytest.raises(ValueError, match="still running"):
        stop_studio_job(jobs, running.workspace, running.id)
    assert terminate == [running.id]
    assert next(job for job in jobs.load_generations() if job.id == running.id).status == "running"


def test_stop_route_requires_auth_and_current_workspace_and_reports_conflicts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    monkeypatch.setattr("evidenceforge.studio.service.reconcile_jobs", lambda *_args: [])
    paths = StudioPaths(
        **{
            name: tmp_path / "private" / name
            for name in ("config", "data", "state", "cache", "logs")
        }
    )
    app = create_app(paths, "secret")
    headers = {"X-EForge-Token": "secret"}
    with TestClient(app) as client:
        jobs = app.state.studio.jobs
        target = _job(jobs, "generation", "queued")
        target.workspace = workspace
        jobs.save_generation(target)
        foreign = _job(jobs, "evaluation", "queued", foreign=True)
        assert client.post(f"/v1/jobs/{target.id}/stop").status_code == 401
        assert client.post(f"/v1/jobs/{foreign.id}/stop", headers=headers).status_code == 404
        assert client.post(f"/v1/jobs/{target.id}/stop", headers=headers).status_code == 200
        assert client.post(f"/v1/jobs/{target.id}/stop", headers=headers).status_code == 409
        assert (target.output_root / "evidence.log").is_file()


def test_job_summary_retains_output_ownership_and_treats_legacy_unknown_as_unowned(
    jobs: StudioJobStore,
) -> None:
    target = _job(jobs, "generation", "completed")
    payload = target.model_dump(mode="json")
    payload.pop("owned_output")
    assert job_summary(payload)["owned_output"] is False
    payload["owned_output"] = True
    assert job_summary(payload)["owned_output"] is True


def test_running_evaluation_does_not_treat_pending_json_as_an_unreadable_report(
    jobs: StudioJobStore,
) -> None:
    job = _job(jobs, "evaluation", "running")
    job.result_file.write_text("")
    assert "scorecard" not in job_summary(job.model_dump(mode="json"))


def test_historical_failed_evaluation_exposes_cli_error_without_rewriting_state(
    jobs: StudioJobStore,
) -> None:
    job = _job(jobs, "evaluation", "failed")
    job.result_file.write_text("")
    job.log_file.write_text(
        "Error: Evaluation failed: Evaluation corpus exceeds the supported envelope:\n864106704 corpus bytes exceeds 536870912\n"
    )
    job.status_message = "Invalid JSON: EOF while parsing a value"
    summary = job_summary(job.model_dump(mode="json"))
    assert "864106704 corpus bytes exceeds 536870912" in summary["scorecard"]["error"]
    assert summary["status_message"] == summary["scorecard"]["error"]
    assert job.status_message == "Invalid JSON: EOF while parsing a value"


def test_studio_evaluation_uses_automatic_resource_management(jobs: StudioJobStore) -> None:
    from evidenceforge.studio.jobs import queue_studio_evaluation
    from evidenceforge.studio.settings import StudioSettings

    generation = _job(jobs, "generation", "completed")
    settings = StudioSettings()
    job = queue_studio_evaluation(jobs, generation, settings)
    assert "--allow-large-evaluation" not in job.command
    assert jobs.load_evaluations()[0].command == job.command
    settings.max_concurrent_generations = 5
    assert "--allow-large-evaluation" not in jobs.load_evaluations()[0].command
