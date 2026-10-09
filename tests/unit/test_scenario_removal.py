"""Scenario retirement contracts through shared files, CLI, and Studio."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from evidenceforge.artifacts.lifecycle import (
    ArtifactError,
    _publication_lock,
    create_draft,
    list_versions,
    publish,
    suggest_version,
)
from evidenceforge.artifacts.removal import (
    remove_scenario,
    retired_scenario_sources,
    review_scenario_deletion,
)
from evidenceforge.cli.commands import app as cli_app
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
from evidenceforge.desktop.library import discover_scenarios
from evidenceforge.desktop.state import EvaluationJob, GenerationJob
from evidenceforge.studio.service import create_app
from evidenceforge.studio.store import Conversation, ImportedBundle
from tests.unit.test_studio_service import _paths

HEADERS = {"X-EForge-Token": "removal-test"}


def _scenario(workspace: Path, name: str = "case") -> Path:
    path = workspace / "scenarios" / name / "scenario.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile("tests/fixtures/scenarios/minimal.yaml", path)
    return path


def test_legacy_removal_preserves_companions_other_scenarios_and_runs(tmp_path: Path) -> None:
    source = _scenario(tmp_path)
    peer = _scenario(tmp_path, "peer")
    asset = source.parent / "ENVIRONMENT.md"
    asset.write_text("Keep the briefing")
    run = source.parent / "data" / "run"
    run.mkdir(parents=True)
    (run / "GENERATION_MANIFEST.json").write_text("captured")
    review = review_scenario_deletion(source, tmp_path)
    assert review.removable and not review.whole_artifact and review.files == 1
    result = remove_scenario(source, tmp_path, review.revision)
    assert not source.exists() and result.deleted_path == source
    assert asset.read_text() == "Keep the briefing"
    assert (run / "GENERATION_MANIFEST.json").read_text() == "captured"
    assert peer.exists() and source in retired_scenario_sources(tmp_path)
    assert not (tmp_path / ".eforge/deleted-scenarios").exists()


@pytest.mark.parametrize("published", [False, True])
def test_managed_removal_retires_only_selected_draft_or_release(
    tmp_path: Path, published: bool
) -> None:
    source = _scenario(tmp_path)
    set_publisher(
        tmp_path,
        PublisherIdentity(publisher="testing", publisher_display_name="Testing"),
        scope="project",
        force=False,
    )
    draft = create_draft(source, project_root=tmp_path, upgrade=True)
    branch = create_draft(draft, project_root=tmp_path)
    selected = publish(draft, project_root=tmp_path, accept_warnings=True) if published else draft
    review = review_scenario_deletion(selected, tmp_path)
    assert review.whole_artifact and review.removable
    result = remove_scenario(selected, tmp_path, review.revision)
    assert not selected.exists() and not review.target.exists()
    assert (
        result.deleted_path == review.target
        and not (tmp_path / ".eforge/deleted-scenarios").exists()
    )
    assert branch.exists() and source.exists()
    assert selected not in {item.path for item in discover_scenarios(tmp_path, [])}
    if published:
        assert (
            draft.exists()
            and list_versions(tmp_path, publisher="testing", kind="scenario", name="minimal-test")
            == []
        )
        assert (
            suggest_version(tmp_path, publisher="testing", kind="scenario", name="minimal-test")
            == "1.0.1"
        )
        with pytest.raises(ArtifactError, match="already published or reserved"):
            publish(draft, project_root=tmp_path, version="1.0.0", accept_warnings=True)


def test_stale_review_new_inclusion_and_symlinks_refuse_removal(tmp_path: Path) -> None:
    source = _scenario(tmp_path)
    review = review_scenario_deletion(source, tmp_path)
    source.write_text(source.read_text() + "\n# changed\n")
    with pytest.raises(FileExistsError, match="Review deletion again"):
        remove_scenario(source, tmp_path, review.revision)
    review = review_scenario_deletion(source, tmp_path)
    consumer = _scenario(tmp_path, "consumer")
    consumer.write_text("includes: [../case/scenario.yaml]\n")
    with pytest.raises(FileExistsError):
        remove_scenario(source, tmp_path, review.revision)
    blocked = review_scenario_deletion(source, tmp_path)
    assert str(consumer) in blocked.consumers and not blocked.removable
    with pytest.raises(ArtifactError, match="inclusion references"):
        remove_scenario(source, tmp_path, blocked.revision)
    consumer.unlink()
    review = review_scenario_deletion(source, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / ".eforge").mkdir(exist_ok=True)
    (tmp_path / ".eforge/deletions").symlink_to(outside)
    with pytest.raises(ArtifactError, match="symbolic links"):
        remove_scenario(source, tmp_path, review.revision)
    assert source.exists() and not list(outside.iterdir())


def test_cli_deletion_requires_exact_review_without_studio(tmp_path: Path) -> None:
    source = _scenario(tmp_path)
    runner = CliRunner()
    arguments = ["scenario", "delete", str(source), "--project-root", str(tmp_path), "--json"]
    result = runner.invoke(cli_app, arguments)
    assert result.exit_code == 0, result.output
    review = json.loads(result.stdout)
    assert source.exists() and review["removable"]
    result = runner.invoke(cli_app, [*arguments, "--revision", review["revision"]])
    assert result.exit_code == 0, result.output
    assert not source.exists() and Path(json.loads(result.stdout)["deleted_path"]) == source


def test_studio_removal_blocks_authoring_and_reconciles_failed_index_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    source = _scenario(workspace)
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "removal-test")
    studio = app.state.studio
    item = studio.store.upsert_item(workspace, "scenario", discover_scenarios(workspace, [])[0])
    conversation = Conversation(workspace=workspace, item_id=item.id, title="Editing", active=True)
    studio.store.save_conversation(conversation)
    with TestClient(app) as client:
        conversation.active = True
        studio.store.save_conversation(conversation)
        review = client.get(f"/v1/scenarios/{item.id}/deletion", headers=HEADERS).json()
        assert not review["removable"] and "authoring" in review["problems"][0]
        response = client.post(
            f"/v1/scenarios/{item.id}/delete",
            headers=HEADERS,
            json={"revision": review["revision"]},
        )
        assert response.status_code == 409 and source.exists()
        conversation.active = False
        studio.store.save_conversation(conversation)
        run = workspace / "runs" / "captured"
        run.mkdir(parents=True)
        captured = run / "RESOLVED_SCENARIO.yaml"
        captured.write_text("captured inputs")
        job = GenerationJob(
            id="captured-run",
            scenario=source,
            workspace=workspace,
            output_root=run,
            progress_file=run / "progress.json",
            log_file=run / "generation.log",
            started_at=1,
            status="completed",
            input_snapshot=captured,
        )
        studio.store.save_job(job.id, workspace, "generation", job)
        review = client.get(f"/v1/scenarios/{item.id}/deletion", headers=HEADERS).json()
        original_remove = studio.store.remove_scenario
        monkeypatch.setattr(
            studio.store,
            "remove_scenario",
            lambda _id: (_ for _ in ()).throw(ValueError("Index failure")),
        )
        response = client.post(
            f"/v1/scenarios/{item.id}/delete",
            headers=HEADERS,
            json={"revision": review["revision"]},
        )
        assert response.status_code == 409 and not source.exists()
        assert "permanently deleted" in response.text
        assert studio.store.item(item.id) and studio.store.conversation(conversation.id)
        monkeypatch.setattr(studio.store, "remove_scenario", original_remove)
        response = client.post("/v1/library/refresh", headers=HEADERS)
        assert response.status_code == 200, response.text
        assert not source.exists() and studio.store.item(item.id) is None
        assert studio.store.conversation(conversation.id) is None
        assert not (workspace / ".eforge/deleted-scenarios").exists()
        jobs = client.get("/v1/jobs", headers=HEADERS).json()
        assert any(entry["id"] == job.id for entry in jobs)
        assert captured.read_text() == "captured inputs"


def test_interrupted_deletion_reconciles_index_on_refresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    source = _scenario(workspace)
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "removal-test")
    studio = app.state.studio
    item = studio.store.upsert_item(workspace, "scenario", discover_scenarios(workspace, [])[0])
    review = review_scenario_deletion(source, workspace)
    remove_scenario(source, workspace, review.revision)
    assert studio.store.item(item.id)
    with TestClient(app) as client:
        response = client.post("/v1/library/refresh", headers=HEADERS)
        assert response.status_code == 200 and studio.store.item(item.id) is None


def test_publication_lock_and_partial_file_deletion_allow_reviewed_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _scenario(tmp_path)
    companion = source.parent / "README.md"
    companion.write_text("fixture")
    review = review_scenario_deletion(source, tmp_path, include_files=True)
    with _publication_lock(tmp_path), pytest.raises(ArtifactError, match="in progress"):
        remove_scenario(source, tmp_path, review.revision, include_files=True)
    original_unlink = os.unlink

    def fail_on_companion(path: object, **kwargs: object) -> None:
        if str(path).endswith("README.md"):
            raise PermissionError("Simulated locked companion")
        original_unlink(path, **kwargs)

    monkeypatch.setattr(os, "unlink", fail_on_companion)
    with pytest.raises(ArtifactError, match="some files may already be permanently removed"):
        remove_scenario(source, tmp_path, review.revision, include_files=True)
    assert source.exists() and source not in retired_scenario_sources(tmp_path)
    monkeypatch.setattr(os, "unlink", original_unlink)
    current = review_scenario_deletion(source, tmp_path, include_files=True)
    remove_scenario(source, tmp_path, current.revision, include_files=True)
    assert not source.parent.exists()


def test_fragments_generated_documents_and_foreign_sources_are_protected(tmp_path: Path) -> None:
    source = _scenario(tmp_path)
    fragment = source.parent / "fragment.yaml"
    fragment.write_text("environment: {}\n")
    generated = source.parent / "RESOLVED_SCENARIO.yaml"
    generated.write_text("kind: evidenceforge.resolved-scenario\nschema_version: '1.0'\n")
    for path in (fragment, generated):
        with pytest.raises(ArtifactError, match="discovered authored scenario"):
            review_scenario_deletion(path, tmp_path)
        assert path.exists()
    with pytest.raises(ArtifactError, match="Only local workspace"):
        review_scenario_deletion(source, tmp_path / "other")


def test_full_folder_removal_handles_large_data_and_protects_shared_scenario_folders(
    tmp_path: Path,
) -> None:
    source = _scenario(tmp_path)
    large = source.parent / "data" / "logs.json"
    large.parent.mkdir()
    with large.open("wb") as stream:
        stream.truncate(80 * 1024 * 1024)
    review = review_scenario_deletion(source, tmp_path, include_files=True)
    assert review.bytes > 80 * 1024 * 1024 and review.target == source.parent
    remove_scenario(source, tmp_path, review.revision, include_files=True)
    assert not source.parent.exists()
    source = _scenario(tmp_path)
    other = source.parent / "other.yaml"
    shutil.copyfile(source, other)
    with pytest.raises(ArtifactError, match="shared by scenarios"):
        review_scenario_deletion(source, tmp_path, include_files=True)
    assert source.exists() and other.exists()


def test_studio_full_cleanup_removes_owned_runs_inputs_evaluations_and_private_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    source = _scenario(workspace)
    peer = _scenario(workspace, "peer")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "removal-test")
    studio = app.state.studio
    item = studio.store.upsert_item(
        workspace,
        "scenario",
        next(entry for entry in discover_scenarios(workspace, []) if entry.path == source),
    )
    with TestClient(app) as client:
        run = workspace / "runs" / "test-one"
        run.mkdir(parents=True)
        (run / ".eforge-desktop-job.json").write_text(json.dumps({"job_id": "test-one"}))
        (run / "GENERATION_MANIFEST.json").write_text("{}")
        (run / "logs.json").write_text("generated fixture")
        inputs = studio.jobs.directory / "inputs" / "test-one"
        inputs.mkdir(parents=True)
        captured = inputs / "RESOLVED_SCENARIO.yaml"
        captured.write_text("captured fixture")
        job = GenerationJob(
            id="test-one",
            scenario=source,
            workspace=workspace,
            output_root=run,
            progress_file=studio.jobs.directory / "jobs/test-one-resume-fixture.jsonl",
            progress_history=[studio.jobs.directory / "jobs/test-one.jsonl"],
            log_file=studio.jobs.directory / "jobs/test-one.log",
            started_at=1,
            status="completed",
            input_snapshot=captured,
            owned_output=True,
        )
        for path in [job.progress_file, *job.progress_history, job.log_file]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("private run fixture")
        studio.store.save_job(job.id, workspace, "generation", job)
        report = studio.paths.state / "jobs" / "eval-one.json"
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text("{}")
        evaluation = EvaluationJob(
            id="eval-one",
            generation_id=job.id,
            workspace=workspace,
            output_root=run,
            result_file=report,
            log_file=report.with_suffix(".log"),
            command=[],
            created_at=1,
            status="completed",
        )
        studio.store.save_job(evaluation.id, workspace, "evaluation", evaluation)
        from evidenceforge.studio.contexts import scenario_context_path, scenario_overlay_root

        overlay = scenario_overlay_root(source, workspace)
        overlay.mkdir(parents=True)
        (overlay / "fixture.yaml").write_text("{}")
        context = scenario_context_path(source, workspace)
        context.parent.mkdir(parents=True)
        context.write_text("{}")
        nested_bundle = source.parent / "data/cli-bundle"
        nested_bundle.mkdir(parents=True)
        (nested_bundle / "fixture.json").write_text("{}")
        imported = ImportedBundle(
            workspace=workspace,
            root=nested_bundle,
            scenario_name="CLI fixture",
            created_at=1,
            size_bytes=2,
            manifest_sha256="a" * 64,
        )
        studio.store.save_imported_bundle(imported)
        outside = tmp_path / "external-bundle"
        outside.mkdir()
        (outside / "fixture.json").write_text("{}")
        external = imported.model_copy(update={"id": "external-bundle", "root": outside})
        studio.store.save_imported_bundle(external)
        review_response = client.get(
            f"/v1/scenarios/{item.id}/deletion?include_files=true", headers=HEADERS
        )
        assert review_response.status_code == 200, review_response.text
        review = review_response.json()
        assert review["run_count"] == 1 and review["run_paths"] == [str(run)]
        report.write_text('{"changed": true}')
        stale = client.post(
            f"/v1/scenarios/{item.id}/delete",
            headers=HEADERS,
            json={"revision": review["revision"], "include_files": True},
        )
        assert stale.status_code == 409 and source.exists() and run.exists()
        review = client.get(
            f"/v1/scenarios/{item.id}/deletion?include_files=true", headers=HEADERS
        ).json()
        response = client.post(
            f"/v1/scenarios/{item.id}/delete",
            headers=HEADERS,
            json={"revision": review["revision"], "include_files": True},
        )
        assert response.status_code == 200, response.text
        assert not source.parent.exists() and not run.exists() and not inputs.exists()
        assert not report.exists() and not overlay.exists() and not context.exists()
        assert not any(
            path.exists() for path in [job.progress_file, *job.progress_history, job.log_file]
        )
        assert studio.store.job_payloads(workspace) == [] and peer.exists()
        assert studio.store.imported_bundle(imported.id) is None
        assert studio.store.imported_bundle(external.id) is not None and outside.exists()
        assert not (workspace / ".eforge/deleted-scenarios").exists()


def test_full_cleanup_refuses_active_shared_and_foreign_run_ownership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    source = _scenario(workspace)
    peer = _scenario(workspace, "peer")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "removal-test")
    studio = app.state.studio
    item = studio.store.upsert_item(
        workspace,
        "scenario",
        next(entry for entry in discover_scenarios(workspace, []) if entry.path == source),
    )
    run = workspace / "runs/test-one"
    run.mkdir(parents=True)
    marker = run / ".eforge-desktop-job.json"
    marker.write_text(json.dumps({"job_id": "test-one"}))
    job = GenerationJob(
        id="test-one",
        scenario=source,
        workspace=workspace,
        output_root=run,
        progress_file=run / "progress.json",
        log_file=run / "generation.log",
        started_at=1,
        status="paused",
        owned_output=True,
    )
    studio.store.save_job(job.id, workspace, "generation", job)
    client = TestClient(app)
    route = f"/v1/scenarios/{item.id}"
    review = client.get(route + "/deletion?include_files=true", headers=HEADERS).json()
    assert not review["removable"] and "generation" in review["problems"][0]
    response = client.post(
        route + "/delete",
        headers=HEADERS,
        json={"revision": review["revision"], "include_files": True},
    )
    assert response.status_code == 409 and source.exists() and run.exists()
    job.status = "failed"
    studio.store.save_job(job.id, workspace, "generation", job)
    shared = job.model_copy(update={"id": "peer-run", "scenario": peer})
    studio.store.save_job(shared.id, workspace, "generation", shared)
    response = client.get(route + "/deletion?include_files=true", headers=HEADERS)
    assert response.status_code == 400 and "shared by another run" in response.text
    studio.store.delete_job(shared.id)
    marker.write_text(json.dumps({"job_id": "foreign-run"}))
    response = client.get(route + "/deletion?include_files=true", headers=HEADERS)
    assert response.status_code == 400 and "ownership changed" in response.text
    assert source.exists() and peer.exists() and run.exists()
    client.close()
    studio.store.close()
