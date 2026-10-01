"""Local service contracts exercised without a desktop window."""

from __future__ import annotations

import asyncio
import io
import json
import subprocess
import sys
import time
import zipfile
from hashlib import sha256
from pathlib import Path
from threading import Event

import psutil
import pytest
from fastapi.testclient import TestClient

from evidenceforge.desktop.controller import _worker_tick
from evidenceforge.desktop.job_store import ControlIntent
from evidenceforge.desktop.jobs import resume_generation
from evidenceforge.desktop.state import AppSettings, EvaluationJob, GenerationJob
from evidenceforge.studio.codex import CodexClient, CodexThreadNotReadyError, CodexTimeoutError
from evidenceforge.studio.jobs import StudioJobStore, job_summary, queue_studio_generation
from evidenceforge.studio.lifecycle import clone_scenario
from evidenceforge.studio.paths import StudioPaths, default_workspace, studio_paths
from evidenceforge.studio.service import StudioService, create_app
from evidenceforge.studio.settings import SettingsStore, StudioSettings
from evidenceforge.studio.store import Conversation, StudioStore


def _paths(root: Path) -> StudioPaths:
    return StudioPaths(
        config=root / "config",
        data=root / "data",
        state=root / "state",
        cache=root / "cache",
        logs=root / "logs",
    )


def _scenario(workspace: Path, name: str) -> Path:
    path = workspace / "scenarios" / name / "scenario.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"name: {name}\nversion: '1.0'\nenvironment:\n  users: []\n  systems: []\n",
        encoding="utf-8",
    )
    return path


def _progress_line(completed: int, total: int = 4) -> str:
    return (
        json.dumps(
            {
                "schema_version": 1,
                "event": "hour_progress",
                "data": {
                    "completed_simulated_hours": completed,
                    "total_simulated_hours": total,
                    "hour": completed + 1,
                    "total_hours": total,
                },
            }
        )
        + "\n"
    )


def _external_bundle(root: Path, name: str = "external") -> Path:
    root.mkdir(parents=True)
    resolved = root / "RESOLVED_SCENARIO.yaml"
    resolved.write_text("scenario:\n  name: external\n", encoding="utf-8")
    (root / "GROUND_TRUTH.md").write_text("# Ground truth\n", encoding="utf-8")
    (root / "GENERATION_MANIFEST.json").write_text(
        json.dumps(
            {
                "kind": "evidenceforge.generation-manifest",
                "schema_version": "1.0",
                "created_at": "2026-10-01T12:00:00Z",
                "scenario": name,
                "evidenceforge_version": "2.1.2",
                "runtime": {"python": "3.12", "platform": "darwin"},
                "generation_seed": 7,
                "output_target": "default",
                "formats": ["zeek_conn"],
                "oob_hosts": [],
                "overrides": {},
                "selected_packs": [],
                "compiled_sha256": "a" * 64,
                "resolved_file_sha256": sha256(resolved.read_bytes()).hexdigest(),
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    return root


def test_external_bundle_import_is_read_only_and_workspace_scoped(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    other = tmp_path / "other"
    root = _external_bundle(tmp_path / "cli-output")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(_paths(tmp_path / "private"), "secret")) as client:
        assert client.post("/v1/bundles/import", json={"path": str(root)}).status_code == 401
        response = client.post("/v1/bundles/import", headers=headers, json={"path": str(root)})
        assert response.status_code == 200, response.text
        bundle = response.json()
        assert bundle["scenario_name"] == "external"
        assert bundle["size_bytes"] > 0
        assert client.get("/v1/bootstrap", headers=headers).json()["imported_bundles"] == [bundle]
        files = client.get(f"/v1/bundles/{bundle['id']}/files", headers=headers).json()
        assert {entry["path"] for entry in files["files"]} == {
            "GENERATION_MANIFEST.json",
            "GROUND_TRUTH.md",
            "RESOLVED_SCENARIO.yaml",
        }
        assert (
            client.get(f"/v1/bundles/{bundle['id']}/files/GROUND_TRUTH.md", headers=headers).text
            == "# Ground truth\n"
        )
        assert client.get(
            f"/v1/bundles/{bundle['id']}/files/../outside", headers=headers
        ).status_code in {400, 404}
        archive = client.get(f"/v1/bundles/{bundle['id']}/bundle.zip", headers=headers)
        assert archive.status_code == 200
        with zipfile.ZipFile(io.BytesIO(archive.content)) as contents:
            assert contents.read("run/GROUND_TRUTH.md") == b"# Ground truth\n"
        again = client.post("/v1/bundles/import", headers=headers, json={"path": str(root)}).json()
        assert again["id"] == bundle["id"]
        client.post("/v1/workspaces/select", headers=headers, json={"path": str(other)})
        assert client.get("/v1/bootstrap", headers=headers).json()["imported_bundles"] == []
        assert client.get(f"/v1/bundles/{bundle['id']}/files", headers=headers).status_code == 404
        client.post("/v1/workspaces/select", headers=headers, json={"path": str(workspace)})
        assert client.delete(f"/v1/bundles/{bundle['id']}", headers=headers).status_code == 200
        assert root.is_dir()
        assert client.get("/v1/bootstrap", headers=headers).json()["imported_bundles"] == []


def test_external_bundle_discovery_skips_owned_and_rejects_changed_manifest(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    root = _external_bundle(workspace / "runs" / "example" / "run-one")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(_paths(tmp_path / "private"), "secret")) as client:
        assert client.post("/v1/bundles/discover", headers=headers).json() == {"imported": 1}
        assert client.post("/v1/bundles/discover", headers=headers).json() == {"imported": 0}
        bundle = client.get("/v1/bootstrap", headers=headers).json()["imported_bundles"][0]
        manifest = root / "GENERATION_MANIFEST.json"
        manifest.write_text(manifest.read_text() + "\n", encoding="utf-8")
        assert client.get(f"/v1/bundles/{bundle['id']}/files", headers=headers).status_code == 409
        manifest.write_text(manifest.read_text().rstrip(), encoding="utf-8")
        (root / "RESOLVED_SCENARIO.yaml").write_text("tampered", encoding="utf-8")
        assert client.get(f"/v1/bundles/{bundle['id']}/files", headers=headers).status_code == 409
        invalid = _external_bundle(tmp_path / "invalid")
        (invalid / "RESOLVED_SCENARIO.yaml").write_text("tampered", encoding="utf-8")
        assert (
            client.post(
                "/v1/bundles/import", headers=headers, json={"path": str(invalid)}
            ).status_code
            == 400
        )
        (invalid / "GENERATION_MANIFEST.json").write_text("{}", encoding="utf-8")
        assert (
            client.post(
                "/v1/bundles/import", headers=headers, json={"path": str(invalid)}
            ).status_code
            == 400
        )
        linked = tmp_path / "linked"
        linked.symlink_to(root, target_is_directory=True)
        assert (
            client.post(
                "/v1/bundles/import", headers=headers, json={"path": str(linked)}
            ).status_code
            == 400
        )


def test_export_folder_is_saved_per_workspace(tmp_path: Path, monkeypatch: object) -> None:
    first = tmp_path / "first-workspace"
    second = tmp_path / "second-workspace"
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(first))
    paths = _paths(tmp_path / "private")
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(paths, "secret")) as client:
        assert client.get("/v1/export-location").status_code == 401
        assert client.get("/v1/export-location", headers=headers).json() == {"directory": None}
        invalid = client.put(
            "/v1/export-location", headers=headers, json={"directory": str(tmp_path / "absent")}
        )
        assert invalid.status_code == 400
        saved = client.put(
            "/v1/export-location", headers=headers, json={"directory": str(export_dir)}
        )
        assert saved.json() == {"directory": str(export_dir)}
        client.post("/v1/workspaces/select", headers=headers, json={"path": str(second)})
        assert client.get("/v1/export-location", headers=headers).json() == {"directory": None}
        client.post("/v1/workspaces/select", headers=headers, json={"path": str(first)})
        assert client.get("/v1/export-location", headers=headers).json() == {
            "directory": str(export_dir)
        }
    with TestClient(create_app(paths, "secret")) as client:
        assert client.get("/v1/export-location", headers=headers).json() == {
            "directory": str(export_dir)
        }


def test_scenario_clone_copies_authored_files_and_project_without_history(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    original = _scenario(workspace, "alpha")
    companion = original.parent / "ENVIRONMENT.md"
    companion.write_text("Original briefing\n", encoding="utf-8")
    paths = _paths(tmp_path / "private")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(paths, "secret")) as client:
        item = next(
            entry
            for entry in client.get("/v1/bootstrap", headers=headers).json()["items"]
            if entry["path"] == str(original)
        )
        project = client.post(
            "/v1/projects", headers=headers, json={"name": "Alpha project"}
        ).json()
        client.patch(f"/v1/items/{item['id']}", headers=headers, json={"project_id": project["id"]})
        response = client.post(
            f"/v1/scenarios/{item['id']}/clone", headers=headers, json={"name": "alpha-copy"}
        )
        assert response.status_code == 200
        cloned = response.json()
        target = Path(cloned["path"])
        assert cloned["id"] != item["id"]
        assert cloned["name"] == "alpha-copy"
        assert cloned["project_id"] == project["id"]
        assert target.parent != original.parent
        assert (target.parent / "ENVIRONMENT.md").read_text() == "Original briefing\n"
        assert "name: alpha\n" in original.read_text()
        assert client.get("/v1/bootstrap", headers=headers).json()["conversations"] == []
        duplicate = client.post(
            f"/v1/scenarios/{item['id']}/clone", headers=headers, json={"name": "alpha-copy"}
        )
        assert duplicate.status_code == 409
        assert (
            client.post(
                f"/v1/scenarios/{item['id']}/clone", headers=headers, json={"name": "../escape"}
            ).status_code
            == 400
        )


def test_scenario_clone_rejects_links_and_shared_source_folders(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    original = _scenario(workspace, "alpha")
    (original.parent / "outside-link").symlink_to(tmp_path)
    with pytest.raises(ValueError, match="contains a link"):
        clone_scenario(original, workspace, "alpha-copy")
    assert not (workspace / "scenarios" / "alpha-copy").exists()
    (original.parent / "outside-link").unlink()
    (original.parent / "other.yaml").write_text(
        "name: other\nversion: '1.0'\nenvironment:\n  users: []\n  systems: []\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="multiple scenarios"):
        clone_scenario(original, workspace, "alpha-copy")
    shared = workspace / "scenarios" / "shared.yaml"
    shared.write_text("name: shared\nversion: '1.0'\n", encoding="utf-8")
    copied = clone_scenario(shared, workspace, "shared-copy")
    assert copied.read_text(encoding="utf-8").startswith('name: "shared-copy"')
    assert not (copied.parent / "other.yaml").exists()
    linked_workspace = tmp_path / "linked-workspace"
    linked_workspace.mkdir()
    (linked_workspace / "scenarios").symlink_to(workspace / "scenarios")
    with pytest.raises(ValueError, match="must not be a link"):
        clone_scenario(original, linked_workspace, "linked-copy")


def test_pack_clone_uses_cli_and_configures_project_publisher_when_requested(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(_paths(tmp_path / "private"), "secret")) as client:
        item = next(
            entry
            for entry in client.get("/v1/bootstrap", headers=headers).json()["items"]
            if entry["kind"] == "industry_pack" and entry["name"] == "finance"
        )
        assert client.get("/v1/packs/publisher").status_code == 401
        assert client.get("/v1/packs/publisher", headers=headers).json()["configured"] is False
        route = f"/v1/packs/{item['id']}/clone"
        request = {"name": "finance-studio", "version": "1.0.0"}
        assert client.post(route, headers=headers, json=request).status_code == 409
        response = client.post(
            route,
            headers=headers,
            json={
                **request,
                "publisher": "studio-test",
                "publisher_display_name": "Studio Test",
            },
        )
        assert response.status_code == 200, response.text
        cloned = response.json()
        assert cloned["id"] != item["id"]
        assert cloned["kind"] == "industry_pack"
        assert cloned["name"] == "finance-studio"
        assert cloned["path"].startswith(str(workspace / ".eforge" / "packs"))
        manifest = Path(cloned["path"]).read_text(encoding="utf-8")
        assert "publisher: studio-test" in manifest
        assert "name: finance-studio" in manifest
        publisher = client.get("/v1/packs/publisher", headers=headers).json()
        assert publisher["publisher"] == "studio-test"
        assert publisher["scope"] == "project"
        assert client.post(route, headers=headers, json=request).status_code == 400


def test_scenario_two_draft_promotes_and_keeps_conversation(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "secret")
    headers = {"X-EForge-Token": "secret"}
    with TestClient(app) as client:
        draft = client.post(
            "/v1/conversations",
            headers=headers,
            json={"draft_kind": "scenario", "name": "My new scenario"},
        ).json()
        assert draft["draft_name"] == "My new scenario"
        target = Path(draft["draft_path"])
        target.parent.mkdir(parents=True)
        target.write_text(
            "scenario_version: '2.0'\nname: authored-two\nenvironment:\n  users: []\n  systems: []\n",
            encoding="utf-8",
        )
        client.post("/v1/library/refresh", headers=headers)
        snapshot = client.get("/v1/bootstrap", headers=headers).json()
        item = next(entry for entry in snapshot["items"] if entry["path"] == str(target))
        linked = next(entry for entry in snapshot["conversations"] if entry["id"] == draft["id"])
        assert item["version"] == "2.0"
        assert item["name"] == "authored-two"
        assert linked["item_id"] == item["id"]
        assert linked["draft_kind"] is None


def test_checkpoint_setting_regeneration_and_incomplete_bundle_cleanup(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    scenario = _scenario(workspace, "short")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    paths = _paths(tmp_path / "private")
    app = create_app(paths, "secret")
    headers = {"X-EForge-Token": "secret"}
    with TestClient(app) as client:
        settings = client.get("/v1/settings", headers=headers).json()
        assert settings["checkpoint_hours"] == 24
        settings["checkpoint_hours"] = 6
        assert client.put("/v1/settings", headers=headers, json=settings).status_code == 200
        assert SettingsStore(paths).load().checkpoint_hours == 6
        original = queue_studio_generation(
            app.state.studio.jobs, scenario, workspace, app.state.studio.settings
        )
        original.status = "stopped"
        app.state.studio.jobs.save_generation(original)
        (original.output_root / "partial.log").write_text("unfinished", encoding="utf-8")
        files = client.get(f"/v1/jobs/{original.id}/files", headers=headers)
        assert files.status_code == 200
        assert any(entry["path"] == "partial.log" for entry in files.json()["files"])
        download = client.get(f"/v1/jobs/{original.id}/files/partial.log", headers=headers)
        assert download.content == b"unfinished"
        rerun = client.post(f"/v1/jobs/{original.id}/regenerate", headers=headers)
        assert rerun.status_code == 200, rerun.text
        assert rerun.json()["id"] != original.id
        assert rerun.json()["output_root"] != str(original.output_root)
        assert rerun.json()["checkpoint_hours"] == 6
        assert scenario.is_file()
        deleted = client.delete(f"/v1/jobs/{original.id}/incomplete-bundle", headers=headers)
        assert deleted.status_code == 200, deleted.text
        assert not original.output_root.exists()
        assert scenario.is_file()
        assert original.id not in {
            job["id"] for job in client.get("/v1/jobs", headers=headers).json()
        }


def test_delete_incomplete_bundle_rejects_unowned_and_completed_outputs(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    scenario = _scenario(workspace, "safe")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "secret")
    headers = {"X-EForge-Token": "secret"}
    with TestClient(app) as client:
        job = queue_studio_generation(
            app.state.studio.jobs, scenario, workspace, app.state.studio.settings
        )
        job.status = "stopped"
        app.state.studio.jobs.save_generation(job)
        marker = job.output_root / ".eforge-desktop-job.json"
        marker.unlink()
        assert (
            client.delete(f"/v1/jobs/{job.id}/incomplete-bundle", headers=headers).status_code
            == 409
        )
        assert job.output_root.exists()
        marker.write_text(json.dumps({"job_id": job.id}), encoding="utf-8")
        (job.output_root / "GENERATION_MANIFEST.json").write_text("{}", encoding="utf-8")
        assert (
            client.delete(f"/v1/jobs/{job.id}/incomplete-bundle", headers=headers).status_code
            == 409
        )
        assert job.output_root.exists()


def test_resume_retains_progress_from_prior_attempts(tmp_path: Path, monkeypatch: object) -> None:
    workspace = tmp_path / "workspace"
    scenario = _scenario(workspace, "alpha")
    original = tmp_path / "private" / "jobs" / "run-one.jsonl"
    original.parent.mkdir(parents=True)
    original.write_text(_progress_line(2), encoding="utf-8")
    job = GenerationJob(
        id="run-one",
        scenario=scenario,
        output_root=workspace / "runs" / "one",
        progress_file=original,
        log_file=tmp_path / "private" / "jobs" / "run-one.log",
        started_at=time.time(),
        status="paused",
        workspace=workspace,
    )
    (job.output_root / ".eforge-generation").mkdir(parents=True)
    monkeypatch.setattr(
        "evidenceforge.generation.checkpoints.store."
        "IncrementalCheckpointStore.recovery_index_entries",
        lambda self, read_only: ((1, "0" * 64),),
    )
    monkeypatch.setattr(
        "evidenceforge.desktop.jobs._start_process", lambda command, cwd, log_file: (99, 1.0)
    )
    resume_generation(job, workspace, tmp_path / "private")
    assert job.status == "running"
    assert job.progress_history == [original]
    assert job_summary(json.loads(job.model_dump_json()))["progress"]["completed_hours"] == 2
    job.progress_file.write_text(_progress_line(3), encoding="utf-8")
    assert job_summary(json.loads(job.model_dump_json()))["progress"]["completed_hours"] == 3

    legacy = job.model_copy(update={"progress_history": []})
    assert job_summary(json.loads(legacy.model_dump_json()))["progress"]["completed_hours"] == 3


def test_progress_append_emits_job_update_without_status_change(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    scenario = _scenario(workspace, "alpha")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "local-secret")
    headers = {"X-EForge-Token": "local-secret"}
    progress_file = tmp_path / "private" / "state" / "jobs" / "steady.jsonl"
    progress_file.parent.mkdir(parents=True)
    progress_file.write_text(_progress_line(1), encoding="utf-8")
    job = GenerationJob(
        id="steady",
        scenario=scenario,
        output_root=workspace / "runs" / "steady",
        progress_file=progress_file,
        log_file=progress_file.with_suffix(".log"),
        started_at=time.time(),
        status="paused",
        workspace=workspace,
    )
    with TestClient(app) as client:
        app.state.studio.jobs.save_generation(job)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            events = client.get("/v1/events", headers=headers).json()
            if any(
                event["kind"] == "job.updated" and event["entity_id"] == job.id for event in events
            ):
                break
            time.sleep(0.05)
        else:
            raise AssertionError("Initial job event was not emitted")
        after = max(event["seq"] for event in events)
        progress_file.write_text(_progress_line(1) + _progress_line(2), encoding="utf-8")
        while time.monotonic() < deadline:
            updates = client.get(f"/v1/events?after={after}", headers=headers).json()
            if any(
                event["kind"] == "job.updated"
                and event["entity_id"] == job.id
                and event["payload"]["progress"]["completed_hours"] == 2
                for event in updates
            ):
                break
            time.sleep(0.05)
        else:
            raise AssertionError("Progress append was not broadcast")
        assert app.state.studio.jobs.load_generations()[0].status == "paused"


def test_missing_checkpoint_is_stopped_and_resume_fails_once(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    scenario = _scenario(workspace, "alpha")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "local-secret")
    headers = {"X-EForge-Token": "local-secret"}
    job = GenerationJob(
        id="no-checkpoint",
        scenario=scenario,
        output_root=workspace / "runs" / "no-checkpoint",
        progress_file=tmp_path / "private" / "state" / "jobs" / "no-checkpoint.jsonl",
        log_file=tmp_path / "private" / "state" / "jobs" / "no-checkpoint.log",
        started_at=time.time(),
        status="running",
        status_message="Pause requested",
        workspace=workspace,
    )
    (job.output_root / ".eforge-generation").mkdir(parents=True)
    with TestClient(app) as client:
        app.state.studio.jobs.save_generation(job)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            saved = app.state.studio.jobs.load_generations()[0]
            if saved.status == "stopped":
                break
            time.sleep(0.05)
        assert saved.status == "stopped"
        assert "resumable checkpoint" in saved.status_message
        response = client.post("/v1/jobs/resume", headers=headers, json={"generation_id": job.id})
        assert response.status_code == 409
        assert app.state.studio.intent.action == "open"
        assert saved.status == "stopped"
        assert "resumable checkpoint" in response.json()["detail"]
        assert not job.log_file.exists()


def test_resume_request_is_consumed_once(tmp_path: Path, monkeypatch: object) -> None:
    workspace = tmp_path / "workspace"
    scenario = _scenario(workspace, "alpha")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "local-secret")
    headers = {"X-EForge-Token": "local-secret"}
    job = GenerationJob(
        id="resumable",
        scenario=scenario,
        output_root=workspace / "runs" / "resumable",
        progress_file=tmp_path / "private" / "state" / "jobs" / "resumable.jsonl",
        log_file=tmp_path / "private" / "state" / "jobs" / "resumable.log",
        started_at=time.time(),
        status="paused",
        workspace=workspace,
    )
    (job.output_root / ".eforge-generation").mkdir(parents=True)
    monkeypatch.setattr(
        "evidenceforge.generation.checkpoints.store."
        "IncrementalCheckpointStore.recovery_index_entries",
        lambda self, read_only: ((1, "0" * 64),),
    )
    launches: list[list[str]] = []

    def fake_start(command: list[str], *, cwd: Path, log_file: Path) -> tuple[int, float]:
        launches.append(command)
        return 999999, 1.0

    monkeypatch.setattr("evidenceforge.desktop.jobs._start_process", fake_start)
    with TestClient(app) as client:
        app.state.studio.jobs.save_generation(job)
        assert (
            client.post(
                "/v1/jobs/resume", headers=headers, json={"generation_id": job.id}
            ).status_code
            == 200
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and app.state.studio.intent.action != "open":
            time.sleep(0.05)
        assert app.state.studio.intent.action == "open"
        time.sleep(1)
        assert len(launches) == 1


def test_platform_paths_and_default_workspace_can_be_isolated(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setenv("EFORGE_STUDIO_HOME", str(tmp_path / "private"))
    monkeypatch.setenv(
        "EFORGE_STUDIO_DEFAULT_WORKSPACE", str(tmp_path / "documents" / "EvidenceForge")
    )
    paths = studio_paths()
    assert paths.settings_file == tmp_path / "private" / "config" / "settings.json"
    assert paths.database_file == tmp_path / "private" / "data" / "studio.sqlite"
    assert default_workspace() == tmp_path / "documents" / "EvidenceForge"
    settings = StudioSettings()
    assert settings.workspace == default_workspace()
    SettingsStore(paths).save(settings)
    assert SettingsStore(paths).load() == settings


def test_linux_xdg_documents_and_private_directories(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.delenv("EFORGE_STUDIO_HOME", raising=False)
    monkeypatch.delenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", raising=False)
    monkeypatch.setattr("evidenceforge.studio.paths.sys.platform", "linux")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    assert default_workspace() == Path.home() / "EvidenceForge"
    dirs = tmp_path / "config" / "user-dirs.dirs"
    dirs.parent.mkdir(parents=True)
    dirs.write_text(f'XDG_DOCUMENTS_DIR="{tmp_path}/my-documents"\n', encoding="utf-8")
    assert default_workspace() == tmp_path / "my-documents" / "EvidenceForge"
    paths = studio_paths()
    assert paths.settings_file == tmp_path / "config" / "evidenceforge" / "settings.json"
    assert paths.database_file == tmp_path / "data" / "evidenceforge" / "studio.sqlite"
    assert paths.logs == tmp_path / "state" / "evidenceforge"


def test_catalog_identity_and_organization_survive_rescan(tmp_path: Path) -> None:
    from evidenceforge.desktop.library import discover_scenarios

    workspace = tmp_path / "workspace"
    scenario = _scenario(workspace, "alpha")
    scenario.write_text(
        scenario.read_text(encoding="utf-8") + "  hostname: SENSOR-ALPHA\n",
        encoding="utf-8",
    )
    source = discover_scenarios(workspace, [])[0]
    store = StudioStore(tmp_path / "private" / "studio.sqlite")
    try:
        first = store.upsert_item(workspace, "scenario", source)
        first.hidden = True
        first.folder = "Exercises"
        store.save_item(first)
        repeated = store.upsert_item(workspace, "scenario", source)
        assert repeated.id == first.id
        assert repeated.hidden
        assert repeated.folder == "Exercises"
        assert [item.id for item in store.search_items(workspace, "alpha")] == [first.id]
        assert [item.id for item in store.search_items(workspace, "yaml:sensor-alpha")] == [
            first.id
        ]
        assert store.search_items(workspace, "name:sensor-alpha") == []
        assert [item.id for item in store.search_items(workspace, '"SENSOR-ALPHA" alpha')] == [
            first.id
        ]
    finally:
        store.close()


def test_projects_group_scenarios_without_moving_files(tmp_path: Path, monkeypatch: object) -> None:
    workspace = tmp_path / "workspace"
    alpha = _scenario(workspace, "alpha")
    _scenario(workspace, "bravo")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    paths = _paths(tmp_path / "private")
    headers = {"X-EForge-Token": "secret"}
    app = create_app(paths, "secret")
    with TestClient(app) as client:
        items = {
            item["name"]: item
            for item in client.get("/v1/bootstrap", headers=headers).json()["items"]
        }
        created = client.post(
            "/v1/projects",
            headers=headers,
            json={"name": "  Incident response  ", "description": "Training cases"},
        )
        assert created.status_code == 200
        project_id = created.json()["id"]
        assert created.json()["name"] == "Incident response"
        draft = client.post(
            "/v1/conversations",
            headers=headers,
            json={"draft_kind": "scenario", "project_id": project_id},
        ).json()
        client.post(
            "/v1/views",
            headers=headers,
            json={"name": "Training cases", "project_id": project_id},
        )
        assert (
            client.post(
                "/v1/projects", headers=headers, json={"name": "INCIDENT RESPONSE"}
            ).status_code
            == 409
        )
        assert client.post("/v1/projects", headers=headers, json={"name": "   "}).status_code == 400
        assigned = client.patch(
            f"/v1/items/{items['alpha']['id']}", headers=headers, json={"project_id": project_id}
        )
        assert assigned.json()["project_id"] == project_id
        assert alpha.is_file()
        client.post("/v1/library/refresh", headers=headers)
        snapshot = client.get("/v1/bootstrap", headers=headers).json()
        assert [project["id"] for project in snapshot["projects"]] == [project_id]
        assert (
            next(item for item in snapshot["items"] if item["name"] == "alpha")["project_id"]
            == project_id
        )
        assert (
            next(item for item in snapshot["items"] if item["name"] == "bravo")["project_id"]
            is None
        )
        renamed = client.patch(
            f"/v1/projects/{project_id}", headers=headers, json={"name": "Casework"}
        )
        assert renamed.json()["id"] == project_id
        assert renamed.json()["name"] == "Casework"
        assert (
            client.patch(
                f"/v1/items/{items['alpha']['id']}", headers=headers, json={"project_id": "missing"}
            ).status_code
            == 404
        )
        other_workspace = tmp_path / "other-workspace"
        client.post("/v1/workspaces/select", headers=headers, json={"path": str(other_workspace)})
        assert client.get("/v1/projects", headers=headers).json() == []
        assert client.get("/v1/views", headers=headers).json() == []
        assert (
            client.patch(
                f"/v1/items/{items['alpha']['id']}",
                headers=headers,
                json={"project_id": project_id},
            ).status_code
            == 404
        )
        assert (
            client.patch(
                f"/v1/projects/{project_id}", headers=headers, json={"name": "Wrong workspace"}
            ).status_code
            == 404
        )
        client.post("/v1/workspaces/select", headers=headers, json={"path": str(workspace)})
        removed = client.delete(f"/v1/projects/{project_id}", headers=headers)
        assert removed.json() == {"status": "deleted", "ungrouped": 1}
        saved_view = client.get("/v1/views", headers=headers).json()[0]
        assert saved_view["project_id"] is None
        assert saved_view["ungrouped"]
        assert (
            next(
                chat
                for chat in client.get("/v1/conversations", headers=headers).json()
                if chat["id"] == draft["id"]
            )["draft_project_id"]
            is None
        )
        assert client.get("/v1/projects", headers=headers).json() == []
        assert (
            next(
                item
                for item in client.get("/v1/bootstrap", headers=headers).json()["items"]
                if item["name"] == "alpha"
            )["project_id"]
            is None
        )
        assert alpha.is_file()
    reopened = StudioStore(paths.database_file)
    try:
        assert reopened.projects(workspace) == []
        assert reopened.item(items["alpha"]["id"]).project_id is None
    finally:
        reopened.close()


def test_saved_views_are_scoped_to_workspace_and_can_be_recalled(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    _scenario(workspace, "alpha")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    paths = _paths(tmp_path / "private")
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(paths, "secret")) as client:
        project = client.post("/v1/projects", headers=headers, json={"name": "Training"}).json()
        view = {
            "name": "Active exercises",
            "kind": "scenario",
            "search": "yaml:domain-controller",
            "project_id": project["id"],
            "show_hidden": True,
        }
        assert client.post("/v1/views", json=view).status_code == 401
        created = client.post("/v1/views", headers=headers, json=view)
        assert created.status_code == 200
        assert created.json()["project_id"] == project["id"]
        assert client.get("/v1/bootstrap", headers=headers).json()["views"] == [created.json()]
        assert (
            client.post(
                "/v1/views", headers=headers, json={**view, "name": "active exercises"}
            ).status_code
            == 409
        )
        assert (
            client.post(
                "/v1/views",
                headers=headers,
                json={**view, "name": "Missing", "project_id": "missing"},
            ).status_code
            == 404
        )
        other_workspace = tmp_path / "other-workspace"
        client.post("/v1/workspaces/select", headers=headers, json={"path": str(other_workspace)})
        assert client.get("/v1/views", headers=headers).json() == []
        client.post("/v1/workspaces/select", headers=headers, json={"path": str(workspace)})
        assert client.get("/v1/views", headers=headers).json() == [created.json()]
        assert client.delete("/v1/views/Active%20exercises", headers=headers).status_code == 200
        assert client.get("/v1/views", headers=headers).json() == []


def test_virtual_folders_organize_items_and_saved_views_without_moving_files(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    scenario = _scenario(workspace, "alpha")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(_paths(tmp_path / "private"), "secret")) as client:
        item = client.get("/v1/bootstrap", headers=headers).json()["items"][0]
        assert (
            client.post("/v1/folders", headers=headers, json={"name": "../../bad"}).status_code
            == 400
        )
        assert client.post("/v1/folders", headers=headers, json={"name": " Training "}).json() == {
            "name": "Training"
        }
        assert (
            client.post("/v1/folders", headers=headers, json={"name": "training"}).status_code
            == 409
        )
        assert (
            client.patch(
                f"/v1/items/{item['id']}", headers=headers, json={"folder": "Training"}
            ).json()["folder"]
            == "Training"
        )
        assert (
            client.post(
                "/v1/views", headers=headers, json={"name": "Training work", "folder": "Training"}
            ).status_code
            == 200
        )
        renamed = client.patch("/v1/folders/Training", headers=headers, json={"name": "Active"})
        assert renamed.json() == {"name": "Active"}
        snapshot = client.get("/v1/bootstrap", headers=headers).json()
        assert snapshot["folders"] == ["Active"]
        assert snapshot["items"][0]["folder"] == "Active"
        assert snapshot["views"][0]["folder"] == "Active"
        assert scenario.is_file()
        assert client.delete("/v1/folders/Active", headers=headers).status_code == 200
        snapshot = client.get("/v1/bootstrap", headers=headers).json()
        assert snapshot["folders"] == []
        assert snapshot["items"][0]["folder"] is None
        assert snapshot["views"][0]["folder"] is None
        assert scenario.is_file()


def test_draft_conversation_links_authored_file_and_project(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    paths = _paths(tmp_path / "private")
    headers = {"X-EForge-Token": "secret"}
    app = create_app(paths, "secret")
    with TestClient(app) as client:
        project = client.post("/v1/projects", headers=headers, json={"name": "Casework"}).json()
        created = client.post(
            "/v1/conversations",
            headers=headers,
            json={"draft_kind": "scenario", "project_id": project["id"], "name": "New case"},
        )
        assert created.status_code == 200, created.text
        draft = created.json()
        target = Path(draft["draft_path"])
        assert draft["item_id"] is None
        assert draft["draft_project_id"] == project["id"]
        assert draft["draft_name"] == "New case"
        assert target.parent.parent == workspace / "scenarios"
        assert not target.exists()
        assert (
            client.post(
                "/v1/conversations",
                headers=headers,
                json={"draft_kind": "scenario", "project_id": "missing"},
            ).status_code
            == 404
        )
        assert (
            client.post(
                "/v1/conversations",
                headers=headers,
                json={"draft_kind": "scenario", "item_id": "item"},
            ).status_code
            == 400
        )
        target.parent.mkdir(parents=True)
        target.write_text(
            "name: new-case\nversion: '1.0'\nenvironment:\n  users: []\n  systems: []\n",
            encoding="utf-8",
        )
        active_draft = app.state.studio.store.conversation(draft["id"])
        active_draft.active = True
        app.state.studio.store.save_conversation(active_draft)
        client.post("/v1/library/refresh", headers=headers)
        assert app.state.studio.store.conversation(draft["id"]).item_id is not None
        active_draft.active = False
        app.state.studio.store.save_conversation(active_draft)
        client.post("/v1/library/refresh", headers=headers)
        snapshot = client.get("/v1/bootstrap", headers=headers).json()
        item = next(item for item in snapshot["items"] if item["path"] == str(target))
        linked = next(chat for chat in snapshot["conversations"] if chat["id"] == draft["id"])
        assert item["project_id"] == project["id"]
        assert linked["item_id"] == item["id"]
        assert linked["draft_kind"] is None
        assert linked["draft_path"] == str(target)
        client.post("/v1/library/refresh", headers=headers)
        assert client.get("/v1/conversations", headers=headers).json()[0]["item_id"] == item["id"]
        pack_draft = client.post(
            "/v1/conversations", headers=headers, json={"draft_kind": "industry_pack"}
        ).json()
        pack_path = Path(pack_draft["draft_path"])
        assert pack_path.parent.parent == workspace / ".eforge" / "packs"
        assert (
            client.post(
                "/v1/conversations",
                headers=headers,
                json={"draft_kind": "industry_pack", "project_id": project["id"]},
            ).status_code
            == 400
        )
        pack_path.parent.mkdir(parents=True)
        pack_path.write_text(
            "name: training-industry\ntype: industry\nversion: '1.0'\n",
            encoding="utf-8",
        )
        client.post("/v1/library/refresh", headers=headers)
        pack_item = next(
            entry
            for entry in client.get("/v1/bootstrap", headers=headers).json()["items"]
            if entry["path"] == str(pack_path)
        )
        assert pack_item["kind"] == "industry_pack"
        assert (
            next(
                chat
                for chat in client.get("/v1/conversations", headers=headers).json()
                if chat["id"] == pack_draft["id"]
            )["item_id"]
            == pack_item["id"]
        )
    reopened = StudioStore(paths.database_file)
    try:
        assert reopened.conversation(draft["id"]).item_id == item["id"]
        assert reopened.item(item["id"]).project_id == project["id"]
    finally:
        reopened.close()


def test_validation_revision_is_stale_after_authored_yaml_changes(tmp_path: Path) -> None:
    from evidenceforge.desktop.library import discover_scenarios
    from evidenceforge.studio.service import ValidationResult

    workspace = tmp_path / "workspace"
    scenario = _scenario(workspace, "alpha")
    store = StudioStore(tmp_path / "studio.sqlite")
    try:
        source = discover_scenarios(workspace, [])[0]
        original = store.upsert_item(workspace, "scenario", source)
        store.save_validation(
            original.id,
            original.source_sha256,
            ValidationResult(exit_code=0, report={"severity_counts": {"warning": 0}}),
        )
        scenario.write_text(
            scenario.read_text(encoding="utf-8") + "description: revised\n", encoding="utf-8"
        )
        updated = store.upsert_item(workspace, "scenario", discover_scenarios(workspace, [])[0])
        assert updated.id == original.id
        assert updated.source_sha256 != original.source_sha256
        assert (
            store.validations([updated.id])[updated.id]["source_sha256"] == original.source_sha256
        )
    finally:
        store.close()


def test_completed_evaluation_summary_restores_saved_scorecard(tmp_path: Path) -> None:
    result_file = tmp_path / "evaluation.json"
    result_file.write_text(
        json.dumps(
            {
                "scenario_name": "casework",
                "evaluated_at": "2026-09-30T16:00:00Z",
                "overall_score": 87.6,
                "acceptance_passed": True,
                "total_records": 12345,
            }
        ),
        encoding="utf-8",
    )
    job = EvaluationJob(
        id="evaluation-1",
        generation_id="generation-1",
        workspace=tmp_path,
        output_root=tmp_path / "run",
        result_file=result_file,
        log_file=tmp_path / "evaluation.log",
        command=[],
        created_at=1,
        status="completed",
    )
    summary = job_summary(json.loads(job.model_dump_json()))
    assert summary["scorecard"]["overall_score"] == 87.6
    assert summary["scorecard"]["acceptance_passed"] is True
    assert summary["scorecard"]["total_records"] == 12345
    result_file.write_text("not JSON", encoding="utf-8")
    assert job_summary(json.loads(job.model_dump_json()))["scorecard"]["error"]


def test_scorecard_detail_reads_only_saved_workspace_evaluation(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    other_workspace = tmp_path / "other"
    paths = _paths(tmp_path / "private")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(paths, "secret")
    result_file = paths.state / "jobs" / "evaluation-1.json"
    result_file.parent.mkdir(parents=True, exist_ok=True)
    result_file.write_text(
        json.dumps(
            {
                "scenario_name": "casework",
                "evaluated_at": "2026-09-30T16:00:00Z",
                "overall_score": 87.6,
                "acceptance_passed": True,
                "total_records": 12345,
                "source_counts": {"zeek_conn": 321},
                "pillars": [
                    {
                        "number": 1,
                        "name": "Parseability",
                        "weight": 0.2,
                        "score": 92,
                        "sub_scores": [
                            {"name": "Schema", "key": "schema", "weight": 1, "score": 92}
                        ],
                    }
                ],
                "acceptance_criteria": [
                    {
                        "name": "Schema gate",
                        "pillar": "Parseability",
                        "sub_score_key": "schema",
                        "threshold": 80,
                        "actual": 92,
                        "passed": True,
                        "level": "hard",
                    }
                ],
                "flags": ["Review timestamps"],
            }
        ),
        encoding="utf-8",
    )
    job = EvaluationJob(
        id="evaluation-1",
        generation_id="generation-1",
        workspace=workspace,
        output_root=workspace / "run",
        result_file=result_file,
        log_file=paths.state / "jobs" / "evaluation-1.log",
        command=[],
        created_at=1,
        status="completed",
    )
    app.state.studio.store.save_job(job.id, workspace, "evaluation", job)
    headers = {"X-EForge-Token": "secret"}
    with TestClient(app) as client:
        assert client.get("/v1/jobs/evaluation-1/scorecard").status_code == 401
        response = client.get("/v1/jobs/evaluation-1/scorecard", headers=headers)
        assert response.status_code == 200
        detail = response.json()
        assert detail["overall_score"] == 87.6
        assert detail["pillars"][0]["sub_scores"][0]["score"] == 92
        assert detail["acceptance_criteria"][0]["passed"] is True
        client.post("/v1/workspaces/select", headers=headers, json={"path": str(other_workspace)})
        assert client.get("/v1/jobs/evaluation-1/scorecard", headers=headers).status_code == 404
        client.post("/v1/workspaces/select", headers=headers, json={"path": str(workspace)})
        result_file.write_text("invalid JSON", encoding="utf-8")
        assert client.get("/v1/jobs/evaluation-1/scorecard", headers=headers).status_code == 422


def test_service_auth_workspace_chat_and_validation(tmp_path: Path, monkeypatch: object) -> None:
    workspace = tmp_path / "workspace"
    _scenario(workspace, "alpha")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "local-secret")
    with TestClient(app) as client:
        assert client.get("/v1/bootstrap").status_code == 401
        headers = {"X-EForge-Token": "local-secret"}
        snapshot = client.get("/v1/bootstrap", headers=headers).json()
        assert snapshot["settings"]["workspace"] == str(workspace)
        assert len([item for item in snapshot["items"] if item["kind"] == "scenario"]) == 1
        item_id = snapshot["items"][0]["id"]
        created = client.post("/v1/conversations", headers=headers, json={"item_id": item_id})
        assert created.status_code == 200
        assert created.json()["item_id"] == item_id
        assert (
            client.get("/v1/conversations", headers=headers).json()[0]["id"] == created.json()["id"]
        )
        wrong = client.post("/v1/validate", headers=headers, json={"scenario_id": "missing"})
        assert wrong.status_code == 404
        next_workspace = tmp_path / "other"
        switched = client.post(
            "/v1/workspaces/select", headers=headers, json={"path": str(next_workspace)}
        )
        assert switched.status_code == 200
        assert (next_workspace / "scenarios").is_dir()
        assert (next_workspace / "runs").is_dir()
        assert not [item for item in switched.json()["items"] if item["kind"] == "scenario"]


def test_conversation_controls_and_generation_capacity_persist(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    _scenario(workspace, "alpha")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "secret")
    headers = {"X-EForge-Token": "secret"}
    with TestClient(app) as client:
        item_id = client.get("/v1/bootstrap", headers=headers).json()["items"][0]["id"]
        chat = client.post("/v1/conversations", headers=headers, json={"item_id": item_id}).json()
        renamed = client.patch(
            f"/v1/conversations/{chat['id']}", headers=headers, json={"title": "Timeline review"}
        )
        assert renamed.json()["title"] == "Timeline review"
        assert client.delete(f"/v1/conversations/{chat['id']}", headers=headers).status_code == 200
        assert client.get("/v1/conversations", headers=headers).json() == []
        settings = client.get("/v1/settings", headers=headers).json()
        settings["max_concurrent_generations"] = 1
        assert client.put("/v1/settings", headers=headers, json=settings).status_code == 200
    assert SettingsStore(_paths(tmp_path / "private")).load().max_concurrent_generations == 1


def test_answered_codex_requests_return_active_chat_to_working(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    _scenario(workspace, "alpha")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "secret")

    async def fake_respond(_request_id: str, _result: dict[str, object]) -> None:
        return None

    monkeypatch.setattr(app.state.studio.codex, "respond", fake_respond)
    headers = {"X-EForge-Token": "secret"}
    with TestClient(app) as client:
        item_id = client.get("/v1/bootstrap", headers=headers).json()["items"][0]["id"]
        created = client.post(
            "/v1/conversations", headers=headers, json={"item_id": item_id}
        ).json()
        conversation = Conversation.model_validate(created)
        conversation.thread_id = "thread-alpha"
        conversation.active = True
        conversation.needs_attention = True
        app.state.studio.store.save_conversation(conversation)
        app.state.studio.pending_codex_requests = {
            "first": {
                "method": "item/tool/requestUserInput",
                "params": {"threadId": "thread-alpha"},
            },
            "second": {
                "method": "item/tool/requestUserInput",
                "params": {"threadId": "thread-alpha"},
            },
        }
        first = client.post(
            "/v1/codex/reply", headers=headers, json={"request_id": "first", "result": {}}
        )
        assert first.status_code == 200
        assert app.state.studio.store.conversation(conversation.id).needs_attention
        second = client.post(
            "/v1/codex/reply", headers=headers, json={"request_id": "second", "result": {}}
        )
        assert second.status_code == 200
        resumed = app.state.studio.store.conversation(conversation.id)
        assert resumed.active
        assert not resumed.needs_attention


def test_abandoned_chat_turns_do_not_count_after_restart_or_codex_disconnect(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "secret")
    studio = app.state.studio
    conversation = Conversation(
        workspace=workspace, thread_id="thread-alpha", active=True, needs_attention=True
    )
    studio.store.save_conversation(conversation)
    with TestClient(app) as client:
        snapshot = client.get("/v1/bootstrap", headers={"X-EForge-Token": "secret"}).json()
        assert not snapshot["conversations"][0]["active"]
        assert not snapshot["conversations"][0]["needs_attention"]

        conversation.active = True
        conversation.needs_attention = True
        studio.store.save_conversation(conversation)
        studio.pending_codex_requests["approval"] = {
            "method": "item/tool/requestUserInput",
            "params": {"threadId": "thread-alpha"},
        }
        asyncio.run(studio._codex_event("codex/disconnected", {}))
        recovered = studio.store.conversation(conversation.id)
        assert recovered is not None
        assert not recovered.active
        assert not recovered.needs_attention
        assert not studio.pending_codex_requests


def test_controller_holds_queued_generations_at_selected_capacity(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    scenario = _scenario(workspace, "alpha")
    store = StudioStore(tmp_path / "studio.sqlite")
    jobs = StudioJobStore(store, tmp_path / "state")
    starts: list[list[str]] = []

    def fake_start(command: list[str], *, cwd: Path, log_file: Path) -> tuple[int, float]:
        starts.append(command)
        return 1000 + len(starts), time.time()

    monkeypatch.setattr("evidenceforge.desktop.controller._start_process", fake_start)
    try:
        for number in range(3):
            jobs.save_generation(
                GenerationJob(
                    id=f"job-{number}",
                    scenario=scenario,
                    output_root=tmp_path / f"run-{number}",
                    progress_file=tmp_path / f"progress-{number}.jsonl",
                    log_file=tmp_path / f"job-{number}.log",
                    started_at=time.time(),
                    status="queued",
                    workspace=workspace,
                    command=["fake", str(number)],
                )
            )
        _worker_tick(
            jobs, ControlIntent(action="open", settings=AppSettings(max_concurrent_generations=1))
        )
        assert len(starts) == 1
        assert [job.status for job in jobs.load_generations()].count("queued") == 2
    finally:
        store.close()


def test_completed_bundle_export_keeps_runs_separate_and_includes_report(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    scenario = _scenario(workspace, "alpha")
    (scenario.parent / "ENVIRONMENT.md").write_text("Analyst context", encoding="utf-8")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "secret")
    headers = {"X-EForge-Token": "secret"}
    with TestClient(app) as client:
        service = app.state.studio
        item_id = client.get("/v1/bootstrap", headers=headers).json()["items"][0]["id"]
        run = workspace / "runs" / "alpha" / "run-one"
        (run / "data").mkdir(parents=True)
        (run / "data" / "events.log").write_text("event\n", encoding="utf-8")
        (run / "GROUND_TRUTH.md").write_text("answer key", encoding="utf-8")
        (run / "RESOLVED_SCENARIO.yaml").write_text("name: alpha\n", encoding="utf-8")
        (run / "GENERATION_MANIFEST.json").write_text("{}", encoding="utf-8")
        generation = GenerationJob(
            id="generation-one",
            scenario=scenario,
            output_root=run,
            progress_file=tmp_path / "progress.jsonl",
            log_file=tmp_path / "generation.log",
            started_at=time.time(),
            status="completed",
            workspace=workspace,
            source_sha256=sha256(scenario.read_bytes()).hexdigest(),
        )
        service.jobs.save_generation(generation)
        report = tmp_path / "evaluation.json"
        report.write_text('{"score": 92}', encoding="utf-8")
        service.jobs.save_evaluation(
            EvaluationJob(
                id="evaluation-one",
                generation_id=generation.id,
                workspace=workspace,
                output_root=run,
                result_file=report,
                log_file=tmp_path / "evaluation.log",
                command=["fake"],
                created_at=time.time(),
                status="completed",
            )
        )
        response = client.get(f"/v1/items/{item_id}/bundles/{generation.id}.zip", headers=headers)
        assert response.status_code == 200
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            names = set(archive.namelist())
            assert "run/data/events.log" in names
            assert "run/GROUND_TRUTH.md" in names
            assert "run/RESOLVED_SCENARIO.yaml" in names
            assert "authored/scenario.yaml" in names
            assert "authored/ENVIRONMENT.md" in names
            assert "evaluations/evaluation-one.json" in names
        (run / "unsafe-link").symlink_to(scenario)
        assert (
            client.get(
                f"/v1/items/{item_id}/bundles/{generation.id}.zip", headers=headers
            ).status_code
            == 400
        )
        assert (
            client.get(f"/v1/items/{item_id}/bundles/other-run.zip", headers=headers).status_code
            == 404
        )


def test_two_generation_progress_streams_reconcile_independently(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    _scenario(workspace, "alpha")
    _scenario(workspace, "bravo")
    fake = tmp_path / "fake-eforge"
    fake.write_text(
        "#!" + sys.executable + "\n"
        "import json, pathlib, sys, time\n"
        "args = sys.argv\n"
        "progress = pathlib.Path(args[args.index('--progress-jsonl') + 1])\n"
        "output = pathlib.Path(args[args.index('--output') + 1])\n"
        "progress.parent.mkdir(parents=True, exist_ok=True)\n"
        "for completed in (1, 2):\n"
        "    with progress.open('a') as stream:\n"
        "        stream.write(json.dumps({'schema_version': 1, 'event': 'hour_progress', "
        "'data': {'completed_simulated_hours': completed, 'total_simulated_hours': 2, "
        "'hour': completed, 'total_hours': 2}}) + '\\n')\n"
        "    time.sleep(0.15)\n"
        "(output / 'GENERATION_MANIFEST.json').write_text('{}')\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    monkeypatch.setenv("EFORGE_DESKTOP_EFORGE_BIN", str(fake))
    app = create_app(_paths(tmp_path / "private"), "local-secret")
    headers = {"X-EForge-Token": "local-secret"}
    with TestClient(app) as client:
        items = client.get("/v1/bootstrap", headers=headers).json()["items"]
        ids = [item["id"] for item in items if item["kind"] == "scenario"]
        assert len(ids) == 2
        created = [
            client.post("/v1/jobs/generations", headers=headers, json={"scenario_id": item_id})
            for item_id in ids
        ]
        assert all(response.status_code == 200 for response in created)
        assert created[0].json()["id"] != created[1].json()["id"]
        deadline = time.monotonic() + 8
        jobs: list[dict[str, object]] = []
        while time.monotonic() < deadline:
            jobs = client.get("/v1/jobs", headers=headers).json()
            if len(jobs) == 2 and all(job["status"] == "completed" for job in jobs):
                break
            time.sleep(0.1)
        assert len(jobs) == 2
        assert all(job["status"] == "completed" for job in jobs)
        assert all(job["progress"]["completed_hours"] == 2 for job in jobs)
        assert len({job["progress_file"] for job in jobs}) == 2
        assert all(
            Path(str(job["output_root"]), "GENERATION_MANIFEST.json").is_file() for job in jobs
        )
        events = client.get("/v1/events", headers=headers).json()
        assert any(event["kind"] == "job.updated" for event in events)


def test_codex_turn_uses_scenario_context_and_preserves_fast_completion(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    scenario = _scenario(workspace, "alpha")
    calls = tmp_path / "codex-calls.jsonl"
    fake = tmp_path / "fake-codex"
    fake.write_text(
        "#!" + sys.executable + "\n"
        "import json, sys\n"
        f"calls = open({str(calls)!r}, 'a', encoding='utf-8')\n"
        "for line in sys.stdin:\n"
        "    request = json.loads(line)\n"
        "    assert isinstance(request.get('params'), dict)\n"
        "    if 'id' not in request: continue\n"
        "    calls.write(json.dumps(request) + '\\n'); calls.flush()\n"
        "    method = request['method']\n"
        "    result = {}\n"
        "    if method == 'skills/list':\n"
        "        result = {'data': [{'skills': [{'name': 'eforge-scenario', "
        "'path': '/tmp/skills/eforge-scenario/SKILL.md', 'enabled': True}]}]}\n"
        "    elif method == 'thread/start': result = {'thread': {'id': 'thread-alpha'}}\n"
        "    elif method == 'thread/read': result = {'thread': {'turns': []}}\n"
        "    elif method == 'model/list': result = {'data': []}\n"
        "    elif method == 'account/read': result = {'account': {'type': 'chatgpt'}}\n"
        "    if method == 'turn/start':\n"
        "        print(json.dumps({'method': 'turn/completed', 'params': "
        "{'threadId': 'thread-alpha', 'turn': {'status': 'completed'}}}), flush=True)\n"
        "        result = {'turn': {'id': 'turn-alpha', 'status': 'completed'}}\n"
        "    print(json.dumps({'id': request['id'], 'result': result}), flush=True)\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    monkeypatch.setenv("EFORGE_DESKTOP_CODEX_BIN", str(fake))
    app = create_app(_paths(tmp_path / "private"), "local-secret")
    headers = {"X-EForge-Token": "local-secret"}
    with TestClient(app) as client:
        item_id = next(
            item["id"]
            for item in client.get("/v1/bootstrap", headers=headers).json()["items"]
            if item["kind"] == "scenario"
        )
        chat = client.post("/v1/conversations", headers=headers, json={"item_id": item_id}).json()
        response = client.post(
            f"/v1/conversations/{chat['id']}/turns",
            headers=headers,
            json={"text": "Validate this scenario"},
        )
        assert response.status_code == 200, response.text
        assert response.json()["active"] is False
        assert response.json()["turn_id"] == "turn-alpha"
        assert response.json()["delivery"] == "confirmed"
        assert (
            client.get(f"/v1/conversations/{chat['id']}/history", headers=headers).status_code
            == 200
        )
    records = [json.loads(line) for line in calls.read_text(encoding="utf-8").splitlines()]
    started = next(record for record in records if record["method"] == "thread/start")
    assert str(scenario) in started["params"]["developerInstructions"]
    turn = next(record for record in records if record["method"] == "turn/start")
    assert "thread/resume" not in [record["method"] for record in records]
    assert turn["params"]["input"][0] == {"type": "text", "text": "Validate this scenario"}
    assert turn["params"]["input"][1]["name"] == "eforge-scenario"


def test_uncertain_codex_turn_preserves_attempt_without_overwriting_fast_completion(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    _scenario(workspace, "alpha")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "local-secret")
    studio = app.state.studio
    headers = {"X-EForge-Token": "local-secret"}

    async def fake_call(method: str, params: dict[str, object], *, timeout: float = 30) -> dict:
        if method == "turn/start":
            if params["threadId"] == "fast-completion":
                await studio._codex_event(
                    "turn/completed",
                    {"threadId": "fast-completion", "turn": {"status": "completed"}},
                )
            raise CodexTimeoutError("Codex did not answer turn/start")
        return {"thread": {"status": {"type": "active"}, "turns": []}}

    monkeypatch.setattr(studio.codex, "call", fake_call)
    with TestClient(app) as client:
        item_id = next(
            item["id"]
            for item in client.get("/v1/bootstrap", headers=headers).json()["items"]
            if item["kind"] == "scenario"
        )
        for thread_id, expected_active in (("uncertain", True), ("fast-completion", False)):
            created = client.post(
                "/v1/conversations", headers=headers, json={"item_id": item_id}
            ).json()
            chat = studio.store.conversation(created["id"])
            assert chat is not None
            chat.thread_id = thread_id
            studio.store.save_conversation(chat)
            response = client.post(
                f"/v1/conversations/{chat.id}/turns",
                headers=headers,
                json={"text": "Check the current scenario"},
            )
            assert response.status_code == 200, response.text
            assert response.json()["delivery"] == "uncertain"
            assert response.json()["active"] is expected_active
            assert studio.store.conversation(chat.id).active is expected_active


def test_signed_out_codex_stays_available_for_login(tmp_path: Path, monkeypatch: object) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "local-secret")
    studio = app.state.studio
    calls: list[str] = []

    async def fake_call(method: str, _params: dict[str, object], *, timeout: float = 30) -> dict:
        if method == "thread/loaded/list":
            return {"data": []}
        calls.append(method)
        if method == "account/read":
            return {"account": None}
        raise AssertionError(f"Signed-out status should not call {method}")

    monkeypatch.setattr(studio.codex, "call", fake_call)
    with TestClient(app) as client:
        response = client.get("/v1/codex/status", headers={"X-EForge-Token": "local-secret"})
        assert response.status_code == 200
        assert response.json()["available"] is True
        assert response.json()["account_ready"] is False
        assert response.json()["models"] == {"data": []}
        assert calls == ["account/read"]


def test_new_draft_turn_uses_its_target_path_and_authoring_skill(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    calls = tmp_path / "codex-calls.jsonl"
    fake = tmp_path / "fake-codex"
    fake.write_text(
        "#!" + sys.executable + "\n"
        "import json, sys\n"
        f"calls = open({str(calls)!r}, 'a', encoding='utf-8')\n"
        "for line in sys.stdin:\n"
        "    request = json.loads(line)\n"
        "    if 'id' not in request: continue\n"
        "    calls.write(json.dumps(request) + '\\n'); calls.flush()\n"
        "    method = request['method']\n"
        "    result = {}\n"
        "    if method == 'skills/list':\n"
        "        result = {'data': [{'skills': [{'name': 'eforge-scenario', "
        "'path': '/tmp/skills/eforge-scenario/SKILL.md', 'enabled': True}]}]}\n"
        "    elif method == 'thread/start': result = {'thread': {'id': 'thread-draft'}}\n"
        "    elif method == 'thread/read': result = {'thread': {'turns': []}}\n"
        "    if method == 'turn/start':\n"
        "        print(json.dumps({'method': 'turn/completed', 'params': "
        "{'threadId': 'thread-draft', 'turn': {'status': 'completed'}}}), flush=True)\n"
        "    print(json.dumps({'id': request['id'], 'result': result}), flush=True)\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    monkeypatch.setenv("EFORGE_DESKTOP_CODEX_BIN", str(fake))
    app = create_app(_paths(tmp_path / "private"), "local-secret")
    headers = {"X-EForge-Token": "local-secret"}
    with TestClient(app) as client:
        draft = client.post(
            "/v1/conversations", headers=headers, json={"draft_kind": "scenario"}
        ).json()
        response = client.post(
            f"/v1/conversations/{draft['id']}/turns",
            headers=headers,
            json={"text": "Create a branch office investigation"},
        )
        assert response.status_code == 200, response.text
        assert response.json()["active"] is False
        assert not Path(draft["draft_path"]).exists()
    records = [json.loads(line) for line in calls.read_text(encoding="utf-8").splitlines()]
    started = next(record for record in records if record["method"] == "thread/start")
    assert draft["draft_path"] in started["params"]["developerInstructions"]
    turn = next(record for record in records if record["method"] == "turn/start")
    assert turn["params"]["input"][1]["name"] == "eforge-scenario"


def test_close_conflict_and_paused_reopen_require_explicit_resume(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    scenario = _scenario(workspace, "alpha")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "local-secret")
    headers = {"X-EForge-Token": "local-secret"}
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(10)"], start_new_session=True
    )
    try:
        with TestClient(app) as client:
            settings = client.get("/v1/settings", headers=headers).json()
            settings["quit"]["action"] = "pause"
            client.put("/v1/settings", headers=headers, json=settings)
            job = GenerationJob(
                id="older-no-checkpoints",
                scenario=scenario,
                output_root=workspace / "runs" / "older",
                progress_file=tmp_path / "progress.jsonl",
                log_file=tmp_path / "generation.log",
                pid=process.pid,
                process_created_at=psutil.Process(process.pid).create_time(),
                started_at=time.time(),
                status="running",
                workspace=workspace,
                checkpoint_hours=0,
            )
            app.state.studio.jobs.save_generation(job)
            conflict = client.post("/v1/session/close", headers=headers)
            assert conflict.status_code == 409
            assert conflict.json()["detail"]["job_ids"] == [job.id]
            resolved = client.post(
                "/v1/session/close",
                headers=headers,
                json={"generation_exceptions": {job.id: "continue"}},
            )
            assert resolved.status_code == 200
            assert app.state.studio.intent.generation_exceptions[job.id] == "continue"
            client.post("/v1/session/open", headers=headers)
            assert app.state.studio.intent.action == "pause"
            response = client.post(
                "/v1/jobs/resume", headers=headers, json={"generation_id": job.id}
            )
            assert response.status_code == 409
            assert app.state.studio.intent.action == "pause"
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_delete_on_quit_requires_confirmation_and_cors_is_narrow(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(tmp_path / "workspace"))
    app = create_app(_paths(tmp_path / "private"), "local-secret")
    headers = {"X-EForge-Token": "local-secret"}
    with TestClient(app) as client:
        preflight = client.options(
            "/v1/bootstrap",
            headers={
                "Origin": "tauri://localhost",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "X-EForge-Token",
            },
        )
        assert preflight.headers["access-control-allow-origin"] == "tauri://localhost"
        settings = client.get("/v1/settings", headers=headers).json()
        settings["quit"]["action"] = "kill"
        settings["quit"]["kill_incomplete_bundles"] = "delete"
        client.put("/v1/settings", headers=headers, json=settings)
        assert client.post("/v1/session/close", headers=headers).status_code == 409
        assert (
            client.post(
                "/v1/session/close", headers=headers, json={"confirm_delete": True}
            ).status_code
            == 200
        )


def test_authoring_quit_choice_is_durable_and_stop_does_not_block_close(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "local-secret")
    studio = app.state.studio
    interrupted = Event()
    calls: list[str] = []

    async def fake_call(
        method: str, _params: dict[str, object], *, timeout: float = 30
    ) -> dict[str, object]:
        calls.append(method)
        if method == "turn/interrupt":
            interrupted.set()
            await asyncio.sleep(0.4)
        if method == "thread/read":
            return {"thread": {"status": {"type": "active"}}}
        return {"data": []}

    monkeypatch.setattr(studio.codex, "call", fake_call)
    headers = {"X-EForge-Token": "local-secret"}
    with TestClient(app) as client:
        studio.store.save_conversation(
            Conversation(workspace=workspace, thread_id="active-turn", active=True)
        )
        start = time.monotonic()
        response = client.post("/v1/session/close", headers=headers)
        assert response.status_code == 200
        assert time.monotonic() - start < 0.3
        assert studio.store.load_control()["authoring_turns"] == "stop"
        assert interrupted.wait(timeout=2)
        client.post("/v1/session/open", headers=headers)

        calls.clear()
        settings = client.get("/v1/settings", headers=headers).json()
        settings["quit"]["authoring_turns"] = "finish"
        assert client.put("/v1/settings", headers=headers, json=settings).status_code == 200
        response = client.post("/v1/session/close", headers=headers)
        assert response.status_code == 200
        assert studio.store.load_control()["authoring_turns"] == "finish"
        time.sleep(0.1)
        assert "turn/interrupt" not in calls


def test_codex_health_reports_stall_and_recovers(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(tmp_path / "workspace"))
    studio = StudioService(_paths(tmp_path / "private"), "secret")
    probes = 0

    async def probe(
        method: str, params: dict[str, object] | None = None, *, timeout: float = 30
    ) -> dict[str, object]:
        nonlocal probes
        assert method == "thread/loaded/list"
        assert params == {}
        probes += 1
        if probes == 1:
            raise CodexTimeoutError("Codex did not answer the health probe")
        return {"data": []}

    monkeypatch.setattr(studio.codex, "call", probe)

    async def exercise() -> None:
        await studio.check_codex_health()
        assert studio.codex_health.state == "stalled"
        await studio.check_codex_health()
        assert studio.codex_health.state == "connected"

    try:
        asyncio.run(exercise())
    finally:
        studio.store.close()


def test_completed_codex_history_clears_stale_interruption_note(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(tmp_path / "workspace"))
    studio = StudioService(_paths(tmp_path / "private"), "secret")
    conversation = Conversation(
        workspace=studio.settings.workspace,
        thread_id="saved-thread",
        connection_note="Studio restarted before this turn finished",
    )
    studio.store.save_conversation(conversation)
    try:
        asyncio.run(
            studio.reconcile_codex_thread(
                conversation,
                {"thread": {"status": {"type": "notLoaded"}, "turns": [{"status": "completed"}]}},
            )
        )
        saved = studio.store.conversation(conversation.id)
        assert saved is not None
        assert saved.connection_note is None
    finally:
        studio.store.close()


def test_empty_new_codex_rollout_is_pending_without_disconnect(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    _scenario(workspace, "alpha")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "secret")
    studio = app.state.studio
    history_reads = 0

    async def fake_call(
        method: str, params: dict[str, object] | None = None, *, timeout: float = 30
    ) -> dict[str, object]:
        nonlocal history_reads
        if method == "thread/read":
            if params and params.get("includeTurns"):
                history_reads += 1
                if history_reads == 1:
                    raise CodexThreadNotReadyError("Codex is still saving this conversation")
                return {"thread": {"turns": [{"id": "turn-1", "status": "completed"}]}}
            raise CodexThreadNotReadyError("Codex is still saving this conversation")
        return {"data": []}

    monkeypatch.setattr(studio.codex, "call", fake_call)
    headers = {"X-EForge-Token": "secret"}
    with TestClient(app) as client:
        item_id = client.get("/v1/bootstrap", headers=headers).json()["items"][0]["id"]
        chat_id = client.post(
            "/v1/conversations", headers=headers, json={"item_id": item_id}
        ).json()["id"]
        chat = studio.store.conversation(chat_id)
        assert chat is not None
        chat.thread_id = "new-thread"
        chat.active = True
        studio.store.save_conversation(chat)
        first = client.get(f"/v1/conversations/{chat_id}/history", headers=headers)
        assert first.status_code == 200
        assert first.json() == {"thread": {"turns": []}, "history_pending": True}
        asyncio.run(studio.check_codex_health())
        assert studio.codex_health.state == "connected"
        assert studio.store.conversation(chat_id).active
        second = client.get(f"/v1/conversations/{chat_id}/history", headers=headers)
        assert second.status_code == 200
        assert second.json()["thread"]["turns"][0]["id"] == "turn-1"


def test_reconnect_requires_acknowledging_active_turns_and_keeps_thread(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    _scenario(workspace, "alpha")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "secret")
    studio = app.state.studio
    calls: list[str] = []

    async def fake_call(
        method: str, params: dict[str, object] | None = None, *, timeout: float = 30
    ) -> dict[str, object]:
        calls.append(method)
        return {"data": []}

    async def fake_start() -> None:
        calls.append("start")

    async def fake_stop() -> None:
        calls.append("stop")

    monkeypatch.setattr(studio.codex, "call", fake_call)
    monkeypatch.setattr(studio.codex, "start", fake_start)
    monkeypatch.setattr(studio.codex, "stop", fake_stop)
    headers = {"X-EForge-Token": "secret"}
    with TestClient(app) as client:
        item_id = client.get("/v1/bootstrap", headers=headers).json()["items"][0]["id"]
        chat_id = client.post(
            "/v1/conversations", headers=headers, json={"item_id": item_id}
        ).json()["id"]
        chat = studio.store.conversation(chat_id)
        assert chat is not None
        chat.thread_id = "saved-thread"
        chat.active = True
        studio.store.save_conversation(chat)
        refused = client.post("/v1/codex/reconnect", headers=headers, json={})
        assert refused.status_code == 409
        assert "stop" not in calls
        accepted = client.post(
            "/v1/codex/reconnect", headers=headers, json={"interrupt_active": True}
        )
        assert accepted.status_code == 200
        assert accepted.json()["state"] == "connected"
        saved = studio.store.conversation(chat_id)
        assert saved is not None
        assert saved.thread_id == "saved-thread"
        assert not saved.active
        assert saved.connection_note is not None
        assert calls.index("stop") < calls.index("start")


def test_codex_response_is_not_blocked_by_slow_notification_handler(tmp_path: Path) -> None:
    fake = tmp_path / "fake-codex"
    fake.write_text(
        "#!" + sys.executable + "\n"
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    request = json.loads(line)\n"
        "    method = request.get('method')\n"
        "    if method == 'thread/read':\n"
        "        print(json.dumps({'method': 'item/started', 'params': {}}), flush=True)\n"
        "    if 'id' in request:\n"
        "        result = {'ok': True, 'history': 'x' * 131072}\n"
        "        print(json.dumps({'id': request['id'], 'result': result}), flush=True)\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)

    async def exercise() -> None:
        release_event = asyncio.Event()
        event_started = asyncio.Event()

        async def on_event(method: str, params: dict[str, object]) -> None:
            if method == "item/started":
                event_started.set()
                await release_event.wait()

        async def on_request(request_id: int | str, method: str, params: dict[str, object]) -> None:
            return None

        client = CodexClient(fake, on_event, on_request)
        try:
            result = await client.call("thread/read", {"threadId": "example"}, timeout=1)
            assert result["ok"] is True
            assert len(result["history"]) == 131072
            await asyncio.wait_for(event_started.wait(), timeout=1)
        finally:
            release_event.set()
            await client.stop()

    asyncio.run(exercise())


def test_codex_notification_failure_does_not_end_event_stream() -> None:
    async def exercise() -> None:
        seen: list[str] = []

        async def on_event(method: str, _params: dict[str, object]) -> None:
            seen.append(method)
            if method == "item/started":
                raise ValueError("invalid event")

        async def on_request(
            _request_id: int | str, _method: str, _params: dict[str, object]
        ) -> None:
            return None

        client = CodexClient(None, on_event, on_request)
        queue: asyncio.Queue[tuple[str, int | str | None, str, dict[str, object]]] = asyncio.Queue()
        task = asyncio.create_task(client._dispatch_notifications(queue))
        try:
            queue.put_nowait(("event", None, "item/started", {}))
            queue.put_nowait(("event", None, "turn/completed", {}))
            await asyncio.wait_for(queue.join(), timeout=1)
            assert seen == ["item/started", "turn/completed"]
            assert not task.done()
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(exercise())


def test_bundle_exports_and_verified_complete_deletion(tmp_path: Path, monkeypatch: object) -> None:
    workspace = tmp_path / "workspace"
    scenario = _scenario(workspace, "alpha")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    paths = _paths(tmp_path / "private")
    app = create_app(paths, "secret")
    headers = {"X-EForge-Token": "secret"}
    complete_root = workspace / "runs" / "alpha" / "complete"
    complete_root.mkdir(parents=True)
    (complete_root / ".eforge-desktop-job.json").write_text(
        '{"job_id":"complete"}', encoding="utf-8"
    )
    (complete_root / "GENERATION_MANIFEST.json").write_text("{}", encoding="utf-8")
    (complete_root / "GROUND_TRUTH.md").write_text("# Ground truth\n", encoding="utf-8")
    complete = GenerationJob(
        id="complete",
        scenario=scenario,
        output_root=complete_root,
        progress_file=paths.state / "jobs" / "complete.jsonl",
        log_file=paths.state / "jobs" / "complete.log",
        started_at=10,
        submitted_at=9,
        status="completed",
        workspace=workspace,
        owned_output=True,
    )
    app.state.studio.jobs.save_generation(complete)
    result = paths.state / "jobs" / "evaluation.json"
    result.parent.mkdir(parents=True, exist_ok=True)
    result.write_text("{}", encoding="utf-8")
    evaluation = EvaluationJob(
        id="evaluation",
        generation_id=complete.id,
        workspace=workspace,
        output_root=complete_root,
        result_file=result,
        log_file=paths.state / "jobs" / "evaluation.log",
        command=[],
        created_at=11,
        status="completed",
    )
    app.state.studio.jobs.save_evaluation(evaluation)

    partial_root = workspace / "runs" / "alpha" / "partial"
    partial_root.mkdir()
    (partial_root / ".eforge-desktop-job.json").write_text('{"job_id":"partial"}', encoding="utf-8")
    (partial_root / "partial.log").write_text("partial output", encoding="utf-8")
    partial = complete.model_copy(
        update={"id": "partial", "output_root": partial_root, "status": "stopped"}
    )
    app.state.studio.jobs.save_generation(partial)
    with TestClient(app) as client:
        assert client.get("/v1/jobs/bundle-sizes").status_code == 401
        sizes = client.get("/v1/jobs/bundle-sizes", headers=headers).json()
        assert sizes == {
            "complete": sum(path.stat().st_size for path in complete_root.iterdir()),
            "partial": sum(path.stat().st_size for path in partial_root.iterdir()),
        }
        assert client.get("/v1/jobs/complete/bundle.zip").status_code == 401
        assert client.post("/v1/jobs/complete/bundle.zip/ticket").status_code == 401
        ticket = client.post("/v1/jobs/complete/bundle.zip/ticket", headers=headers).json()[
            "ticket"
        ]
        streamed = client.get(f"/v1/jobs/complete/bundle.zip?ticket={ticket}")
        assert streamed.status_code == 200
        assert client.get(f"/v1/jobs/complete/bundle.zip?ticket={ticket}").status_code == 401
        saved = client.get("/v1/jobs/complete/bundle.zip", headers=headers)
        assert saved.status_code == 200
        assert 'filename="alpha-complete.zip"' in saved.headers["content-disposition"]
        with zipfile.ZipFile(io.BytesIO(saved.content)) as archive:
            assert "run/GROUND_TRUTH.md" in archive.namelist()
            assert "authored/scenario.yaml" in archive.namelist()
            assert "evaluations/evaluation.json" in archive.namelist()
        preview = client.get(
            "/v1/jobs/complete/files/GROUND_TRUTH.md",
            headers={**headers, "Range": "bytes=0-7"},
        )
        assert preview.status_code == 206
        assert preview.content == b"# Ground"
        partial_zip = client.get("/v1/jobs/partial/bundle.zip", headers=headers)
        assert partial_zip.status_code == 200
        assert 'filename="alpha-partial-partial.zip"' in partial_zip.headers["content-disposition"]
        with zipfile.ZipFile(io.BytesIO(partial_zip.content)) as archive:
            assert archive.read("run/partial.log") == b"partial output"
        assert client.delete("/v1/jobs/complete/bundle", headers=headers).status_code == 200
        assert not complete_root.exists()
        assert not result.exists()
        remaining = client.get("/v1/jobs", headers=headers).json()
        assert {entry["id"] for entry in remaining} == {"partial"}
        assert (
            client.delete("/v1/jobs/partial/incomplete-bundle", headers=headers).status_code == 200
        )
        assert not partial_root.exists()


def test_bundle_deletion_rejects_unowned_or_mismatched_output(
    tmp_path: Path, monkeypatch: object
) -> None:
    workspace = tmp_path / "workspace"
    scenario = _scenario(workspace, "alpha")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    paths = _paths(tmp_path / "private")
    app = create_app(paths, "secret")
    root = workspace / "runs" / "alpha" / "foreign"
    root.mkdir(parents=True)
    (root / ".eforge-desktop-job.json").write_text('{"job_id":"other"}', encoding="utf-8")
    (root / "GENERATION_MANIFEST.json").write_text("{}", encoding="utf-8")
    job = GenerationJob(
        id="foreign",
        scenario=scenario,
        output_root=root,
        progress_file=paths.state / "jobs" / "foreign.jsonl",
        log_file=paths.state / "jobs" / "foreign.log",
        started_at=10,
        status="completed",
        workspace=workspace,
        owned_output=True,
    )
    app.state.studio.jobs.save_generation(job)
    with TestClient(app) as client:
        response = client.delete("/v1/jobs/foreign/bundle", headers={"X-EForge-Token": "secret"})
        assert response.status_code == 409
        assert root.is_dir()


def test_codex_classifies_empty_rollout_as_history_pending(tmp_path: Path) -> None:
    fake = tmp_path / "fake-codex"
    fake.write_text(
        "#!" + sys.executable + "\n"
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    request = json.loads(line)\n"
        "    if 'id' not in request: continue\n"
        "    if request['method'] == 'thread/read':\n"
        "        response = {'id': request['id'], 'error': {'message': "
        "'failed to read session metadata /tmp/new.jsonl: rollout at /tmp/new.jsonl is empty'}}\n"
        "    else:\n"
        "        response = {'id': request['id'], 'result': {}}\n"
        "    print(json.dumps(response), flush=True)\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)

    async def exercise() -> None:
        async def on_event(method: str, params: dict[str, object]) -> None:
            return None

        async def on_request(request_id: int | str, method: str, params: dict[str, object]) -> None:
            return None

        client = CodexClient(fake, on_event, on_request)
        try:
            try:
                await client.call("thread/read", {"threadId": "new-thread"}, timeout=1)
            except CodexThreadNotReadyError:
                pass
            else:
                raise AssertionError("Expected the transient empty-rollout error")
        finally:
            await client.stop()

    asyncio.run(exercise())
