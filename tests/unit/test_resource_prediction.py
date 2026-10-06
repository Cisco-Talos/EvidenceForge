"""Resource-only CLI and durable Studio prediction lifecycle contracts."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from hashlib import sha256
from pathlib import Path
from threading import Event

import pytest
import yaml
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from evidenceforge.cli.commands import app
from evidenceforge.desktop.library import discover_scenarios
from evidenceforge.resources import ResourcePrediction, predict_resources
from evidenceforge.studio import forecasts as forecasts_module
from evidenceforge.studio import service as service_module
from evidenceforge.studio.forecasts import (
    PredictionRecord,
    prediction_destination,
    prediction_key,
    run_prediction,
)
from evidenceforge.studio.imports import dependency_health
from evidenceforge.studio.service import StudioService, create_app
from evidenceforge.studio.settings import StudioSettings
from evidenceforge.studio.store import StudioStore
from tests.unit.test_studio_service import _paths


def _source(workspace: Path) -> Path:
    source = workspace / "scenarios/test/scenario.yaml"
    source.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__).resolve().parents[1] / "fixtures/scenarios/minimal.yaml", source)
    return source


def test_prediction_cli_is_read_only_and_matches_validation_forecast(tmp_path: Path) -> None:
    source = _source(tmp_path / "workspace")
    before = source.read_bytes()
    destination = tmp_path / "new-output/runs"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "resources",
            "predict",
            str(source),
            "--destination",
            str(destination),
            "--checkpoint-hours",
            "30",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    prediction = ResourcePrediction.model_validate_json(result.stdout)
    assert prediction.available
    assert prediction.schema_version == "1.0"
    assert prediction.source_sha256 == sha256(before).hexdigest()
    assert prediction.checkpoint_hours == 30
    validation = runner.invoke(app, ["validate", str(source), "--checkpoint-hours", "30", "--json"])
    assert validation.exit_code == 0, validation.output
    report = json.loads(validation.stdout)["resource_forecast"]
    assert prediction.forecast is not None
    for name in ("memory", "final_output", "disk", "checkpoint_workspace"):
        assert getattr(prediction.forecast, name).model_dump() == report[name]
    assert not destination.parent.exists()
    assert not (source.parents[2] / ".eforge").exists()
    assert source.read_bytes() == before


@pytest.mark.parametrize(
    "input_text", ["name: missing-fields\n", "scenario_version: 2.0\ncomposition: [invalid]\n"]
)
def test_prediction_errors_have_json_and_never_create_destination(
    tmp_path: Path, input_text: str
) -> None:
    source = tmp_path / "invalid.yaml"
    source.write_text(input_text)
    destination = tmp_path / "never-created"
    result = CliRunner().invoke(
        app, ["resources", "predict", str(source), "--destination", str(destination), "--json"]
    )
    assert result.exit_code == 1
    prediction = ResourcePrediction.model_validate_json(result.stdout)
    assert not prediction.available
    assert prediction.error
    assert not destination.exists()


def test_prediction_keys_cover_preferences_and_overlays_change_dependency_freshness(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    source = _source(workspace)
    settings = StudioSettings(workspace=workspace)
    before = dependency_health(source, workspace)
    overlay = workspace / ".eforge/config/activity/dns_registry.yaml"
    overlay.parent.mkdir(parents=True)
    overlay.write_text("domains: []\n")
    after = dependency_health(source, workspace)
    assert before.fingerprint != after.fingerprint
    assert after.ready
    store = StudioStore(_paths(tmp_path / "app").database_file)
    try:
        item = store.upsert_item(workspace, "scenario", discover_scenarios(workspace, [])[0])
        key = prediction_key(item, before.fingerprint, settings)
        assert key != prediction_key(item, after.fingerprint, settings)
        assert key != prediction_key(
            item, before.fingerprint, settings.model_copy(update={"checkpoint_hours": 6})
        )
        other = settings.model_copy(
            update={"output_parents": {str(workspace.resolve()): tmp_path / "exports"}}
        )
        assert prediction_destination(other) == tmp_path / "exports"
        assert key != prediction_key(item, before.fingerprint, other)
    finally:
        store.close()


def test_output_parent_paths_match_prediction_and_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    settings = StudioSettings(
        workspace=tmp_path / "workspace",
        output_parents={"~/workspace": Path("~/exports/../bundles")},
    )
    assert settings.output_parents == {str(tmp_path / "workspace"): tmp_path / "bundles"}
    assert prediction_destination(settings) == tmp_path / "bundles"
    assert not (tmp_path / "bundles").exists()


@pytest.mark.parametrize("failure", ["invalid-report", "timeout", "contradictory-exit"])
def test_cli_prediction_failures_are_actionable_without_raw_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    workspace = tmp_path / "workspace"
    _source(workspace)
    settings = StudioSettings(workspace=workspace)
    store = StudioStore(_paths(tmp_path / "app").database_file)
    item = store.upsert_item(workspace, "scenario", discover_scenarios(workspace, [])[0])
    store.close()
    raw_output = "malformed output that must not be shown"

    def command(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        if failure == "timeout":
            raise subprocess.TimeoutExpired("eforge", 60, output=raw_output)
        stdout = raw_output
        if failure == "contradictory-exit":
            stdout = ResourcePrediction(
                available=True, destination=workspace / "runs"
            ).model_dump_json()
        return subprocess.CompletedProcess("eforge", 1, stdout, raw_output)

    monkeypatch.setattr(forecasts_module.subprocess, "run", command)
    record = run_prediction(item, "dependencies", settings)
    assert not record.result.available
    assert record.result.error
    assert raw_output not in record.result.error
    if failure == "invalid-report":
        assert "Check its version and tool path" in record.result.error
    elif failure == "timeout":
        assert "60 seconds" in record.result.error
    assert not (workspace / "runs").exists()


def test_prediction_refresh_is_authorized_and_workspace_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    _source(workspace)
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))

    def run(
        item: service_module.CatalogItem, dependencies: str, settings: StudioSettings
    ) -> PredictionRecord:
        return PredictionRecord(
            source_sha256=item.source_sha256,
            dependency_fingerprint=dependencies,
            input_fingerprint=prediction_key(item, dependencies, settings),
            completed_at=123,
            result=predict_resources(
                item.path, prediction_destination(settings), project_root=item.workspace
            ),
        )

    monkeypatch.setattr(service_module, "run_prediction", run)
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(_paths(tmp_path / "app"), "secret")) as client:
        snapshot = client.get("/v1/bootstrap", headers=headers).json()
        item_id = next(item["id"] for item in snapshot["items"] if item["kind"] == "scenario")
        route = f"/v1/scenarios/{item_id}/resources/predict"
        assert client.post(route).status_code == 401
        response = client.post(route, headers=headers)
        assert response.status_code == 200, response.text
        record = PredictionRecord.model_validate(response.json())
        assert record.result.available
        assert client.get("/v1/bootstrap", headers=headers).json()["forecasts"][item_id]
        assert (
            client.post(
                "/v1/workspaces/select", headers=headers, json={"path": str(tmp_path / "other")}
            ).status_code
            == 200
        )
        assert client.post(route, headers=headers).status_code == 404
        assert client.get("/v1/bootstrap", headers=headers).json()["forecasts"] == {}


@pytest.mark.asyncio
async def test_background_prediction_streams_persists_and_reuses_unchanged_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    source = _source(workspace)
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    paths = _paths(tmp_path / "app")
    calls: list[str] = []

    def run(
        item: service_module.CatalogItem, dependencies: str, settings: StudioSettings
    ) -> PredictionRecord:
        calls.append(item.id)
        return PredictionRecord(
            source_sha256=item.source_sha256,
            dependency_fingerprint=dependencies,
            input_fingerprint=prediction_key(item, dependencies, settings),
            completed_at=123,
            result=predict_resources(
                item.path,
                prediction_destination(settings),
                project_root=workspace,
                checkpoint_hours=settings.checkpoint_hours,
            ),
        )

    monkeypatch.setattr(service_module, "run_prediction", run)
    studio = StudioService(paths, "secret")
    await studio.scan()
    item = studio.store.items(workspace, "scenario")[0]
    queue: asyncio.Queue[service_module.StudioEvent] = asyncio.Queue()
    studio.subscribers.add(queue)
    studio.prediction_task = asyncio.create_task(studio._prediction_loop())
    try:
        event = await asyncio.wait_for(queue.get(), timeout=5)
        assert event.kind == "scenario.forecast"
        assert event.entity_id == item.id
        assert event.payload["result"]["available"]
        assert list((workspace / "runs").iterdir()) == []
        await studio.scan()
        await asyncio.sleep(0)
        assert calls == [item.id]
        assert (
            studio.snapshot()["forecasts"][item.id]["source_sha256"]
            == sha256(source.read_bytes()).hexdigest()
        )
    finally:
        await studio.stop()
    reopened = StudioService(paths, "secret")
    try:
        await reopened.scan()
        assert item.id in reopened.snapshot()["forecasts"]
        assert reopened.prediction_pending == {}
        assert calls == [item.id]
    finally:
        await reopened.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("changed", ["source", "overlay", "workspace"])
async def test_predictions_changed_during_inspection_are_not_published(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    workspace = tmp_path / "workspace"
    source = _source(workspace)
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    started, release = Event(), Event()
    result = predict_resources(source, workspace / "runs", project_root=workspace)

    def run(
        item: service_module.CatalogItem, dependencies: str, settings: StudioSettings
    ) -> PredictionRecord:
        started.set()
        assert release.wait(5)
        return PredictionRecord(
            source_sha256=item.source_sha256,
            dependency_fingerprint=dependencies,
            input_fingerprint=prediction_key(item, dependencies, settings),
            completed_at=123,
            result=result,
        )

    monkeypatch.setattr(service_module, "run_prediction", run)
    studio = StudioService(_paths(tmp_path / "app"), "secret")
    await studio.scan()
    item = studio.store.items(workspace, "scenario")[0]
    dependencies = studio.store.dependency_health([item.id])[item.id]["fingerprint"]
    task = asyncio.create_task(
        studio.predict_item(item, dependencies, studio.settings.model_copy(deep=True))
    )
    try:
        assert await asyncio.to_thread(started.wait, 5)
        if changed == "source":
            data = yaml.safe_load(source.read_text())
            data["description"] = "Changed during prediction"
            source.write_text(yaml.safe_dump(data))
        elif changed == "overlay":
            overlay = workspace / ".eforge/config/activity/dns_registry.yaml"
            overlay.parent.mkdir(parents=True)
            overlay.write_text("domains: []\n")
        else:
            studio.settings.workspace = tmp_path / "other"
        release.set()
        assert await task is None
        assert studio.store.resource_predictions([item.id]) == {}
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        await studio.stop()
