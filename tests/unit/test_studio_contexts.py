"""Explicit scope changes share CLI inputs and leave frozen generations unchanged."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from evidenceforge.composition import compile_scenario
from evidenceforge.config.context import select_context
from evidenceforge.studio.contexts import (
    configuration_state,
    configure_scenario,
    context_path,
    copy_scenario_configuration,
    export_configuration,
    project_overlay_root,
    scenario_overlay_root,
)
from evidenceforge.studio.imports import ScenarioImportRequest, dependency_health, prepare_scenario
from evidenceforge.studio.jobs import StudioJobStore, queue_studio_generation
from evidenceforge.studio.service import create_app
from evidenceforge.studio.settings import StudioSettings
from evidenceforge.studio.store import Project, StudioStore
from tests.unit.test_studio_service import _paths, _scenario


def test_scopes_are_opt_in_and_private_clone_does_not_share_patches(tmp_path: Path) -> None:
    source = _scenario(tmp_path, "alpha", valid=True)
    project = Project(workspace=tmp_path, name="Clinic")
    assert configure_scenario(source, tmp_path, project) is None
    assert not (tmp_path / ".eforge").exists()
    project.overlay_enabled = True
    selected = configure_scenario(source, tmp_path, project, scenario_enabled=True)
    assert selected is not None
    assert [layer.path for layer in select_context(context=selected).overlays] == [
        project_overlay_root(project),
        scenario_overlay_root(source, tmp_path),
    ]
    patch = scenario_overlay_root(source, tmp_path) / "activity/dns_registry.yaml"
    patch.parent.mkdir()
    patch.write_text("valid_tags: {clinic: Clinical services}\n")
    clone = _scenario(tmp_path, "clone", valid=True)
    copy_scenario_configuration(source, clone, tmp_path, project)
    cloned_patch = scenario_overlay_root(clone, tmp_path) / patch.relative_to(patch.parents[1])
    assert cloned_patch.read_bytes() == patch.read_bytes()
    cloned_patch.write_text("valid_tags: {clone: Private clone}\n")
    assert "clone" not in patch.read_text()
    configure_scenario(source, tmp_path, None, scenario_enabled=False)
    assert context_path(source, tmp_path) is None
    assert patch.is_file()
    disabled_clone = _scenario(tmp_path, "disabled-clone", valid=True)
    copy_scenario_configuration(source, disabled_clone, tmp_path, None)
    assert context_path(disabled_clone, tmp_path) is None
    assert (
        scenario_overlay_root(disabled_clone, tmp_path) / "activity/dns_registry.yaml"
    ).read_bytes() == patch.read_bytes()


def test_scope_display_follows_selected_layer_order(tmp_path: Path) -> None:
    source = _scenario(tmp_path, "alpha", valid=True)
    project = Project(workspace=tmp_path, name="Clinic", overlay_enabled=True)
    selected = configure_scenario(source, tmp_path, project, scenario_enabled=True)
    assert selected is not None
    imported = tmp_path / "imported-config"
    imported.mkdir()
    document = yaml.safe_load(selected.read_text())
    document["overlays"].insert(1, {"name": "Imported", "path": str(imported)})
    selected.write_text(yaml.safe_dump(document))
    state = configuration_state(source, tmp_path, project)
    assert [scope.name for scope in state.scopes] == [
        "Workspace",
        "Project · Clinic",
        "Imported",
        "Scenario",
    ]


def test_queued_context_is_frozen_and_external_edits_change_freshness(tmp_path: Path) -> None:
    source = _scenario(tmp_path, "alpha", valid=True)
    selected = configure_scenario(source, tmp_path, None, scenario_enabled=True)
    assert selected is not None
    patch = scenario_overlay_root(source, tmp_path) / "activity/dns_registry.yaml"
    patch.parent.mkdir()
    patch.write_text("valid_tags: {clinic: Clinical services}\n")
    before = dependency_health(source, tmp_path)
    store = StudioStore(tmp_path / "private/studio.sqlite")
    try:
        job = queue_studio_generation(
            StudioJobStore(store, tmp_path / "private"),
            source,
            tmp_path,
            StudioSettings(workspace=tmp_path),
        )
        frozen = compile_scenario(job.input_snapshot)
        assert (
            frozen.effective_config.overlay_layers[0].files["activity/dns_registry.yaml"][
                "valid_tags"
            ]["clinic"]
            == "Clinical services"
        )
        patch.write_text("valid_tags: {clinic: Changed services}\n")
        after = dependency_health(source, tmp_path)
        assert after.ready and after.fingerprint != before.fingerprint
        assert compile_scenario(job.input_snapshot).digests == frozen.digests
        selected.unlink()
        assert compile_scenario(job.input_snapshot).digests == frozen.digests
    finally:
        store.close()


def test_configured_moves_require_confirmation_and_missing_layers_block_jobs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    source = _scenario(workspace, "alpha", valid=True)
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(_paths(tmp_path / "app"), "secret")) as client:
        item = next(
            row
            for row in client.get("/v1/bootstrap", headers=headers).json()["items"]
            if row["path"] == str(source)
        )
        project = client.post(
            "/v1/projects", headers=headers, json={"name": "Clinic", "overlay_enabled": True}
        ).json()
        endpoint = f"/v1/items/{item['id']}"
        assert (
            client.patch(endpoint, headers=headers, json={"project_id": project["id"]}).status_code
            == 409
        )
        moved = client.patch(
            endpoint,
            headers=headers,
            json={"project_id": project["id"], "confirm_configuration_change": True},
        )
        assert moved.status_code == 200, moved.text
        selected = context_path(source, workspace)
        assert selected is not None
        report = client.get(f"/v1/scenarios/{item['id']}/environment", headers=headers).json()
        assert report["valid"], report["error"]
        assert [scope["enabled"] for scope in report["configuration"]["scopes"]] == [
            True,
            True,
            False,
        ]
        assert str(selected) in report["configuration"]["cli_command"]
        layer = Path(report["configuration"]["scopes"][1]["root"])
        layer.rmdir()
        health = dependency_health(source, workspace)
        assert not health.ready and health.rows[0].kind == "overlay"
        assert "missing" in health.rows[0].detail
        # Missing explicit selection cannot be replaced by CWD defaults.
        store = client.app.state.studio.store
        with pytest.raises(ValueError, match="dependencies"):
            queue_studio_generation(
                StudioJobStore(store, tmp_path / "private"),
                source,
                workspace,
                StudioSettings(workspace=workspace),
            )


def test_context_files_remain_relative_after_workspace_is_relocated(tmp_path: Path) -> None:
    original = tmp_path / "original"
    source = _scenario(original, "alpha", valid=True)
    selected = configure_scenario(source, original, None, scenario_enabled=True)
    assert selected is not None
    document = yaml.safe_load(selected.read_text())
    assert not Path(document["project_root"]).is_absolute()
    assert not Path(document["overlays"][0]["path"]).is_absolute()
    relocated = tmp_path / "relocated"
    original.rename(relocated)
    moved = relocated / selected.relative_to(original)
    assert context_path(relocated / source.relative_to(original), relocated) == moved
    selection = select_context(context=moved)
    assert selection.project_root == relocated
    assert compile_scenario(relocated / source.relative_to(original), context=moved)


def test_context_export_import_reviews_copies_and_survives_source_removal(tmp_path: Path) -> None:
    workspace = tmp_path / "source"
    source = _scenario(workspace, "alpha", valid=True)
    configure_scenario(source, workspace, None, scenario_enabled=True)
    overlay = scenario_overlay_root(source, workspace) / "activity/dns_registry.yaml"
    overlay.parent.mkdir()
    overlay.write_text("valid_tags: {clinic: Clinical services}\n")
    received = tmp_path / "received/authored"
    received.mkdir(parents=True)
    (received / "scenario.yaml").write_bytes(source.read_bytes())
    for filename, content in export_configuration(source, workspace).items():
        path = received / filename
        if filename.endswith("/"):
            path.mkdir(parents=True, exist_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    destination = tmp_path / "destination"
    destination.mkdir()
    request = ScenarioImportRequest(
        path=received / "scenario.yaml",
        name="imported",
        configuration_context=received / "configuration/context.yaml",
    )
    plan = prepare_scenario(request, destination, tmp_path / "cache")
    try:
        assert not (destination / ".eforge").exists()
        assert any(row.kind == "overlay" and row.status == "copy" for row in plan.review.rows)
        staged = plan.stage / plan.target
        compiled = compile_scenario(staged, context=context_path(staged, plan.stage))
        assert (
            compiled.effective_config.overlay_layers[0].files["activity/dns_registry.yaml"][
                "valid_tags"
            ]["clinic"]
            == "Clinical services"
        )
        imported = plan.commit(destination, [])
        assert imported is not None
        import shutil

        shutil.rmtree(received.parent)
        assert dependency_health(imported, destination).ready
        compiled_after = compile_scenario(imported, context=context_path(imported, destination))
        assert (
            compiled_after.effective_config.overlay_layers
            == compiled.effective_config.overlay_layers
        )
    finally:
        plan.close()


def test_import_review_rejects_changed_context_layer(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source = _scenario(source_root, "alpha", valid=True)
    context = configure_scenario(source, source_root, None, scenario_enabled=True)
    destination = tmp_path / "destination"
    destination.mkdir()
    plan = prepare_scenario(
        ScenarioImportRequest(path=source, name="imported", configuration_context=context),
        destination,
        tmp_path / "cache",
    )
    try:
        layer = scenario_overlay_root(source, source_root) / "activity"
        layer.mkdir()
        (layer / "dns_registry.yaml").write_text("valid_tags: {new: Added after review}\n")
        with pytest.raises(FileExistsError, match="configuration changed"):
            plan.commit(destination, [])
        assert not (destination / "scenarios").exists()
    finally:
        plan.close()
