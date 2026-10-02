"""Read-only environment contracts, CLI provenance, and overlay boundaries."""

from __future__ import annotations

import json
import shutil
import subprocess
from hashlib import sha256
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from evidenceforge.studio import environment as environment_module
from evidenceforge.studio.environment import inspect_environment, overlay_files
from evidenceforge.studio.service import create_app
from evidenceforge.studio.settings import StudioSettings
from tests.unit.test_studio_service import _paths


def _source(workspace: Path) -> Path:
    source = workspace / "scenarios/test/scenario.yaml"
    source.parent.mkdir(parents=True)
    fixture = Path(__file__).resolve().parents[1] / "fixtures/scenarios/minimal.yaml"
    shutil.copyfile(fixture, source)
    return source


def test_environment_resolves_real_exact_pack_and_include_origins_without_writing(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    source = _source(workspace)
    data = yaml.safe_load(source.read_text())
    data.pop("version")
    data["scenario_version"] = "2.0"
    data["composition"] = {
        "industries": [
            {
                "source": "package",
                "publisher": "evidenceforge",
                "name": "healthcare",
                "version": "1.0.0",
            }
        ]
    }
    description = data.pop("description")
    include = source.parent / "description.yaml"
    include.write_text(yaml.safe_dump({"description": description}))
    data["includes"] = [include.name]
    source.write_text(yaml.safe_dump(data, sort_keys=False))
    before = {path: path.read_bytes() for path in workspace.rglob("*") if path.is_file()}
    report = inspect_environment(StudioSettings(workspace=workspace), source, workspace)
    assert report.valid, report.error
    assert report.source_sha256 == sha256(source.read_bytes()).hexdigest()
    assert report.compiled_sha256
    assert report.authored_kind == "scenario-2.0"
    assert report.selected_packs[0].name == "healthcare"
    assert report.selected_packs[0].version == "1.0.0"
    assert report.selected_packs[0].source == "package"
    assert len(report.selected_packs[0].digest) == 64
    assert report.field_origins["description"].endswith("-description.yaml")
    assert report.catalog_origins
    assert report.effective_scenario["environment"]["users"]
    assert not (workspace / ".eforge").exists()
    assert before == {path: path.read_bytes() for path in workspace.rglob("*") if path.is_file()}


def test_environment_routes_require_auth_and_active_workspace_and_only_known_overlay_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    source = _source(workspace)
    overlay = workspace / ".eforge/config/personas/analyst.yaml"
    overlay.parent.mkdir(parents=True)
    overlay.write_text("name: analyst\n")
    outside = tmp_path / "outside.yaml"
    outside.write_text("private: true\n")
    (overlay.parent / "linked.yaml").symlink_to(outside)
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(_paths(tmp_path / "app"), "secret")) as client:
        item = next(
            entry
            for entry in client.get("/v1/bootstrap", headers=headers).json()["items"]
            if entry["path"] == str(source)
        )
        endpoint = f"/v1/scenarios/{item['id']}/environment"
        assert client.get(endpoint).status_code == 401
        files_endpoint = f"/v1/environment/{item['id']}/files/"
        assert client.get(files_endpoint + "personas/analyst.yaml").status_code == 401
        assert (
            client.get(files_endpoint + "personas/analyst.yaml", headers=headers).text
            == overlay.read_text()
        )
        assert (
            client.get(files_endpoint + "personas/linked.yaml", headers=headers).status_code == 404
        )
        assert (
            client.get(files_endpoint + "%2e%2e/outside.yaml", headers=headers).status_code == 404
        )
        assert client.get(files_endpoint + "%2Fetc%2Fpasswd", headers=headers).status_code == 404
        assert client.get(files_endpoint + "missing.yaml", headers=headers).status_code == 404
        client.post(
            "/v1/workspaces/select", headers=headers, json={"path": str(tmp_path / "other")}
        )
        assert client.get(endpoint, headers=headers).status_code == 404
        assert (
            client.get(files_endpoint + "personas/analyst.yaml", headers=headers).status_code == 404
        )


def test_overlay_directory_links_are_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    (workspace / ".eforge").symlink_to(external)
    with pytest.raises(ValueError, match="symbolic links"):
        overlay_files(workspace)


@pytest.mark.parametrize("failure", ["missing", "invalid-json", "timeout", "invalid-shape"])
def test_environment_cli_failures_remain_inspectable_and_do_not_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    workspace = tmp_path / "workspace"
    source = _source(workspace)
    before = source.read_bytes()

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert "--explain-composition" in command
        assert "--include-effective-scenario" in command
        assert kwargs["cwd"] == workspace
        assert "--output" not in command
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 180)
        if failure == "invalid-shape":
            return subprocess.CompletedProcess(
                command, 0, json.dumps({"valid": True, "composition": []}), ""
            )
        return subprocess.CompletedProcess(
            command,
            1,
            "no JSON"
            if failure == "invalid-json"
            else json.dumps({"valid": False, "error": "missing exact pack test@1.0.0"}),
            "",
        )

    monkeypatch.setattr(environment_module.subprocess, "run", run)
    report = inspect_environment(StudioSettings(workspace=workspace), source, workspace)
    assert not report.valid
    assert report.error
    assert report.overlay_files == []
    assert report.source_sha256 == sha256(before).hexdigest()
    assert source.read_bytes() == before
