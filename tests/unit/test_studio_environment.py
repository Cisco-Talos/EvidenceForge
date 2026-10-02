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
from typer.testing import CliRunner

from evidenceforge.cli.commands import app
from evidenceforge.studio import environment as environment_module
from evidenceforge.studio.environment import (
    EnvironmentReport,
    _populate_declarations,
    inspect_environment,
    overlay_files,
)
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
    include.write_text("# Included description\n\n" + yaml.safe_dump({"description": description}))
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
    declaration = next(entry for entry in report.declarations if entry.path == "description")
    assert declaration.value_found
    assert declaration.value == description
    assert declaration.source == "description.yaml"
    assert declaration.line == 3
    assert declaration.source_key
    assert report.declaration_content(declaration.source_key) == include.read_text()
    catalogs = [entry for entry in report.declarations if entry.layer == "Pack catalog"]
    assert catalogs
    assert all(entry.value_found and entry.source_key and entry.line for entry in catalogs)
    assert "_declaration_contents" not in report.model_dump()
    assert not (workspace / ".eforge").exists()
    assert before == {path: path.read_bytes() for path in workspace.rglob("*") if path.is_file()}


def test_source_declarations_keep_organization_input_values_before_scenario_overrides(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    source = _source(workspace)
    fixture = Path(__file__).resolve().parents[1] / "fixtures/scenarios/northstar-health-pack.yaml"
    data = yaml.safe_load(fixture.read_text())
    data.setdefault("environment", {})["description"] = "Scenario-specific environment"
    source.write_text(yaml.safe_dump(data, sort_keys=False))
    report = inspect_environment(StudioSettings(workspace=workspace), source, workspace)
    assert report.valid, report.error
    entries = [entry for entry in report.declarations if entry.path == "environment.description"]
    organization = next(entry for entry in entries if entry.layer == "Organization")
    scenario = next(entry for entry in entries if entry.layer == "Scenario")
    assert organization.value_found and scenario.value_found
    assert organization.value != scenario.value
    assert scenario.value == report.effective_scenario["environment"]["description"]
    assert organization.source_key and organization.source_key.startswith("packs/")
    assert organization.source_key.endswith("model/environment.yaml")
    assert organization.line and scenario.line
    for entry in (organization, scenario):
        assert entry.source_key and entry.line
        content = report.declaration_content(entry.source_key)
        assert content and "description:" in content.splitlines()[entry.line - 1]


def test_declaration_lines_follow_structure_instead_of_searching_repeated_text(
    tmp_path: Path,
) -> None:
    content = (
        "# Header\n"
        "defaults: &defaults\n"
        "  inherited: repeated\n"
        "  overridden: old\n"
        "first: repeated\n"
        "nested:\n"
        "  description: |\n"
        "    repeated\n"
        "    multiline\n"
        "  users:\n"
        "    - name: repeated\n"
        "    - name: repeated\n"
        "      ip.address: 192.0.2.10\n"
        "  list: [same, same]\n"
        "  <<: *defaults\n"
        "  overridden: new\n"
        "  alias: *defaults\n"
        "duplicate: first\n"
        "duplicate: last\n"
        "a:\n"
        "  b: nested\n"
        "a.b: dotted\n"
    )
    expected = {
        "first": 5,
        "nested.description": 7,
        "nested.users.0.name": 11,
        "nested.users.1.name": 12,
        "nested.users.1.ip.address": 13,
        "nested.list.1": 14,
        "nested.inherited": 3,
        "nested.overridden": 16,
        "nested.alias": 17,
        "nested.alias.inherited": 3,
        "duplicate": 19,
        "a.b": 21,
    }
    report = EnvironmentReport(
        source_sha256="source",
        project_root=tmp_path,
        overlay_root=tmp_path,
        field_origins=dict.fromkeys([*expected, "missing.field"], "sources/test.yaml"),
    )
    _populate_declarations(report, {"sources/test.yaml": content})
    for entry in report.declarations:
        assert entry.line == expected.get(entry.path)
    assert report.declarations[-1].value_found is False
    assert next(entry for entry in report.declarations if entry.path == "duplicate").value == "last"
    assert next(entry for entry in report.declarations if entry.path == "a.b").value == "nested"


def test_declaration_viewing_requires_auth_exact_revision_and_known_captured_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    source = _source(workspace)
    include = source.parent / "description.yaml"
    data = yaml.safe_load(source.read_text())
    include.write_text(yaml.safe_dump({"description": data.pop("description")}))
    data["includes"] = [include.name]
    source.write_text(yaml.safe_dump(data))
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(_paths(tmp_path / "app"), "secret")) as client:
        item = next(
            entry
            for entry in client.get("/v1/bootstrap", headers=headers).json()["items"]
            if entry["path"] == str(source)
        )
        report = client.get(f"/v1/scenarios/{item['id']}/environment", headers=headers).json()
        entry = next(entry for entry in report["declarations"] if entry["path"] == "description")
        assert entry["line"] == 1
        base = f"/v1/environment/{item['id']}/declarations/files/{report['compiled_sha256']}/"
        endpoint = base + entry["source_key"]
        assert client.get(endpoint).status_code == 401
        assert client.get(endpoint, headers=headers).text == include.read_text()
        assert client.get(base + "sources/unknown.yaml", headers=headers).status_code == 404
        assert client.get(base + "%2e%2e/outside.yaml", headers=headers).status_code == 404
        assert client.get(base + "%2Fetc%2Fpasswd", headers=headers).status_code == 404
        include.write_text("description: A changed source\n")
        assert client.get(endpoint, headers=headers).status_code == 409
        client.post(
            "/v1/workspaces/select", headers=headers, json={"path": str(tmp_path / "other")}
        )
        assert client.get(endpoint, headers=headers).status_code == 404


def test_resolve_declaration_sources_are_optional_and_do_not_change_compiled_identity(
    tmp_path: Path,
) -> None:
    source = _source(tmp_path)
    runner = CliRunner()
    command = [
        "resolve",
        str(source),
        "--project-root",
        str(tmp_path),
        "--explain-composition",
        "--json",
    ]
    original = runner.invoke(app, command)
    inspected = runner.invoke(app, [*command, "--include-declaration-sources"])
    assert original.exit_code == inspected.exit_code == 0
    original_payload = json.loads(original.stdout)
    inspected_payload = json.loads(inspected.stdout)
    assert "declaration_sources" not in original_payload
    sources = inspected_payload.pop("declaration_sources")
    assert inspected_payload == original_payload
    assert source.read_text() in sources.values()
    rejected = runner.invoke(
        app, ["resolve", str(source), "--include-declaration-sources", "--json"]
    )
    assert rejected.exit_code != 0
    assert "requires --explain-composition --json" in json.loads(rejected.stdout)["error"]


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
