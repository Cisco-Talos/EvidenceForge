"""Friendly naming remains portable, optional and independent of generation identity."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from pydantic import ValidationError
from typer.testing import CliRunner

from evidenceforge.artifacts.lifecycle import (
    ArtifactError,
    create_draft,
    create_new_draft,
    inspect_artifact,
    publish,
    set_display_name,
    verify_release,
)
from evidenceforge.artifacts.portable import export_release, import_release
from evidenceforge.cli.commands import app
from evidenceforge.composition import compile_scenario
from evidenceforge.composition.identity import semantic_resolved_sha256
from evidenceforge.composition.models import PackManifest, PackReference
from evidenceforge.composition.packs import PackRepository
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
from evidenceforge.desktop.library import discover_packs, discover_scenarios
from evidenceforge.naming import storage_name, validate_display_name, validate_name
from evidenceforge.studio.lifecycle import clone_scenario, rename_scenario
from evidenceforge.studio.service import create_app
from evidenceforge.studio.state_database import MIGRATIONS, inspect_database, migrate_database
from evidenceforge.studio.state_upgrade import StateCoordinator
from tests.support.studio_state import inventory, legacy
from tests.unit.test_studio_service import _paths


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "unused-home")
    set_publisher(
        tmp_path,
        PublisherIdentity(publisher="testing", publisher_display_name="Tests"),
        scope="project",
        force=False,
    )
    return tmp_path


@pytest.mark.parametrize("name", ["_name", "-name", "7name", "A" * 500])
def test_scenario_names_share_full_identifier_and_safe_storage(name: str) -> None:
    assert validate_name(name, "scenario") == name
    assert len(storage_name(name)) <= 200
    if name != name.lower():
        assert storage_name(name) != storage_name(name.lower())


@pytest.mark.parametrize("value", ["", "  ", "line\nbreak", "line\u2028break", "\x00bad"])
def test_display_title_rejects_blank_or_multiline_text(value: str) -> None:
    with pytest.raises(ValueError):
        validate_display_name(value)


def test_title_changes_integrity_preserve_generation_and_portable_release(project: Path) -> None:
    source = project / "scenario.yaml"
    shutil.copyfile("tests/fixtures/scenarios/minimal.yaml", source)
    original = source.read_bytes()
    draft = create_draft(source, project_root=project, display_name="Healthcare — Équipe ①")
    before = compile_scenario(draft, project_root=project)
    digest = inspect_artifact(draft)["digest"]
    set_display_name(draft, "Healthcare — Edited", expected_digest=digest)
    after = compile_scenario(draft, project_root=project)
    assert before.scenario == after.scenario
    assert semantic_resolved_sha256(before) == semantic_resolved_sha256(after)
    assert inspect_artifact(draft)["digest"] != digest
    assert source.read_bytes() == original
    with pytest.raises(ArtifactError, match="changed"):
        set_display_name(draft, "Stale", expected_digest=digest)
    release = publish(draft, project_root=project, accept_warnings=True)
    assert inspect_artifact(release)["display_name"] == "Healthcare — Edited"
    archive = export_release(release, project / "scenario.efscenario")
    assert inspect_artifact(archive)["display_name"] == inspect_artifact(release)["display_name"]
    imported = import_release(archive, project_root=project / "other")
    assert inspect_artifact(imported)["display_name"] == "Healthcare — Edited"
    assert semantic_resolved_sha256(compile_scenario(imported)) == semantic_resolved_sha256(after)
    with pytest.raises(ArtifactError, match="immutable"):
        set_display_name(release, "Forbidden")
    branch = create_draft(release, project_root=project)
    assert inspect_artifact(branch)["display_name"] == "Healthcare — Edited"
    set_display_name(branch, None)
    assert inspect_artifact(branch)["display_name"] is None
    assert inspect_artifact(branch)["name"] == before.scenario.name
    assert (
        inspect_artifact(branch)["lifecycle"]["parents"][0]["digest"]
        == inspect_artifact(release)["digest"]
    )


@pytest.mark.parametrize("kind", ["industry", "organization"])
def test_pack_titles_are_optional_and_integrity_sealed(project: Path, kind: str) -> None:
    name = "a" * 300
    draft = create_new_draft(kind, name, description="Test", project_root=project)
    assert inspect_artifact(draft)["display_name"] is None
    set_display_name(draft, "Friendly Pack — Santé")
    first = publish(draft, project_root=project, accept_warnings=True)
    one = verify_release(first.parent.parent)
    set_display_name(draft, "Renamed title")
    second = publish(draft, project_root=project, accept_warnings=True)
    two = verify_release(second.parent.parent)
    assert one.semantic_digest == two.semantic_digest
    assert one.digest != two.digest
    archive = export_release(second, project / "pack.efpack")
    assert inspect_artifact(archive)["display_name"] == "Renamed title"
    imported = import_release(archive, project_root=project / "other")
    assert inspect_artifact(imported)["display_name"] == "Renamed title"
    item = next(item for item in discover_packs(project, kind) if item.path == second)
    assert item.name == name and item.display_name == "Renamed title"


def test_legacy_clone_and_rename_accept_leading_symbols_and_long_names(project: Path) -> None:
    root = project / "scenarios" / "original"
    root.mkdir(parents=True)
    source = root / "scenario.yaml"
    shutil.copyfile("tests/fixtures/scenarios/minimal.yaml", source)
    for name in ["_clone", "-clone", "A" * 500]:
        target = clone_scenario(source, project, name)
        assert yaml.safe_load(target.read_bytes())["name"] == name
        rename_scenario(target, name + "_edit", hashlib.sha256(target.read_bytes()).hexdigest())
        assert yaml.safe_load(target.read_bytes())["name"] == name + "_edit"
        assert (
            next(item for item in discover_scenarios(project, []) if item.path == target).name
            == name + "_edit"
        )


def test_title_edit_preserves_includes_comments_and_permissions(project: Path) -> None:
    source = project / "scenario.yaml"
    shutil.copyfile("tests/fixtures/scenarios/minimal.yaml", source)
    draft = create_draft(source, project_root=project)
    draft.write_text(draft.read_text() + "includes: [title.yaml]\n# keep root\n")
    owner = draft.parent / "title.yaml"
    owner.write_text("# keep title\ndisplay_name: Old # keep comment\n")
    owner.chmod(0o640)
    set_display_name(draft, "New Title")
    assert "# keep title" in owner.read_text() and "# keep comment" in owner.read_text()
    assert "# keep root" in draft.read_text()
    assert owner.stat().st_mode & 0o777 == 0o640
    assert inspect_artifact(draft)["display_name"] == "New Title"


@pytest.mark.parametrize(
    "group,kind", [("scenario", "scenario"), ("pack", "industry"), ("pack", "organization")]
)
def test_native_cli_creation_title_edit_and_clear(project: Path, group: str, kind: str) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            group,
            "new-draft",
            "a" * 300,
            "--kind",
            kind,
            "--display-name",
            "Friendly Native Title",
            "--project-root",
            str(project),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    path = json.loads(result.output)["path"]
    for arguments in [["--value", "Edited Title"], ["--clear"]]:
        result = runner.invoke(
            app, [group, "display-name", path, *arguments, "--project-root", str(project), "--json"]
        )
        assert result.exit_code == 0, result.output
    assert json.loads(result.output)["display_name"] is None
    assert json.loads(result.output)["name"] == "a" * 300


def test_version_one_database_gets_reviewed_naming_migration(project: Path) -> None:
    selected = legacy(project / "state")
    before = inventory(selected.database_file)
    migrate_database(selected.database_file, "old-runtime", migrations=MIGRATIONS[:1])
    assert inspect_database(selected.database_file) == 1
    coordinator = StateCoordinator(selected)
    try:
        assert coordinator.status.state == "pending" and coordinator.status.incompatible
        assert coordinator.apply(coordinator.status.operation_id).state == "ready"
        assert inspect_database(selected.database_file) == 2
        assert inventory(selected.database_file) == before
        assert coordinator.status.backup_path
    finally:
        coordinator.close()


def test_studio_creation_title_edit_and_long_identifiers(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(project))
    headers = {"X-EForge-Token": "naming"}
    with TestClient(create_app(_paths(project / "private"), "naming")) as client:
        response = client.post(
            "/v1/packs",
            headers=headers,
            json={
                "name": "a" * 300,
                "kind": "industry_pack",
                "description": "Test",
                "display_name": "Friendly Sector",
            },
        )
        assert response.status_code == 200, response.text
        item = response.json()["item"]
        assert item["display_name"] == "Friendly Sector" and len(item["name"]) == 300
        endpoint = f"/v1/items/{item['id']}/lifecycle"
        info = client.get(endpoint, headers=headers).json()
        response = client.post(
            endpoint,
            headers=headers,
            json={
                "action": "display-name",
                "display_name": "New Friendly Sector",
                "expected_digest": info["digest"],
            },
        )
        assert response.status_code == 200, response.text
        assert client.get(endpoint, headers=headers).json()["display_name"] == "New Friendly Sector"
        conversation = client.post(
            "/v1/conversations",
            headers=headers,
            json={
                "draft_kind": "scenario",
                "name": "_" + "A" * 300,
                "display_name": "Friendly Scenario",
            },
        )
        assert conversation.status_code == 200, conversation.text
        identity = conversation.json()["id"]
        resumed = client.get("/v1/bootstrap", headers=headers).json()["conversations"]
        assert (
            next(chat for chat in resumed if chat["id"] == identity)["draft_display_name"]
            == "Friendly Scenario"
        )


def test_legacy_pack_manifest_shape_and_digest_metadata_remain_unchanged() -> None:
    # Locate installed bundled fixture independent of package tree arrangement.
    pack = PackRepository(project_root=Path.cwd()).resolve(
        PackReference(
            source="package", publisher="evidenceforge", name="northstar-health", version="1.0.0"
        ),
        expected_type="organization",
    )
    data = pack.manifest.model_dump(mode="json")
    assert "display_name" not in data and pack.manifest.pack_schema_version == "2.0"
    with pytest.raises(ValidationError, match="schema 3"):
        PackManifest.model_validate({**data, "display_name": "Legacy title"})


def test_completed_version_one_installation_reopens_with_separate_reviewed_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.studio import state_database, state_upgrade
    from tests.support.studio_state import paths

    selected = paths(tmp_path)
    migrate = migrate_database
    with monkeypatch.context() as patch:
        patch.setattr(state_database, "DATABASE_VERSION", 1)
        patch.setattr(state_upgrade, "DATABASE_VERSION", 1)
        patch.setattr(
            state_upgrade,
            "migrate_database",
            lambda *args, **kwargs: migrate(*args, **kwargs, migrations=MIGRATIONS[:1]),
        )
        old = StateCoordinator(selected)
        old.initialize_if_fresh()
        assert old.status.state == "ready", old.status.error
        assert old.status.versions["database"] == 1
        old.close()
    current = StateCoordinator(selected)
    try:
        assert current.status.state == "pending", current.status.error
        assert current.status.warning and current.status.incompatible
        assert current.apply(current.status.operation_id).state == "ready", current.status.error
        assert inspect_database(selected.database_file) == 2
        assert current.status.backup_path
    finally:
        current.close()
