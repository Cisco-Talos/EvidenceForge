"""Studio delegates publication to the same portable file authority as the CLI."""

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from evidenceforge.artifacts.lifecycle import create_draft, inspect_artifact
from evidenceforge.composition.packs import PackRepository, parse_pack_cli_reference
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
from evidenceforge.studio.service import create_app
from tests.unit.test_studio_service import _paths

HEADERS = {"X-EForge-Token": "lifecycle"}


def test_properties_use_files_enforce_review_and_record_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    original = workspace / "scenario.yaml"
    shutil.copyfile("tests/fixtures/scenarios/minimal.yaml", original)
    draft = create_draft(original, project_root=workspace)
    with TestClient(create_app(_paths(tmp_path / "private"), "lifecycle")) as client:
        snapshot = client.get("/v1/bootstrap", headers=HEADERS).json()
        item = next(item for item in snapshot["items"] if item["path"] == str(draft))
        endpoint = f"/v1/items/{item['id']}/properties"
        assert client.get(endpoint).status_code == 401
        info = client.get(endpoint, headers=HEADERS).json()
        response = client.patch(
            endpoint,
            headers=HEADERS,
            json={"display_name": "API title", "expected_digest": info["digest"]},
        )
        assert response.status_code == 200, response.text
        assert inspect_artifact(draft)["display_name"] == "API title"
        assert (
            client.patch(
                endpoint,
                headers=HEADERS,
                json={"description": "Stale", "expected_digest": info["digest"]},
            ).status_code
            == 409
        )
        info = client.get(endpoint, headers=HEADERS).json()
        checked = client.post(
            f"/v1/items/{item['id']}/lifecycle",
            headers=HEADERS,
            json={"action": "validate", "expected_digest": info["digest"]},
        )
        assert checked.status_code == 200, checked.text
        assert client.get(endpoint, headers=HEADERS).json()["validated_with"]


def test_existing_legacy_anonymous_draft_and_release_share_derived_library_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    source = workspace / "scenarios/original.yaml"
    source.parent.mkdir(parents=True)
    shutil.copyfile("tests/fixtures/scenarios/minimal.yaml", source)
    original_bytes = source.read_bytes()
    old_draft = create_draft(source, project_root=workspace)
    draft_bytes = old_draft.read_bytes()
    set_publisher(
        workspace,
        PublisherIdentity(publisher="testing", publisher_display_name="Tests"),
        scope="project",
        force=False,
    )
    with TestClient(create_app(_paths(tmp_path / "private"), "lifecycle")) as client:
        snapshot = client.get("/v1/bootstrap", headers=HEADERS).json()
        draft_item = next(item for item in snapshot["items"] if item["path"] == str(old_draft))
        endpoint = f"/v1/items/{draft_item['id']}/lifecycle"
        review = client.get(endpoint, headers=HEADERS).json()
        result = client.post(
            endpoint,
            headers=HEADERS,
            json={
                "action": "publish",
                "expected_digest": review["digest"],
                "accept_warnings": True,
            },
        )
        assert result.status_code == 200, result.text
        snapshot = client.get("/v1/bootstrap", headers=HEADERS).json()
        scenarios = [item for item in snapshot["items"] if item["kind"] == "scenario"]
        assert len(scenarios) == 3
        groups = [snapshot["artifact_groups"][item["id"]] for item in scenarios]
        assert len({group["key"] for group in groups}) == 1
        assert all(group["publisher"] == "testing" for group in groups)
        assert draft_item["publisher"] == ""
        assert source.read_bytes() == original_bytes
        assert old_draft.read_bytes() == draft_bytes
        # A later upgrade acquires the configured publisher in the portable file itself.
        original_item = next(item for item in scenarios if item["path"] == str(source))
        upgraded = client.post(
            f"/v1/items/{original_item['id']}/lifecycle",
            headers=HEADERS,
            json={"action": "upgrade"},
        )
        assert upgraded.status_code == 200, upgraded.text
        assert (
            inspect_artifact(Path(upgraded.json()["path"]))["lifecycle"]["publisher"] == "testing"
        )


def test_pack_asset_edit_validate_review_and_publish_keeps_current_closure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    set_publisher(
        workspace,
        PublisherIdentity(publisher="testing", publisher_display_name="Tests"),
        scope="project",
        force=False,
    )
    with TestClient(create_app(_paths(tmp_path / "private"), "lifecycle")) as client:
        created = client.post(
            "/v1/packs",
            headers=HEADERS,
            json={
                "kind": "organization_pack",
                "name": "publication-test",
                "description": "Editable organization",
            },
        )
        assert created.status_code == 200, created.text
        item = created.json()["item"]
        source = Path(item["path"])
        original = source.read_bytes()
        endpoint = f"/v1/items/{item['id']}/lifecycle"
        before = client.get(endpoint, headers=HEADERS).json()
        page = client.get(f"/v1/items/{item['id']}/assets?category=users", headers=HEADERS).json()
        changed = client.post(
            f"/v1/items/{item['id']}/assets",
            headers=HEADERS,
            json={
                "revision": page["revision"],
                "category": "stale_accounts",
                "key": "former.employee",
                "value": {
                    "username": "former.employee",
                    "last_active": "2025-01-01",
                    "reason": "Former employee",
                },
            },
        )
        assert changed.status_code == 200, changed.text
        assert source.read_bytes() == original
        validation = client.get(f"/v1/packs/{item['id']}/review", headers=HEADERS)
        assert validation.status_code == 200 and validation.json()["valid"], validation.text
        outdated = client.post(
            endpoint,
            headers=HEADERS,
            json={
                "action": "publish",
                "expected_digest": before["digest"],
                "accept_warnings": True,
            },
        )
        assert outdated.status_code == 409 and "source changed after review" in outdated.text
        current = client.get(endpoint, headers=HEADERS).json()
        assert current["digest"] != before["digest"]
        published = client.post(
            endpoint,
            headers=HEADERS,
            json={
                "action": "publish",
                "expected_digest": current["digest"],
                "accept_warnings": True,
            },
        )
        assert published.status_code == 200, published.text
        reference, kind = parse_pack_cli_reference(published.json()["path"])
        release = PackRepository(workspace).resolve(reference, expected_type=kind)
        assert release.environment["stale_accounts"][0]["username"] == "former.employee"
        assert source.read_bytes() == original
        assert inspect_artifact(source)["lifecycle"]["status"] == "draft"


@pytest.mark.parametrize("kind", ["industry_pack", "organization_pack"])
def test_anonymous_draft_sessions_notes_publish_fork_and_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    with TestClient(create_app(_paths(tmp_path / "private"), "lifecycle")) as client:
        created = client.post(
            "/v1/packs",
            headers=HEADERS,
            json={"kind": kind, "name": "repeatable", "description": "An anonymous draft"},
        )
        assert created.status_code == 200, created.text
        item = created.json()["item"]
        assert item["version"] == ""
        endpoint = f"/v1/items/{item['id']}/lifecycle"
        assert client.get(endpoint).status_code == 401
        info = client.get(endpoint, headers=HEADERS).json()
        assert info["lifecycle"]["status"] == "draft"
        assert not info["upgrade_available"]
        note = client.post(
            endpoint,
            headers=HEADERS,
            json={
                "action": "notes",
                "notes": "User-reviewed changes",
                "expected_digest": info["digest"],
            },
        )
        assert note.status_code == 200
        assert (
            client.post(
                endpoint,
                headers=HEADERS,
                json={"action": "publish", "expected_digest": info["digest"]},
            ).status_code
            == 409
        )
        from evidenceforge.composition.publisher import PublisherIdentity, set_publisher

        set_publisher(
            workspace,
            PublisherIdentity(publisher="testing", publisher_display_name="Tests"),
            scope="project",
            force=False,
        )
        published = client.post(endpoint, headers=HEADERS, json={"action": "publish"})
        assert published.status_code == 200, published.text
        release_path = Path(published.json()["path"])
        assert inspect_artifact(Path(item["path"]))["lifecycle"]["status"] == "draft"
        released = next(
            row
            for row in client.get("/v1/items", headers=HEADERS).json()
            if row["path"] == str(release_path)
        )
        released_endpoint = f"/v1/items/{released['id']}/lifecycle"
        original = release_path.read_bytes()
        metadata = client.get(released_endpoint, headers=HEADERS).json()
        assert metadata["lifecycle"]["version"] == "1.0.0"
        assert metadata["versions"][0]["path"] == str(release_path)
        assert (
            client.post(
                released_endpoint,
                headers=HEADERS,
                json={"action": "notes", "notes": "Cannot mutate"},
            ).status_code
            == 409
        )
        page = client.get(f"/v1/items/{released['id']}/assets", headers=HEADERS).json()
        assert not any(category["editable"] for category in page["categories"])
        exported = client.get(f"/v1/packs/{released['id']}/export", headers=HEADERS)
        assert exported.status_code == 200, exported.text
        archive = tmp_path / "portable.efpack"
        archive.write_bytes(exported.content)
        assert (
            client.post(
                "/v1/artifacts/import", headers=HEADERS, json={"path": str(archive)}
            ).status_code
            == 200
        )
        chat = client.post("/v1/conversations", headers=HEADERS, json={"item_id": released["id"]})
        assert chat.status_code == 200, chat.text
        assert chat.json()["item_id"] != released["id"]
        assert release_path.read_bytes() == original


def test_scenario_upgrade_reports_repairable_findings_without_rewriting_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    source = workspace / "scenarios/broken/scenario.yaml"
    source.parent.mkdir(parents=True)
    original = b"version: '1.0'\nname: broken\nenvironment: {}\nstoryline: broken\n"
    source.write_bytes(original)
    with TestClient(create_app(_paths(tmp_path / "private"), "lifecycle")) as client:
        item = next(
            row
            for row in client.get("/v1/items", headers=HEADERS).json()
            if row["path"] == str(source)
        )
        result = client.post(
            f"/v1/items/{item['id']}/lifecycle", headers=HEADERS, json={"action": "upgrade"}
        )
        assert result.status_code == 200, result.text
        assert result.json()["findings"][0]["severity"] == "error"
        assert inspect_artifact(Path(result.json()["path"]))["lifecycle"]["status"] == "draft"
        assert source.read_bytes() == original


@pytest.mark.parametrize("marker", [None, "9.0"])
def test_present_schema_marker_is_authoritative_across_compiler_cli_and_import(
    tmp_path: Path, marker: object
) -> None:
    import yaml
    from typer.testing import CliRunner

    from evidenceforge.cli.commands import app
    from evidenceforge.composition import compile_scenario
    from evidenceforge.models.exceptions import SchemaValidationError
    from evidenceforge.studio.imports import ScenarioImportRequest, prepare_scenario

    source = tmp_path / "scenario.yaml"
    data = yaml.safe_load(Path("tests/fixtures/scenarios/minimal.yaml").read_text())
    data["schema_version"] = marker
    source.write_text(yaml.safe_dump(data))
    with pytest.raises(SchemaValidationError):
        compile_scenario(source)
    result = CliRunner().invoke(app, ["validate", str(source), "--json"])
    assert result.exit_code != 0
    assert "schema_version" in result.output
    with pytest.raises(SchemaValidationError):
        prepare_scenario(
            ScenarioImportRequest(path=source, name="imported"),
            tmp_path / "workspace",
            tmp_path / "cache",
        )
