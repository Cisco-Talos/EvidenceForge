"""Header title edits preserve identity and branch immutable or legacy sources explicitly."""

import json
import os
import shutil
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from evidenceforge.artifacts.lifecycle import (
    ArtifactError,
    create_draft,
    create_new_draft,
    inspect_artifact,
    list_drafts,
    publish,
    set_artifact_names,
    set_display_name,
    set_release_notes,
)
from evidenceforge.cli.commands import app
from evidenceforge.composition.packs import PackRepository, parse_pack_cli_reference
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
from evidenceforge.studio import artifact_api
from evidenceforge.studio.display_names import DisplayNameContext, DisplayNameSuggestion
from evidenceforge.studio.service import create_app
from tests.unit.test_studio_service import _paths

HEADERS = {"X-EForge-Token": "title-editor"}


def test_split_name_edits_restore_originals_if_one_replacement_fails(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    draft = create_draft(legacy_scenario(workspace), project_root=workspace)
    draft.write_text(draft.read_text() + "includes: [title.yaml]\n# retain root\n")
    title = draft.parent / "title.yaml"
    title.write_text("# retain title\ndisplay_name: Original # retain comment\n")
    title.chmod(0o640)
    original = {path: path.read_bytes() for path in (draft, title)}
    replace = os.replace
    calls = 0

    def fail_second(source: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated replacement failure")
        replace(source, destination)

    digest = inspect_artifact(draft)["digest"]
    monkeypatch.setattr(os, "replace", fail_second)
    with pytest.raises(OSError, match="simulated"):
        set_artifact_names(
            draft, "new-id", "New Title", project_root=workspace, expected_digest=digest
        )
    assert {path: path.read_bytes() for path in original} == original
    assert title.stat().st_mode & 0o777 == 0o640
    assert not list(draft.parent.glob(".*.names*"))
    monkeypatch.setattr(os, "replace", replace)
    set_artifact_names(draft, "new-id", "New Title", project_root=workspace, expected_digest=digest)
    assert "# retain root" in draft.read_text()
    assert "# retain title" in title.read_text() and "# retain comment" in title.read_text()
    assert inspect_artifact(draft)["name"] == "new-id"
    assert title.stat().st_mode & 0o777 == 0o640


def test_pack_rename_remaps_catalog_namespaces_and_lists_exact_consumers(
    workspace: Path, tmp_path: Path
) -> None:
    original = Path(
        "src/evidenceforge/config/packs/evidenceforge/industry/healthcare/1.0.0/pack.yaml"
    )
    draft = create_draft(original, project_root=workspace)
    before = inspect_artifact(draft)
    namespace = f"draft-{before['lifecycle']['draft_id']}/healthcare"
    catalog = draft.parent / "catalogs/traffic_catalog.yaml"
    catalog.write_text(
        catalog.read_text().replace(
            "application: clinical-portal", f"application: {namespace}:clinical-portal"
        )
    )
    consumer = legacy_scenario(workspace)
    data = yaml.safe_load(consumer.read_text())
    data.pop("version", None)
    data["scenario_version"] = "2.0"
    data["composition"] = {
        "industries": [
            {
                "source": "draft",
                "name": "healthcare",
                "draft_id": before["lifecycle"]["draft_id"],
                "path": str(draft.parent),
            }
        ]
    }
    consumer.write_text(yaml.safe_dump(data, sort_keys=False))
    with TestClient(create_app(_paths(tmp_path / "private"), "title-editor")) as client:
        item = next(
            row
            for row in client.get("/v1/items", headers=HEADERS).json()
            if row["path"] == str(draft)
        )
        reviewed = client.get(f"/v1/items/{item['id']}/lifecycle?names=true", headers=HEADERS)
        assert reviewed.status_code == 200, reviewed.text
        assert any(row["path"] == str(consumer) for row in reviewed.json()["name_consumers"])
    unchanged_consumer = consumer.read_bytes()
    set_artifact_names(
        draft,
        "clinical",
        "Clinical",
        project_root=workspace,
        expected_digest=inspect_artifact(draft)["digest"],
    )
    assert (
        f"draft-{before['lifecycle']['draft_id']}/clinical:clinical-portal" in catalog.read_text()
    )
    assert namespace not in catalog.read_text()
    assert consumer.read_bytes() == unchanged_consumer
    reference, kind = parse_pack_cli_reference(str(draft))
    PackRepository(workspace).resolve(reference, expected_type=kind)


@pytest.mark.parametrize("kind", ["scenario", "industry", "organization"])
@pytest.mark.parametrize("published", [False, True])
def test_identifier_edits_preserve_drafts_or_branch_published_sources(
    workspace: Path, tmp_path: Path, kind: str, published: bool
) -> None:
    draft = (
        create_draft(legacy_scenario(workspace), project_root=workspace)
        if kind == "scenario"
        else create_new_draft(kind, "original", description="Testing", project_root=workspace)
    )
    set_display_name(draft, "Friendly Original")
    set_release_notes(draft, "Keep these notes")
    source = publish(draft, project_root=workspace, accept_warnings=True) if published else draft
    before = inspect_artifact(source)
    original = source.read_bytes()
    with TestClient(create_app(_paths(tmp_path / "private"), "title-editor")) as client:
        item = next(
            row
            for row in client.get("/v1/items", headers=HEADERS).json()
            if row["path"] == str(source)
        )
        response = client.post(
            f"/v1/items/{item['id']}/lifecycle",
            headers=HEADERS,
            json={
                "action": "identity",
                "name": "renamed",
                "display_name": "Friendly Renamed",
                "expected_digest": before["digest"],
            },
        )
        assert response.status_code == 200, response.text
        result = Path(response.json()["path"])
    info = inspect_artifact(result)
    assert info["name"] == "renamed" and info["display_name"] == "Friendly Renamed"
    assert info["lifecycle"]["release_notes"] == "Keep these notes"
    assert info["lifecycle"]["status"] == "draft" and not info["lifecycle"].get("version")
    if published:
        assert result != source and source.read_bytes() == original
        assert info["lifecycle"]["parents"][0]["digest"] == before["digest"]
    else:
        assert result == source and info["lifecycle"]["draft_id"] == before["lifecycle"]["draft_id"]
    with pytest.raises(ArtifactError, match="source changed"):
        set_artifact_names(
            result, "stale", None, project_root=workspace, expected_digest=before["digest"]
        )


@pytest.mark.parametrize(
    "kind,group", [("scenario", "scenario"), ("industry", "pack"), ("organization", "pack")]
)
def test_cli_identifier_rename_uses_portable_file_services(
    workspace: Path, kind: str, group: str
) -> None:
    draft = (
        create_draft(legacy_scenario(workspace), project_root=workspace)
        if kind == "scenario"
        else create_new_draft(kind, "test", description="Testing", project_root=workspace)
    )
    set_display_name(draft, "Keep this title")
    response = CliRunner().invoke(
        app,
        [
            group,
            "rename",
            str(draft),
            "new-id",
            "--expected-digest",
            inspect_artifact(draft)["digest"],
            "--project-root",
            str(workspace),
            "--json",
        ],
    )
    assert response.exit_code == 0, response.output
    assert json.loads(response.output)["path"] == str(draft)
    assert inspect_artifact(draft)["display_name"] == "Keep this title"


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "workspace"
    root.mkdir()
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(root))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    set_publisher(
        root,
        PublisherIdentity(publisher="testing", publisher_display_name="Tests"),
        scope="project",
        force=False,
    )
    return root


def legacy_scenario(workspace: Path) -> Path:
    source = workspace / "scenarios/test/scenario.yaml"
    source.parent.mkdir(parents=True)
    shutil.copyfile("tests/fixtures/scenarios/minimal.yaml", source)
    return source


@pytest.mark.parametrize("kind", ["scenario", "industry", "organization"])
@pytest.mark.parametrize("published", [False, True])
def test_title_preview_and_save_keep_identity_and_preserve_published_sources(
    workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, published: bool
) -> None:
    draft = (
        create_draft(legacy_scenario(workspace), project_root=workspace)
        if kind == "scenario"
        else create_new_draft(kind, "test", description="Testing", project_root=workspace)
    )
    set_display_name(draft, "Original friendly title")
    set_release_notes(draft, "Keep these notes")
    source = publish(draft, project_root=workspace, accept_warnings=True) if published else draft
    original = source.read_bytes()
    captured = inspect_artifact(source)

    async def preview(context: DisplayNameContext, binary: Path | None) -> DisplayNameSuggestion:
        return DisplayNameSuggestion(display_name="A different friendly title")

    monkeypatch.setattr(artifact_api, "suggest_display_name", preview)
    with TestClient(create_app(_paths(tmp_path / "private"), "title-editor")) as client:
        item = next(
            row
            for row in client.get("/v1/items", headers=HEADERS).json()
            if row["path"] == str(source)
        )
        suggested = client.post(
            "/v1/assist/display-name",
            headers=HEADERS,
            json={"item_id": item["id"], "expected_digest": captured["digest"]},
        )
        assert suggested.status_code == 200, suggested.text
        assert source.read_bytes() == original
        endpoint = f"/v1/items/{item['id']}/lifecycle"
        if published:
            protected = client.post(
                endpoint,
                headers=HEADERS,
                json={
                    "action": "display-name",
                    "display_name": "Cannot overwrite",
                    "expected_digest": captured["digest"],
                },
            )
            assert protected.status_code == 409 and "immutable" in protected.text
            for missing in (None, ""):
                unreviewed = client.post(
                    endpoint,
                    headers=HEADERS,
                    json={
                        "action": "display-name",
                        "display_name": "Unreviewed",
                        "draft_if_needed": True,
                        "expected_digest": missing,
                    },
                )
                assert unreviewed.status_code == 409 and "Inspect" in unreviewed.text
        saved = client.post(
            endpoint,
            headers=HEADERS,
            json={
                "action": "display-name",
                "display_name": suggested.json()["display_name"],
                "draft_if_needed": True,
                "expected_digest": captured["digest"],
            },
        )
        assert saved.status_code == 200, saved.text
        result = Path(saved.json()["path"])
        info = inspect_artifact(result)
        assert (
            info["name"] == captured["name"]
            and info["display_name"] == "A different friendly title"
        )
        assert info["lifecycle"]["status"] == "draft"
        assert info["lifecycle"]["release_notes"] == "Keep these notes"
        assert not info["lifecycle"].get("version")
        if published:
            assert result != source and source.read_bytes() == original
            assert inspect_artifact(source)["digest"] == captured["digest"]
            assert info["lifecycle"]["publisher"] == captured["lifecycle"]["publisher"]
            assert info["lifecycle"]["parents"][0]["digest"] == captured["digest"]
        else:
            assert (
                result == source
                and info["lifecycle"]["draft_id"] == captured["lifecycle"]["draft_id"]
            )


def test_title_edit_adopts_legacy_without_rewriting_original(
    workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = legacy_scenario(workspace)
    original = source.read_bytes()

    async def preview(context: DisplayNameContext, binary: Path | None) -> DisplayNameSuggestion:
        return DisplayNameSuggestion(display_name="Friendly legacy scenario")

    monkeypatch.setattr(artifact_api, "suggest_display_name", preview)
    with TestClient(create_app(_paths(tmp_path / "private"), "title-editor")) as client:
        item = next(
            row
            for row in client.get("/v1/items", headers=HEADERS).json()
            if row["path"] == str(source)
        )
        digest = inspect_artifact(source)["digest"]
        response = client.post(
            "/v1/assist/display-name",
            headers=HEADERS,
            json={"item_id": item["id"], "expected_digest": digest},
        )
        assert response.status_code == 200
        assert not list_drafts(workspace)
        saved = client.post(
            f"/v1/items/{item['id']}/lifecycle",
            headers=HEADERS,
            json={
                "action": "display-name",
                "display_name": "Friendly legacy scenario",
                "draft_if_needed": True,
                "expected_digest": digest,
            },
        )
        assert saved.status_code == 200, saved.text
        info = inspect_artifact(Path(saved.json()["path"]))
        assert info["schema_version"] == "3.0" and source.read_bytes() == original
        assert info["lifecycle"]["parents"][0]["digest"] == digest


def test_clearing_published_title_creates_draft_and_keeps_release_title(
    workspace: Path, tmp_path: Path
) -> None:
    draft = create_new_draft("industry", "health", description="Testing", project_root=workspace)
    set_display_name(draft, "Original title")
    release = publish(draft, project_root=workspace, accept_warnings=True)
    with TestClient(create_app(_paths(tmp_path / "private"), "title-editor")) as client:
        item = next(
            row
            for row in client.get("/v1/items", headers=HEADERS).json()
            if row["path"] == str(release)
        )
        response = client.post(
            f"/v1/items/{item['id']}/lifecycle",
            headers=HEADERS,
            json={
                "action": "display-name",
                "display_name": None,
                "draft_if_needed": True,
                "expected_digest": inspect_artifact(release)["digest"],
            },
        )
        assert response.status_code == 200, response.text
        assert not inspect_artifact(Path(response.json()["path"]))["display_name"]
        assert inspect_artifact(release)["display_name"] == "Original title"


def test_changed_review_never_creates_a_branch_or_overwrites_a_title(
    workspace: Path, tmp_path: Path
) -> None:
    source = create_new_draft("industry", "health", description="Testing", project_root=workspace)
    digest = inspect_artifact(source)["digest"]
    set_display_name(source, "Someone else's edit")
    before = list_drafts(workspace)
    with TestClient(create_app(_paths(tmp_path / "private"), "title-editor")) as client:
        item = next(
            row
            for row in client.get("/v1/items", headers=HEADERS).json()
            if row["path"] == str(source)
        )
        response = client.post(
            f"/v1/items/{item['id']}/lifecycle",
            headers=HEADERS,
            json={
                "action": "display-name",
                "display_name": "Stale title",
                "draft_if_needed": True,
                "expected_digest": digest,
            },
        )
        assert response.status_code == 409 and "source changed" in response.text
        assert list_drafts(workspace) == before
        assert inspect_artifact(source)["display_name"] == "Someone else's edit"
