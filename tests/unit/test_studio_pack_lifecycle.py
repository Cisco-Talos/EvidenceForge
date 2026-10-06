"""Studio pack lifecycle acceptance on disposable workspaces and exact versions."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from evidenceforge.composition.compiler import compile_scenario
from evidenceforge.composition.models import PackReference
from evidenceforge.composition.packs import PackRepository
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
from evidenceforge.desktop.library import discover_packs
from evidenceforge.models.exceptions import PackError
from evidenceforge.studio.contexts import scenario_context_path
from evidenceforge.studio.pack_lifecycle import (
    remove_workspace_pack,
    review_pack,
    review_pack_deletion,
)
from evidenceforge.studio.service import create_app
from evidenceforge.studio.store import Conversation
from tests.unit.test_studio_service import _paths

HEADERS = {"X-EForge-Token": "pack-test"}


def _pack(workspace: Path, kind: str = "industry", version: str = "1.0.0") -> Path:
    workspace.mkdir(parents=True, exist_ok=True)
    return (
        PackRepository(workspace).create_skeleton(
            kind, "office", version, publisher="training", publisher_display_name="Training"
        )
        / "pack.yaml"
    )


def _consumer(workspace: Path, kind: str, version: str = "1.0.0") -> Path:
    fixture = Path(__file__).parents[1] / "fixtures/scenarios/minimal.yaml"
    data = yaml.safe_load(fixture.read_text())
    data.pop("version", None)
    data["scenario_version"] = "2.0"
    ref = {"source": "project", "publisher": "training", "name": "office", "version": version}
    data["composition"] = {"industries": [ref]} if kind == "industry" else {"organization": ref}
    path = workspace / "scenarios" / "consumer" / "scenario.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    return path


@pytest.mark.parametrize("kind", ["industry", "organization"])
def test_create_edit_validate_export_import_consume_and_delete_exact_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    set_publisher(
        workspace,
        PublisherIdentity(publisher="training", publisher_display_name="Training"),
        scope="project",
        force=False,
    )
    app = create_app(_paths(tmp_path / "private"), "pack-test")
    client = TestClient(app)
    created = client.post(
        "/v1/packs",
        headers=HEADERS,
        json={
            "kind": f"{kind}_pack",
            "name": "office",
            "description": "Reusable office assets",
            "publisher": "training",
            "publisher_display_name": "Training",
        },
    )
    assert created.status_code == 200, created.text
    original = created.json()["item"]
    original_bytes = Path(original["path"]).read_bytes()
    category = "storage_catalog" if kind == "industry" else "users"
    page = client.get(
        f"/v1/items/{original['id']}/assets?category={category}", headers=HEADERS
    ).json()
    detail = client.get(
        f"/v1/items/{original['id']}/assets/detail",
        params={"category": category, "revision": page["revision"]},
        headers=HEADERS,
    )
    assert detail.status_code == 200, detail.text
    value = (
        {
            "description": "Office files",
            "data": {
                "directories": ["Reports"],
                "subjects": ["weekly-report"],
                "files": [{"extension": ".pdf", "mime": "application/pdf", "weight": 1}],
            },
        }
        if kind == "industry"
        else {
            "username": "pack.author",
            "full_name": "Pack Author",
            "email": "author@office.example",
        }
    )
    changed = client.post(
        f"/v1/items/{original['id']}/assets",
        headers=HEADERS,
        json={
            "revision": page["revision"],
            "category": category,
            "key": "office-files" if kind == "industry" else "pack.author",
            "value": value,
            "version": "0.1.1",
        },
    )
    assert changed.status_code == 200, changed.text
    items = client.get("/v1/items", headers=HEADERS).json()
    revised = next(
        item for item in items if item["name"] == "office" and item["version"] == "0.1.1"
    )
    assert Path(original["path"]).read_bytes() == original_bytes
    review = client.get(f"/v1/packs/{revised['id']}/review", headers=HEADERS)
    assert review.status_code == 200 and review.json()["valid"], review.text
    digest = review.json()["digest"]
    exported = client.get(f"/v1/packs/{revised['id']}/export", headers=HEADERS)
    assert exported.status_code == 200, exported.text
    release = tmp_path / "office.efpack"
    release.write_bytes(exported.content)
    destination = tmp_path / "destination"
    destination.mkdir()
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(destination))
    imported_app = create_app(_paths(tmp_path / "destination-private"), "pack-test")
    imported_client = TestClient(imported_app)
    prepared = imported_client.post(
        "/v1/imports/pack/preview", headers=HEADERS, json={"path": str(release)}
    )
    assert prepared.status_code == 200, prepared.text
    plan = prepared.json()
    committed = imported_client.post(
        f"/v1/imports/{plan['id']}/commit",
        headers=HEADERS,
        json={
            "accepted_publishers": plan["publishers"],
        },
    )
    assert committed.status_code == 200, committed.text
    imported = next(
        item
        for item in imported_client.get("/v1/items", headers=HEADERS).json()
        if item["name"] == "office" and item["pack_source"] == "workspace"
    )
    assert review_pack(Path(imported["path"]), destination).digest == digest
    scenario = _consumer(destination, kind, "0.1.1")
    compiled = compile_scenario(scenario, project_root=destination)
    assert any(pack.digest == digest for pack in compiled.selected_packs)
    blocked = imported_client.get(f"/v1/packs/{imported['id']}/deletion", headers=HEADERS).json()
    assert not blocked["removable"] and any("Scenario:" in item for item in blocked["consumers"])
    # The source workspace has no consumers; remove the original exact draft only.
    url = f"/v1/packs/{original['id']}"
    assert client.get(url + "/deletion").status_code == 401
    removal = client.get(url + "/deletion", headers=HEADERS).json()
    assert removal["removable"]
    result = client.post(url + "/delete", headers=HEADERS, json={"revision": removal["revision"]})
    assert result.status_code == 200, result.text
    recovery = Path(result.json()["recovery_path"])
    assert (recovery / "pack.yaml").read_bytes() == original_bytes
    assert not Path(original["path"]).exists()
    assert Path(revised["path"]).exists() and release.exists()
    assert app.state.studio.store.item(original["id"]) is None
    assert not app.state.studio.store.conversations(workspace, original["id"])
    assert all(entry.path.parent != recovery for entry in discover_packs(workspace, kind))
    client.close()
    imported_client.close()
    app.state.studio.store.close()
    imported_app.state.studio.store.close()


def test_deletion_rechecks_all_files_and_new_consumers(tmp_path: Path) -> None:
    source = _pack(tmp_path)
    review = review_pack_deletion(source, tmp_path)
    (source.parent / "README.md").write_text("Changed companion")
    with pytest.raises(FileExistsError, match="changed"):
        remove_workspace_pack(source, tmp_path, review.revision)
    review = review_pack_deletion(source, tmp_path)
    _consumer(tmp_path, "industry")
    with pytest.raises(FileExistsError, match="changed"):
        remove_workspace_pack(source, tmp_path, review.revision)
    assert source.exists()
    current = review_pack_deletion(source, tmp_path)
    with pytest.raises(PackError, match="dependent"):
        remove_workspace_pack(source, tmp_path, current.revision)


def test_deletion_distinguishes_other_versions_packages_and_context_roots(tmp_path: Path) -> None:
    source = _pack(tmp_path)
    _pack(tmp_path, version="1.0.1")
    _consumer(tmp_path, "industry", "1.0.1")
    assert review_pack_deletion(source, tmp_path).removable
    repository = PackRepository(tmp_path)
    bundled = repository.resolve(
        PackReference(source="package", publisher="evidenceforge", name="finance", version="1.0.0"),
        expected_type="industry",
    )
    with pytest.raises(PackError, match="bundled"):
        review_pack_deletion(bundled.root / "pack.yaml", tmp_path)
    foreign = tmp_path / "foreign"
    foreign_source = _pack(foreign)
    with pytest.raises(PackError, match="workspace"):
        review_pack_deletion(foreign_source, tmp_path)


def test_deletion_blocks_locked_organization_and_included_path_consumers(tmp_path: Path) -> None:
    industry = _pack(tmp_path)
    organization = PackRepository(tmp_path).create_skeleton(
        "organization", "company", "1.0.0", publisher="training", publisher_display_name="Training"
    )
    manifest = yaml.safe_load((organization / "pack.yaml").read_text())
    manifest["industry_dependencies"] = [
        {
            "source": "project",
            "publisher": "training",
            "name": "office",
            "version_constraint": "==1.0.0",
        }
    ]
    (organization / "pack.yaml").write_text(yaml.safe_dump(manifest))
    repository = PackRepository(tmp_path)
    pack = repository.resolve(
        PackReference(source="project", publisher="training", name="company", version="1.0.0"),
        expected_type="organization",
    )
    repository.update_lock(pack, repository.proposed_lock(pack))
    review = review_pack_deletion(industry, tmp_path)
    assert any("Organization pack: training/company@1.0.0" == entry for entry in review.consumers)
    scenario = _consumer(tmp_path, "industry")
    data = yaml.safe_load(scenario.read_text())
    composition = data.pop("composition")
    composition["industries"][0].update(source="path", path=str(industry.parent))
    (scenario.parent / "packs.yaml").write_text(yaml.safe_dump({"composition": composition}))
    data["includes"] = ["packs.yaml"]
    scenario.write_text(yaml.safe_dump(data))
    assert any("Scenario:" in entry for entry in review_pack_deletion(industry, tmp_path).consumers)


def test_corrupt_catalog_can_be_removed_but_unknown_consumers_and_links_refuse(
    tmp_path: Path,
) -> None:
    source = _pack(tmp_path)
    (source.parent / "catalogs/persona_catalog.yaml").write_text("persona_catalog: broken")
    assert not review_pack(source, tmp_path).valid
    review = review_pack_deletion(source, tmp_path)
    assert review.removable
    unknown = tmp_path / "scenarios/corrupt/scenario.yaml"
    unknown.parent.mkdir(parents=True)
    unknown.write_text("name: [broken")
    assert not review_pack_deletion(source, tmp_path, [unknown]).removable
    external = tmp_path / "external"
    external.write_text("keep")
    (source.parent / "link").symlink_to(external)
    with pytest.raises(PackError, match="symlink"):
        review_pack_deletion(source, tmp_path)
    assert external.read_text() == "keep"


def test_unreadable_organization_manifests_cannot_hide_consumers(tmp_path: Path) -> None:
    source = _pack(tmp_path)
    organization = PackRepository(tmp_path).create_skeleton(
        "organization", "company", "1.0.0", publisher="training", publisher_display_name="Training"
    )
    manifest = organization / "pack.yaml"
    manifest.write_text("name: [broken")
    assert all(item.path != manifest for item in discover_packs(tmp_path, "organization"))
    review = review_pack_deletion(source, tmp_path)
    assert not review.removable
    assert any(str(manifest) in problem for problem in review.problems)
    manifest.unlink()
    review = review_pack_deletion(source, tmp_path, organization_paths=[manifest])
    assert not review.removable
    assert any(str(manifest) in problem for problem in review.problems)


def test_recovery_path_substitution_and_failed_index_cleanup_preserve_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    source = _pack(workspace)
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "pack-test")
    entry = next(item for item in discover_packs(workspace, "industry") if item.path == source)
    item = app.state.studio.store.upsert_item(workspace, "industry_pack", entry)
    client = TestClient(app)
    review = client.get(f"/v1/packs/{item.id}/deletion", headers=HEADERS).json()
    monkeypatch.setattr(
        app.state.studio.store,
        "remove_pack",
        lambda _id: (_ for _ in ()).throw(ValueError("Index failure")),
    )
    result = client.post(
        f"/v1/packs/{item.id}/delete", headers=HEADERS, json={"revision": review["revision"]}
    )
    assert result.status_code == 400 and source.exists()
    recovery = workspace / ".eforge/deleted-packs"
    shutil.rmtree(recovery)
    foreign = tmp_path / "outside"
    foreign.mkdir()
    recovery.symlink_to(foreign, target_is_directory=True)
    with pytest.raises(OSError):
        remove_workspace_pack(source, workspace, review["revision"])
    assert source.exists() and not list(foreign.iterdir())
    client.close()
    app.state.studio.store.close()


def test_explicit_scenario_context_uses_its_selected_pack_root(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    source = _pack(workspace)
    foreign = tmp_path / "foreign"
    _pack(foreign)
    scenario = _consumer(workspace, "industry")
    assert not review_pack_deletion(source, workspace).removable
    context = scenario_context_path(scenario, workspace)
    context.parent.mkdir(parents=True)
    context.write_text(yaml.safe_dump({"context_version": "1.0", "project_root": str(foreign)}))
    assert review_pack_deletion(source, workspace).removable


def test_interrupted_retirement_reconciles_index_and_active_authoring_refuses_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    workspace = tmp_path / "workspace"
    source = _pack(workspace)
    artifact = workspace / "runs/captured/RESOLVED_SCENARIO.yaml"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("immutable captured pack content")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    app = create_app(_paths(tmp_path / "private"), "pack-test")
    studio = app.state.studio
    entry = next(item for item in discover_packs(workspace, "industry") if item.path == source)
    item = studio.store.upsert_item(workspace, "industry_pack", entry)
    studio.store.save_conversation(Conversation(workspace=workspace, item_id=item.id, active=True))
    client = TestClient(app)
    path = f"/v1/packs/{item.id}"
    assert client.get(path + "/review").status_code == 401
    assert client.post(path + "/delete", json={"revision": "a" * 64}).status_code == 401
    review = review_pack_deletion(source, workspace)
    assert not client.get(path + "/deletion", headers=HEADERS).json()["removable"]
    assert (
        client.post(
            path + "/delete", headers=HEADERS, json={"revision": review.revision}
        ).status_code
        == 409
    )
    studio.store.delete_conversation(studio.store.conversations(workspace, item.id)[0].id)
    # Simulate termination after the atomic file move but before the SQLite transaction.
    removed = remove_workspace_pack(source, workspace, review.revision)
    assert studio.store.item(item.id) is not None
    asyncio.run(studio.scan())
    assert studio.store.item(item.id) is None
    assert (removed.recovery_path / "pack.yaml").exists()
    assert artifact.read_text() == "immutable captured pack content"
    client.close()
    studio.store.close()
