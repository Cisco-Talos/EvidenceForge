"""Reviewed scenario and pack copies stay independent, scoped, and recoverable."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

import evidenceforge.studio.imports as import_module
import evidenceforge.studio.service as service_module
from evidenceforge.composition.models import PackReference
from evidenceforge.composition.packs import LoadedPack, PackRepository
from evidenceforge.desktop.library import discover_scenarios
from evidenceforge.models.exceptions import ConfigurationError, PathSafetyError
from evidenceforge.studio.imports import (
    PackImportRequest,
    ScenarioImportRequest,
    build_portable_archive,
    dependency_health,
    prepare_archive,
    prepare_scenario,
)
from evidenceforge.studio.lifecycle import rename_scenario
from evidenceforge.studio.paths import StudioPaths
from evidenceforge.studio.service import ValidationResult, create_app
from evidenceforge.studio.settings import StudioSettings
from evidenceforge.utils import load_scenario_source_graph


def _write(path: Path, data: dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def _scenario(path: Path, composition: dict[str, object] | None = None) -> Path:
    return _write(
        path,
        {
            "name": "original",
            "scenario_version": "2.0",
            **(
                {"composition": composition}
                if composition
                else {"environment": {"users": [], "systems": []}}
            ),
        },
    )


def _pack(workspace: Path, kind: str, name: str) -> LoadedPack:
    workspace.mkdir(parents=True, exist_ok=True)
    repository = PackRepository(workspace)
    reference = PackReference(
        source="package", publisher="evidenceforge", name=name, version="1.0.0"
    )
    source = repository.resolve(reference, expected_type=kind)
    repository.copy(
        source,
        name=name,
        version="1.0.0",
        publisher="evidenceforge",
        publisher_display_name="EvidenceForge Official",
    )
    return repository.resolve(
        reference.model_copy(update={"source": "project"}), expected_type=kind
    )


def _multi_source(root: Path) -> tuple[LoadedPack, list[LoadedPack]]:
    industries = [_pack(root / name, "industry", name) for name in ("healthcare", "finance")]
    organization = _pack(root / "organization", "organization", "metrolink-specialty-care")
    manifest = yaml.safe_load((organization.root / "pack.yaml").read_text())
    # Include-fragment ownership must also survive relocation.
    dependencies = [
        {
            "source": "path",
            "path": str(pack.root),
            "type": "industry",
            "publisher": "evidenceforge",
            "name": pack.manifest.name,
            "version_constraint": ">=1.0.0,<2.0.0",
        }
        for pack in industries
    ]
    manifest.pop("industry_dependencies")
    manifest["includes"] = ["dependencies.yaml"]
    _write(organization.root / "pack.yaml", manifest)
    _write(organization.root / "dependencies.yaml", {"industry_dependencies": dependencies})
    _write(
        organization.root / "pack.lock.yaml",
        {
            "lock_schema_version": "1.0",
            "dependencies": [
                {
                    "publisher": "evidenceforge",
                    "type": "industry",
                    "name": pack.manifest.name,
                    "version": "1.0.0",
                    "digest": pack.digest,
                }
                for pack in industries
            ],
        },
    )
    organization = PackRepository(root / "organization").resolve(
        PackReference(
            source="project",
            publisher="evidenceforge",
            name="metrolink-specialty-care",
            version="1.0.0",
        ),
        expected_type="organization",
    )
    return organization, industries


def _paths(root: Path) -> StudioPaths:
    return StudioPaths(
        config=root / "config",
        data=root / "data",
        state=root / "state",
        cache=root / "cache",
        logs=root / "logs",
    )


def test_nested_includes_metadata_assets_and_document_selection(tmp_path: Path) -> None:
    source = _write(tmp_path / "source/scenario.yaml", {"includes": ["../shared/metadata.yaml"]})
    _write(
        tmp_path / "shared/metadata.yaml",
        {"name": "old", "version": "1.0", "includes": ["nested/env.yaml"]},
    )
    _write(
        tmp_path / "shared/nested/env.yaml",
        {"environment": {"users": [], "systems": [], "email": {"corpus": "messages.yaml"}}},
    )
    corpus = _write(tmp_path / "shared/nested/messages.yaml", {"messages": []})
    (source.parent / "ENVIRONMENT.md").write_text("# Environment\n")
    (source.parent / "PRIVATE.md").write_text("Not selected")
    originals = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    workspace = tmp_path / "destination"
    workspace.mkdir()
    plan = prepare_scenario(
        ScenarioImportRequest(path=source, name="imported", documents=["ENVIRONMENT.md"]),
        workspace,
        tmp_path / "cache",
    )
    try:
        path = plan.commit(workspace, [])
        graph = load_scenario_source_graph(path)
        assert graph.data["name"] == "imported"
        assert graph.data["environment"]["email"]["corpus"].endswith(corpus.name)
        assert all(entry.path.is_relative_to(workspace) for entry in graph.sources)
        assert len(discover_scenarios(workspace, [])) == 1
        assert (path.parent / "ENVIRONMENT.md").is_file()
        assert not (path.parent / "PRIVATE.md").exists()
        assert dependency_health(path, workspace).ready
        rename_scenario(path, "renamed", hashlib.sha256(path.read_bytes()).hexdigest())
        assert load_scenario_source_graph(path).data["name"] == "renamed"
        assert all(path.read_bytes() == content for path, content in originals.items())
    finally:
        plan.close()


def test_missing_pack_can_import_and_later_resolve(tmp_path: Path) -> None:
    reference = {
        "source": "project",
        "publisher": "evidenceforge",
        "name": "healthcare",
        "version": "1.0.0",
    }
    source = _scenario(tmp_path / "source/scenario.yaml", {"industries": [reference]})
    workspace = tmp_path / "destination"
    workspace.mkdir()
    plan = prepare_scenario(
        ScenarioImportRequest(path=source, name="imported"), workspace, tmp_path / "cache"
    )
    try:
        assert any(row.status == "missing" for row in plan.review.rows)
        path = plan.commit(workspace, [])
        initial = dependency_health(path, workspace)
        assert not initial.ready
        assert discover_scenarios(workspace, [])[0].path == path
        pack = _pack(workspace, "industry", "healthcare")
        updated = dependency_health(path, workspace)
        assert updated.ready
        assert updated.fingerprint != initial.fingerprint
        assert updated.rows[0].source == str(pack.root / "pack.yaml")
    finally:
        plan.close()


def test_multiple_source_workspaces_copy_exact_versions_and_rebind_fragment(tmp_path: Path) -> None:
    organization, industries = _multi_source(tmp_path / "sources")
    source = _scenario(
        tmp_path / "author/scenario.yaml",
        {
            "organization": {
                "source": "project",
                "publisher": "evidenceforge",
                "name": organization.manifest.name,
                "version": "1.0.0",
            }
        },
    )
    workspace = tmp_path / "destination"
    workspace.mkdir()
    plan = prepare_scenario(
        ScenarioImportRequest(
            path=source,
            name="imported",
            source_workspaces=[
                tmp_path / "sources/organization",
                *(tmp_path / f"sources/{pack.manifest.name}" for pack in industries),
            ],
        ),
        workspace,
        tmp_path / "cache",
    )
    try:
        rows = [row for row in plan.review.rows if row.kind == "pack"]
        assert len(rows) == 3
        assert all(row.status == "copy" for row in rows)
        org_row = next(row for row in rows if "organization:" in row.key)
        assert org_row.digest != org_row.source_digest
        path = plan.commit(workspace, plan.review.publishers)
        shutil.rmtree(tmp_path / "sources")
        assert dependency_health(path, workspace).ready
        copied = PackRepository(workspace).resolve(
            PackReference(
                source="project",
                publisher="evidenceforge",
                name=organization.manifest.name,
                version="1.0.0",
            ),
            expected_type="organization",
        )
        assert all(
            dependency.source == "project" and dependency.path is None
            for dependency in copied.manifest.industry_dependencies
        )
        assert [entry.digest for entry in copied.lock.dependencies] == [
            pack.digest for pack in industries
        ]
    finally:
        plan.close()


def test_portable_export_import_reuses_and_never_overwrites_conflicts(tmp_path: Path) -> None:
    organization, _industries = _multi_source(tmp_path / "sources")
    archive = tmp_path / "portable.efpack"
    build_portable_archive(PackRepository(tmp_path / "sources/organization"), organization, archive)
    repeated = tmp_path / "repeated.efpack"
    build_portable_archive(
        PackRepository(tmp_path / "sources/organization"), organization, repeated
    )
    assert archive.read_bytes() == repeated.read_bytes()
    workspace = tmp_path / "destination"
    workspace.mkdir()
    shutil.rmtree(tmp_path / "sources")
    request = PackImportRequest(path=archive)
    plan = prepare_archive(request, workspace, tmp_path / "cache")
    try:
        with pytest.raises(ValueError, match="publisher"):
            plan.commit(workspace, [])
        plan.commit(workspace, plan.review.publishers)
    finally:
        plan.close()
    reused = prepare_archive(request, workspace, tmp_path / "cache")
    try:
        assert all(row.status == "available" for row in reused.review.rows)
        reused.commit(workspace, reused.review.publishers)
    finally:
        reused.close()
    manifest = workspace / ".eforge/packs/evidenceforge/industry/healthcare/1.0.0/pack.yaml"
    manifest.write_text(manifest.read_text() + "\n# local edit\n")
    preserved = manifest.read_bytes()
    conflict = prepare_archive(request, workspace, tmp_path / "cache")
    try:
        assert not conflict.review.can_import
        assert any(row.status == "conflict" for row in conflict.review.rows)
        with pytest.raises(ValueError, match="conflicts"):
            conflict.commit(workspace, conflict.review.publishers)
        assert manifest.read_bytes() == preserved
    finally:
        conflict.close()


@pytest.mark.parametrize("change", ["source", "destination", "workspace"])
def test_stale_reviews_refuse_publication(tmp_path: Path, change: str) -> None:
    source = _scenario(tmp_path / "source/scenario.yaml")
    workspace = tmp_path / "destination"
    workspace.mkdir()
    plan = prepare_scenario(
        ScenarioImportRequest(path=source, name="imported"), workspace, tmp_path / "cache"
    )
    try:
        if change == "source":
            source.write_text(source.read_text() + "\n# edit\n")
        elif change == "destination":
            (workspace / "scenarios/imported").mkdir(parents=True)
        with pytest.raises(FileExistsError):
            plan.commit(tmp_path / "other" if change == "workspace" else workspace, [])
        assert not (workspace / "scenarios/imported/scenario.yaml").exists()
    finally:
        plan.close()


def test_failed_publish_rolls_back_only_new_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _scenario(tmp_path / "source/scenario.yaml")
    workspace = tmp_path / "destination"
    workspace.mkdir()
    retained = _scenario(workspace / "scenarios/existing/scenario.yaml")
    plan = prepare_scenario(
        ScenarioImportRequest(path=source, name="imported"), workspace, tmp_path / "cache"
    )

    def fail_replace(_source: Path, _target: Path) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(import_module.os, "replace", fail_replace)
    try:
        with pytest.raises(OSError, match="disk full"):
            plan.commit(workspace, [])
        assert not (workspace / "scenarios/imported").exists()
        assert retained.is_file()
    finally:
        plan.close()


@pytest.mark.parametrize("unsafe", ["link", "corpus_escape", "include_cycle"])
def test_unsafe_or_cyclic_sources_are_refused_before_copy(tmp_path: Path, unsafe: str) -> None:
    source = _scenario(tmp_path / "source/scenario.yaml")
    if unsafe == "link":
        link = source.with_name("link.yaml")
        link.symlink_to(source)
        source = link
    elif unsafe == "corpus_escape":
        _write(
            source,
            {
                "name": "original",
                "version": "1.0",
                "environment": {"email": {"corpus": "../secret.yaml"}},
            },
        )
        _write(tmp_path / "secret.yaml", {"private": True})
    else:
        _write(source, {"name": "original", "version": "1.0", "includes": ["scenario.yaml"]})
    with pytest.raises((ValueError, OSError, ConfigurationError, PathSafetyError)):
        prepare_scenario(
            ScenarioImportRequest(path=source, name="imported"),
            tmp_path / "destination",
            tmp_path / "cache",
        )
    assert not (tmp_path / "destination/scenarios").exists()


def test_service_review_validation_commit_and_dependency_refresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "destination"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    source = _scenario(
        tmp_path / "source/scenario.yaml",
        {
            "industries": [
                {
                    "source": "project",
                    "publisher": "evidenceforge",
                    "name": "healthcare",
                    "version": "1.0.0",
                }
            ]
        },
    )
    validations: list[Path] = []

    def validate(_settings: object, scenario: Path, root: Path) -> ValidationResult:
        validations.append(scenario)
        assert root != workspace if len(validations) == 1 else root == workspace
        return ValidationResult(exit_code=1, error="Advisory schema finding")

    monkeypatch.setattr(service_module, "_validate_source", validate)
    paths = _paths(tmp_path / "private")
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(paths, "secret")) as client:
        request = {"path": str(source), "name": "imported"}
        assert client.post("/v1/imports/scenario/preview", json=request).status_code == 401
        assert (
            client.post(
                "/v1/imports/scenario/preview",
                headers=headers,
                json={**request, "name": "invalid name"},
            ).status_code
            == 422
        )
        project = client.post("/v1/projects", headers=headers, json={"name": "Training"}).json()
        review = client.post(
            "/v1/imports/scenario/preview",
            headers=headers,
            json={**request, "project_id": project["id"]},
        ).json()
        assert not validations
        assert not (workspace / "scenarios/imported").exists()
        advisory = client.post(f"/v1/imports/{review['id']}/validate", headers=headers)
        assert advisory.json()["exit_code"] == 1
        result = client.post(f"/v1/imports/{review['id']}/commit", headers=headers, json={}).json()
        item = result["item"]
        assert item["name"] == "imported" and item["project_id"] == project["id"]
        snapshot = client.get("/v1/bootstrap", headers=headers).json()
        assert validations[-1] == Path(item["path"])
        assert snapshot["validations"][item["id"]]["result"]["error"] == "Advisory schema finding"
        assert not snapshot["dependencies"][item["id"]]["ready"]
        assert (
            client.post(
                "/v1/jobs/generations", headers=headers, json={"scenario_id": item["id"]}
            ).status_code
            == 409
        )
        _pack(workspace, "industry", "healthcare")
        health = client.post(
            f"/v1/scenarios/{item['id']}/dependencies/refresh", headers=headers
        ).json()
        assert health["ready"]
        assert health["changed_at"] > 0
        # A Studio import also refreshes all scenario health automatically.
        manifest = workspace / ".eforge/packs/evidenceforge/industry/healthcare/1.0.0/pack.yaml"
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        manifest.write_text(manifest.read_text() + "\n# authored edit\n")
        refreshed = client.post("/v1/library/refresh", headers=headers)
        assert refreshed.status_code == 200
        assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
    with TestClient(create_app(paths, "secret")) as client:
        snapshot = client.get("/v1/bootstrap", headers=headers).json()
        assert snapshot["dependencies"][item["id"]]["ready"]
        assert snapshot["dependencies"][item["id"]]["fingerprint"] != health["fingerprint"]


def test_pack_import_refreshes_missing_scenarios_and_export_is_authenticated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "destination"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    source = _scenario(
        workspace / "scenarios/example/scenario.yaml",
        {
            "industries": [
                {
                    "source": "project",
                    "publisher": "evidenceforge",
                    "name": "healthcare",
                    "version": "1.0.0",
                }
            ]
        },
    )
    source_workspace = tmp_path / "source-workspace"
    _pack(source_workspace, "industry", "healthcare")
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(_paths(tmp_path / "private"), "secret")) as client:
        snapshot = client.get("/v1/bootstrap", headers=headers).json()
        item = next(item for item in snapshot["items"] if item["path"] == str(source))
        assert not snapshot["dependencies"][item["id"]]["ready"]
        review = client.post(
            "/v1/imports/pack/preview", headers=headers, json={"path": str(source_workspace)}
        ).json()
        response = client.post(
            f"/v1/imports/{review['id']}/commit",
            headers=headers,
            json={"accepted_publishers": review["publishers"]},
        )
        assert response.status_code == 200, response.text
        assert response.json()["packs"] == 1
        snapshot = client.get("/v1/bootstrap", headers=headers).json()
        assert snapshot["dependencies"][item["id"]]["ready"]
        pack = next(
            item
            for item in snapshot["items"]
            if item["kind"] == "industry_pack" and Path(item["path"]).is_relative_to(workspace)
        )
        assert client.get(f"/v1/packs/{pack['id']}/export").status_code == 401
        exported = client.get(f"/v1/packs/{pack['id']}/export", headers=headers)
        assert exported.status_code == 200, exported.text
        assert exported.headers["content-disposition"].endswith('"healthcare-1.0.0.efpack"')


def test_health_names_missing_and_conflicting_locked_industry(tmp_path: Path) -> None:
    organization, industries = _multi_source(tmp_path / "sources")
    source = _scenario(
        tmp_path / "source/scenario.yaml",
        {
            "organization": {
                "source": "path",
                "publisher": "evidenceforge",
                "name": organization.manifest.name,
                "version": "1.0.0",
                "path": str(organization.root),
            }
        },
    )
    manifest = industries[0].root / "pack.yaml"
    available = dependency_health(source, tmp_path)
    assert available.ready
    assert {row.source for row in available.rows if row.kind == "pack"} == {
        str(pack.root / "pack.yaml") for pack in [organization, *industries]
    }
    original = manifest.read_text()
    manifest.write_text(original + "\n# changed locked bytes\n")
    health = dependency_health(source, tmp_path)
    assert not health.ready
    assert any(
        row.key == "evidenceforge:industry:healthcare@1.0.0"
        and row.status == "conflict"
        and row.source == str(manifest)
        for row in health.rows
    )
    shutil.rmtree(industries[0].root)
    health = dependency_health(source, tmp_path)
    assert any(
        row.key == "evidenceforge:industry:healthcare@1.0.0" and row.status == "missing"
        for row in health.rows
    )


def test_prepared_and_imported_scenario_pass_real_cli_validation(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "fixtures/scenarios/minimal.yaml"
    workspace = tmp_path / "destination"
    workspace.mkdir()
    plan = prepare_scenario(
        ScenarioImportRequest(path=source, name="imported", documents=[]),
        workspace,
        tmp_path / "cache",
    )
    try:
        settings = StudioSettings(workspace=workspace)
        staged = service_module._validate_source(settings, plan.stage / plan.target, plan.stage)
        assert staged.exit_code == 0, staged.error
        imported = plan.commit(workspace, [])
        actual = service_module._validate_source(settings, imported, workspace)
        assert actual.exit_code == 0, actual.error
        assert actual.report["valid"]
    finally:
        plan.close()


def test_import_reviews_and_dependency_routes_cannot_cross_workspaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(first))
    source = _scenario(first / "scenarios/existing/scenario.yaml")
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(_paths(tmp_path / "private"), "secret")) as client:
        snapshot = client.get("/v1/bootstrap", headers=headers).json()
        item = next(item for item in snapshot["items"] if item["path"] == str(source))
        project = client.post(
            "/v1/projects", headers=headers, json={"name": "First project"}
        ).json()
        review = client.post(
            "/v1/imports/scenario/preview",
            headers=headers,
            json={"path": str(source), "name": "copy"},
        ).json()
        assert (
            client.post(
                "/v1/workspaces/select", headers=headers, json={"path": str(second)}
            ).status_code
            == 200
        )
        assert (
            client.post(f"/v1/imports/{review['id']}/commit", headers=headers, json={}).status_code
            == 404
        )
        assert (
            client.post(
                f"/v1/scenarios/{item['id']}/dependencies/refresh", headers=headers
            ).status_code
            == 404
        )
        assert (
            client.post(
                "/v1/validate", headers=headers, json={"scenario_id": item["id"]}
            ).status_code
            == 404
        )
        assert (
            client.post(
                "/v1/imports/scenario/preview",
                headers=headers,
                json={"path": str(source), "name": "copy", "project_id": project["id"]},
            ).status_code
            == 404
        )
        assert not (first / "scenarios/copy").exists()
        assert not (second / "scenarios/copy").exists()


@pytest.mark.parametrize("section", ["environment", "composition"])
def test_schema_findings_do_not_block_import_or_crash_dependency_checks(
    tmp_path: Path, section: str
) -> None:
    source = _write(
        tmp_path / "source/scenario.yaml",
        {"name": "invalid", "version": "1.0", section: "invalid scalar"},
    )
    workspace = tmp_path / "destination"
    workspace.mkdir()
    plan = prepare_scenario(
        ScenarioImportRequest(path=source, name="repair-me"), workspace, tmp_path / "cache"
    )
    try:
        imported = plan.commit(workspace, [])
        assert discover_scenarios(workspace, [])[0].name == "repair-me"
        assert isinstance(dependency_health(imported, workspace).ready, bool)
    finally:
        plan.close()


@pytest.mark.parametrize("source_kind", ["workspace", "release"])
def test_pack_subset_keeps_exact_dependencies_and_leaves_other_packs_out(
    tmp_path: Path, source_kind: str
) -> None:
    organization, industries = _multi_source(tmp_path / "sources")
    workspace = tmp_path / "destination"
    workspace.mkdir()
    source = tmp_path / "sources/organization"
    if source_kind == "release":
        source = tmp_path / "portable.efpack"
        build_portable_archive(
            PackRepository(tmp_path / "sources/organization"), organization, source
        )
    plan = prepare_archive(PackImportRequest(path=source), workspace, tmp_path / "cache")
    healthcare_key = "evidenceforge:industry:healthcare@1.0.0"
    org_key = "evidenceforge:organization:metrolink-specialty-care@1.0.0"
    try:
        assert plan.selected_pack_keys([org_key]) == {
            healthcare_key,
            org_key,
            "evidenceforge:industry:finance@1.0.0",
        }
        with pytest.raises(ValueError, match="at least one"):
            plan.commit(workspace, plan.review.publishers, [])
        with pytest.raises(ValueError, match="not part"):
            plan.commit(workspace, plan.review.publishers, ["unknown:industry:pack@1.0.0"])
        # Changes to unselected workspace inputs must not affect a selected standalone pack.
        if source_kind == "workspace":
            (industries[1].root / "pack.yaml").write_text("changed after review")
        plan.commit(workspace, plan.review.publishers, [healthcare_key])
        roots = list((workspace / ".eforge/packs").rglob("pack.yaml"))
        assert len(roots) == 1
        assert roots[0].parent.parent.name == "healthcare"
    finally:
        plan.close()


def test_selected_organization_automatically_imports_its_locked_closure(tmp_path: Path) -> None:
    organization, _industries = _multi_source(tmp_path / "sources")
    workspace = tmp_path / "destination"
    workspace.mkdir()
    plan = prepare_archive(
        PackImportRequest(path=tmp_path / "sources/organization"), workspace, tmp_path / "cache"
    )
    try:
        key = "evidenceforge:organization:metrolink-specialty-care@1.0.0"
        plan.commit(workspace, plan.review.publishers, [key])
        imported = PackRepository(workspace).resolve(
            PackReference(
                source="project",
                publisher="evidenceforge",
                name=organization.manifest.name,
                version="1.0.0",
            ),
            expected_type="organization",
        )
        assert len(PackRepository(workspace).validate_semantics(imported)) == 2
        assert len(list((workspace / ".eforge/packs").rglob("pack.yaml"))) == 3
    finally:
        plan.close()


def test_pack_subset_ignores_unselected_conflict_and_assigns_only_new_copies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    _pack(source, "industry", "healthcare")
    _pack(source, "industry", "finance")
    workspace = tmp_path / "destination"
    existing = _pack(workspace, "industry", "finance")
    manifest = existing.root / "pack.yaml"
    manifest.write_text(manifest.read_text() + "\n# local changes\n")
    original = manifest.read_bytes()
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    paths = _paths(tmp_path / "private")
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(paths, "secret")) as client:
        project = client.post("/v1/projects", headers=headers, json={"name": "Training"}).json()
        preview = {"path": str(source), "project_id": project["id"]}
        assert (
            client.post(
                "/v1/imports/pack/preview",
                headers=headers,
                json={**preview, "project_id": "missing"},
            ).status_code
            == 404
        )
        review = client.post("/v1/imports/pack/preview", headers=headers, json=preview).json()
        assert not review["can_import"]
        response = client.post(
            f"/v1/imports/{review['id']}/commit",
            headers=headers,
            json={
                "accepted_publishers": review["publishers"],
                "selected_packs": ["evidenceforge:industry:healthcare@1.0.0"],
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["packs"] == 1
        packs = [
            item
            for item in client.get("/v1/bootstrap", headers=headers).json()["items"]
            if Path(item["path"]).is_relative_to(workspace)
        ]
        assert (
            next(item for item in packs if item["name"] == "healthcare")["project_id"]
            == project["id"]
        )
        assert next(item for item in packs if item["name"] == "finance")["project_id"] is None
        assert manifest.read_bytes() == original
    with TestClient(create_app(paths, "secret")) as client:
        imported = next(
            item
            for item in client.get("/v1/bootstrap", headers=headers).json()["items"]
            if item["project_id"]
        )
        assert imported["name"] == "healthcare"
        assert imported["imported"]
