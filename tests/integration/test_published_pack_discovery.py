"""Published pack discovery and exact resolution use the same file authority."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from evidenceforge.artifacts.discovery import discover_publications
from evidenceforge.artifacts.lifecycle import create_draft, create_new_draft, publish
from evidenceforge.cli.commands import app
from evidenceforge.composition import compile_scenario
from evidenceforge.composition.models import PackReference, PackType
from evidenceforge.composition.packs import PackRepository, parse_pack_cli_reference
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
from evidenceforge.composition.releases import build_efpack, hydrate_release, import_efpack
from evidenceforge.desktop.library import discover_packs
from evidenceforge.models.exceptions import PackError

runner = CliRunner()


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    root = tmp_path / "workspace"
    root.mkdir()
    set_publisher(
        root,
        PublisherIdentity(publisher="testing", publisher_display_name="Tests"),
        scope="project",
        force=False,
    )
    return root


def _publish(project: Path, kind: PackType, name: str = "talos-enterprises") -> tuple[Path, Path]:
    draft = create_new_draft(
        kind,
        name,
        description="Reusable test pack",
        project_root=project,
        display_name="Talos Enterprises",
    )
    return draft, publish(draft, project_root=project, version="1.0.0", accept_warnings=True)


def _list(project: Path, scope: str = "all") -> tuple[int, dict[str, Any]]:
    result = runner.invoke(
        app, ["pack", "list", "--json", "--scope", scope, "--project-root", str(project)]
    )
    assert result.stdout, result.exception
    return result.exit_code, json.loads(result.stdout)


def _files(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }


@pytest.mark.parametrize("kind", ["industry", "organization"])
def test_published_pack_is_listed_shown_and_discovered_without_writes(
    project: Path, kind: PackType
) -> None:
    draft, release = _publish(project, kind)
    before = _files(project)
    reference = f"project:testing:{kind}:talos-enterprises@1.0.0"

    code, payload = _list(project)
    assert code == 0 and not payload["issues"]
    listed = [entry for entry in payload["packs"] if entry["name"] == "talos-enterprises"]
    assert len(listed) == 1
    record = listed[0]
    assert record["reference"] == reference
    assert record["publisher"] == "testing"
    assert record["display_name"] == "Talos Enterprises"
    assert record["version"] == "1.0.0" and record["pack_schema_version"] == "3.0"
    assert record["scope"] == "project-release" and record["source"] == "project"
    assert record["resolvable"] and not record["mutable"]
    assert record["hydration_state"] == "native"
    assert record["location"] == str(release.parent)
    assert set(record["exports"]) == {
        "persona_catalog",
        "process_catalog",
        "application_catalog",
        "destination_catalog",
        "traffic_catalog",
        "storage_catalog",
    }

    shown = runner.invoke(
        app, ["pack", "show", reference, "--json", "--project-root", str(project)]
    )
    assert shown.exit_code == 0, shown.stdout
    assert json.loads(shown.stdout)["digest"] == record["digest"]
    assert json.loads(shown.stdout)["exports"] == record["exports"]
    items = discover_packs(project, kind)
    assert any(item.path == release for item in items)
    assert not any(item.path == draft for item in items)
    publications, issues = discover_publications(project, kinds=(kind,))
    assert not issues and [entry.source for entry in publications] == [release]
    assert any(pack.root == release.parent for pack in PackRepository(project).list())
    assert _files(project) == before
    assert not (project / ".eforge/packs").exists()


@pytest.mark.parametrize(
    "scope,present",
    [
        ("all", True),
        ("project", True),
        ("project-release", True),
        ("package", False),
        ("user-release", False),
    ],
)
def test_published_pack_scope_contract(project: Path, scope: str, present: bool) -> None:
    _publish(project, "industry")
    code, payload = _list(project, scope)
    assert code == 0
    assert any(entry["name"] == "talos-enterprises" for entry in payload["packs"]) is present


def test_published_industry_locks_into_an_organization_and_scenario(project: Path) -> None:
    _publish(project, "industry", "robotics")
    org = create_new_draft(
        "organization", "talos-enterprises", description="Organization", project_root=project
    )
    manifest = yaml.safe_load(org.read_bytes())
    manifest["industry_dependencies"] = [
        {
            "source": "project",
            "publisher": "testing",
            "type": "industry",
            "name": "robotics",
            "version_constraint": "==1.0.0",
        }
    ]
    org.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    minimal = yaml.safe_load(Path("tests/fixtures/scenarios/minimal.yaml").read_bytes())
    (org.parent / "model/environment.yaml").write_text(
        yaml.safe_dump({"environment": minimal["environment"]}), encoding="utf-8"
    )
    repository = PackRepository(project)
    reference, kind = parse_pack_cli_reference(str(org))
    loaded = repository.resolve(reference, expected_type=kind)
    lock = repository.proposed_lock(loaded)
    assert lock.dependencies[0].name == "robotics"
    repository.update_lock(loaded, lock)
    release = publish(org, project_root=project, version="1.0.0", accept_warnings=True)

    original = project / "scenario.yaml"
    original.write_text(yaml.safe_dump(minimal), encoding="utf-8")
    scenario = create_draft(original, project_root=project)
    document = yaml.safe_load(scenario.read_bytes())
    document["environment"] = {}
    document["composition"] = {
        "organization": {
            "source": "project",
            "publisher": "testing",
            "name": "talos-enterprises",
            "version": "1.0.0",
        }
    }
    scenario.write_text(yaml.safe_dump(document), encoding="utf-8")
    before = _files(project)
    code, payload = _list(project)
    assert code == 0
    organization = next(entry for entry in payload["packs"] if entry["name"] == "talos-enterprises")
    assert organization["locked_dependencies"][0]["name"] == "robotics"
    compiled = compile_scenario(scenario, project_root=project)
    assert {entry.name for entry in compiled.selected_packs} == {"robotics", "talos-enterprises"}
    assert compiled.scenario.environment.systems[0].hostname == "TEST-01"
    assert organization["location"] == str(release.parent)
    assert _files(project) == before


def _legacy_copy(project: Path, release: Path) -> Path:
    destination = project / ".eforge/packs/testing/industry/talos-enterprises/1.0.0"
    shutil.copytree(release.parent, destination)
    return destination


def test_identical_project_and_published_copies_have_one_authoritative_entry(project: Path) -> None:
    _draft, release = _publish(project, "industry")
    _legacy_copy(project, release)
    code, payload = _list(project)
    assert code == 0 and not payload["issues"]
    matches = [entry for entry in payload["packs"] if entry["name"] == "talos-enterprises"]
    assert len(matches) == 1 and matches[0]["location"] == str(release.parent)
    selected = PackRepository(project).resolve(
        PackReference(
            source="project", publisher="testing", name="talos-enterprises", version="1.0.0"
        ),
        expected_type="industry",
    )
    assert selected.root == release.parent


def test_conflicting_project_identity_is_reported_and_cannot_resolve(project: Path) -> None:
    _draft, release = _publish(project, "industry")
    _publish(project, "organization", "healthy")
    copied = _legacy_copy(project, release)
    manifest = copied / "pack.yaml"
    manifest.write_text(
        manifest.read_text().replace("Reusable test pack", "Different contents"), encoding="utf-8"
    )
    code, payload = _list(project)
    assert code == 2 and not payload["valid"]
    assert any(entry["name"] == "healthy" for entry in payload["packs"])
    assert not any(entry["name"] == "talos-enterprises" for entry in payload["packs"])
    assert len(payload["issues"]) == 1
    assert "conflicting contents" in payload["issues"][0]["error"]
    with pytest.raises(PackError, match="conflicting contents"):
        PackRepository(project).resolve(
            PackReference(
                source="project", publisher="testing", name="talos-enterprises", version="1.0.0"
            ),
            expected_type="industry",
        )


@pytest.mark.parametrize("damage", ["receipt", "source", "missing-receipt"])
def test_damaged_publication_does_not_hide_other_packs(project: Path, damage: str) -> None:
    _draft, release = _publish(project, "industry")
    _publish(project, "organization", "healthy")
    if damage == "receipt":
        (release.parent.parent / "release.json").write_text("[]", encoding="utf-8")
    elif damage == "source":
        release.write_text(release.read_text() + "# damaged\n", encoding="utf-8")
    else:
        (release.parent.parent / "release.json").unlink()
    code, payload = _list(project)
    assert code == 2 and not payload["valid"]
    assert any(entry["name"] == "healthy" for entry in payload["packs"])
    assert any(entry["source"] == "package" for entry in payload["packs"])
    assert not any(entry["name"] == "talos-enterprises" for entry in payload["packs"])
    assert len(payload["issues"]) == 1
    assert payload["issues"][0]["scope"] == "project-release"
    assert payload["issues"][0]["location"] == str(release.parent.parent)
    assert any(item.name == "healthy" for item in discover_packs(project, "organization"))
    discover_packs(project, "industry")  # A damaged receipt also cannot break Studio's scan.


def test_publication_at_an_alias_path_is_not_advertised_as_resolvable(project: Path) -> None:
    _draft, release = _publish(project, "industry")
    actual = release.parent.parent
    alias = actual.parents[1] / "wrong-name" / actual.name
    alias.parent.mkdir()
    actual.rename(alias)
    code, payload = _list(project)
    assert code == 2
    assert not any(entry["name"] == "talos-enterprises" for entry in payload["packs"])
    assert "repository identity" in payload["issues"][0]["error"]


def test_publication_discovery_does_not_follow_directory_or_receipt_links(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _draft, release = _publish(project, "industry")
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "release.json"
    secret.write_text("DO_NOT_READ", encoding="utf-8")
    link = project / ".eforge/artifacts/releases/linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
        receipt = release.parent.parent / "release.json"
        receipt.unlink()
        receipt.symlink_to(secret)
    except OSError:
        pytest.skip("Native symlink creation is unavailable")
    original = Path.read_bytes

    def bounded_read(path: Path) -> bytes:
        assert path != secret
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", bounded_read)
    code, payload = _list(project)
    assert code == 2 and len(payload["issues"]) == 2
    assert "DO_NOT_READ" not in json.dumps(payload)
    assert all("symbolic links" in issue["error"] for issue in payload["issues"])


def test_explicit_project_selection_does_not_search_parents(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _publish(project, "industry")
    nested = project / "empty-child"
    nested.mkdir()
    monkeypatch.chdir(nested)
    result = runner.invoke(app, ["pack", "list", "--json"])
    assert result.exit_code == 0
    assert not any(
        entry["name"] == "talos-enterprises" for entry in json.loads(result.stdout)["packs"]
    )
    assert not (nested / ".eforge").exists()
    code, explicit = _list(project)
    assert code == 0 and any(entry["name"] == "talos-enterprises" for entry in explicit["packs"])


def test_legacy_imported_releases_retain_their_hydration_contract(project: Path) -> None:
    _publish(project, "industry")
    repository = PackRepository(project)
    package = repository.resolve(
        PackReference(source="package", publisher="evidenceforge", name="finance", version="1.0.0"),
        expected_type="industry",
    )
    archive = project / "finance.efpack"
    build_efpack(repository, package, archive)
    import_efpack(
        archive, project_root=project, scope="project", accepted_publishers={"evidenceforge"}
    )
    code, payload = _list(project, "project-release")
    assert code == 0
    native = next(entry for entry in payload["packs"] if entry["name"] == "talos-enterprises")
    legacy = next(entry for entry in payload["packs"] if entry["name"] == "finance")
    assert native["resolvable"] and native["hydration_state"] == "native"
    assert not legacy["resolvable"] and legacy["hydration_state"] == "dehydrated"
    hydrate_release("evidenceforge:industry:finance@1.0.0", project, scope="project")
    code, payload = _list(project)
    assert code == 0
    legacy = next(
        entry
        for entry in payload["packs"]
        if entry["name"] == "finance" and entry["scope"] == "project-release"
    )
    assert legacy["hydration_state"] == "hydrated" and not legacy["resolvable"]
    assert any(
        entry["name"] == "finance" and entry["scope"] == "project" and entry["resolvable"]
        for entry in payload["packs"]
    )


def test_invalid_legacy_entry_preserves_valid_publications(project: Path) -> None:
    _publish(project, "industry")
    bad = project / ".eforge/packs/testing/industry/broken/1.0.0"
    bad.mkdir(parents=True)
    code, payload = _list(project)
    assert code == 2
    assert any(entry["name"] == "talos-enterprises" for entry in payload["packs"])
    assert payload["issues"][0]["scope"] == "project"
    code, payload = _list(project, "project-release")
    assert code == 0 and payload["issues"] == []


def test_long_identifiers_use_receipt_identity_instead_of_storage_folder(project: Path) -> None:
    name = "a" * 300
    _draft, release = _publish(project, "industry", name)
    code, payload = _list(project)
    assert code == 0
    record = next(entry for entry in payload["packs"] if entry["name"] == name)
    assert record["reference"] == f"project:testing:industry:{name}@1.0.0"
    assert record["location"] == str(release.parent)
    assert release.parent.parent.parent.name != name


def test_in_progress_publication_staging_is_not_an_invalid_release(project: Path) -> None:
    _publish(project, "industry")
    staging = (
        project
        / ".eforge/artifacts/releases/testing/industry/talos-enterprises/.publish-in-progress"
    )
    staging.mkdir()
    code, payload = _list(project)
    assert code == 0 and not payload["issues"]


def test_a_version_replaced_by_a_file_is_an_isolated_inventory_issue(project: Path) -> None:
    _draft, release = _publish(project, "industry")
    version = release.parent.parent
    shutil.rmtree(version)
    version.write_text("damaged publication", encoding="utf-8")
    code, payload = _list(project)
    assert code == 2 and len(payload["issues"]) == 1
    assert "not a directory" in payload["issues"][0]["error"]
    assert any(entry["source"] == "package" for entry in payload["packs"])
