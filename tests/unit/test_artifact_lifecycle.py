"""Shared lifecycle acceptance without Studio imports, state or helper processes."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from evidenceforge.artifacts.lifecycle import (
    ArtifactError,
    create_draft,
    inspect_artifact,
    publish,
    verify_release,
)
from evidenceforge.artifacts.portable import export_release, import_release
from evidenceforge.composition import compile_scenario
from evidenceforge.composition.packs import PackRepository, parse_pack_cli_reference
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
from evidenceforge.models.exceptions import SchemaValidationError
from evidenceforge.schema import identify_document, update_top_level


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


def _scenario(project: Path) -> Path:
    path = project / "scenario.yaml"
    shutil.copyfile("tests/fixtures/scenarios/minimal.yaml", path)
    return path


@pytest.mark.parametrize("marker", [None, "", 3, "9.0"])
def test_present_invalid_marker_never_falls_through(marker: object) -> None:
    with pytest.raises(SchemaValidationError):
        identify_document(
            {
                "name": "test",
                "environment": {},
                "schema_version": marker,
                "scenario_version": "2.0",
                "version": "1.0",
            }
        )


@pytest.mark.parametrize(
    "document,family",
    [
        ({"kind": "evidenceforge.resolved-scenario", "schema_version": "1.0"}, "resolved"),
        ({"name": "fragment", "version": "3.0"}, "fragment"),
        ({"environment": {}, "schema_version": "3.0"}, "fragment"),
        ({"publisher_schema_version": "1.0", "version": "9.0"}, "configuration"),
        ({"kind": "evidenceforge.generation-manifest", "schema_version": "1.0"}, "generated"),
        ({"name": "legacy", "environment": {}}, "scenario"),
    ],
)
def test_family_precedes_version(document: dict, family: str) -> None:
    assert identify_document(document).family == family


def test_upgrade_retains_comments_includes_and_invalid_draft(project: Path) -> None:
    source = project / "scenario.yaml"
    original = b"# leading\nversion: '1.0' # schema\nname: demo\nincludes: [environment.yaml]\n# notes\nstoryline: broken\n"
    source.write_bytes(original)
    include = project / "environment.yaml"
    include.write_bytes(b"# keep this comment\nenvironment:\n  description: repair me\n")
    draft = create_draft(source, project_root=project, upgrade=True)
    assert source.read_bytes() == original
    assert (draft.parent / include.name).read_bytes() == include.read_bytes()
    assert "# leading" in draft.read_text() and "# notes" in draft.read_text()
    data = yaml.safe_load(draft.read_text())
    assert data["schema_version"] == "3.0" and data["status"] == "draft"
    assert "scenario_version" not in data
    assert inspect_artifact(draft)["lifecycle"]["status"] == "draft"


def test_draft_sessions_branching_and_publication(project: Path) -> None:
    source = _scenario(project)
    first = create_draft(source, project_root=project, upgrade=True)
    second = create_draft(source, project_root=project)
    assert (
        inspect_artifact(first)["lifecycle"]["draft_id"]
        != inspect_artifact(second)["lifecycle"]["draft_id"]
    )
    info = inspect_artifact(first)
    assert "version" not in info["lifecycle"]
    assert info == inspect_artifact(first)
    release = publish(first, project_root=project, accept_warnings=True)
    assert inspect_artifact(release)["lifecycle"]["version"] == "1.0.0"
    branch = create_draft(release, project_root=project)
    parent = inspect_artifact(branch)["lifecycle"]["parents"][0]
    assert parent["version"] == "1.0.0"
    assert parent["digest"] == inspect_artifact(release)["digest"]
    assert inspect_artifact(first)["lifecycle"]["status"] == "draft"
    with pytest.raises(ArtifactError, match="already published"):
        publish(second, project_root=project, version="1.0.0", accept_warnings=True)


def test_frozen_configuration_portable_round_trip_and_tamper(project: Path, tmp_path: Path) -> None:
    draft = create_draft(_scenario(project), project_root=project)
    release = publish(draft, project_root=project, accept_warnings=True)
    compiled = compile_scenario(release, project_root=project)
    archive = export_release(release, project / "release.efscenario")
    assert compile_scenario(archive).scenario == compiled.scenario
    other = project / "other-project"
    imported = import_release(archive, project_root=other)
    assert import_release(archive, project_root=other) == imported
    assert (
        compile_scenario(imported, project_root=other).effective_config == compiled.effective_config
    )
    imported.write_text(imported.read_text() + "# external edit\n")
    with pytest.raises(ArtifactError, match="modified"):
        compile_scenario(imported)
    recovered = create_draft(imported, project_root=other, recover=True)
    assert (
        recovered.read_text().endswith("# external edit\n")
        or "# external edit" in recovered.read_text()
    )


def test_execution_seed_override_preserves_release_and_refreshes_run_identity(
    project: Path,
) -> None:
    from evidenceforge.composition.artifacts import build_resolved_document
    from evidenceforge.composition.identity import semantic_resolved_sha256

    release = publish(
        create_draft(_scenario(project), project_root=project),
        project_root=project,
        accept_warnings=True,
    )
    digest = inspect_artifact(release)["digest"]
    original = compile_scenario(release)
    run = compile_scenario(release, generation_seed=2718)
    resolved = build_resolved_document(run)
    assert run.scenario.generation_seed == 2718
    assert compile_scenario(release).scenario.generation_seed == original.scenario.generation_seed
    assert semantic_resolved_sha256(run) != semantic_resolved_sha256(original)
    assert resolved.scenario["generation_seed"] == 2718
    assert inspect_artifact(release)["digest"] == digest


@pytest.mark.parametrize("kind", ["industry", "organization"])
def test_anonymous_pack_draft_and_published_pack(project: Path, kind: str) -> None:
    repository = PackRepository(project)
    source = repository.create_skeleton(
        kind, "example", "1.0.0", publisher="testing", publisher_display_name="Tests"
    )
    draft = create_draft(source / "pack.yaml", project_root=project)
    draft.write_bytes(update_top_level(draft.read_bytes(), {}, remove={"publisher"}))
    reference, pack_type = parse_pack_cli_reference(str(draft))
    assert reference.source == "draft" and reference.publisher is None and reference.version is None
    pack = repository.resolve(reference, expected_type=pack_type)
    assert pack.selected().source == "draft"
    release = publish(draft, project_root=project)
    loaded_reference, loaded_type = parse_pack_cli_reference(str(release))
    loaded = repository.resolve(loaded_reference, expected_type=loaded_type)
    assert loaded.manifest.status == "published"
    archive = export_release(release, project / f"{kind}.efpack")
    imported = import_release(archive, project_root=project / "elsewhere")
    assert verify_release(imported.parent.parent).digest == inspect_artifact(release)["digest"]


def test_cli_upgrade_resume_publish_inspect_export_import(project: Path) -> None:
    from evidenceforge.cli.commands import app

    runner = CliRunner()
    common = ["--project-root", str(project), "--json"]
    result = runner.invoke(app, ["scenario", "upgrade", str(_scenario(project)), *common])
    assert result.exit_code == 0, result.output

    draft = json.loads(result.output)["path"]
    assert inspect_artifact(Path(draft))["lifecycle"]["publisher"] == "testing"
    for command in ("resume", "inspect"):
        result = runner.invoke(app, ["scenario", command, draft, *common])
        assert result.exit_code == 0, result.output
    result = runner.invoke(app, ["scenario", "publish", draft, "--accept-warnings", *common])
    assert result.exit_code == 0, result.output
    release = json.loads(result.output)["path"]
    result = runner.invoke(
        app, ["scenario", "export", release, str(project / "test.efscenario"), *common]
    )
    assert result.exit_code == 0, result.output


def test_draft_pack_testing_promotion_and_frozen_dependency(project: Path) -> None:
    from evidenceforge.artifacts.promotion import promote_dependency

    repository = PackRepository(project)
    original = repository.create_skeleton(
        "industry", "experimental", "1.0.0", publisher="testing", publisher_display_name="Tests"
    )
    pack_draft = create_draft(original / "pack.yaml", project_root=project)
    draft_id = inspect_artifact(pack_draft)["lifecycle"]["draft_id"]
    scenario = create_draft(_scenario(project), project_root=project)
    scenario.write_bytes(
        update_top_level(
            scenario.read_bytes(),
            {
                "composition": {
                    "industries": [
                        {
                            "source": "draft",
                            "draft_id": draft_id,
                            "name": "experimental",
                            "path": str(pack_draft.parent),
                        }
                    ]
                }
            },
        )
    )
    compiled = compile_scenario(scenario, project_root=project)
    assert compiled.selected_packs[0].source == "draft"
    with pytest.raises(ArtifactError, match="published dependencies"):
        publish(scenario, project_root=project, accept_warnings=True)
    pack_release = publish(pack_draft, project_root=project)
    before = scenario.read_bytes()
    preview = promote_dependency(scenario, pack_release, project_root=project, draft_id=draft_id)
    assert not preview["applied"] and preview["diffs"]
    assert scenario.read_bytes() == before
    promote_dependency(scenario, pack_release, project_root=project, draft_id=draft_id, apply=True)
    release = publish(scenario, project_root=project, accept_warnings=True)
    archive = export_release(release, project / "with-dependency.efscenario")
    other = project / "other"
    imported = import_release(archive, project_root=other)
    shutil.rmtree(original)
    shutil.rmtree(pack_release.parent.parent)
    assert compile_scenario(imported, project_root=other).selected_packs
    copied_draft = create_draft(imported, project_root=other)
    assert compile_scenario(copied_draft, project_root=other).selected_packs


def test_organization_draft_uses_exact_anonymous_industry_snapshot(project: Path) -> None:
    from evidenceforge.composition.models import LockedDraftPack

    repository = PackRepository(project)
    industry = repository.create_skeleton(
        "industry", "draft-sector", "1.0.0", publisher="testing", publisher_display_name="Tests"
    )
    industry_draft = create_draft(industry / "pack.yaml", project_root=project)
    draft_id = inspect_artifact(industry_draft)["lifecycle"]["draft_id"]
    organization = repository.create_skeleton(
        "organization", "draft-org", "1.0.0", publisher="testing", publisher_display_name="Tests"
    )
    organization_draft = create_draft(organization / "pack.yaml", project_root=project)
    organization_draft.write_bytes(
        update_top_level(
            organization_draft.read_bytes(),
            {
                "industry_dependencies": [
                    {
                        "source": "draft",
                        "draft_id": draft_id,
                        "name": "draft-sector",
                        "path": str(industry_draft.parent),
                    }
                ]
            },
        )
    )
    reference, kind = parse_pack_cli_reference(str(organization_draft))
    loaded = repository.resolve(reference, expected_type=kind)
    lock = repository.proposed_lock(loaded)
    assert isinstance(lock.dependencies[0], LockedDraftPack)
    assert "publisher" not in lock.model_dump(mode="json")["dependencies"][0]
    (organization_draft.parent / "pack.lock.yaml").write_text(
        yaml.safe_dump(lock.model_dump(mode="json"))
    )
    loaded = repository.resolve(reference, expected_type=kind)
    assert repository.validate_semantics(loaded)[0].source == "draft"
    with pytest.raises(ArtifactError, match="published dependencies"):
        publish(organization_draft, project_root=project)


def test_notes_and_lineage_change_integrity_without_changing_generation(project: Path) -> None:
    from evidenceforge.artifacts.lifecycle import set_release_notes
    from evidenceforge.composition.identity import semantic_resolved_sha256

    draft = create_draft(_scenario(project), project_root=project)
    before = compile_scenario(draft, project_root=project)
    old_digest = inspect_artifact(draft)["digest"]
    set_release_notes(draft, "Reviewed notes", expected_digest=old_digest)
    after = compile_scenario(draft, project_root=project)
    assert before.scenario == after.scenario
    assert semantic_resolved_sha256(before) == semantic_resolved_sha256(after)
    assert inspect_artifact(draft)["digest"] != old_digest
    with pytest.raises(ArtifactError, match="changed"):
        set_release_notes(draft, "Stale editor", expected_digest=old_digest)
    published = publish(draft, project_root=project, accept_warnings=True)
    with pytest.raises(ArtifactError, match="immutable"):
        set_release_notes(published, "Cannot modify")
    assert inspect_artifact(published)["lifecycle"]["release_notes"] == "Reviewed notes"


def test_fork_of_captured_draft_preserves_configuration_and_missing_parent(project: Path) -> None:
    released = publish(
        create_draft(_scenario(project), project_root=project),
        project_root=project,
        accept_warnings=True,
    )
    draft = create_draft(released, project_root=project)
    fork = create_draft(draft, project_root=project, name="new-identity", publisher="another-team")
    shutil.rmtree(released.parent.parent)
    shutil.rmtree(draft.parent.parent)
    compiled = compile_scenario(fork, project_root=project)
    assert compiled.scenario.name == "new-identity"
    assert inspect_artifact(fork)["lifecycle"]["parents"][0]["draft_id"]


def test_legacy_logical_name_survives_upgrade_and_portable_identity(project: Path) -> None:
    from urllib.parse import quote

    from evidenceforge.artifacts.lifecycle import list_versions, resolve_reference, storage_name

    source = _scenario(project)
    name = "Finance_Exercise"
    source.write_bytes(update_top_level(source.read_bytes(), {"name": name}))
    draft = create_draft(source, project_root=project, upgrade=True)
    assert compile_scenario(draft, project_root=project).scenario.name == name
    assert storage_name(name) in draft.parts
    release = publish(draft, project_root=project, accept_warnings=True)
    reference = f"testing:scenario:{quote(name, safe='')}@1.0.0"
    assert resolve_reference(reference, project) == release
    assert (
        list_versions(project, kind="scenario", name=name, publisher="testing")[0]["name"] == name
    )
    imported = import_release(
        export_release(release, project / "named.efscenario"), project_root=project / "elsewhere"
    )
    assert compile_scenario(imported).scenario.name == name

    # Invalid semantic names remain discoverable for repair, without becoming paths.
    source.write_bytes(update_top_level(source.read_bytes(), {"name": "../Finance — Équipe"}))
    repairable = create_draft(source, project_root=project, upgrade=True)
    assert storage_name("../Finance — Équipe") in repairable.parts
    assert inspect_artifact(repairable)["name"] == "../Finance — Équipe"


def test_draft_discovery_source_snapshot_and_multiple_exact_parents(project: Path) -> None:
    from evidenceforge.artifacts.lifecycle import create_new_draft, list_drafts
    from evidenceforge.cli.commands import app

    scenario = create_draft(_scenario(project), project_root=project)
    pack = create_new_draft("industry", "repairable", description="Test", project_root=project)
    digest = inspect_artifact(pack)["digest"]
    (pack.parent / "catalogs/personas.yaml").write_text("personas: broken\n")
    assert inspect_artifact(pack)["digest"] != digest
    assert {item["path"] for item in list_drafts(project)} == {str(scenario), str(pack)}
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scenario",
            "draft",
            str(scenario),
            "--parent",
            str(pack),
            "--project-root",
            str(project),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    branch = Path(json.loads(result.output)["path"])
    assert len(inspect_artifact(branch)["lifecycle"]["parents"]) == 2
    result = runner.invoke(
        app, ["scenario", "suggest-version", str(branch), "--project-root", str(project), "--json"]
    )
    assert json.loads(result.output) == {"version": "1.0.0"}
    assert "scenario_version" not in yaml.safe_load(branch.read_bytes())


def test_upgrade_only_changes_scenario_sources_not_asset_versions() -> None:
    from evidenceforge.schema import upgrade_sources

    files = {
        "scenario.yaml": b"version: '1.0'\nname: test\nenvironment: {}\n",
        "assets/corpus.yaml": b"# asset metadata\nversion: '1.0'\nmessages: []\n",
    }
    upgraded = upgrade_sources(files, "scenario.yaml", "scenario", {"scenario.yaml"})
    assert upgraded["assets/corpus.yaml"] == files["assets/corpus.yaml"]


def test_namespace_remapping_preserves_notes_descriptions_and_comments() -> None:
    from evidenceforge.artifacts.lifecycle import _remap_namespace

    content = (
        b"# old/name:person\nrelease_notes: 'old/name:person'\n"
        b"description: old/name:person\nuser:\n  persona: 'old/name:person' # old/name:person\n"
    )
    remapped = _remap_namespace({"source.yaml": content}, "old/name", "new/name")["source.yaml"]
    assert remapped == content.replace(b"persona: 'old/name:person'", b"persona: 'new/name:person'")


def test_promotion_preserves_other_relative_draft_dependencies(project: Path) -> None:
    import os

    from evidenceforge.artifacts.lifecycle import create_new_draft
    from evidenceforge.artifacts.promotion import promote_dependency

    first = create_new_draft("industry", "first", description="First", project_root=project)
    other = create_new_draft("industry", "other", description="Other", project_root=project)
    org = create_new_draft("organization", "org", description="Org", project_root=project)
    dependencies = [
        {
            "source": "draft",
            "draft_id": inspect_artifact(path)["lifecycle"]["draft_id"],
            "name": path_name,
            "path": os.path.relpath(path.parent, org.parent),
        }
        for path, path_name in ((first, "first"), (other, "other"))
    ]
    org.write_bytes(update_top_level(org.read_bytes(), {"industry_dependencies": dependencies}))
    repository = PackRepository(project)
    reference, kind = parse_pack_cli_reference(str(org))
    loaded = repository.resolve(reference, expected_type=kind)
    repository.update_lock(loaded, repository.proposed_lock(loaded))
    release = publish(first, project_root=project)
    promote_dependency(
        org, release, project_root=project, draft_id=dependencies[0]["draft_id"], apply=True
    )
    selected = repository.validate_semantics(repository.resolve(reference, expected_type=kind))
    assert [pack.source for pack in selected] == ["path", "draft"]
    assert yaml.safe_load(org.read_text())["industry_dependencies"][1] == dependencies[1]


def test_existing_pack_labels_are_reserved_and_captured_context_is_reused(project: Path) -> None:
    from evidenceforge.artifacts.lifecycle import suggest_version

    source = (
        PackRepository(project).create_skeleton(
            "industry", "existing", "1.0.0", publisher="testing", publisher_display_name="Tests"
        )
        / "pack.yaml"
    )
    draft = create_draft(source, project_root=project)
    assert (
        suggest_version(project, kind="industry", name="existing", publisher="testing") == "1.0.1"
    )
    with pytest.raises(ArtifactError, match="already published"):
        publish(draft, project_root=project, version="1.0.0")
    release = publish(draft, project_root=project)
    branch = create_draft(release, project_root=project)
    bound = yaml.safe_load(branch.read_text())["configuration_context"]
    assert (branch.parent / bound).resolve().is_file()
    assert publish(branch, project_root=project).is_file()


def test_interrupt_and_input_change_leave_no_release(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import evidenceforge.artifacts.lifecycle as lifecycle

    draft = create_draft(_scenario(project), project_root=project)
    original = lifecycle._publish_directory

    def interrupt(stage: Path, target: Path) -> None:
        raise OSError("interrupted before publication")

    monkeypatch.setattr(lifecycle, "_publish_directory", interrupt)
    with pytest.raises(OSError, match="interrupted"):
        publish(draft, project_root=project, accept_warnings=True)
    assert not (project / ".eforge/artifacts/releases/testing/scenario/minimal-test/1.0.0").exists()
    monkeypatch.setattr(lifecycle, "_publish_directory", original)
    captured = lifecycle._configuration_files
    calls = 0

    def change(source: Path, root: Path, context: Path | None) -> dict[str, bytes]:
        nonlocal calls
        calls += 1
        if calls == 1:
            source.write_text(source.read_text() + "# concurrent edit\n")
        return captured(source, root, context)

    monkeypatch.setattr(lifecycle, "_configuration_files", change)
    with pytest.raises(ArtifactError, match="authored files changed"):
        publish(draft, project_root=project, accept_warnings=True)


def test_conflicting_portable_release_and_unsafe_recovery_are_rejected(project: Path) -> None:
    first = create_draft(_scenario(project), project_root=project)
    release = publish(first, project_root=project, accept_warnings=True)
    archive = export_release(release, project / "one.efscenario")
    other = project / "other"
    imported = import_release(archive, project_root=other)
    second = create_draft(_scenario(project), project_root=other)
    from evidenceforge.artifacts.lifecycle import set_release_notes

    set_publisher(
        other,
        PublisherIdentity(publisher="testing", publisher_display_name="Tests"),
        scope="project",
        force=False,
    )
    set_release_notes(second, "Different integrity under the same identity")
    third = project / "third"
    set_publisher(
        third,
        PublisherIdentity(publisher="testing", publisher_display_name="Tests"),
        scope="project",
        force=False,
    )
    alternate = publish(second, project_root=third, version="1.0.0", accept_warnings=True)
    conflicting = export_release(alternate, project / "conflict.efscenario")
    with pytest.raises(ArtifactError, match="different contents"):
        import_release(conflicting, project_root=other)
    receipt_path = imported.parent.parent / "release.json"
    data = json.loads(receipt_path.read_bytes())
    data["entrypoint"] = "../../scenario.yaml"
    receipt_path.write_text(json.dumps(data))
    with pytest.raises(ArtifactError, match="unsafe"):
        create_draft(imported, project_root=other, recover=True)


@pytest.mark.slow
def test_cli_only_publication_round_trip_generation_and_evaluation(project: Path) -> None:
    import os
    import subprocess
    import sys

    executable = [sys.executable, "-c", "from evidenceforge.cli.commands import app; app()"]
    environment = {**os.environ, "EFORGE_STUDIO_HOME": str(project / "unused-studio")}

    def cli(*arguments: str) -> str:
        result = subprocess.run(
            [*executable, *arguments],
            cwd=project,
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout

    refs = {}
    for kind in ("industry", "organization"):
        draft = json.loads(
            cli(
                "pack",
                "new-draft",
                f"acceptance-{kind}",
                "--kind",
                kind,
                "--display-name",
                f"Acceptance {kind.title()} Pack",
                "--json",
            )
        )["path"]
        if kind == "organization":
            path = Path(draft)
            dependency = {**refs["industry"], "type": "industry", "version_constraint": "==1.0.0"}
            dependency.pop("version")
            path.write_bytes(
                update_top_level(path.read_bytes(), {"industry_dependencies": [dependency]})
            )
            cli("pack", "lock", draft, "--apply", "--json")
        cli("pack", "validate", draft, "--json")
        release = json.loads(cli("pack", "publish", draft, "--json"))["path"]
        refs[kind] = {
            "source": "path",
            "publisher": "testing",
            "name": f"acceptance-{kind}",
            "version": "1.0.0",
            "path": str(Path(release).parent),
        }
    source = _scenario(project)
    data = yaml.safe_load(source.read_bytes())
    data["time_window"]["warmup"] = "1h"
    source.write_text(yaml.safe_dump(data, sort_keys=False))
    legacy_output = project / "legacy-run"
    cli("generate", str(source), "--output", str(legacy_output), "--seed", "31")
    draft = Path(json.loads(cli("scenario", "upgrade", str(source), "--json"))["path"])
    draft.write_bytes(
        update_top_level(
            draft.read_bytes(), {"composition": {"organization": refs["organization"]}}
        )
    )
    cli("scenario", "resume", str(draft), "--json")
    cli("scenario", "display-name", str(draft), "--value", "Portable Acceptance Scenario", "--json")
    cli("validate", str(draft), "--json")
    release = json.loads(cli("scenario", "publish", str(draft), "--accept-warnings", "--json"))[
        "path"
    ]
    archive = project / "acceptance.efscenario"
    cli("scenario", "export", release, str(archive), "--json")
    destination = project / "portable"
    destination.mkdir()
    imported = json.loads(
        cli(
            "scenario", "import-release", str(archive), "--project-root", str(destination), "--json"
        )
    )["path"]
    # The portable release works after all authoring workspaces, dependencies and contexts disappear.
    shutil.rmtree(project / ".eforge/artifacts")
    source.unlink()
    output = destination / "run"
    cli(
        "generate",
        imported,
        "--project-root",
        str(destination),
        "--output",
        str(output),
        "--seed",
        "31",
    )
    report = json.loads(cli("eval", str(output), "--format", "json"))
    assert report["total_records"] > 0
    legacy_logs = {
        file.relative_to(legacy_output / "data"): file.read_bytes()
        for file in (legacy_output / "data").rglob("*")
        if file.is_file()
    }
    upgraded_logs = {
        file.relative_to(output / "data"): file.read_bytes()
        for file in (output / "data").rglob("*")
        if file.is_file()
    }
    assert upgraded_logs == legacy_logs
    assert (output / "RESOLVED_SCENARIO.yaml").is_file()
    assert not (project / "unused-studio").exists()


def test_concurrent_publication_has_one_winner(project: Path) -> None:
    import subprocess
    import sys

    draft = create_draft(_scenario(project), project_root=project)
    command = [
        sys.executable,
        "-c",
        "from evidenceforge.cli.commands import app; app()",
        "scenario",
        "publish",
        str(draft),
        "--project-root",
        str(project),
        "--version",
        "1.0.0",
        "--accept-warnings",
        "--json",
    ]
    processes = [
        subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(2)
    ]
    results = [(process, process.communicate(timeout=60)) for process in processes]
    assert sorted(process.returncode for process, _ in results) == [0, 1]
    winner = next(
        json.loads(output[0])["path"] for process, output in results if process.returncode == 0
    )
    assert inspect_artifact(Path(winner))["lifecycle"]["version"] == "1.0.0"
