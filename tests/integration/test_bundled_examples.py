"""Portable collection integrity and file-based use without Studio."""

import json
import os
import shutil
from pathlib import Path

import pytest

from evidenceforge.artifacts.lifecycle import (
    ArtifactError,
    create_draft,
    inspect_artifact,
    validation_findings,
    verify_release,
)
from evidenceforge.artifacts.portable import import_release
from evidenceforge.artifacts.removal import (
    remove_scenario,
    retired_versions,
    review_scenario_deletion,
)
from evidenceforge.composition import compile_scenario
from evidenceforge.examples import collection_digest, discover_examples, examples_directory
from tests.support.examples import publish_example


@pytest.fixture
def published(tmp_path: Path) -> Path:
    return publish_example(tmp_path / "author")


def test_shipping_collection_is_complete_and_valid(tmp_path: Path) -> None:
    root = examples_directory()
    assert (root / "README.md").is_file()
    examples = discover_examples(root)
    assert {example.receipt.name for example in examples} >= {
        "cedar-vale-invoice-phishing",
        "northstar-stolen-credentials",
        "lantern-works-web-compromise",
        "alderbrook-insider-exfiltration",
        "juniper-vale-macos-dns",
    }
    for example in examples:
        findings = validation_findings(
            example.root / example.receipt.entrypoint, project_root=tmp_path
        )
        expected_tls_gaps = example.receipt.name in {
            "alderbrook-insider-exfiltration",
            "juniper-vale-macos-dns",
        }
        assert len(findings) == int(expected_tls_gaps), findings
        for finding in findings:
            assert finding["severity"] == "warning"
            assert "http result" in finding["message"]
            assert "encrypted application" in finding["message"]


def test_shipping_examples_import_and_fork_in_an_unrelated_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "unused-home")
    workspace = tmp_path / "unrelated-workspace"
    for example in discover_examples():
        imported = import_release(example.root, project_root=workspace)
        compiled = compile_scenario(imported, project_root=workspace)
        assert compiled.scenario.name == example.receipt.name
        draft = create_draft(imported, project_root=workspace, inherit_publisher=False)
        assert compile_scenario(draft, project_root=workspace).scenario.name == example.receipt.name
        assert (
            inspect_artifact(draft)["lifecycle"]["parents"][0]["digest"] == example.receipt.digest
        )
        original_source = example.root / "source"
        for original in original_source.rglob("*"):
            if original.is_file() and original != example.root / example.receipt.entrypoint:
                assert (draft.parent / original.relative_to(original_source)).read_bytes() == (
                    original.read_bytes()
                )


@pytest.mark.slow
@pytest.mark.parametrize(
    "example_root",
    [example.root for example in discover_examples()],
    ids=[example.identity for example in discover_examples()],
)
def test_shipping_example_generates_after_import(tmp_path: Path, example_root: Path) -> None:
    from typer.testing import CliRunner

    from evidenceforge.cli.commands import app

    workspace = tmp_path / "workspace"
    source = import_release(example_root, project_root=workspace)
    bundle = workspace / "run"
    result = CliRunner().invoke(
        app,
        ["generate", str(source), "--project-root", str(workspace), "--output", str(bundle)],
    )
    assert result.exit_code == 0, result.output[-6000:]
    assert (bundle / "GENERATION_MANIFEST.json").is_file()
    assert (bundle / "GROUND_TRUTH.json").is_file()
    if example_root.parent.name == "cedar-vale-invoice-phishing":
        assert list((bundle / "artifacts/email").glob("*.eml"))
    evaluated = CliRunner().invoke(app, ["eval", str(bundle), "--format", "json"])
    assert evaluated.exit_code == 0, evaluated.output[-6000:]
    report = json.loads(evaluated.stdout)
    assert report["acceptance_passed"], report["acceptance_criteria"]
    agreement = report["supplementary"]["ground_truth_agreement"]
    assert not agreement["failure_counts"], agreement["findings"]
    categories = {category["key"]: category["score"] for category in report["categories"]}
    for category in ("source_schema", "canonical_invariants", "scenario_completeness"):
        assert categories[category] == 100, (category, categories[category])


def test_empty_and_populated_collection_identity(tmp_path: Path, published: Path) -> None:
    collection = tmp_path / "examples"
    collection.mkdir()
    empty = collection_digest(discover_examples(collection))
    target = collection / "example-one/1.0.0"
    shutil.copytree(published, target)
    examples = discover_examples(collection)
    assert len(examples) == 1
    assert examples[0].identity == "evidenceforge/example-one@1.0.0"
    assert collection_digest(examples) != empty
    (target / "source/assets/message.eml").write_text("modified", encoding="utf-8")
    with pytest.raises(ArtifactError, match="modified"):
        discover_examples(collection)


def test_cached_package_resources_are_copied_to_independent_verified_files(
    tmp_path: Path, published: Path
) -> None:
    collection = tmp_path / "examples"
    root = collection / "example-one/1.0.0"
    shutil.copytree(published, root, copy_function=os.link)
    assert len(discover_examples(collection)) == 1
    with pytest.raises(ArtifactError, match="unlinked"):
        verify_release(root)
    source = import_release(root, project_root=tmp_path / "workspace", allow_hardlinks=True)
    assert source.stat().st_nlink == 1
    assert (
        verify_release(source.parent.parent).digest
        == verify_release(published, allow_hardlinks=True).digest
    )


def test_import_and_fork_preserve_all_companions_and_frozen_inputs(
    tmp_path: Path, published: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "unused-home")
    workspace = tmp_path / "destination"
    imported = import_release(published, project_root=workspace)
    assert import_release(published, project_root=workspace) == imported
    draft = create_draft(imported, project_root=workspace, inherit_publisher=False)
    assert (draft.parent / "assets/message.eml").read_bytes() == (
        published / "source/assets/message.eml"
    ).read_bytes()
    assert (draft.parent / "ENVIRONMENT.md").is_file()
    metadata = inspect_artifact(draft)["lifecycle"]
    assert metadata.get("publisher") is None
    assert metadata["parents"][0]["publisher"] == "evidenceforge"
    assert metadata["parents"][0]["digest"] == verify_release(published).digest
    shutil.rmtree(tmp_path / "author")
    assert compile_scenario(imported, project_root=workspace).scenario.name == "example-one"
    assert compile_scenario(draft, project_root=workspace).scenario.name == "example-one"


def test_deleted_release_can_only_restore_exact_original(tmp_path: Path, published: Path) -> None:
    workspace = tmp_path / "destination"
    source = import_release(published, project_root=workspace)
    review = review_scenario_deletion(source, workspace)
    remove_scenario(source, workspace, review.revision)
    with pytest.raises(ArtifactError, match="reserved"):
        import_release(published, project_root=workspace)
    conflicting = publish_example(tmp_path / "other-author")
    with pytest.raises(ArtifactError, match="original digest"):
        import_release(conflicting, project_root=workspace, restore_deleted=True)
    assert import_release(published, project_root=workspace, restore_deleted=True) == source
    assert retired_versions(
        workspace, kind="scenario", name="example-one", publisher="evidenceforge"
    ) == {"1.0.0"}


@pytest.mark.slow
def test_installed_example_generates_without_original_authoring_workspace(
    tmp_path: Path, published: Path
) -> None:
    from typer.testing import CliRunner

    from evidenceforge.cli.commands import app

    workspace = tmp_path / "destination"
    source = import_release(published, project_root=workspace)
    shutil.rmtree(tmp_path / "author")
    result = CliRunner().invoke(
        app,
        [
            "generate",
            str(source),
            "--output",
            str(workspace / "run"),
            "--project-root",
            str(workspace),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (workspace / "run/GENERATION_MANIFEST.json").is_file()
