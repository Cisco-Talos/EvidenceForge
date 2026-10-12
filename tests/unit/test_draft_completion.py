"""Publication completes only its exact draft, without losing authored or Studio history."""

from pathlib import Path

import pytest

from evidenceforge.artifacts import lifecycle
from evidenceforge.artifacts.completion import published_draft_sources
from evidenceforge.artifacts.lifecycle import (
    ArtifactError,
    assert_mutable,
    create_draft,
    create_new_draft,
    inspect_artifact,
    list_drafts,
    publish,
    set_release_notes,
)
from evidenceforge.artifacts.removal import delete_artifact_files
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
from evidenceforge.desktop.library import discover_packs, discover_scenarios


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    set_publisher(
        tmp_path,
        PublisherIdentity(publisher="testing", publisher_display_name="Tests"),
        scope="project",
        force=False,
    )
    return tmp_path


def draft(workspace: Path, kind: str) -> Path:
    if kind == "scenario":
        source = workspace / "original.yaml"
        source.write_bytes(Path("tests/fixtures/scenarios/minimal.yaml").read_bytes())
        return create_draft(source, project_root=workspace)
    return create_new_draft(kind, "example", description="Test", project_root=workspace)


@pytest.mark.parametrize("kind", ["scenario", "industry", "organization"])
def test_publication_completes_exact_draft_and_new_revision_gets_new_identity(
    workspace: Path, kind: str
) -> None:
    source = draft(workspace, kind)
    sibling = create_draft(source, project_root=workspace)
    original = source.read_bytes()
    info = inspect_artifact(source)
    release = publish(source, project_root=workspace, accept_warnings=True)
    assert published_draft_sources(workspace) == {source: release}
    assert {entry["path"] for entry in list_drafts(workspace)} == {str(sibling)}
    items = (
        discover_scenarios(workspace, [source])
        if kind == "scenario"
        else discover_packs(workspace, kind)
    )
    assert source not in {item.path for item in items}
    assert release in {item.path for item in items}
    assert source.read_bytes() == original
    with pytest.raises(ArtifactError, match="has been published"):
        set_release_notes(source, "Cannot keep editing the completed draft")
    with pytest.raises(ArtifactError, match="has been published"):
        assert_mutable(source.parent / "new-component.yaml")
    with pytest.raises(ArtifactError, match="has been published"):
        publish(source, project_root=workspace, accept_warnings=True)
    revision = create_draft(release, project_root=workspace)
    assert inspect_artifact(revision)["lifecycle"]["draft_id"] != info["lifecycle"]["draft_id"]
    second = publish(revision, project_root=workspace, accept_warnings=True)
    assert inspect_artifact(second)["lifecycle"]["version"] == "1.0.1"
    assert_mutable(sibling)


def test_publishing_fork_does_not_complete_its_unpublished_parent(workspace: Path) -> None:
    source = draft(workspace, "scenario")
    branch = create_draft(source, project_root=workspace)
    release = publish(branch, project_root=workspace, accept_warnings=True)
    assert published_draft_sources(workspace) == {branch: release}
    assert_mutable(source)


def test_failed_publication_leaves_draft_available_for_edits_and_retry(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = draft(workspace, "scenario")
    real = lifecycle._publish_directory

    def fail(staging: Path, destination: Path) -> None:
        raise OSError("Interrupted before atomic publication")

    monkeypatch.setattr(lifecycle, "_publish_directory", fail)
    with pytest.raises(OSError, match="Interrupted"):
        publish(source, project_root=workspace, accept_warnings=True)
    assert published_draft_sources(workspace) == {}
    set_release_notes(source, "Ready to retry")
    assert list_drafts(workspace)[0]["path"] == str(source)
    monkeypatch.setattr(lifecycle, "_publish_directory", real)
    release = publish(source, project_root=workspace, accept_warnings=True)
    assert published_draft_sources(workspace) == {source: release}


def test_unpublished_external_edits_are_not_hidden_by_historical_publication(
    workspace: Path,
) -> None:
    source = draft(workspace, "scenario")
    publish(source, project_root=workspace, accept_warnings=True)
    source.write_text(source.read_text() + "\n# Prior application allowed continued editing\n")
    assert published_draft_sources(workspace) == {}
    assert_mutable(source)
    assert list_drafts(workspace)[0]["path"] == str(source)


@pytest.mark.parametrize("kind", ["scenario", "industry", "organization"])
def test_deleting_release_does_not_resurrect_its_completed_draft(
    workspace: Path, kind: str
) -> None:
    source = draft(workspace, kind)
    release = publish(source, project_root=workspace, accept_warnings=True)
    delete_artifact_files(release, release.parent.parent, workspace, kind)
    assert not release.exists()
    assert published_draft_sources(workspace) == {source: release}
    assert list_drafts(workspace) == []
    with pytest.raises(ArtifactError, match="has been published"):
        set_release_notes(source, "Should remain completed")
