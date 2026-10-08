"""Publisher defaults and exact ancestry keep one family visible without rewriting sources."""

import shutil
from pathlib import Path

import pytest
import yaml

from evidenceforge.artifacts.lifecycle import (
    create_draft,
    create_new_draft,
    inspect_artifact,
    publish,
)
from evidenceforge.artifacts.lineage import group_lineage, inspect_lineage
from evidenceforge.composition.packs import PackRepository, parse_pack_cli_reference
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
from evidenceforge.desktop.library import discover_scenarios
from evidenceforge.schema import update_top_level
from evidenceforge.studio.artifact_groups import inspect_groups
from evidenceforge.studio.store import CatalogItem


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    return tmp_path


def _configure(workspace: Path, publisher: str = "testing", scope: str = "project") -> None:
    set_publisher(
        workspace,
        PublisherIdentity(publisher=publisher, publisher_display_name=publisher.title()),
        scope=scope,
        force=True,
    )


def _legacy(workspace: Path) -> Path:
    source = workspace / "scenario.yaml"
    shutil.copyfile("tests/fixtures/scenarios/minimal.yaml", source)
    return source


@pytest.mark.parametrize("kind", ["scenario", "industry", "organization"])
def test_new_drafts_use_configured_publisher_without_allocating_version(
    workspace: Path, kind: str
) -> None:
    anonymous = create_new_draft(kind, "example", description="Test", project_root=workspace)
    assert inspect_artifact(anonymous)["lifecycle"].get("publisher") is None
    _configure(workspace, "user", "user")
    _configure(workspace, "project")
    assigned = create_new_draft(kind, "example", description="Test", project_root=workspace)
    metadata = inspect_artifact(assigned)["lifecycle"]
    assert metadata["publisher"] == "project"
    assert "version" not in metadata
    assert metadata["draft_id"] != inspect_artifact(anonymous)["lifecycle"]["draft_id"]
    assert inspect_artifact(anonymous)["lifecycle"].get("publisher") is None


@pytest.mark.parametrize("kind", ["industry", "organization"])
def test_pack_drafts_adopt_missing_publisher_but_preserve_recorded_namespaces(
    workspace: Path, kind: str
) -> None:
    source = create_new_draft(kind, "example", description="Test", project_root=workspace)
    original = source.read_bytes()
    _configure(workspace)
    assigned = create_draft(source, project_root=workspace)
    assert inspect_artifact(assigned)["lifecycle"]["publisher"] == "testing"
    assert source.read_bytes() == original
    reference, pack_type = parse_pack_cli_reference(str(assigned))
    assert (
        PackRepository(workspace).resolve(reference, expected_type=pack_type).manifest.publisher
        == f"draft-{inspect_artifact(assigned)['lifecycle']['draft_id']}"
    )
    foreign = (
        PackRepository(workspace).create_skeleton(
            kind, "foreign", "1.0.0", publisher="another", publisher_display_name="Another"
        )
        / "pack.yaml"
    )
    fork = create_draft(foreign, project_root=workspace)
    assert inspect_artifact(fork)["lifecycle"]["publisher"] == "another"
    assert inspect_lineage(foreign).publisher == "another"


@pytest.mark.parametrize("scope", ["user", "project"])
def test_adopted_legacy_source_uses_configured_publisher_and_preserves_original(
    workspace: Path, scope: str
) -> None:
    source = _legacy(workspace)
    original = source.read_bytes()
    _configure(workspace, scope=scope)
    draft = create_draft(source, project_root=workspace, upgrade=True)
    assert inspect_artifact(draft)["lifecycle"]["publisher"] == "testing"
    assert source.read_bytes() == original
    assert inspect_artifact(draft)["lifecycle"]["parents"][0].get("publisher") is None


def test_draft_publisher_precedence_and_repeated_sessions(workspace: Path) -> None:
    source = _legacy(workspace)
    anonymous = create_draft(source, project_root=workspace)
    assert inspect_artifact(anonymous)["lifecycle"].get("publisher") is None
    _configure(workspace)
    explicit = create_draft(source, project_root=workspace, publisher="chosen")
    _configure(workspace, "different")
    inherited = create_draft(explicit, project_root=workspace)
    assert inspect_artifact(inherited)["lifecycle"]["publisher"] == "chosen"
    overridden = create_draft(explicit, project_root=workspace, publisher="override")
    assert inspect_artifact(overridden)["lifecycle"]["publisher"] == "override"
    before = inspect_artifact(inherited)
    assert inspect_artifact(inherited) == before
    release = publish(inherited, project_root=workspace, accept_warnings=True)
    assert inspect_artifact(release)["lifecycle"]["publisher"] == "chosen"
    assert inspect_artifact(inherited) == before


def _old_family(workspace: Path) -> tuple[Path, Path, Path]:
    source = _legacy(workspace)
    draft = create_draft(source, project_root=workspace)
    _configure(workspace)
    release = publish(draft, project_root=workspace, accept_warnings=True)
    return source, draft, release


def test_existing_anonymous_draft_and_legacy_original_group_with_release(workspace: Path) -> None:
    paths = dict(zip(("original", "draft", "release"), _old_family(workspace), strict=True))
    original_bytes = {key: path.read_bytes() for key, path in paths.items()}
    records = {key: inspect_lineage(path) for key, path in paths.items()}
    # Existing releases predate the explicit finalized-draft parent. Shared legacy ancestry
    # remains enough to reconnect them without modifying the sealed release.
    records["release"] = records["release"].model_copy(
        update={"parents": [parent for parent in records["release"].parents if not parent.draft_id]}
    )
    groups = group_lineage(records)
    assert len({group.key for group in groups.values()}) == 1
    assert all(group.publisher == "testing" for group in groups.values())
    assert records["original"].publisher is None and records["draft"].publisher is None
    assert original_bytes == {key: path.read_bytes() for key, path in paths.items()}
    # Filtering or an unavailable ancestor does not remove their exact shared parent record.
    missing = group_lineage({key: value for key, value in records.items() if key != "original"})
    assert missing["draft"].key == missing["release"].key


@pytest.mark.parametrize("kind", ["scenario", "industry", "organization"])
def test_publication_records_standalone_anonymous_draft_snapshot(
    workspace: Path, kind: str
) -> None:
    draft = create_new_draft(kind, "standalone", description="Test", project_root=workspace)
    if kind == "scenario":
        envelope = yaml.safe_load(draft.read_text())
        draft.write_bytes(
            update_top_level(
                Path("tests/fixtures/scenarios/minimal.yaml").read_bytes(),
                {
                    key: envelope[key]
                    for key in ("name", "schema_version", "status", "draft_id", "parents")
                },
                remove={"scenario_version", "version"},
            )
        )
    original = draft.read_bytes()
    before = inspect_artifact(draft)
    _configure(workspace)
    release = publish(draft, project_root=workspace, accept_warnings=True)
    parent = inspect_artifact(release)["lifecycle"]["parents"][0]
    assert parent["draft_id"] == before["lifecycle"]["draft_id"]
    assert parent["digest"] == before["digest"]
    assert draft.read_bytes() == original
    groups = group_lineage({"draft": inspect_lineage(draft), "release": inspect_lineage(release)})
    assert groups["draft"].key == groups["release"].key
    assert groups["draft"].publisher == "testing"
    draft.write_text(draft.read_text() + "\n# continue editing the same draft\n")
    assert inspect_artifact(draft)["digest"] != parent["digest"]
    continued = group_lineage(
        {"draft": inspect_lineage(draft), "release": inspect_lineage(release)}
    )
    assert continued["draft"].key == continued["release"].key
    assert inspect_artifact(release)["lifecycle"]["parents"][0] == parent


def test_changed_legacy_content_does_not_match_recorded_parent(workspace: Path) -> None:
    source, draft, release = _old_family(workspace)
    source.write_text(source.read_text() + "\n# external change\n")
    groups = group_lineage(
        {
            key: inspect_lineage(path)
            for key, path in zip(
                ("source", "draft", "release"), (source, draft, release), strict=True
            )
        }
    )
    assert groups["source"].publisher is None
    assert groups["source"].key != groups["release"].key
    assert groups["draft"].key == groups["release"].key


def test_publisher_forks_are_separate_and_shared_anonymous_ancestor_is_ambiguous(
    workspace: Path,
) -> None:
    source, draft, release = _old_family(workspace)
    fork = create_draft(source, project_root=workspace, publisher="another")
    fork_release = publish(fork, project_root=workspace, accept_warnings=True)
    records = {
        key: inspect_lineage(path)
        for key, path in zip(
            ("source", "draft", "release", "fork", "fork-release"),
            (source, draft, release, fork, fork_release),
            strict=True,
        )
    }
    groups = group_lineage(records)
    assert groups["release"].publisher == "testing"
    assert groups["fork"].publisher == "another"
    assert groups["fork"].key == groups["fork-release"].key
    assert groups["release"].key != groups["fork"].key
    assert groups["source"].publisher is None and groups["draft"].publisher is None


def test_renamed_forks_and_unrelated_equal_names_remain_separate(workspace: Path) -> None:
    source, draft, release = _old_family(workspace)
    fork = create_draft(source, project_root=workspace, name="forked-name")
    unrelated = workspace / "unrelated.yaml"
    unrelated.write_bytes(
        update_top_level(source.read_bytes(), {"description": "Different source"})
    )
    groups = group_lineage(
        {
            key: inspect_lineage(path)
            for key, path in zip(
                ("source", "draft", "release", "fork", "unrelated"),
                (source, draft, release, fork, unrelated),
                strict=True,
            )
        }
    )
    assert groups["fork"].key != groups["release"].key
    assert groups["unrelated"].publisher is None
    assert groups["unrelated"].key != groups["source"].key


def test_repairable_semantic_errors_remain_visible_when_ancestry_inspection_fails(
    workspace: Path,
) -> None:
    source = _legacy(workspace)
    draft = create_draft(source, project_root=workspace)
    draft.write_bytes(update_top_level(draft.read_bytes(), {"environment": "repair me"}))
    assert draft in {item.path for item in discover_scenarios(workspace, [])}
    item = CatalogItem(
        id="repairable", workspace=workspace, kind="scenario", path=draft, name="minimal-test"
    )
    assert inspect_groups([item]) == {}
