"""Release-note previews use exact ancestors and never save or publish a draft."""

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from evidenceforge.artifacts.comparison import compare_parent
from evidenceforge.artifacts.lifecycle import (
    _parent,
    create_draft,
    create_new_draft,
    inspect_artifact,
    publish,
    set_release_notes,
)
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
from evidenceforge.schema import ParentReference
from evidenceforge.studio import artifact_api, assistance
from evidenceforge.studio.assistance import AssistanceError
from evidenceforge.studio.display_names import DisplayNameContext
from evidenceforge.studio.release_notes import (
    ReleaseNotesContext,
    ReleaseNotesSuggestion,
    notes_context,
    suggest_release_notes,
)
from evidenceforge.studio.service import create_app
from tests.unit.test_studio_display_names import PreviewClient
from tests.unit.test_studio_service import _paths

HEADERS = {"X-EForge-Token": "notes"}


def test_notes_compare_exact_draft_parents_across_forks_and_missing_ancestors(
    tmp_path: Path,
) -> None:
    first = create_new_draft("organization", "northstar", description="Old", project_root=tmp_path)
    second = create_new_draft(
        "organization", "meridian", description="Other", project_root=tmp_path
    )
    parent = _parent(second)
    assert parent is not None
    child = create_draft(first, name="fork", project_root=tmp_path, additional_parents=[parent])
    environment = child.parent / "model/environment.yaml"
    environment.write_text("environment:\n  stale_accounts:\n    - username: former.employee\n")
    parents = [
        ParentReference.model_validate(raw)
        for raw in inspect_artifact(child)["lifecycle"]["parents"]
    ]
    context = notes_context(
        child, tmp_path, DisplayNameContext(kind="organization_pack", name="fork"), parents, [], ""
    )
    assert len(context.parents) == 2 and not context.findings
    assert all(comparison.status == "available" for comparison in context.parents)
    assert all(
        "former.employee" in comparison.changes["model/environment.yaml"]
        for comparison in context.parents
    )
    # The same identity with changed content is never used as the recorded ancestor.
    set_release_notes(first, "Changed after branching")
    second.unlink()
    unavailable = notes_context(child, tmp_path, context.artifact, parents, [first], "")
    assert all(comparison.status == "unavailable" for comparison in unavailable.parents)
    assert len(unavailable.findings) == 2
    assert "cannot be verified" in unavailable.findings[0]


def test_notes_find_published_parent_without_studio_and_refuse_tampered_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    set_publisher(
        tmp_path,
        PublisherIdentity(publisher="testing", publisher_display_name="Tests"),
        scope="project",
        force=False,
    )
    draft = create_new_draft("industry", "health", description="Health", project_root=tmp_path)
    release = publish(draft, project_root=tmp_path, accept_warnings=True)
    child = create_draft(release, project_root=tmp_path)
    parent = _parent(release)
    assert parent is not None
    set_release_notes(child, "Reviewed draft notes")
    comparison = compare_parent(child, parent, tmp_path, [])
    assert comparison.status == "available" and "pack.yaml" in comparison.changed_files
    assert "Reviewed draft notes" in comparison.changes["pack.yaml"]
    release.write_bytes(release.read_bytes() + b"# external change\n")
    assert compare_parent(child, parent, tmp_path, [release]).status == "unavailable"


def test_notes_compare_legacy_includes_and_bound_large_source_changes(tmp_path: Path) -> None:
    source = tmp_path / "scenario.yaml"
    source.write_text("name: legacy\nversion: '1.0'\nincludes: [environment.yaml]\n")
    include = tmp_path / "environment.yaml"
    include.write_text("environment:\n  description: Original organization\n")
    child = create_draft(source, project_root=tmp_path)
    parent = _parent(source)
    assert parent is not None
    (child.parent / "environment.yaml").write_text(
        "environment:\n  description: New organization\n"
    )
    comparison = compare_parent(child, parent, tmp_path, [source])
    assert comparison.status == "available"
    assert "New organization" in comparison.changes["environment.yaml"]
    bounded = compare_parent(child, parent, tmp_path, [source], character_budget=40)
    assert bounded.truncated and sum(map(len, bounded.changes.values())) <= 40
    long_notes = notes_context(
        child,
        tmp_path,
        DisplayNameContext(kind="scenario", name="legacy"),
        [parent],
        [source],
        "x" * 5000,
    )
    assert len(long_notes.current_notes) == 4000
    assert "4,000" in long_notes.findings[0]


def test_notes_report_binary_assets_as_partial_comparisons(tmp_path: Path) -> None:
    source = create_new_draft("organization", "assets", description="Test", project_root=tmp_path)
    (source.parent / "asset.bin").write_bytes(b"\xff\xfe")
    child = create_draft(source, project_root=tmp_path)
    (child.parent / "asset.bin").write_bytes(b"\xff\xfd")
    parent = _parent(source)
    assert parent is not None
    comparison = compare_parent(child, parent, tmp_path, [])
    assert comparison.truncated and "Binary asset changed" in comparison.changes["asset.bin"]


@pytest.mark.parametrize("kind", ["scenario", "industry", "organization"])
def test_notes_api_is_explicit_authenticated_and_preserves_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    source = create_new_draft(
        kind, "health", description="Northstar Health", project_root=workspace
    )
    original = source.read_bytes()
    contexts: list[ReleaseNotesContext] = []

    async def preview(context: ReleaseNotesContext, binary: Path | None) -> ReleaseNotesSuggestion:
        contexts.append(context)
        return ReleaseNotesSuggestion(release_notes="Initial healthcare definition.")

    monkeypatch.setattr(artifact_api, "suggest_release_notes", preview)
    with TestClient(create_app(_paths(tmp_path / "private"), "notes")) as client:
        item = next(
            row
            for row in client.get("/v1/items", headers=HEADERS).json()
            if row["path"] == str(source)
        )
        assert not contexts
        body = {
            "item_id": item["id"],
            "expected_digest": inspect_artifact(source)["digest"],
            "notes": "Unsaved manual note",
        }
        assert client.post("/v1/assist/release-notes", json=body).status_code == 401
        response = client.post("/v1/assist/release-notes", headers=HEADERS, json=body)
        assert response.status_code == 200, response.text
        assert response.json() == {
            "release_notes": "Initial healthcare definition.",
            "findings": [],
        }
        assert contexts[0].current_notes == "Unsaved manual note"
        assert contexts[0].artifact.kind == item["kind"] and not contexts[0].parents
        assert source.read_bytes() == original
        assert inspect_artifact(source)["lifecycle"]["status"] == "draft"
        assert not inspect_artifact(source)["lifecycle"].get("release_notes")
        set_release_notes(source, "Manual update")
        assert (
            client.post("/v1/assist/release-notes", headers=HEADERS, json=body).status_code == 409
        )
        assert len(contexts) == 1


@pytest.mark.parametrize("failure", ["changed", "unavailable"])
def test_notes_api_rechecks_snapshot_and_reports_ai_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    source = create_new_draft("organization", "test", description="Test", project_root=workspace)
    original = source.read_bytes()

    async def preview(context: ReleaseNotesContext, binary: Path | None) -> ReleaseNotesSuggestion:
        if failure == "unavailable":
            raise AssistanceError("AI is unavailable")
        # An asset-only change must invalidate the preview even when pack.yaml is unchanged.
        (source.parent / "model/environment.yaml").write_text(
            "environment: {description: Changed}\n"
        )
        return ReleaseNotesSuggestion(release_notes="Stale notes")

    monkeypatch.setattr(artifact_api, "suggest_release_notes", preview)
    with TestClient(create_app(_paths(tmp_path / "private"), "notes")) as client:
        item = next(
            row
            for row in client.get("/v1/items", headers=HEADERS).json()
            if row["path"] == str(source)
        )
        response = client.post(
            "/v1/assist/release-notes",
            headers=HEADERS,
            json={"item_id": item["id"], "expected_digest": inspect_artifact(source)["digest"]},
        )
        assert response.status_code == (409 if failure == "changed" else 503), response.text
        assert source.read_bytes() == original


def test_notes_api_reports_missing_ancestors_with_preview(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    parent = create_new_draft("industry", "health", description="Health", project_root=workspace)
    source = create_draft(parent, project_root=workspace)
    parent.unlink()

    async def preview(context: ReleaseNotesContext, binary: Path | None) -> ReleaseNotesSuggestion:
        assert context.parents[0].status == "unavailable" and context.findings
        return ReleaseNotesSuggestion(release_notes="Healthcare definition; prior changes unknown.")

    monkeypatch.setattr(artifact_api, "suggest_release_notes", preview)
    with TestClient(create_app(_paths(tmp_path / "private"), "notes")) as client:
        item = next(
            row
            for row in client.get("/v1/items", headers=HEADERS).json()
            if row["path"] == str(source)
        )
        response = client.post(
            "/v1/assist/release-notes",
            headers=HEADERS,
            json={"item_id": item["id"], "expected_digest": inspect_artifact(source)["digest"]},
        )
        assert response.status_code == 200, response.text
        assert "cannot be verified" in response.json()["findings"][0]


@pytest.mark.parametrize("published", [False, True])
def test_notes_api_requires_a_schema3_draft_before_calling_ai(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, published: bool
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    if published:
        set_publisher(
            workspace,
            PublisherIdentity(publisher="testing", publisher_display_name="Tests"),
            scope="project",
            force=False,
        )
        draft = create_new_draft("industry", "test", description="Test", project_root=workspace)
        source = publish(draft, project_root=workspace, accept_warnings=True)
    else:
        source = workspace / "scenarios/test/scenario.yaml"
        source.parent.mkdir(parents=True)
        source.write_text("scenario_version: '2.0'\nname: test\nenvironment: {}\n")

    async def forbidden(
        context: ReleaseNotesContext, binary: Path | None
    ) -> ReleaseNotesSuggestion:
        pytest.fail("Non-draft attempted an AI request")

    monkeypatch.setattr(artifact_api, "suggest_release_notes", forbidden)
    with TestClient(create_app(_paths(tmp_path / "private"), "notes")) as client:
        item = next(
            row
            for row in client.get("/v1/items", headers=HEADERS).json()
            if row["path"] == str(source)
        )
        response = client.post(
            "/v1/assist/release-notes",
            headers=HEADERS,
            json={"item_id": item["id"], "expected_digest": inspect_artifact(source)["digest"]},
        )
        assert response.status_code == 409 and "Schema 3 draft" in response.text


@pytest.mark.parametrize(
    "output",
    [
        '{"release_notes":"  "}',
        '{"release_notes":"x","publish":true}',
        '{"release_notes":12}',
        "not json",
    ],
)
@pytest.mark.asyncio
async def test_invalid_ai_notes_never_return_an_accepted_preview(
    monkeypatch: pytest.MonkeyPatch, output: str
) -> None:
    monkeypatch.setattr(assistance, "CodexClient", PreviewClient)
    monkeypatch.setattr(PreviewClient, "instances", [])
    monkeypatch.setattr(PreviewClient, "output", output)
    context = ReleaseNotesContext(
        artifact=DisplayNameContext(kind="scenario", name="test"), current_notes=""
    )
    with pytest.raises(AssistanceError, match="invalid release notes"):
        await suggest_release_notes(context, None)
    assert PreviewClient.instances[0].stopped


@pytest.mark.asyncio
async def test_notes_preview_uses_shared_read_only_service(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(assistance, "CodexClient", PreviewClient)
    monkeypatch.setattr(PreviewClient, "instances", [])
    monkeypatch.setattr(
        PreviewClient,
        "output",
        '{"release_notes":"Added a stale account.\\nRetained the environment."}',
    )
    context = ReleaseNotesContext(
        artifact=DisplayNameContext(kind="organization_pack", name="test"), current_notes=""
    )
    result = await suggest_release_notes(context, None)
    assert result.release_notes == "Added a stale account.\nRetained the environment."
    client = PreviewClient.instances[0]
    assert client.stopped and not client.cwd.exists()
    assert client.calls[1][1]["sandbox"] == "read-only"
    assert client.calls[2][1]["outputSchema"]["additionalProperties"] is False


@pytest.mark.asyncio
async def test_oversized_ai_context_never_launches_client(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("Oversized context launched the AI client")

    monkeypatch.setattr(assistance, "CodexClient", forbidden)
    context = ReleaseNotesContext(
        artifact=DisplayNameContext(kind="scenario", name="test"), current_notes="x" * (128 * 1024)
    )
    with pytest.raises(AssistanceError, match="Too much context"):
        await suggest_release_notes(context, None)
