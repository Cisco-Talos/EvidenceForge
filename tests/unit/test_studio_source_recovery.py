"""Managed draft creation and recovery retain history without rewriting source truth."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from evidenceforge.artifacts.lifecycle import create_new_draft
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
from evidenceforge.desktop.library import discover_scenarios
from evidenceforge.desktop.state import GenerationJob
from evidenceforge.studio.service import StudioService, create_app
from evidenceforge.studio.store import Conversation
from tests.unit.test_studio_service import _paths

RecoveryClient = tuple[TestClient, StudioService, Path]

HEADERS = {"X-EForge-Token": "recovery"}


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[RecoveryClient]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    monkeypatch.setenv("EFORGE_DESKTOP_CODEX_BIN", str(tmp_path / "no-codex"))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    app = create_app(_paths(tmp_path / "private"), "recovery")
    with TestClient(app) as test_client:
        yield test_client, app.state.studio, workspace


def _create(client: TestClient, name: str = "Test-1") -> dict[str, Any]:
    response = client.post(
        "/v1/conversations",
        headers=HEADERS,
        json={"draft_kind": "scenario", "name": name, "display_name": "Test 1"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _scenarios(client: TestClient) -> list[dict[str, Any]]:
    return [
        item
        for item in client.get("/v1/bootstrap", headers=HEADERS).json()["items"]
        if item["kind"] == "scenario"
    ]


def test_creation_has_canonical_file_and_edits_do_not_fork(client: RecoveryClient) -> None:
    api, studio, workspace = client
    chat = _create(api)
    path = Path(chat["draft_path"])
    assert path.is_file()
    assert path.is_relative_to(workspace / ".eforge/artifacts/drafts/scenario")
    assert (path.parent.parent / "draft.json").is_file()
    data = yaml.safe_load(path.read_text())
    assert (data["schema_version"], data["status"], data["name"]) == ("3.0", "draft", "Test-1")
    assert data["display_name"] == "Test 1"
    assert chat["item_id"] and chat["draft_kind"] is None
    another = api.post("/v1/conversations", headers=HEADERS, json={"item_id": chat["item_id"]})
    assert another.status_code == 200
    assert another.json()["item_id"] == chat["item_id"]
    assert len(_scenarios(api)) == 1
    assert studio.store.draft_identity(studio.store.item(chat["item_id"])) == data["draft_id"]


def test_starter_skips_forecast_and_gates_actions_then_authored_content_restores_them(
    client: RecoveryClient,
) -> None:
    api, studio, workspace = client
    chat = _create(api)
    item_id = chat["item_id"]
    source = Path(chat["draft_path"])
    snapshot = api.get("/v1/bootstrap", headers=HEADERS).json()
    assert item_id in snapshot["starter_drafts"]
    assert item_id not in snapshot["forecasts"]
    assert item_id not in studio.prediction_pending
    endpoint = f"/v1/items/{item_id}/lifecycle"
    assert api.get(endpoint, headers=HEADERS).json()["starter_draft"]
    for route, payload in [
        (f"/v1/scenarios/{item_id}/resources/predict", None),
        ("/v1/jobs/generations", {"scenario_id": item_id}),
        (endpoint, {"action": "publish"}),
    ]:
        response = api.post(route, headers=HEADERS, json=payload)
        assert response.status_code == 409, response.text
        assert "Ready to author" in response.json()["detail"]
    # Explicit validation remains available, with field-level findings.
    checked = api.post("/v1/validate", headers=HEADERS, json={"scenario_id": item_id})
    assert checked.status_code == 200, checked.text
    assert checked.json()["exit_code"] != 0
    issues = checked.json()["report"]["issues"]
    assert {"environment.users", "environment.systems"} <= {issue["field_path"] for issue in issues}
    assert "errors.pydantic.dev" not in checked.text
    authored = yaml.safe_load(source.read_bytes())
    minimal = yaml.safe_load(Path("tests/fixtures/scenarios/minimal.yaml").read_bytes())
    minimal.pop("version")
    authored.update(minimal)
    source.write_text(yaml.safe_dump(authored))
    forecast = api.post(f"/v1/scenarios/{item_id}/resources/predict", headers=HEADERS)
    assert forecast.status_code == 200, forecast.text
    assert forecast.json()["result"]["available"]
    assert item_id not in api.get("/v1/bootstrap", headers=HEADERS).json()["starter_drafts"]
    assert not api.get(endpoint, headers=HEADERS).json()["starter_draft"]
    set_publisher(
        workspace,
        PublisherIdentity(publisher="testing", publisher_display_name="Tests"),
        scope="project",
        force=False,
    )
    published = api.post(
        endpoint, headers=HEADERS, json={"action": "publish", "accept_warnings": True}
    )
    assert published.status_code == 200, published.text


def test_edited_invalid_draft_publication_returns_readable_fields(client: RecoveryClient) -> None:
    api, _studio, workspace = client
    chat = _create(api)
    source = Path(chat["draft_path"])
    data = yaml.safe_load(source.read_bytes())
    data["environment"]["description"] = "Authoring has started, but entities are missing"
    source.write_text(yaml.safe_dump(data))
    set_publisher(
        workspace,
        PublisherIdentity(publisher="testing", publisher_display_name="Tests"),
        scope="project",
        force=False,
    )
    response = api.post(
        f"/v1/items/{chat['item_id']}/lifecycle", headers=HEADERS, json={"action": "publish"}
    )
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["message"] == "Scenario needs changes before publication."
    assert {"environment.users", "environment.systems"} <= {
        issue["field_path"] for issue in detail["issues"]
    }
    assert "input_value" not in response.text and "errors.pydantic.dev" not in response.text


def test_missing_scaffold_survives_scan_and_removal_preserves_history(
    client: RecoveryClient,
) -> None:
    api, studio, workspace = client
    chat = _create(api)
    path = Path(chat["draft_path"])
    receipt = path.parent.parent / "draft.json"
    receipt_bytes = receipt.read_bytes()
    source_bytes = path.read_bytes()
    path.unlink()
    api.post("/v1/library/refresh", headers=HEADERS)
    snapshot = api.get("/v1/bootstrap", headers=HEADERS).json()
    assert snapshot["missing_sources"] == [chat["item_id"]]
    assert api.delete(f"/v1/scenarios/{chat['item_id']}/registration").status_code == 401
    removed = api.delete(f"/v1/scenarios/{chat['item_id']}/registration", headers=HEADERS)
    assert removed.status_code == 200, removed.text
    assert not _scenarios(api)
    assert studio.store.conversation(chat["id"]).thread_id == chat["thread_id"]
    assert studio.store.conversation(chat["id"]).item_id == chat["item_id"]
    assert receipt.read_bytes() == receipt_bytes
    api.post("/v1/library/refresh", headers=HEADERS)
    assert not _scenarios(api)
    path.write_bytes(source_bytes)
    api.post("/v1/library/refresh", headers=HEADERS)
    assert _scenarios(api)[0]["id"] == chat["item_id"]
    assert studio.store.conversation(chat["id"]).item_id == chat["item_id"]


def test_unique_move_keeps_id_project_chats_and_immutable_runs(client: RecoveryClient) -> None:
    api, studio, workspace = client
    project = api.post("/v1/projects", headers=HEADERS, json={"name": "Recovery"}).json()
    chat = api.post(
        "/v1/conversations",
        headers=HEADERS,
        json={"draft_kind": "scenario", "name": "moving", "project_id": project["id"]},
    ).json()
    old = Path(chat["draft_path"])
    original = old.read_bytes()
    job = GenerationJob(
        id="retained",
        workspace=workspace,
        scenario=old,
        output_root=workspace / "runs/retained",
        progress_file=studio.paths.state / "jobs/retained.jsonl",
        log_file=studio.paths.state / "jobs/retained.log",
        status="stopped",
        started_at=1,
    )
    studio.store.save_job(job.id, workspace, "generation", job)
    job_bytes = studio.store.job_payloads(workspace)
    target = workspace / "scenarios/moved/scenario.yaml"
    target.parent.mkdir(parents=True)
    old.rename(target)
    api.post("/v1/library/refresh", headers=HEADERS)
    items = _scenarios(api)
    assert len(items) == 1
    assert items[0]["id"] == chat["item_id"]
    assert items[0]["path"] == str(target)
    assert items[0]["project_id"] == project["id"]
    assert studio.store.conversation(chat["id"]).draft_path == target
    assert studio.store.job_payloads(workspace) == job_bytes
    assert target.read_bytes() == original
    snapshot = api.get("/v1/bootstrap", headers=HEADERS).json()
    assert set(snapshot["source_paths"][chat["item_id"]]) == {str(old), str(target)}
    assert not snapshot["missing_sources"]
    api.post("/v1/library/refresh", headers=HEADERS)
    assert _scenarios(api)[0]["id"] == chat["item_id"]


def test_preexisting_duplicate_registration_merges_both_conversations(
    client: RecoveryClient,
) -> None:
    api, studio, workspace = client
    chat = _create(api)
    old = Path(chat["draft_path"])
    target = workspace / "scenarios/agent-moved/scenario.yaml"
    target.parent.mkdir(parents=True)
    old.rename(target)
    found = next(source for source in discover_scenarios(workspace, []) if source.path == target)
    duplicate = studio.store.upsert_item(workspace, "scenario", found)
    second = Conversation(workspace=workspace, item_id=duplicate.id, thread_id="preserved-thread")
    studio.store.save_conversation(second)
    api.post("/v1/library/refresh", headers=HEADERS)
    assert len(_scenarios(api)) == 1
    assert studio.store.conversation(second.id).item_id == chat["item_id"]
    assert studio.store.conversation(second.id).thread_id == "preserved-thread"
    assert studio.store.conversation(chat["id"]).item_id == chat["item_id"]


@pytest.mark.parametrize("reason", ["ambiguous", "active", "independent", "legacy"])
def test_unsafe_moves_stay_missing_for_manual_recovery(client: RecoveryClient, reason: str) -> None:
    api, studio, workspace = client
    chat = _create(api)
    old = Path(chat["draft_path"])
    data = old.read_bytes()
    if reason == "legacy":
        old.write_text("name: Test-1\nversion: '1.0'\nenvironment: {users: [], systems: []}\n")
        api.post("/v1/library/refresh", headers=HEADERS)
        data = old.read_bytes()
    target = workspace / "scenarios/one/scenario.yaml"
    target.parent.mkdir(parents=True)
    target.write_bytes(data)
    if reason == "ambiguous":
        other = workspace / "scenarios/two/scenario.yaml"
        other.parent.mkdir(parents=True)
        other.write_bytes(data)
    if reason == "independent":
        independent = create_new_draft("scenario", "Test-1", description="", project_root=workspace)
        target.write_bytes(independent.read_bytes())
    if reason == "active":
        active = studio.store.conversation(chat["id"])
        active.active = True
        studio.store.save_conversation(active)
    old.unlink()
    api.post("/v1/library/refresh", headers=HEADERS)
    snapshot = api.get("/v1/bootstrap", headers=HEADERS).json()
    assert chat["item_id"] in snapshot["missing_sources"]
    endpoint = f"/v1/scenarios/{chat['item_id']}/source"
    response = api.post(endpoint, headers=HEADERS, json={"path": str(target)})
    assert response.status_code == (409 if reason in {"active", "independent"} else 200), (
        response.text
    )
    if reason == "active":
        assert (
            api.delete(f"/v1/scenarios/{chat['item_id']}/registration", headers=HEADERS).status_code
            == 409
        )


def test_recovery_rejects_other_files_symlinks_and_live_source(
    client: RecoveryClient, tmp_path: Path
) -> None:
    api, studio, workspace = client
    chat = _create(api)
    source = Path(chat["draft_path"])
    endpoint = f"/v1/scenarios/{chat['item_id']}/source"
    assert api.post(endpoint, headers=HEADERS, json={"path": str(source)}).status_code == 409
    copy = tmp_path / "external.yaml"
    copy.write_bytes(source.read_bytes())
    source.unlink()
    assert api.post(endpoint, json={"path": str(copy)}).status_code == 401
    assert api.post(endpoint, headers=HEADERS, json={"path": str(copy)}).status_code == 409
    link = workspace / "symlink.yaml"
    link.symlink_to(copy)
    assert api.post(endpoint, headers=HEADERS, json={"path": str(link)}).status_code == 409
    assert studio.store.item(chat["item_id"])


def test_archived_registration_cannot_steal_a_live_relocated_id(client: RecoveryClient) -> None:
    api, studio, workspace = client
    chat = _create(api)
    path = Path(chat["draft_path"])
    content = path.read_bytes()
    path.unlink()
    assert (
        api.delete(f"/v1/scenarios/{chat['item_id']}/registration", headers=HEADERS).status_code
        == 200
    )
    path.write_bytes(content)
    api.post("/v1/library/refresh", headers=HEADERS)
    assert _scenarios(api)[0]["id"] == chat["item_id"]
    moved = workspace / "scenarios/moved/scenario.yaml"
    moved.parent.mkdir(parents=True)
    path.rename(moved)
    api.post("/v1/library/refresh", headers=HEADERS)
    path.write_bytes(content)
    api.post("/v1/library/refresh", headers=HEADERS)
    assert len(_scenarios(api)) == 2
    assert studio.store.item(chat["item_id"]).path == moved


def test_conflicting_projects_require_resolution_before_merge(client: RecoveryClient) -> None:
    api, studio, workspace = client
    chat = _create(api)
    first = api.post("/v1/projects", headers=HEADERS, json={"name": "First"}).json()
    second = api.post("/v1/projects", headers=HEADERS, json={"name": "Second"}).json()
    item = studio.store.item(chat["item_id"])
    item.project_id = first["id"]
    studio.store.save_item(item)
    moved = workspace / "scenarios/moved/scenario.yaml"
    moved.parent.mkdir(parents=True)
    item.path.rename(moved)
    source = next(entry for entry in discover_scenarios(workspace, []) if entry.path == moved)
    target = studio.store.upsert_item(workspace, "scenario", source)
    target.project_id = second["id"]
    studio.store.save_item(target)
    api.post("/v1/library/refresh", headers=HEADERS)
    assert len(_scenarios(api)) == 2
    assert (
        api.post(
            f"/v1/scenarios/{item.id}/source", headers=HEADERS, json={"path": str(moved)}
        ).status_code
        == 409
    )
    assert studio.store.item(item.id).project_id == first["id"]
    assert studio.store.item(target.id).project_id == second["id"]
