"""Publication changes execution permissions without moving or discarding chats."""

import asyncio
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from evidenceforge.artifacts.lifecycle import publish, verify_release
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
from evidenceforge.studio.chat_permissions import ChatAccess, chat_access, verify_chat_permissions
from evidenceforge.studio.codex import CodexUnavailableError
from evidenceforge.studio.service import StudioService, create_app
from tests.unit.test_draft_completion import draft
from tests.unit.test_studio_service import _paths

HEADERS = {"X-EForge-Token": "permissions"}


@pytest.mark.parametrize("kind", ["scenario", "industry", "organization"])
def test_retained_chat_becomes_read_only_and_new_draft_requires_new_chat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    set_publisher(
        workspace,
        PublisherIdentity(publisher="tests", publisher_display_name="Tests"),
        scope="project",
        force=False,
    )
    source = draft(workspace, kind)

    async def quiet_start(self: StudioService) -> None:
        return None

    monkeypatch.setattr(StudioService, "start", quiet_start)
    app = create_app(_paths(tmp_path / "private"), "permissions")
    studio = app.state.studio
    calls: list[tuple[str, dict[str, Any]]] = []
    ignore_policy = False

    async def call(method: str, params: dict[str, Any], *, timeout: float = 30) -> dict[str, Any]:
        calls.append((method, params))
        if method == "model/list":
            return {"data": [{"id": "test-model", "isDefault": True}]}
        if method == "skills/list":
            return {
                "data": [
                    {
                        "skills": [
                            {"name": name, "path": "/skill/SKILL.md"}
                            for name in (
                                "eforge-scenario",
                                "eforge-industry-pack",
                                "eforge-organization-pack",
                            )
                        ]
                    }
                ]
            }
        if method == "config/read":
            return {"layers": [{"config": {"mcp_servers": {"outside-writer": {"enabled": True}}}}]}
        if method in {"thread/start", "thread/resume"}:
            if ignore_policy:
                return {"sandbox": {"type": "workspaceWrite"}}
            policy = (
                {"type": "readOnly", "networkAccess": False}
                if params["sandbox"] == "read-only"
                else {
                    "type": "workspaceWrite",
                    "writableRoots": [],
                    "networkAccess": False,
                    "excludeTmpdirEnvVar": True,
                    "excludeSlashTmp": True,
                }
            )
            return {
                "thread": {"id": params.get("threadId", "draft-thread")},
                "sandbox": policy,
                "cwd": params["cwd"],
                "approvalPolicy": "never",
            }
        if method == "turn/start":
            await studio._codex_event(
                "turn/completed",
                {"threadId": params["threadId"], "turn": {"id": "turn", "status": "completed"}},
            )
            return {"turn": {"id": "turn", "status": "completed"}}
        return {}

    monkeypatch.setattr(studio.codex, "call", call)
    with TestClient(app) as client:
        client.portal.call(studio.scan)
        item = next(entry for entry in studio.store.items(workspace) if entry.path == source)
        chat = client.post("/v1/conversations", headers=HEADERS, json={"item_id": item.id}).json()
        endpoint = f"/v1/conversations/{chat['id']}/turns"
        assert (
            client.post(endpoint, headers=HEADERS, json={"text": "Explain this draft"}).status_code
            == 200
        )
        thread_id = studio.store.conversation(chat["id"]).thread_id
        release = publish(source, project_root=workspace, accept_warnings=True)
        client.portal.call(studio.scan)
        receipt = verify_release(release.parent.parent)
        release_bytes = release.read_bytes()
        source_bytes = source.read_bytes()
        calls.clear()
        ignore_policy = True
        blocked = client.post(endpoint, headers=HEADERS, json={"text": "Change this version"})
        assert blocked.status_code == 503 and "No message was sent" in blocked.text
        assert not any(method == "turn/start" for method, _ in calls)
        assert studio.store.conversation(chat["id"]).thread_id == thread_id
        ignore_policy = False
        calls.clear()
        result = client.post(endpoint, headers=HEADERS, json={"text": "Add another workstation"})
        assert result.status_code == 200, result.text
        assert result.json()["thread_id"] == thread_id
        assert not any(method in {"thread/start", "thread/fork"} for method, _ in calls)
        assert [method for method, _ in calls].index("thread/unsubscribe") < [
            method for method, _ in calls
        ].index("thread/resume")
        resumed = next(params for method, params in calls if method == "thread/resume")
        turn = next(params for method, params in calls if method == "turn/start")
        assert resumed["sandbox"] == "read-only" and resumed["approvalPolicy"] == "never"
        assert "select New draft" in resumed["developerInstructions"]
        assert "Resume and edit" not in resumed["developerInstructions"]
        assert resumed["config"]["mcp_servers"]["outside-writer"] == {"enabled": False}
        assert turn["sandboxPolicy"] == {"type": "readOnly", "networkAccess": False}
        assert turn["cwd"] == str(release.parent)
        assert release.read_bytes() == release_bytes and source.read_bytes() == source_bytes
        assert verify_release(release.parent.parent) == receipt
        assert (
            client.get(f"/v1/conversations/{chat['id']}/access", headers=HEADERS).json()["version"]
            == "1.0.0"
        )
        another = client.post(
            "/v1/conversations", headers=HEADERS, json={"item_id": item.id}
        ).json()
        assert another["item_id"] == item.id  # Questions do not create drafts.
        created = client.post(
            f"/v1/items/{item.id}/lifecycle", headers=HEADERS, json={"action": "draft"}
        )
        assert created.status_code == 200, created.text
        new_source = Path(created.json()["path"])
        new_item = next(
            entry for entry in studio.store.items(workspace) if entry.path == new_source
        )
        new_chat = client.post(
            "/v1/conversations", headers=HEADERS, json={"item_id": new_item.id}
        ).json()
        assert new_chat["id"] != chat["id"]
        assert chat_access(new_source).mode == "draft"
        assert studio.store.conversation(chat["id"]).item_id == item.id


@pytest.mark.parametrize(
    "method,expected",
    [
        ("item/commandExecution/requestApproval", {"decision": "decline"}),
        ("item/fileChange/requestApproval", {"decision": "decline"}),
        ("item/permissions/requestApproval", {"permissions": {}, "scope": "turn"}),
        ("item/tool/call", {"success": False, "contentItems": []}),
        ("mcpServer/elicitation/request", {"action": "decline", "content": None}),
    ],
)
def test_mutation_escalations_are_denied_without_a_user_approval_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str, expected: dict[str, Any]
) -> None:
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(tmp_path / "workspace"))
    app = create_app(_paths(tmp_path / "private"), "permissions")
    studio = app.state.studio
    replies = []

    async def respond(request_id: str, result: dict[str, Any]) -> None:
        replies.append(result)

    monkeypatch.setattr(studio.codex, "respond", respond)
    asyncio.run(studio._codex_request("request", method, {"threadId": "old-thread"}))
    assert replies == [expected] and not studio.pending_codex_requests
    studio.store.close()
    studio.coordinator.close()
    studio.workspace_coordinator.close()


@pytest.mark.parametrize(
    "policy",
    [
        {"type": "workspaceWrite"},
        {"type": "dangerFullAccess"},
        {},
    ],
)
def test_discussion_rejects_missing_or_broadened_permission_acknowledgment(
    tmp_path: Path, policy: dict[str, Any]
) -> None:
    access = ChatAccess(mode="discussion", source=tmp_path / "source.yaml", directory=tmp_path)
    with pytest.raises(CodexUnavailableError, match="did not confirm"):
        verify_chat_permissions(
            {"sandbox": policy, "approvalPolicy": "never", "cwd": str(tmp_path)}, access
        )


def test_draft_rejects_additional_writable_roots(tmp_path: Path) -> None:
    access = ChatAccess(mode="draft", source=tmp_path / "source.yaml", directory=tmp_path)
    with pytest.raises(CodexUnavailableError, match="did not confirm"):
        verify_chat_permissions(
            {
                "cwd": str(tmp_path),
                "approvalPolicy": "never",
                "sandbox": {
                    **access.sandbox,
                    "writableRoots": [str(tmp_path), str(tmp_path.parent)],
                },
            },
            access,
        )


def test_draft_receipt_cannot_grant_writes_to_the_whole_workspace(tmp_path: Path) -> None:
    import json
    import shutil

    source = draft(tmp_path, "scenario")
    container = source.parent.parent
    relocated = tmp_path / "source" / source.name
    shutil.copytree(source.parent, relocated.parent)
    (tmp_path / "draft.json").write_text(
        json.dumps(json.loads((container / "draft.json").read_bytes()))
    )
    with pytest.raises(CodexUnavailableError, match="managed container"):
        chat_access(relocated)
