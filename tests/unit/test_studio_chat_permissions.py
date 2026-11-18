"""Publication changes execution permissions without moving or discarding chats."""

import asyncio
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from evidenceforge.artifacts.lifecycle import publish, verify_release
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
from evidenceforge.studio.chat_permissions import (
    ChatAccess,
    chat_access,
    isolated_chat_config,
    prune_scratch,
    remove_scratch,
    scratch_directory,
    verify_chat_permissions,
    with_scratch,
)
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
                    "writableRoots": [
                        root
                        for root in params["config"]["sandbox_workspace_write"]["writable_roots"]
                        if root != params["cwd"]
                    ],
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
        started = next(params for method, params in calls if method == "thread/start")
        drafted = next(params for method, params in calls if method == "turn/start")
        scratch = (workspace / ".eforge/tmp/chat" / chat["id"]).resolve()
        assert scratch.is_dir() and not scratch.is_relative_to(source.parent.parent)
        assert started["config"]["sandbox_workspace_write"]["writable_roots"] == [
            str(source.parent.parent.resolve()),
            str(scratch),
        ]
        assert drafted["sandboxPolicy"]["writableRoots"][1] == str(scratch)
        assert started["config"]["shell_environment_policy.set"] == {
            name: str(scratch) for name in ("TMPDIR", "TEMP", "TMP")
        }
        assert repr(str(scratch)) in started["developerInstructions"]
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
        assert resumed["config"]["sandbox_workspace_write"]["writable_roots"] == []
        assert "shell_environment_policy.set" not in resumed["config"]
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
        removed = client.delete(f"/v1/conversations/{chat['id']}", headers=HEADERS)
        assert removed.status_code == 200, removed.text
        assert not scratch.exists()


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


def _draft_response(access: ChatAccess, roots: list[str]) -> dict[str, Any]:
    return {
        "cwd": str(access.directory),
        "approvalPolicy": "never",
        "sandbox": {**access.sandbox, "writableRoots": roots},
    }


def test_draft_scratch_must_be_confirmed_and_cannot_be_widened(tmp_path: Path) -> None:
    draft_directory = tmp_path / "draft"
    draft_directory.mkdir()
    access = with_scratch(
        ChatAccess(mode="draft", source=draft_directory / "source.yaml", directory=draft_directory),
        tmp_path,
        "a" * 32,
    )
    scratch = str(access.scratch)
    verify_chat_permissions(_draft_response(access, [scratch]), access)
    for roots in ([], [scratch, str(tmp_path)], [str(tmp_path / ".eforge")]):
        with pytest.raises(CodexUnavailableError, match="did not confirm"):
            verify_chat_permissions(_draft_response(access, roots), access)


def test_discussion_never_receives_a_scratch_folder(tmp_path: Path) -> None:
    access = ChatAccess(mode="discussion", source=tmp_path / "source.yaml", directory=tmp_path)
    assert with_scratch(access, tmp_path, "a" * 32) is access
    assert not (tmp_path / ".eforge").exists()
    assert "shell_environment_policy.set" not in isolated_chat_config({"layers": []}, access)


def test_scratch_environment_keeps_user_assignments_and_overrides_temp(tmp_path: Path) -> None:
    access = with_scratch(
        ChatAccess(mode="draft", source=tmp_path / "source.yaml", directory=tmp_path),
        tmp_path,
        "b" * 32,
    )
    effective = {
        "config": {"shell_environment_policy": {"set": {"LANG": "C.UTF-8", "TMPDIR": "/tmp"}}},
        "layers": [],
    }
    assigned = isolated_chat_config(effective, access)["shell_environment_policy.set"]
    assert assigned == {
        "LANG": "C.UTF-8",
        "TMPDIR": str(access.scratch),
        "TEMP": str(access.scratch),
        "TMP": str(access.scratch),
    }


@pytest.mark.parametrize("identity", ["", "..", "a/b", "a\\b", "x" * 65])
def test_scratch_directory_rejects_unsafe_conversation_identity(
    tmp_path: Path, identity: str
) -> None:
    with pytest.raises(CodexUnavailableError, match="identity"):
        scratch_directory(tmp_path, identity)


def test_prune_scratch_removes_only_orphaned_conversation_folders(tmp_path: Path) -> None:
    live, orphan = "c" * 32, "d" * 32
    for identity in (live, orphan):
        nested = scratch_directory(tmp_path, identity) / "work"
        nested.mkdir(parents=True)
        leftover = nested / "leftover.txt"
        leftover.write_text("temporary")
        leftover.chmod(0o400)
    unrelated = tmp_path / ".eforge/tmp/chat/not a conversation"
    unrelated.mkdir()
    prune_scratch(tmp_path, {live})
    assert scratch_directory(tmp_path, live).is_dir()
    assert not scratch_directory(tmp_path, orphan).exists()
    assert unrelated.is_dir()
    remove_scratch(tmp_path, live)
    remove_scratch(tmp_path, live)  # Already removed: nothing to do.
    assert not scratch_directory(tmp_path, live).exists()
