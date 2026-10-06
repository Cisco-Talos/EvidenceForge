"""Model selection and durable failed-turn recovery for standalone authoring."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from evidenceforge.studio.paths import StudioPaths
from evidenceforge.studio.service import StudioService, create_app
from evidenceforge.studio.store import Conversation


def _app(root: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    async def quiet_start(self: StudioService) -> None:
        return None

    monkeypatch.setattr(StudioService, "start", quiet_start)
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(root / "workspace"))
    paths = StudioPaths(
        **{name: root / name for name in ["config", "data", "state", "cache", "logs"]}
    )
    return create_app(paths, "secret")


@pytest.mark.parametrize("thread_id", [None, "existing-thread"])
@pytest.mark.parametrize("model_id", [None, "chosen-model"])
def test_turn_sends_catalog_default_or_explicit_choice_on_start_and_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, thread_id: str | None, model_id: str | None
) -> None:
    app = _app(tmp_path, monkeypatch)
    studio = app.state.studio
    chat = Conversation(
        workspace=studio.settings.workspace,
        draft_kind="scenario",
        draft_path=studio.settings.workspace / "scenario.yaml",
        thread_id=thread_id,
        model_id=model_id,
    )
    studio.store.save_conversation(chat)
    calls: list[tuple[str, dict[str, Any]]] = []

    async def call(method: str, params: dict[str, Any], *, timeout: float = 30) -> dict[str, Any]:
        calls.append((method, params))
        if method == "model/list":
            return {
                "data": [
                    {"id": "first-model", "isDefault": False},
                    {"id": "catalog-model", "isDefault": True, "defaultReasoningEffort": "medium"},
                ]
            }
        if method == "skills/list":
            return {"data": [{"skills": [{"name": "eforge-scenario", "path": "/skill/SKILL.md"}]}]}
        if method == "thread/start":
            return {"thread": {"id": "new-thread"}}
        if method == "turn/start":
            return {"turn": {"id": "turn-1", "status": "inProgress"}}
        return {}

    monkeypatch.setattr(studio.codex, "call", call)
    with TestClient(app) as client:
        response = client.post(
            f"/v1/conversations/{chat.id}/turns",
            headers={"X-EForge-Token": "secret"},
            json={"text": "Explain the validation findings"},
        )
        assert response.status_code == 200, response.text
        expected = model_id or "catalog-model"
        assert response.json()["model_id"] == expected
        thread_method = "thread/resume" if thread_id else "thread/start"
        assert (
            next(params for method, params in calls if method == thread_method)["model"] == expected
        )
        turn = next(params for method, params in calls if method == "turn/start")
        assert turn["model"] == expected
        if model_id is None:
            assert turn["effort"] == "medium"


def test_empty_catalog_refuses_turn_before_codex_can_inherit_external_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    studio = app.state.studio
    chat = Conversation(workspace=studio.settings.workspace, thread_id="existing-thread")
    studio.store.save_conversation(chat)
    calls: list[str] = []

    async def call(method: str, params: dict[str, Any], *, timeout: float = 30) -> dict[str, Any]:
        calls.append(method)
        return {"data": []}

    monkeypatch.setattr(studio.codex, "call", call)
    with TestClient(app) as client:
        response = client.post(
            f"/v1/conversations/{chat.id}/turns",
            headers={"X-EForge-Token": "secret"},
            json={"text": "Explain this"},
        )
        assert response.status_code == 503
        assert "no models" in response.json()["detail"]
        assert calls == ["model/list"]
        assert not studio.store.conversation(chat.id).active


def test_failed_notification_overrides_lossy_rollout_history_after_reopening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    studio = app.state.studio
    chat = Conversation(workspace=studio.settings.workspace, thread_id="failed-thread")
    studio.store.save_conversation(chat)
    error = {"message": json.dumps({"error": {"message": "The selected model is unavailable."}})}
    studio.store.publish(
        chat.id,
        "conversation.event",
        {
            "method": "turn/completed",
            "params": {
                "threadId": chat.thread_id,
                "turn": {"id": "failed-turn", "status": "failed", "error": error},
            },
        },
    )
    # A different thread's notifications cannot rewrite this history.
    studio.store.publish(
        chat.id,
        "conversation.event",
        {
            "method": "turn/completed",
            "params": {
                "threadId": "unrelated-thread",
                "turn": {"id": "failed-turn", "status": "completed"},
            },
        },
    )
    studio.store.close()
    studio.coordinator.close()
    if studio.workspace_coordinator:
        studio.workspace_coordinator.close()
    app = _app(tmp_path, monkeypatch)
    studio = app.state.studio

    async def call(method: str, params: dict[str, Any], *, timeout: float = 30) -> dict[str, Any]:
        return {
            "thread": {
                "status": {"type": "idle"},
                "turns": [{"id": "failed-turn", "status": "completed", "items": []}],
            }
        }

    monkeypatch.setattr(studio.codex, "call", call)
    with TestClient(app) as client:
        response = client.get(
            f"/v1/conversations/{chat.id}/history", headers={"X-EForge-Token": "secret"}
        )
        assert response.status_code == 200
        turn = response.json()["thread"]["turns"][0]
        assert turn["status"] == "failed"
        assert turn["error"] == error
        assert "failed" in studio.store.conversation(chat.id).connection_note
