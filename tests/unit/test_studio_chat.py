"""Chat lifecycle contracts without inference or the user's running app state."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from evidenceforge.studio.chat import ChatMessageRequest
from evidenceforge.studio.codex import CodexTimeoutError
from evidenceforge.studio.service import StudioService, create_app
from evidenceforge.studio.state_records_v3 import ChatTurn
from evidenceforge.studio.store import Conversation
from tests.support.studio_state import paths


@pytest.fixture
def studio(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> StudioService:
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(tmp_path / "workspace"))
    service = StudioService(paths(tmp_path / "private"), "secret")
    yield service
    service.store.close()
    service.workspace_coordinator.close()
    service.coordinator.close()


def conversation(studio: StudioService, *, active: bool = True) -> Conversation:
    source = studio.settings.workspace / "scenarios" / "draft" / "scenario.yaml"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("name: draft\n", encoding="utf-8")
    result = Conversation(
        workspace=studio.settings.workspace,
        thread_id="thread",
        active=active,
        draft_kind="scenario",
        draft_path=source,
    )
    studio.store.save_conversation(result)
    if active:
        studio.chat.before_submit(result, source)
        studio.chat.bind_turn(result, {"id": "turn-1", "status": "inProgress"})
    return result


@pytest.mark.asyncio
async def test_interrupt_and_steer_use_exact_turn_identity_and_same_clock(
    studio: StudioService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    chat = conversation(studio)
    calls: list[tuple[str, dict[str, Any]]] = []

    async def call(method: str, params: dict[str, Any], *, timeout: float = 30) -> dict[str, Any]:
        calls.append((method, params))
        return {"turnId": "turn-1"}

    monkeypatch.setattr(studio.codex, "call", call)
    before = studio.store.chat.turns(chat.id)[0].started_at
    sent = await studio.chat.send(
        chat,
        ChatMessageRequest(
            message_id="guidance", text="Keep working", mode="steer", expected_turn_id="turn-1"
        ),
    )
    assert sent.state == "accepted"
    assert calls[0][1]["expectedTurnId"] == "turn-1"
    assert calls[0][1]["clientUserMessageId"] == "guidance"
    assert studio.store.chat.turns(chat.id)[0].started_at == before
    await studio.chat.interrupt(chat)
    assert calls[-1] == ("turn/interrupt", {"threadId": "thread", "turnId": "turn-1"})
    assert studio.store.chat.control(chat.id).queue_paused
    with pytest.raises(HTTPException, match="409"):
        await studio.chat.send(
            chat,
            ChatMessageRequest(
                message_id="stale", text="Another thought", mode="steer", expected_turn_id="old"
            ),
        )
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_fast_completion_does_not_resurrect_active_turn_identity(
    studio: StudioService,
) -> None:
    chat = conversation(studio)
    studio.chat.observe(
        chat,
        "turn/completed",
        {
            "threadId": "thread",
            "turn": {"id": "turn-1", "status": "completed", "durationMs": 66000},
        },
    )
    chat.active = False
    studio.store.save_conversation(chat)
    studio.chat.bind_turn(chat, {"id": "turn-1", "status": "inProgress"})
    assert studio.chat.active_id(chat.id) is None
    assert studio.store.chat.turns(chat.id)[0].duration_ms == 66000


@pytest.mark.asyncio
async def test_fifo_queue_dispatches_once_and_retains_edits_until_success(
    studio: StudioService,
) -> None:
    chat = conversation(studio)
    for name in ("second", "third"):
        await studio.chat.send(chat, ChatMessageRequest(message_id=name, text=name, mode="queue"))
    duplicate = await studio.chat.send(
        chat, ChatMessageRequest(message_id="second", text="second", mode="queue")
    )
    assert duplicate.state == "queued"
    assert len(studio.store.chat.inputs(chat.id)) == 2
    sent: list[str] = []

    async def submit(identity: str, entry: Any) -> dict[str, Any]:
        sent.append(entry.text)
        current = studio.store.conversation(identity)
        current.active = True
        studio.store.save_conversation(current)
        studio.chat.bind_turn(current, {"id": entry.id, "status": "inProgress"})
        return {"turn_id": entry.id, "delivery": "confirmed"}

    studio.chat.submit = submit
    chat.active = False
    studio.store.save_conversation(chat)
    await asyncio.gather(studio.chat.dispatch_queue(chat.id), studio.chat.dispatch_queue(chat.id))
    assert sent == ["second"]
    studio.chat.observe(
        studio.store.conversation(chat.id),
        "turn/completed",
        {"turn": {"id": "second", "status": "completed"}},
    )
    chat.active = False
    studio.store.save_conversation(chat)
    await studio.chat.dispatch_queue(chat.id)
    assert sent == ["second", "third"]


@pytest.mark.asyncio
async def test_uncertain_steer_holds_queue_and_reconciles_native_client_id(
    studio: StudioService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    chat = conversation(studio)
    calls = 0

    async def call(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        raise CodexTimeoutError("Codex did not confirm delivery")

    monkeypatch.setattr(studio.codex, "call", call)
    request = ChatMessageRequest(
        message_id="lost", text="Question", mode="steer", expected_turn_id="turn-1"
    )
    with pytest.raises(HTTPException):
        await studio.chat.send(chat, request)
    assert (await studio.chat.send(chat, request)).state == "uncertain"
    assert calls == 1
    assert studio.store.chat.control(chat.id).queue_paused
    native = ChatTurn(
        id="turn-1",
        conversation_id=chat.id,
        thread_id="thread",
        items=[
            {
                "id": "user-item",
                "type": "userMessage",
                "clientId": "lost",
                "content": [{"type": "text", "text": "Question"}],
            }
        ],
    )
    studio.chat.reconcile_inputs([native], chat.id)
    assert studio.store.chat.input("lost").state == "accepted"
    assert studio.store.chat.control(chat.id).queue_paused


@pytest.mark.asyncio
async def test_item_projection_is_ordered_and_completed_text_is_authoritative(
    studio: StudioService,
) -> None:
    chat = conversation(studio)
    for native in (
        {"id": "a", "type": "agentMessage", "phase": "commentary", "text": ""},
        {"id": "tool", "type": "commandExecution", "command": "eforge validate"},
        {"id": "b", "type": "agentMessage", "phase": "final_answer", "text": ""},
    ):
        studio.chat.observe(chat, "item/started", {"turnId": "turn-1", "item": native})
    studio.chat.observe(
        chat, "item/agentMessage/delta", {"turnId": "turn-1", "itemId": "a", "delta": "Working"}
    )
    studio.chat.observe(
        chat,
        "item/completed",
        {
            "turnId": "turn-1",
            "item": {
                "id": "a",
                "type": "agentMessage",
                "phase": "commentary",
                "text": "Working carefully",
            },
        },
    )
    snapshot = studio.chat.snapshot(chat, {})
    assert [item["id"] for item in snapshot.turns[0].items] == ["a", "tool", "b"]
    assert snapshot.turns[0].items[0]["text"] == "Working carefully"


def test_private_view_preferences_and_secret_answers_are_scoped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(tmp_path / "workspace"))
    app = create_app(paths(tmp_path / "private"), "secret")
    headers = {"X-EForge-Token": "secret"}
    with TestClient(app) as client:
        service = app.state.studio
        chat = conversation(service, active=False)
        service.pending_codex_requests[7] = {
            "params": {
                "threadId": "thread",
                "questions": [
                    {"id": "secret", "isSecret": True},
                    {"id": "ordinary", "isSecret": False},
                ],
            }
        }
        response = client.put(
            f"/v1/conversations/{chat.id}/view",
            headers=headers,
            json={
                "draft": "unsent",
                "skill_name": "eforge-scenario",
                "follow_bottom": False,
                "anchor": {"turn_id": "old", "item_id": "last", "offset": -24},
                "answers": {
                    "7": {
                        "secret:text": "DO-NOT-RETAIN",
                        "secret:choice": "__other",
                        "ordinary:text": "chosen",
                    }
                },
            },
        )
        assert response.status_code == 200
        saved = service.store.chat.control(chat.id).view
        assert saved.draft == "unsent" and saved.anchor.offset == -24
        assert "DO-NOT-RETAIN" not in saved.model_dump_json()
        assert saved.answers["7"] == {"ordinary:text": "chosen"}
        response = client.put(
            "/v1/chat/preferences",
            headers=headers,
            json={"workspace": str(service.settings.workspace), "sidebar_collapsed": True},
        )
        assert response.status_code == 200
        assert client.get("/v1/chat/preferences", headers=headers).json()["sidebar_collapsed"]


@pytest.mark.asyncio
async def test_result_links_exclude_files_outside_the_permitted_source(
    studio: StudioService,
) -> None:
    chat = conversation(studio)
    source = chat.draft_path
    source.write_text("name: revised\n", encoding="utf-8")
    outside = studio.settings.workspace / "unrelated.txt"
    outside.write_text("unrelated", encoding="utf-8")
    turn = studio.store.chat.turns(chat.id)[0]
    turn.status = "completed"
    turn.items = [
        {
            "id": "edit",
            "type": "fileChange",
            "status": "completed",
            "changes": [
                {"path": str(outside), "diff": "must not link"},
                {"path": str(source), "diff": "recorded diff"},
            ],
        }
    ]
    studio.store.chat.save_turn(turn)
    await studio.chat.finish_results(chat, turn.id)
    assert [result.path for result in studio.store.chat.turns(chat.id)[0].results] == [str(source)]


def test_restart_holds_queued_and_uncertain_claims(studio: StudioService) -> None:
    from evidenceforge.studio.chat import ChatRuntime
    from evidenceforge.studio.state_records_v3 import ChatInput

    chat = conversation(studio, active=False)
    studio.store.chat.save_input(
        ChatInput(
            id="pending", conversation_id=chat.id, text="Next", mode="queue", created_at=time.time()
        )
    )
    studio.store.chat.save_input(
        ChatInput(
            id="claimed",
            conversation_id=chat.id,
            text="Lost",
            mode="start",
            state="dispatching",
            created_at=time.time(),
        )
    )
    restarted = ChatRuntime(studio)
    assert restarted.store.control(chat.id).queue_paused
    assert restarted.store.input("claimed").state == "uncertain"


@pytest.mark.asyncio
async def test_rejected_rpc_can_be_explicitly_retried_without_replaying_acceptance(
    studio: StudioService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.studio.codex import CodexUnavailableError

    chat = conversation(studio)
    calls = 0

    async def call(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise CodexUnavailableError("Codex turn/steer: Invalid request")
        return {"turnId": "turn-1"}

    monkeypatch.setattr(studio.codex, "call", call)
    request = ChatMessageRequest(
        message_id="retry", text="Guidance", mode="steer", expected_turn_id="turn-1"
    )
    with pytest.raises(HTTPException):
        await studio.chat.send(chat, request)
    assert studio.store.chat.input("retry").state == "rejected"
    assert (await studio.chat.send(chat, request)).state == "accepted"
    assert (await studio.chat.send(chat, request)).state == "accepted"
    assert calls == 2


@pytest.mark.asyncio
async def test_interrupt_waits_for_a_pending_turn_id(
    studio: StudioService, monkeypatch: pytest.MonkeyPatch
) -> None:
    chat = conversation(studio, active=False)
    chat.active = True
    studio.store.save_conversation(chat)
    studio.chat.before_submit(chat, chat.draft_path)
    calls: list[dict[str, Any]] = []

    async def call(method: str, params: dict[str, Any], *, timeout: float = 30) -> dict[str, Any]:
        assert method == "turn/interrupt"
        calls.append(params)
        return {}

    monkeypatch.setattr(studio.codex, "call", call)
    pending = asyncio.create_task(studio.chat.interrupt(chat))
    await asyncio.sleep(0)
    assert not calls
    studio.chat.bind_turn(chat, {"id": "pending-turn", "status": "inProgress"})
    await pending
    assert calls == [{"threadId": "thread", "turnId": "pending-turn"}]


@pytest.mark.asyncio
async def test_idle_health_during_submission_does_not_abandon_its_turn(
    studio: StudioService,
) -> None:
    chat = conversation(studio)
    await studio.reconcile_codex_thread(chat, {"thread": {"status": {"type": "idle"}}})
    assert studio.store.conversation(chat.id).active
    assert studio.chat.active_id(chat.id) == "turn-1"
    studio.chat.starting.discard(chat.id)
    await studio.reconcile_codex_thread(chat, {"thread": {"status": {"type": "idle"}}})
    assert not studio.store.conversation(chat.id).active
    assert studio.chat.active_id(chat.id) is None


def test_partial_terminal_history_retains_item_order_and_native_final_payload(
    studio: StudioService,
) -> None:
    chat = conversation(studio)
    turn = studio.store.chat.turns(chat.id)[0]
    turn.items = [
        {"id": "progress", "type": "agentMessage", "text": "Started"},
        {"id": "tool", "type": "commandExecution", "command": "eforge info"},
        {"id": "final", "type": "agentMessage", "text": "Done"},
    ]
    studio.store.chat.save_turn(turn)
    history = {
        "thread": {
            "turns": [
                {
                    "id": "turn-1",
                    "status": "completed",
                    "items": [
                        {"id": "progress", "type": "agentMessage", "text": "Started"},
                        {
                            "id": "final",
                            "type": "agentMessage",
                            "phase": "final_answer",
                            "text": "Done completely",
                        },
                    ],
                }
            ]
        }
    }
    snapshot = studio.chat.snapshot(chat, history)
    assert [item["id"] for item in snapshot.turns[0].items] == ["progress", "tool", "final"]
    assert snapshot.turns[0].items[-1]["text"] == "Done completely"
    assert studio.chat.snapshot(chat, history).turns == snapshot.turns


@pytest.mark.asyncio
async def test_resolved_server_request_clears_actionable_questions(studio: StudioService) -> None:
    chat = conversation(studio)
    chat.needs_attention = True
    studio.store.save_conversation(chat)
    studio.pending_codex_requests[42] = {"params": {"threadId": "thread", "questions": []}}
    await studio._codex_event("serverRequest/resolved", {"requestId": 42, "threadId": "thread"})
    assert not studio.pending_codex_requests
    assert not studio.store.conversation(chat.id).needs_attention


def test_message_setup_timeout_is_rejected_before_turn_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(tmp_path / "workspace"))
    app = create_app(paths(tmp_path / "private"), "secret")

    async def call(method: str, params: dict[str, Any], *, timeout: float = 30) -> dict[str, Any]:
        raise CodexTimeoutError("Setup timed out")

    monkeypatch.setattr(app.state.studio.codex, "call", call)
    with TestClient(app) as client:
        studio = app.state.studio
        chat = conversation(studio, active=False)
        chat.draft_kind = None  # Exercise the existing legacy source discussion path.
        studio.store.save_conversation(chat)
        response = client.post(
            f"/v1/conversations/{chat.id}/messages",
            headers={"X-EForge-Token": "secret"},
            json={"message_id": "not-started", "text": "Review", "mode": "start"},
        )
        assert response.status_code == 503
        assert studio.store.chat.input("not-started").state == "rejected"
        assert not studio.store.conversation(chat.id).active


def test_fake_app_server_dispatches_fifo_and_holds_work_across_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json
    import sys
    import textwrap

    fake = tmp_path / "fake-codex"
    calls = tmp_path / "calls.jsonl"
    fake.write_text(
        "#!"
        + sys.executable
        + "\n"
        + textwrap.dedent(
            f"""
            import json, sys
            calls = open({str(calls)!r}, 'a', encoding='utf-8')
            turns = []
            for line in sys.stdin:
                request = json.loads(line)
                if 'id' not in request:
                    continue
                calls.write(json.dumps(request) + '\\n')
                calls.flush()
                method, params = request['method'], request['params']
                result = {{}}
                if method == 'account/read':
                    result = {{'account': {{'type': 'chatgpt'}}}}
                elif method == 'model/list':
                    result = {{'data': [{{'id': 'fake', 'isDefault': True}}]}}
                elif method == 'config/read':
                    result = {{'layers': []}}
                elif method in ('thread/start', 'thread/resume'):
                    result = {{'thread': {{'id': 'thread'}}, 'cwd': params['cwd'],
                        'approvalPolicy': 'never', 'sandbox': {{'type': 'readOnly',
                        'networkAccess': False, 'writableRoots': [],
                        'excludeTmpdirEnvVar': True, 'excludeSlashTmp': True}}}}
                elif method == 'thread/read':
                    active = any(turn['status'] == 'inProgress' for turn in turns)
                    result = {{'thread': {{'id': 'thread', 'turns': turns,
                        'status': {{'type': 'active' if active else 'idle'}}}}}}
                elif method == 'turn/start':
                    client_id = params['clientUserMessageId']
                    turn = {{'id': 'native-' + client_id, 'status': 'inProgress',
                        'items': [{{'id': 'user-' + client_id, 'type': 'userMessage',
                        'clientId': client_id, 'content': params['input']}}]}}
                    turns.append(turn)
                    print(json.dumps({{'method': 'turn/started', 'params':
                        {{'threadId': 'thread', 'turn': turn}}}}), flush=True)
                    result = {{'turn': turn}}
                elif method in ('turn/steer', 'turn/interrupt'):
                    turn = turns[-1]
                    key = 'expectedTurnId' if method == 'turn/steer' else 'turnId'
                    if params.get(key) != turn['id'] or params.get('threadId') != 'thread':
                        print(json.dumps({{'id': request['id'], 'error':
                            {{'code': -32602, 'message': 'Invalid turn identity'}}}}), flush=True)
                        continue
                    turn['status'] = 'completed' if method == 'turn/steer' else 'interrupted'
                    turn['items'].append({{'id': 'done-' + turn['id'], 'type': 'agentMessage',
                        'phase': 'final_answer', 'text': 'Done'}})
                    print(json.dumps({{'method': 'turn/completed', 'params':
                        {{'threadId': 'thread', 'turn': turn}}}}), flush=True)
                    result = {{'turnId': turn['id']}}
                print(json.dumps({{'id': request['id'], 'result': result}}), flush=True)
            """
        ),
        encoding="utf-8",
    )
    fake.chmod(0o755)
    monkeypatch.setenv("EFORGE_DESKTOP_CODEX_BIN", str(fake))
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(tmp_path / "workspace"))
    private = paths(tmp_path / "private")
    app = create_app(private, "secret")
    headers = {"X-EForge-Token": "secret"}
    with TestClient(app) as client:
        studio = app.state.studio
        chat = conversation(studio, active=False)
        chat.draft_kind = None  # Exercise the existing legacy source discussion path.
        studio.store.save_conversation(chat)
        base = f"/v1/conversations/{chat.id}"
        response = client.post(
            base + "/messages",
            headers=headers,
            json={"message_id": "first", "text": "First", "mode": "start"},
        )
        assert response.status_code == 200, response.text
        assert response.json()["turn_id"] == "native-first"
        for identity in ("second", "third"):
            response = client.post(
                base + "/messages",
                headers=headers,
                json={"message_id": identity, "text": identity, "mode": "queue"},
            )
            assert response.json()["state"] == "queued"
        assert (
            client.patch(
                base + "/messages/third", headers=headers, json={"text": "Edited third"}
            ).status_code
            == 200
        )
        assert client.delete(base + "/messages/second", headers=headers).status_code == 200
        response = client.post(
            base + "/messages",
            headers=headers,
            json={
                "message_id": "guidance",
                "text": "Finish",
                "mode": "steer",
                "expected_turn_id": "native-first",
            },
        )
        assert response.status_code == 200, response.text
        deadline = time.monotonic() + 5
        while studio.store.chat.input("third").state != "accepted" and time.monotonic() < deadline:
            time.sleep(0.01)
        assert studio.store.chat.input("third").state == "accepted"
        assert studio.chat.active_id(chat.id) == "native-third"
        duplicate = client.post(
            base + "/messages",
            headers=headers,
            json={"message_id": "third", "text": "Edited third", "mode": "queue"},
        )
        assert duplicate.json()["state"] == "accepted"
        assert client.post(base + "/interrupt", headers=headers).status_code == 200
        client.post(
            base + "/messages",
            headers=headers,
            json={"message_id": "held", "text": "Held next", "mode": "queue"},
        )
        assert studio.store.chat.control(chat.id).queue_paused
    app = create_app(private, "secret")
    with TestClient(app) as client:
        studio = app.state.studio
        snapshot = client.get(base + "/chat", headers=headers)
        assert snapshot.json()["queue_paused"]
        assert studio.store.chat.input("held").state == "queued"
        records = [json.loads(line) for line in calls.read_text().splitlines()]
        assert [
            row["params"]["clientUserMessageId"] for row in records if row["method"] == "turn/start"
        ] == ["first", "third"]
        assert client.post(base + "/queue/resume", headers=headers).status_code == 200
        deadline = time.monotonic() + 5
        while studio.store.chat.input("held").state != "accepted" and time.monotonic() < deadline:
            time.sleep(0.01)
        assert studio.store.chat.input("held").state == "accepted"
        assert (
            client.patch(
                base + "/messages/held", headers=headers, json={"text": "Too late"}
            ).status_code
            == 409
        )
        assert client.delete(base + "/messages/held", headers=headers).status_code == 409
    records = [json.loads(line) for line in calls.read_text().splitlines()]
    turns = [row for row in records if row["method"] == "turn/start"]
    assert [row["params"]["clientUserMessageId"] for row in turns] == ["first", "third", "held"]
    assert turns[1]["params"]["input"] == [{"type": "text", "text": "Edited third"}]
    assert all(row["params"]["sandboxPolicy"]["type"] == "readOnly" for row in turns)


def test_concurrent_draft_saves_cannot_clear_a_queue_hold(studio: StudioService) -> None:
    from concurrent.futures import ThreadPoolExecutor

    from evidenceforge.studio.state_records_v3 import ChatViewState

    chat = conversation(studio, active=False)

    def save_drafts() -> None:
        for index in range(40):
            studio.store.chat.update_control(chat.id, view=ChatViewState(draft=f"Draft {index}"))

    def hold_queue() -> None:
        for _ in range(40):
            studio.store.chat.update_control(chat.id, queue_paused=True)

    with ThreadPoolExecutor(max_workers=2) as pool:
        tasks = [pool.submit(save_drafts), pool.submit(hold_queue)]
        for task in tasks:
            task.result(timeout=5)
    control = studio.store.chat.control(chat.id)
    assert control.queue_paused
    assert control.view.draft == "Draft 39"
