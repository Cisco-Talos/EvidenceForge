"""Studio chat lifecycle, durable follow-ups and source-native transcript snapshots."""

from __future__ import annotations

import asyncio
import difflib
import hashlib
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.studio.chat_permissions import chat_access
from evidenceforge.studio.chat_results import (
    ChatTurnSummary,
    recorded_changes,
    result_path,
    source_text,
    summarize_turn,
)
from evidenceforge.studio.codex import (
    CodexDisconnectedError,
    CodexTimeoutError,
    CodexUnavailableError,
)
from evidenceforge.studio.state_records_v3 import (
    ChatInput,
    ChatResult,
    ChatTurn,
    ChatViewState,
)

if TYPE_CHECKING:
    from evidenceforge.studio.service import StudioService
    from evidenceforge.studio.store import Conversation

TERMINAL = {"completed", "failed", "interrupted"}
ChatSubmit = Callable[[str, ChatInput], Awaitable[dict[str, Any]]]


class ChatMessageRequest(BaseModel):
    """Explicit delivery intent and a stable client dispatch identity."""

    model_config = ConfigDict(extra="forbid")
    message_id: str = Field(min_length=1, max_length=128)
    text: str = Field(min_length=1)
    mode: Literal["start", "queue", "steer"] = "start"
    skill_name: str | None = None
    expected_turn_id: str | None = None


class ChatQueuedUpdate(BaseModel):
    """An edit only applies to messages that have not been dispatched."""

    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1)
    skill_name: str | None = None


class ChatSnapshot(BaseModel):
    """A cursor-consistent timeline plus private per-conversation state."""

    model_config = ConfigDict(extra="forbid")
    conversation_id: str
    seq: int
    turns: list[ChatTurnSummary]
    queue: list[ChatInput]
    queue_paused: bool
    active_turn_id: str | None
    view: ChatViewState
    history_pending: bool = False


class ChatResultContent(BaseModel):
    """Verified source contents and an optional recorded change diff."""

    path: str
    text: str
    diff: str | None = None
    item_id: str | None = None


def file_digest(path: Path) -> str | None:
    """Fingerprint source bytes without buffering an entire authored file."""
    try:
        with path.open("rb") as source:
            return hashlib.file_digest(source, "sha256").hexdigest()
    except (OSError, ValueError):
        return None


def merge_items(
    observed: list[dict[str, Any]], native: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Replace native payloads while preserving the order of already observed items."""
    replacements = {item["id"]: item for item in native if isinstance(item.get("id"), str)}
    result = [{**item, **replacements.get(item.get("id"), {})} for item in observed]
    known = {item.get("id") for item in observed}
    for position, item in enumerate(native):
        identity = item.get("id")
        if identity in known:
            continue
        following = {entry.get("id") for entry in native[position + 1 :]}
        insertion = next(
            (index for index, entry in enumerate(result) if entry.get("id") in following),
            len(result),
        )
        result.insert(insertion, item)
        known.add(identity)
    return result


class ChatRuntime:
    """Own turn identities and single-dispatch follow-ups independently of mounted views."""

    def __init__(self, studio: StudioService) -> None:
        self.studio = studio
        self.store = studio.store.chat
        self.locks: dict[str, asyncio.Lock] = {}
        self.ready: dict[str, asyncio.Event] = {}
        self.starting: set[str] = set()
        self.pending_sources: dict[str, tuple[str, str | None, float, str | None]] = {}
        self.pending_source_turns: dict[str, str] = {}
        self.tasks: set[asyncio.Task[None]] = set()
        self.submit: ChatSubmit | None = None
        # Retained claims are held on startup; a lost response is never resent automatically.
        for conversation in studio.store.conversations_all():
            entries = self.store.inputs(conversation.id)
            for entry in entries:
                if entry.state == "dispatching":
                    entry.state = "uncertain"
                    self.store.save_input(entry)
            if any(entry.state in {"queued", "dispatching", "uncertain"} for entry in entries):
                self.pause(conversation.id)

    def lock(self, conversation_id: str) -> asyncio.Lock:
        """Serialize send, edit, removal and automatic dispatch for a conversation."""
        return self.locks.setdefault(conversation_id, asyncio.Lock())

    def pause(self, conversation_id: str) -> None:
        """Keep queued work until explicit user resumption."""
        self.store.update_control(conversation_id, queue_paused=True)

    def pause_workspace(self, workspace: Path) -> None:
        """Hold all queued work when its workspace/window leaves the foreground."""
        for conversation in self.studio.store.conversations(workspace):
            self.pause(conversation.id)

    def active_id(self, conversation_id: str) -> str | None:
        """Return the retained identity only while its conversation remains active."""
        conversation = self.studio.store.conversation(conversation_id)
        if conversation is None or not conversation.active:
            return None
        return next(
            (
                turn.id
                for turn in reversed(self.store.turns(conversation_id))
                if turn.status not in TERMINAL
            ),
            None,
        )

    def before_submit(self, conversation: Conversation, source: Path) -> None:
        """Capture the owning source once before inference begins."""
        before = source_text(source)
        digest = (
            hashlib.sha256(before.encode()).hexdigest()
            if before is not None
            else file_digest(source)
        )
        self.pending_sources[conversation.id] = (str(source), digest, time.time(), before)
        self.pending_source_turns.pop(conversation.id, None)
        self.ready[conversation.id] = asyncio.Event()
        self.starting.add(conversation.id)

    def bind_turn(self, conversation: Conversation, native: dict[str, Any]) -> ChatTurn | None:
        """Bind an RPC/notification identity without resurrecting a completed turn."""
        identity = native.get("id")
        if not isinstance(identity, str) or not identity:
            return None
        turn = next(
            (entry for entry in self.store.turns(conversation.id) if entry.id == identity), None
        )
        if turn is None:
            source, digest, observed, _before = self.pending_sources.get(
                conversation.id, (None, None, time.time(), None)
            )
            if conversation.id in self.pending_sources:
                self.pending_source_turns[conversation.id] = identity
            turn = ChatTurn(
                id=identity,
                conversation_id=conversation.id,
                thread_id=conversation.thread_id or "",
                started_at=observed,
                source_path=source,
                source_sha256=digest,
            )
        if turn.status not in TERMINAL:
            turn.status = str(
                native.get("status") or ("inProgress" if conversation.active else "completed")
            )
        for key, attribute in (
            ("startedAt", "started_at"),
            ("completedAt", "completed_at"),
            ("durationMs", "duration_ms"),
        ):
            value = native.get(key)
            if isinstance(value, (int, float)):
                setattr(turn, attribute, value)
        if native.get("status") in TERMINAL and "error" in native:
            turn.error = native["error"] if isinstance(native["error"], dict) else None
        elif isinstance(native.get("error"), dict):
            turn.error = native["error"]
        if turn.status in TERMINAL:
            turn.completed_at = turn.completed_at or time.time()
            if turn.duration_ms is None and turn.started_at is not None:
                turn.duration_ms = max(0, (turn.completed_at - turn.started_at) * 1000)
        self.store.save_turn(turn)
        if (
            turn.status in TERMINAL
            and turn.status != "completed"
            and self.pending_source_turns.get(conversation.id) == identity
        ):
            self.pending_sources.pop(conversation.id, None)
            self.pending_source_turns.pop(conversation.id, None)
        self.ready.setdefault(conversation.id, asyncio.Event()).set()
        return turn

    def observe(self, conversation: Conversation, method: str, params: dict[str, Any]) -> None:
        """Fold each notification once before publishing its replay cursor."""
        native = params.get("turn")
        identity = native.get("id") if isinstance(native, dict) else params.get("turnId")
        if not isinstance(identity, str):
            identity = self.active_id(conversation.id)
        if not identity:
            return
        turn = self.bind_turn(conversation, {"id": identity})
        if turn is None:
            return
        if method in {"turn/started", "turn/completed"} and isinstance(native, dict):
            turn = self.bind_turn(conversation, native) or turn
            if method == "turn/completed":
                turn.status = str(native.get("status") or "completed")
                turn.completed_at = turn.completed_at or time.time()
                turn.duration_ms = (
                    turn.duration_ms
                    if turn.duration_ms is not None
                    else max(0, (turn.completed_at - (turn.started_at or turn.completed_at)) * 1000)
                )
                if turn.status != "completed":
                    self.pause(conversation.id)
        elif method in {"item/started", "item/completed"}:
            item = params.get("item")
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                index = next(
                    (i for i, old in enumerate(turn.items) if old.get("id") == item["id"]), -1
                )
                previous = turn.items[index] if index >= 0 else {}
                merged = {
                    **previous,
                    **item,
                    "status": item.get("status")
                    or ("completed" if method == "item/completed" else "inProgress"),
                }
                if index < 0:
                    turn.items.append(merged)
                else:
                    turn.items[index] = merged
        elif method.startswith("item/") and "delta" in method.lower():
            item_id = params.get("itemId")
            if isinstance(item_id, str):
                item = next((old for old in turn.items if old.get("id") == item_id), None)
                if item is None:
                    kind = (
                        "agentMessage"
                        if "agentMessage" in method
                        else ("reasoning" if "reasoning" in method else "commandExecution")
                    )
                    item = {"id": item_id, "type": kind, "status": "inProgress"}
                    turn.items.append(item)
                delta = str(params.get("delta") or "")
                if "summaryTextDelta" in method:
                    index = params.get("summaryIndex", 0)
                    if isinstance(index, int) and 0 <= index <= 100:
                        summary = list(item.get("summary") or [])
                        while len(summary) <= index:
                            summary.append("")
                        summary[index] += delta
                        item["summary"] = summary
                elif "agentMessage" in method:
                    item["text"] = str(item.get("text") or "") + delta
                elif "outputDelta" in method:
                    item["aggregatedOutput"] = (str(item.get("aggregatedOutput") or "") + delta)[
                        -262144:
                    ]
        elif method == "error" and params.get("willRetry") is False:
            turn.error = params.get("error") if isinstance(params.get("error"), dict) else None
        self.store.save_turn(turn)
        item = params.get("item")
        if isinstance(item, dict) and item.get("type") == "userMessage":
            self.reconcile_inputs([turn], conversation.id)

    def abandon(self, conversation_id: str) -> None:
        """Retire process-bound identities on confirmed abandonment."""
        self.pause(conversation_id)
        self.pending_sources.pop(conversation_id, None)
        self.pending_source_turns.pop(conversation_id, None)
        for turn in self.store.turns(conversation_id):
            if turn.status not in TERMINAL:
                turn.status = "interrupted"
                turn.completed_at = time.time()
                turn.duration_ms = max(
                    0, (turn.completed_at - (turn.started_at or turn.completed_at)) * 1000
                )
                self.store.save_turn(turn)
        self.ready.setdefault(conversation_id, asyncio.Event()).set()

    async def interrupt(self, conversation: Conversation) -> None:
        """Wait briefly for start identity, then send the exact cancellation precondition."""
        self.pause(conversation.id)
        identity = self.active_id(conversation.id)
        if not identity and conversation.active:
            try:
                await asyncio.wait_for(
                    self.ready.setdefault(conversation.id, asyncio.Event()).wait(), 2
                )
            except TimeoutError:
                pass
            identity = self.active_id(conversation.id)
        current = self.studio.store.conversation(conversation.id)
        if current is None or not current.active:
            return
        if not identity or not current.thread_id:
            raise CodexUnavailableError(
                "The active turn ID is not available yet. Try Stop again shortly."
            )
        await self.studio.codex.call(
            "turn/interrupt", {"threadId": current.thread_id, "turnId": identity}, timeout=5
        )

    def reconcile_inputs(self, turns: list[ChatTurn], conversation_id: str) -> None:
        """Use native client IDs to resolve lost responses without repeating inference."""
        for entry in self.store.inputs(conversation_id):
            if entry.state not in {"uncertain", "dispatching"}:
                continue
            match = next(
                (
                    turn
                    for turn in turns
                    if any(
                        item.get("type") == "userMessage" and item.get("clientId") == entry.id
                        for item in turn.items
                    )
                ),
                None,
            )
            if match:
                entry.state, entry.turn_id, entry.error = "accepted", match.id, None
                self.store.save_input(entry)

    def snapshot(self, conversation: Conversation, history: dict[str, Any]) -> ChatSnapshot:
        """Merge immutable history with cursor-consistent live materializations."""
        saved = {turn.id: turn for turn in self.store.turns(conversation.id)}
        result: list[ChatTurn] = []
        thread = history.get("thread", {})
        natives = thread.get("turns", []) if isinstance(thread, dict) else []
        for native in natives if isinstance(natives, list) else []:
            if not isinstance(native, dict) or not isinstance(native.get("id"), str):
                continue
            existing = saved.pop(native["id"], None)
            turn = existing or ChatTurn(
                id=native["id"],
                conversation_id=conversation.id,
                thread_id=conversation.thread_id or "",
            )
            if existing is None or native.get("status") in TERMINAL:
                if isinstance(native.get("items"), list) and native["items"]:
                    native_items = [item for item in native["items"] if isinstance(item, dict)]
                    # Completed item payloads replace deltas; retain native-missing items.
                    turn.items = merge_items(turn.items, native_items)
                turn.status = str(native.get("status") or turn.status)
                for key, attribute in (
                    ("startedAt", "started_at"),
                    ("completedAt", "completed_at"),
                    ("durationMs", "duration_ms"),
                ):
                    if isinstance(native.get(key), (int, float)):
                        setattr(turn, attribute, native[key])
                if isinstance(native.get("error"), dict):
                    turn.error = native["error"]
                self.store.save_turn(turn)
            result.append(turn)
        result.extend(saved.values())
        self.reconcile_inputs(result, conversation.id)
        control = self.store.control(conversation.id)
        directories: dict[str, Path | None] = {}
        sizes: dict[Path, tuple[int | None, int | None, int | None]] = {}
        presented: list[ChatTurnSummary] = []
        for turn in result:
            source = turn.source_path
            if source and source not in directories:
                try:
                    directories[source] = chat_access(Path(source)).directory
                except (OSError, ValueError, EvidenceForgeError):
                    directories[source] = None
            presented.append(summarize_turn(turn, directories.get(source or ""), sizes))
        return ChatSnapshot(
            conversation_id=conversation.id,
            seq=self.studio.store.latest_seq(),
            turns=presented,
            queue=[
                entry
                for entry in self.store.inputs(conversation.id)
                if entry.state in {"queued", "dispatching", "uncertain"}
            ],
            queue_paused=control.queue_paused,
            active_turn_id=self.active_id(conversation.id),
            view=control.view,
            history_pending=bool(history.get("history_pending")),
        )

    async def send(self, conversation: Conversation, request: ChatMessageRequest) -> ChatInput:
        """Claim a message exactly once and honor its explicit delivery intent."""
        async with self.lock(conversation.id):
            existing = self.store.input(request.message_id)
            if existing:
                if (
                    existing.conversation_id != conversation.id
                    or existing.text != request.text
                    or existing.mode != request.mode
                ):
                    raise HTTPException(409, "This message ID has already been used")
                if existing.state != "rejected":
                    return existing
            entry = ChatInput(
                id=request.message_id,
                conversation_id=conversation.id,
                text=request.text,
                mode=request.mode,
                skill_name=request.skill_name,
                expected_turn_id=request.expected_turn_id,
                created_at=time.time(),
            )
            current = self.studio.store.conversation(conversation.id) or conversation
            control = self.store.control(conversation.id)
            if request.mode == "steer":
                if (
                    not request.expected_turn_id
                    or self.active_id(current.id) != request.expected_turn_id
                ):
                    raise HTTPException(
                        409, "The active turn changed. Your message has not been sent."
                    )
            elif request.mode == "start" and current.active:
                raise HTTPException(409, "This conversation has an active turn")
            if any(
                other.state in {"dispatching", "uncertain"}
                for other in self.store.inputs(current.id)
            ):
                raise HTTPException(409, "An earlier message is still being reconciled")
            if request.mode == "steer" and request.skill_name:
                raise HTTPException(400, "Choose skills when starting a new turn")
            self.store.save_input(entry)
            if request.mode == "queue" and (
                current.active
                or control.queue_paused
                or any(
                    other.id != entry.id and other.state == "queued"
                    for other in self.store.inputs(current.id)
                )
            ):
                await self.studio.emit(current.id, "chat.updated", {})
                return entry
            return await self._dispatch(current, entry)

    async def _dispatch(self, conversation: Conversation, entry: ChatInput) -> ChatInput:
        entry.state = "dispatching"
        self.store.save_input(entry)
        try:
            if entry.mode == "steer":
                result = await self.studio.codex.call(
                    "turn/steer",
                    {
                        "threadId": conversation.thread_id,
                        "expectedTurnId": entry.expected_turn_id,
                        "clientUserMessageId": entry.id,
                        "input": [{"type": "text", "text": entry.text}],
                    },
                )
                entry.turn_id = str(result.get("turnId") or entry.expected_turn_id)
            else:
                if self.submit is None:
                    raise HTTPException(503, "Chat submission is unavailable")
                result = await self.submit(conversation.id, entry)
                entry.turn_id = result.get("turn_id")
                if result.get("delivery") == "uncertain":
                    entry.state = "uncertain"
            if entry.state != "uncertain":
                entry.state = "accepted"
        except HTTPException as error:
            entry.error = str(error.detail)
            uncertain = (
                error.status_code == 503
                and (error.headers or {}).get("X-EForge-Delivery") != "rejected"
            )
            entry.state = (
                "uncertain" if uncertain else ("queued" if entry.mode == "queue" else "rejected")
            )
            self.pause(conversation.id)
            self.store.save_input(entry)
            raise
        except CodexUnavailableError as error:
            entry.error = str(error)
            entry.state = (
                "uncertain"
                if isinstance(error, (CodexTimeoutError, CodexDisconnectedError))
                else "rejected"
            )
            self.pause(conversation.id)
            self.store.save_input(entry)
            raise HTTPException(503, str(error)) from error
        self.store.save_input(entry)
        if entry.state == "uncertain":
            self.pause(conversation.id)
        await self.studio.emit(conversation.id, "chat.updated", {})
        current = self.studio.store.conversation(conversation.id)
        if current and not current.active and entry.state == "accepted":
            self.schedule_queue(conversation.id)
        return entry

    def schedule_queue(self, conversation_id: str) -> None:
        """Do not block the Codex notification dispatcher behind a new turn RPC."""
        task = asyncio.create_task(self.dispatch_queue(conversation_id))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def dispatch_queue(self, conversation_id: str) -> None:
        """Drain one FIFO message after success; terminal events trigger the next."""
        async with self.lock(conversation_id):
            conversation = self.studio.store.conversation(conversation_id)
            if (
                conversation is None
                or conversation.active
                or conversation.workspace != self.studio.settings.workspace
                or self.store.control(conversation_id).queue_paused
                or self.submit is None
            ):
                return
            entries = self.store.inputs(conversation_id)
            if any(entry.state in {"dispatching", "uncertain"} for entry in entries):
                return
            entry = next((entry for entry in entries if entry.state == "queued"), None)
            if entry:
                try:
                    await self._dispatch(conversation, entry)
                except HTTPException:
                    await self.studio.emit(conversation_id, "chat.updated", {})

    async def finish_results(self, conversation: Conversation, identity: str | None) -> None:
        """Retain verified source-local result links without interpreting agent prose."""
        if not identity:
            return
        turn = next(
            (turn for turn in self.store.turns(conversation.id) if turn.id == identity), None
        )
        if not turn or turn.status != "completed":
            return
        baseline = None
        if self.pending_source_turns.get(conversation.id) == identity:
            baseline = self.pending_sources.pop(conversation.id, None)
            self.pending_source_turns.pop(conversation.id, None)
        source = Path(turn.source_path) if turn.source_path else None
        if source is None:
            return
        try:
            access = chat_access(source)
        except (OSError, ValueError, EvidenceForgeError):
            return
        candidates: dict[Path, tuple[str, list[str]]] = {}
        for change in recorded_changes(turn.items):
            try:
                path = result_path(change.path, access.directory)
                previous = (
                    result_path(change.previous_path, access.directory)
                    if change.previous_path
                    else path
                )
            except (OSError, ValueError, EvidenceForgeError):
                continue
            prior_kind, patches = candidates.pop(previous, (change.operation, []))
            if path != previous:
                patches += candidates.pop(path, (change.operation, []))[1]
            kind = change.operation
            if kind in {"edited", "renamed"} and prior_kind in {"created", "renamed"}:
                kind = prior_kind
            if change.diff:
                patches.append(change.diff)
            candidates[path] = (kind, patches)
        if turn.source_sha256 != file_digest(source) and source.is_file():
            candidates.setdefault(source, ("edited" if turn.source_sha256 else "created", []))
            if (
                not candidates[source][1]
                and baseline
                and baseline[:2] == (str(source), turn.source_sha256)
                and baseline[3] is not None
                and (after := source_text(source)) is not None
            ):
                diff = "\n".join(
                    difflib.unified_diff(
                        baseline[3].splitlines(),
                        after.splitlines(),
                        fromfile=str(source),
                        tofile=str(source),
                        lineterm="",
                    )
                )
                if diff:
                    candidates[source][1].append(diff)
            if not candidates[source][1]:
                previous_diff = next(
                    (result.diff for result in turn.results if result.path == str(source)), None
                )
                if previous_diff:
                    candidates[source][1].append(previous_diff)
        results: list[ChatResult] = []
        catalog = self.studio.store.items(conversation.workspace)
        for path, (kind, patches) in candidates.items():
            if kind != "removed" and not path.is_file():
                continue
            item = next((item for item in catalog if item.path.resolve() == path), None)
            results.append(
                ChatResult(
                    id=hashlib.sha256(str(path).encode()).hexdigest()[:24],
                    path=str(path),
                    kind=kind,
                    diff="\n\n".join(patches) or None,
                    item_id=item.id if item else None,
                    item_kind=item.kind if item else None,
                )
            )
        turn.results = results
        self.store.save_turn(turn)
        await self.studio.emit(conversation.id, "chat.updated", {})

    async def close(self) -> None:
        """Cancel only queue workers owned by this source service."""
        for task in tuple(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
