"""Versioned loopback API and event stream for EvidenceForge Studio."""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import sqlite3
import subprocess
import tempfile
import time
import zipfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.background import BackgroundTask

from evidenceforge.cli.install_skills import install_chatgpt_skills, install_skills
from evidenceforge.desktop.controller import _delete_owned_complete, _delete_owned_incomplete
from evidenceforge.desktop.job_store import ControlIntent
from evidenceforge.desktop.jobs import _eforge_command
from evidenceforge.desktop.library import discover_packs, discover_scenarios
from evidenceforge.desktop.progress import GenerationProgress
from evidenceforge.desktop.skill_setup import skill_targets
from evidenceforge.desktop.state import GenerationJob
from evidenceforge.evaluation.models import QualityReport
from evidenceforge.studio.codex import (
    CodexClient,
    CodexThreadNotReadyError,
    CodexTimeoutError,
    CodexUnavailableError,
)
from evidenceforge.studio.jobs import (
    StudioJobStore,
    can_resume,
    controller_settings,
    job_summary,
    progress_signature,
    queue_studio_evaluation,
    queue_studio_generation,
    reconcile_jobs,
    suspend_generation,
)
from evidenceforge.studio.paths import StudioPaths, ensure_workspace, studio_paths
from evidenceforge.studio.settings import SettingsStore, StudioSettings
from evidenceforge.studio.store import (
    CatalogItem,
    Conversation,
    Project,
    SavedView,
    StudioEvent,
    StudioStore,
)


def _archive_stem(name: str) -> str:
    """Return a filesystem-safe scenario name for downloaded archives."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip(".-") or "scenario"


class ExportLocation(BaseModel):
    """Workspace-specific default folder for native Save dialogs."""

    model_config = ConfigDict(extra="forbid")

    directory: Path | None = None


def _bundle_contents_size(root: Path) -> int | None:
    """Sum regular file sizes in a bundle without following links."""
    if root.is_symlink() or not root.is_dir():
        return None
    total = 0
    for directory, children, names in os.walk(root, followlinks=False):
        children[:] = [name for name in children if not (Path(directory) / name).is_symlink()]
        for name in names:
            path = Path(directory) / name
            try:
                if not path.is_symlink() and path.is_file():
                    total += path.stat().st_size
            except OSError:
                continue
    return total


class WorkspaceSelection(BaseModel):
    """A requested local workspace switch."""

    model_config = ConfigDict(extra="forbid")

    path: Path


class GenerationRequest(BaseModel):
    """Inputs for one new GUI-owned generation."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    output_parent: Path | None = None
    checkpoint_hours: int | None = Field(default=None, ge=0)


class EvaluationRequest(BaseModel):
    """Request an evaluation for a completed generation."""

    model_config = ConfigDict(extra="forbid")

    generation_id: str


class ConversationRequest(BaseModel):
    """Create a conversation within a scenario, pack, or draft."""

    model_config = ConfigDict(extra="forbid")

    item_id: str | None = None
    draft_kind: Literal["scenario", "industry_pack", "organization_pack"] | None = None
    project_id: str | None = None
    name: str | None = Field(default=None, min_length=1, max_length=80)


class ConversationUpdate(BaseModel):
    """Preferences and title for one persistent conversation."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=80)
    model_id: str | None = None
    reasoning_effort: str | None = None
    draft_name: str | None = Field(default=None, min_length=1, max_length=80)
    draft_project_id: str | None = None


class TurnRequest(BaseModel):
    """One user message and an optional explicit skill for this turn."""

    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1)
    skill_name: str | None = None


class TurnSubmission(Conversation):
    """Conversation state plus Codex's identity for the submitted turn."""

    turn_id: str | None = None
    delivery: Literal["confirmed", "uncertain"] = "confirmed"


class CodexReply(BaseModel):
    """A user decision for a pending Codex server request."""

    model_config = ConfigDict(extra="forbid")

    request_id: int | str
    result: dict[str, Any]


class SkillInstallRequest(BaseModel):
    """Selected installer targets from Authoring & tools Settings."""

    model_config = ConfigDict(extra="forbid")

    scope: str
    agent: str


class CloseWindowRequest(BaseModel):
    """Explicit resolutions for destructive or non-checkpointable quit cases."""

    model_config = ConfigDict(extra="forbid")

    confirm_delete: bool = False
    generation_exceptions: dict[str, str] = Field(default_factory=dict)


class ItemUpdate(BaseModel):
    """Update virtual organization without changing source YAML."""

    model_config = ConfigDict(extra="forbid")

    hidden: bool | None = None
    folder: str | None = None
    project_id: str | None = None


class FolderRequest(BaseModel):
    """Create or rename a virtual library folder."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)


def clean_folder_name(value: str) -> str:
    """Keep virtual folder names distinct from filesystem paths."""
    name = value.strip()
    if not name or name in {".", ".."} or any(char in name for char in "/\\\n\r\x00"):
        raise HTTPException(
            status_code=400, detail="Use a short folder name without path separators"
        )
    return name


class ProjectRequest(BaseModel):
    """Create a workspace-local group of scenarios."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=240)


class ProjectUpdate(BaseModel):
    """Rename or describe an existing project."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=240)


class ValidationRequest(BaseModel):
    """Validate one indexed scenario through the deterministic CLI."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str


class ValidationResult(BaseModel):
    """Machine-readable CLI validation with its process status."""

    model_config = ConfigDict(extra="forbid")

    exit_code: int
    report: dict[str, Any] | None = None
    error: str = ""


class ResumeRequest(BaseModel):
    """Resume all paused jobs or one selected generation."""

    model_config = ConfigDict(extra="forbid")

    generation_id: str | None = None


class CodexHealth(BaseModel):
    """Current health of the GUI-owned Codex app-server transport."""

    model_config = ConfigDict(extra="forbid")

    state: Literal["checking", "connected", "stalled", "disconnected"] = "checking"
    detail: str = "Checking Codex connection"


class ValidationRecord(BaseModel):
    """The validation result for one authoritative source revision."""

    model_config = ConfigDict(extra="forbid")

    source_sha256: str
    completed_at: float
    result: ValidationResult


class JobScorecard(BaseModel):
    """Compact score extracted from an evaluation report on disk."""

    model_config = ConfigDict(extra="forbid")

    overall_score: float | None = None
    acceptance_passed: bool | None = None
    total_records: int | None = None
    evaluated_at: str | None = None
    error: str | None = None


class ScorecardSubscore(BaseModel):
    """One saved quality measure shown in the desktop scorecard."""

    model_config = ConfigDict(extra="forbid")

    name: str
    score: float | None
    details: str
    skipped: bool


class ScorecardPillar(BaseModel):
    """A quality pillar and its saved measures."""

    model_config = ConfigDict(extra="forbid")

    name: str
    score: float | None
    sub_scores: list[ScorecardSubscore]


class ScorecardCriterion(BaseModel):
    """One threshold decision from the saved evaluation."""

    model_config = ConfigDict(extra="forbid")

    name: str
    threshold: float
    actual: float | None
    passed: bool | None
    level: Literal["hard", "target"]


class ScorecardDetail(BaseModel):
    """Bounded, readable projection of an authoritative evaluation report."""

    model_config = ConfigDict(extra="forbid")

    scenario_name: str
    evaluated_at: str
    overall_score: float | None
    acceptance_passed: bool | None
    total_records: int
    source_counts: dict[str, int]
    pillars: list[ScorecardPillar]
    acceptance_criteria: list[ScorecardCriterion]
    flags: list[str]


class JobSummary(BaseModel):
    """Fields needed to restore a generation or evaluation card."""

    model_config = ConfigDict(extra="ignore")

    id: str
    kind: Literal["generation", "evaluation"]
    status: str
    status_message: str = ""
    scenario: Path | None = None
    generation_id: str | None = None
    output_root: Path
    progress: GenerationProgress | None = None
    started_at: float | None = None
    submitted_at: float | None = None
    created_at: float | None = None
    checkpoint_hours: int | None = None
    can_resume: bool = False
    source_sha256: str | None = None
    scorecard: JobScorecard | None = None


class StudioSnapshot(BaseModel):
    """Coherent service state used on first load and after event replay gaps."""

    model_config = ConfigDict(extra="forbid")

    seq: int
    settings: StudioSettings
    paths: StudioPaths
    items: list[CatalogItem]
    projects: list[Project]
    folders: list[str]
    views: list[SavedView]
    validations: dict[str, ValidationRecord]
    conversations: list[Conversation]
    codex_health: CodexHealth
    jobs: list[JobSummary]


class CodexReconnectRequest(BaseModel):
    """Explicitly acknowledge any active turns before replacing Codex."""

    model_config = ConfigDict(extra="forbid")

    interrupt_active: bool = False


class StudioService:
    """Own application state, job reconciliation, and connected clients."""

    def __init__(self, paths: StudioPaths, token: str) -> None:
        self.paths = paths
        self.token = token
        self.settings_store = SettingsStore(paths)
        self.settings = self.settings_store.load()
        self.settings.workspace = ensure_workspace(self.settings.workspace)
        self.settings_store.save(self.settings)
        self.store = StudioStore(paths.database_file)
        self.jobs = StudioJobStore(self.store, paths.state)
        saved_control = self.store.load_control()
        self.intent = (
            ControlIntent.model_validate(saved_control)
            if saved_control is not None
            else ControlIntent(action="open", settings=controller_settings(self.settings))
        )
        self.subscribers: set[asyncio.Queue[StudioEvent]] = set()
        self.job_task: asyncio.Task[None] | None = None
        self.codex_task: asyncio.Task[None] | None = None
        self.authoring_stop_task: asyncio.Task[None] | None = None
        self.authoring_stop_lock = asyncio.Lock()
        self.pending_codex_requests: dict[int | str, dict[str, Any]] = {}
        self.codex = CodexClient(self.settings.codex_path, self._codex_event, self._codex_request)
        self.codex_health = CodexHealth()
        self.codex_failures = 0
        self.codex_lock = asyncio.Lock()
        self._last_scan = time.monotonic()
        self._progress_signatures: dict[str, tuple[tuple[str, int, int], ...]] = {}

    async def start(self) -> None:
        """Index the selected workspace and start durable job reconciliation."""
        await self._clear_abandoned_turns(
            "Studio restarted before this Codex turn finished. Review its history before continuing."
        )
        await self.scan()
        self.job_task = asyncio.create_task(self._job_loop())
        self.codex_task = asyncio.create_task(self._monitor_codex())

    async def stop(self) -> None:
        """Stop service polling without touching detached CLI processes."""
        if self.authoring_stop_task is not None:
            self.authoring_stop_task.cancel()
            await asyncio.gather(self.authoring_stop_task, return_exceptions=True)
        if self.job_task is not None:
            self.job_task.cancel()
            try:
                await self.job_task
            except asyncio.CancelledError:
                pass
        if self.codex_task is not None:
            self.codex_task.cancel()
            try:
                await self.codex_task
            except asyncio.CancelledError:
                pass
        await self.codex.stop()
        self.store.close()

    async def _codex_event(self, method: str, params: dict[str, Any]) -> None:
        """Persist agent activity and keep conversation state current."""
        if method == "codex/connected":
            self.codex_failures = 0
            await self.set_codex_health("connected", "Codex is responding")
            return
        if method == "codex/disconnected":
            await self.set_codex_health("disconnected", "The Codex process exited")
            await self._clear_abandoned_turns(
                "The Codex connection ended during this turn. Review its history before continuing."
            )
            return
        thread_id = params.get("threadId")
        conversation = (
            self.store.conversation_for_thread(thread_id) if isinstance(thread_id, str) else None
        )
        if conversation is None:
            return
        await self.emit(conversation.id, "conversation.event", {"method": method, "params": params})
        if method == "turn/completed":
            conversation.active = False
            conversation.needs_attention = False
            turn = params.get("turn", {})
            turn_status = turn.get("status") if isinstance(turn, dict) else None
            if turn_status == "failed":
                conversation.connection_note = (
                    "Codex reported that this turn failed. Review its history before continuing."
                )
            elif turn_status == "interrupted":
                conversation.connection_note = (
                    "This Codex turn was interrupted. Review its history before continuing."
                )
            else:
                conversation.connection_note = None
            conversation.updated_at = time.time()
            self.store.save_conversation(conversation)
            await self.emit(
                conversation.id,
                "conversation.updated",
                json.loads(conversation.model_dump_json()),
            )
            await self.scan()
        elif method == "thread/name/updated" and isinstance(params.get("threadName"), str):
            conversation.title = params["threadName"]
            self.store.save_conversation(conversation)
            await self.emit(
                conversation.id,
                "conversation.updated",
                json.loads(conversation.model_dump_json()),
            )

    async def set_codex_health(
        self, state: Literal["checking", "connected", "stalled", "disconnected"], detail: str
    ) -> None:
        """Broadcast health transitions without filling the event log with heartbeat entries."""
        health = CodexHealth(state=state, detail=detail)
        if health == self.codex_health:
            return
        self.codex_health = health
        await self.emit("codex", "codex.health", health.model_dump())

    async def _monitor_codex(self) -> None:
        """Check the transport and reconcile turns even when no window is open."""
        while True:
            await self.check_codex_health()
            if (
                self.intent.action in {"continue", "pause", "kill"}
                and self.intent.authoring_turns == "stop"
            ):
                await self._interrupt_active_turns()
            await asyncio.sleep(8)

    def schedule_authoring_stop(self) -> None:
        """Begin the durable quit request without delaying the window close response."""
        if self.authoring_stop_task is None or self.authoring_stop_task.done():
            self.authoring_stop_task = asyncio.create_task(self._interrupt_active_turns())

    async def _interrupt_active_turns(self) -> None:
        """Request interruption for every active Studio conversation, retrying after failures."""
        async with self.authoring_stop_lock:
            for conversation in self.store.active_conversations():
                if not conversation.thread_id:
                    continue
                try:
                    await self.codex.call(
                        "turn/interrupt", {"threadId": conversation.thread_id}, timeout=5
                    )
                except CodexUnavailableError as error:
                    current = self.store.conversation(conversation.id)
                    if current is not None and current.active:
                        note = f"Could not stop this turn yet: {error}"
                        if current.connection_note != note:
                            current.connection_note = note
                            self.store.save_conversation(current)
                            await self.emit(
                                current.id,
                                "conversation.updated",
                                json.loads(current.model_dump_json()),
                            )

    async def check_codex_health(self) -> None:
        """Use bounded app-server requests to distinguish a stalled process from a live turn."""
        async with self.codex_lock:
            try:
                await self.codex.call("thread/loaded/list", {}, timeout=5)
                for conversation in self.store.active_conversations():
                    if conversation.thread_id is None:
                        continue
                    try:
                        result = await self.codex.call(
                            "thread/read",
                            {"threadId": conversation.thread_id, "includeTurns": False},
                            timeout=5,
                        )
                    except CodexThreadNotReadyError:
                        continue
                    await self.reconcile_codex_thread(conversation, result)
            except CodexTimeoutError as error:
                self.codex_failures += 1
                await self.set_codex_health("stalled", str(error))
            except CodexUnavailableError as error:
                self.codex_failures += 1
                await self.set_codex_health("disconnected", str(error))
            else:
                self.codex_failures = 0
                await self.set_codex_health("connected", "Codex is responding")

    async def reconcile_codex_thread(
        self, conversation: Conversation, result: dict[str, Any]
    ) -> None:
        """Reconcile saved turn state with Codex's authoritative thread status."""
        thread = result.get("thread", {})
        status = thread.get("status", {}) if isinstance(thread, dict) else {}
        status_type = status.get("type") if isinstance(status, dict) else None
        turns = thread.get("turns", []) if isinstance(thread, dict) else []
        last_turn = turns[-1] if isinstance(turns, list) and turns else {}
        last_turn_status = last_turn.get("status") if isinstance(last_turn, dict) else None
        changed = False
        if conversation.active and status_type in {"idle", "notLoaded", "systemError"}:
            conversation.active = False
            conversation.needs_attention = False
            conversation.connection_note = (
                "Codex is no longer working on this turn. Review its history before continuing."
            )
            changed = True
        if conversation.connection_note and last_turn_status == "completed":
            conversation.connection_note = None
            changed = True
        if changed:
            conversation.updated_at = time.time()
            self.store.save_conversation(conversation)
            await self.emit(
                conversation.id,
                "conversation.updated",
                json.loads(conversation.model_dump_json()),
            )

    async def _clear_abandoned_turns(
        self,
        note: str = "The Codex connection ended during this turn. Review its history before continuing.",
    ) -> None:
        """End turn flags when their owning Codex process no longer exists."""
        for request_id in self.pending_codex_requests:
            await self.emit("codex", "codex.input_cleared", {"request_id": request_id})
        self.pending_codex_requests.clear()
        for conversation in self.store.active_conversations():
            conversation.active = False
            conversation.needs_attention = False
            conversation.connection_note = note
            conversation.updated_at = time.time()
            self.store.save_conversation(conversation)
            await self.emit(
                conversation.id,
                "conversation.updated",
                json.loads(conversation.model_dump_json()),
            )

    async def _codex_request(
        self, request_id: int | str, method: str, params: dict[str, Any]
    ) -> None:
        """Park approvals and questions until the user answers in the window."""
        self.pending_codex_requests[request_id] = {"method": method, "params": params}
        thread_id = params.get("threadId")
        conversation = (
            self.store.conversation_for_thread(thread_id) if isinstance(thread_id, str) else None
        )
        if conversation is not None:
            conversation.needs_attention = True
            self.store.save_conversation(conversation)
            await self.emit(
                conversation.id,
                "conversation.updated",
                json.loads(conversation.model_dump_json()),
            )
        await self.emit(
            conversation.id if conversation is not None else "codex",
            "codex.input_requested",
            {"request_id": request_id, "method": method, "params": params},
        )

    async def _job_loop(self) -> None:
        while True:
            intent = self.intent
            changed = await asyncio.to_thread(reconcile_jobs, self.jobs, intent)
            if intent.action == "resume" and self.intent.id == intent.id:
                self.set_intent(
                    ControlIntent(action="open", settings=controller_settings(self.settings))
                )
            visible = self.store.job_payloads(self.settings.workspace)
            visible_ids = {payload["id"] for payload in visible}
            updates = {
                payload["id"]: payload for payload in changed if payload["id"] in visible_ids
            }
            for payload in visible:
                if "scenario" not in payload:
                    continue
                job = GenerationJob.model_validate(payload)
                signature = progress_signature(job)
                if self._progress_signatures.get(job.id) != signature:
                    updates[job.id] = payload
                    self._progress_signatures[job.id] = signature
            for payload in updates.values():
                await self.emit(payload["id"], "job.updated", job_summary(payload))
            if time.monotonic() - self._last_scan >= 10:
                await self.scan()
            await asyncio.sleep(0.75)

    async def emit(self, entity_id: str, kind: str, payload: dict[str, Any]) -> StudioEvent:
        """Commit and broadcast a state change."""
        event = self.store.publish(entity_id, kind, payload)
        for subscriber in tuple(self.subscribers):
            subscriber.put_nowait(event)
        return event

    def set_intent(self, intent: ControlIntent) -> None:
        """Persist a controller instruction before reporting handoff success."""
        self.store.save_control(intent)
        self.intent = intent

    async def scan(self) -> list[CatalogItem]:
        """Discover authoritative YAML without blocking the event loop."""
        workspace = self.settings.workspace
        before = self.store.items(workspace)

        def discover() -> list[CatalogItem]:
            items = [
                self.store.upsert_item(workspace, "scenario", source)
                for source in discover_scenarios(workspace, [])
            ]
            for kind, source_kind in (
                ("industry_pack", "industry"),
                ("organization_pack", "organization"),
            ):
                items.extend(
                    self.store.upsert_item(workspace, kind, source)
                    for source in discover_packs(workspace, source_kind)
                )
            return items

        items = await asyncio.to_thread(discover)
        by_source = {(item.kind, item.path.resolve()): item for item in items}
        for conversation in self.store.conversations(workspace):
            if (
                conversation.item_id
                or conversation.draft_path is None
                or conversation.draft_kind is None
            ):
                continue
            item = by_source.get((conversation.draft_kind, conversation.draft_path.resolve()))
            if item is None:
                continue
            if conversation.draft_project_id and item.kind == "scenario":
                project = self.store.project(conversation.draft_project_id)
                if project and project.workspace.resolve() == workspace.resolve():
                    item.project_id = project.id
                    self.store.save_item(item)
                    await self.emit(item.id, "item.updated", json.loads(item.model_dump_json()))
            conversation.item_id = item.id
            conversation.draft_kind = None
            conversation.draft_project_id = None
            self.store.save_conversation(conversation)
            await self.emit(
                conversation.id,
                "conversation.updated",
                json.loads(conversation.model_dump_json()),
            )
        self._last_scan = time.monotonic()
        if {item.id: item for item in items} != {item.id: item for item in before}:
            await self.emit(str(workspace), "library.refreshed", {"count": len(items)})
        return items

    def snapshot(self) -> dict[str, Any]:
        """Return a coherent view for first load and reconnection."""
        workspace = self.settings.workspace
        items = self.store.items(workspace)
        return {
            "seq": self.store.latest_seq(),
            "settings": json.loads(self.settings.model_dump_json()),
            "paths": json.loads(self.paths.model_dump_json()),
            "items": [json.loads(item.model_dump_json()) for item in items],
            "projects": [
                json.loads(project.model_dump_json()) for project in self.store.projects(workspace)
            ],
            "folders": self.store.folders(workspace),
            "views": [json.loads(view.model_dump_json()) for view in self.store.views(workspace)],
            "validations": self.store.validations([item.id for item in items]),
            "conversations": [
                json.loads(chat.model_dump_json()) for chat in self.store.conversations(workspace)
            ],
            "codex_health": self.codex_health.model_dump(),
            "jobs": [job_summary(payload) for payload in self.store.job_payloads(workspace)],
        }


def create_app(paths: StudioPaths | None = None, token: str | None = None) -> FastAPI:
    """Construct a local-only API with disposable dependency injection for tests."""
    app_paths = paths or studio_paths()
    secret = token or os.environ.get("EFORGE_STUDIO_TOKEN") or ""
    if not secret:
        raise ValueError("A Studio service token is required")
    service = StudioService(app_paths, secret)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await service.start()
        try:
            yield
        finally:
            await service.stop()

    app = FastAPI(title="EvidenceForge Studio API", version="1.0.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "tauri://localhost",
            "http://tauri.localhost",
            "http://localhost:1420",
            "http://127.0.0.1:1420",
        ],
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["X-EForge-Token", "Content-Type"],
    )
    app.state.studio = service
    bundle_download_tickets: dict[str, tuple[str, float]] = {}

    def authorized(x_eforge_token: str | None = Header(default=None)) -> StudioService:
        if x_eforge_token != service.token:
            raise HTTPException(status_code=401, detail="Invalid local service token")
        return service

    @app.get("/v1/health")
    def health(studio: StudioService = Depends(authorized)) -> dict[str, str]:
        return {"status": "ok", "pid": str(os.getpid())}

    @app.get("/v1/bootstrap")
    def bootstrap(studio: StudioService = Depends(authorized)) -> StudioSnapshot:
        return StudioSnapshot.model_validate(studio.snapshot())

    @app.get("/v1/events")
    def events(after: int = 0, studio: StudioService = Depends(authorized)) -> list[StudioEvent]:
        return studio.store.events_after(after)

    @app.websocket("/v1/events/ws")
    async def event_socket(websocket: WebSocket) -> None:
        if websocket.query_params.get("token") != service.token:
            await websocket.close(code=1008)
            return
        queue: asyncio.Queue[StudioEvent] = asyncio.Queue()
        service.subscribers.add(queue)
        await websocket.accept()
        try:
            cursor = int(websocket.query_params.get("after", "0"))
            while True:
                page = service.store.events_after(cursor)
                if not page:
                    break
                for event in page:
                    await websocket.send_text(event.model_dump_json())
                    cursor = event.seq
            while True:
                event = await queue.get()
                if event.seq > cursor:
                    await websocket.send_text(event.model_dump_json())
                    cursor = event.seq
        except (WebSocketDisconnect, ValueError):
            pass
        finally:
            service.subscribers.discard(queue)

    @app.post("/v1/library/refresh")
    async def refresh(studio: StudioService = Depends(authorized)) -> list[CatalogItem]:
        return await studio.scan()

    @app.get("/v1/items")
    def items(
        kind: str | None = None,
        search: str = "",
        studio: StudioService = Depends(authorized),
    ) -> list[CatalogItem]:
        if len(search) > 256:
            raise HTTPException(status_code=400, detail="Search is too long")
        found = (
            studio.store.search_items(studio.settings.workspace, search)
            if search.strip()
            else studio.store.items(studio.settings.workspace, kind)
        )
        return [item for item in found if kind is None or item.kind == kind]

    @app.patch("/v1/items/{item_id}")
    async def update_item(
        item_id: str, update: ItemUpdate, studio: StudioService = Depends(authorized)
    ) -> CatalogItem:
        item = studio.store.item(item_id)
        if item is None or item.workspace.resolve() != studio.settings.workspace.resolve():
            raise HTTPException(status_code=404, detail="Item not found")
        changes = update.model_dump(exclude_unset=True)
        if "folder" in changes and changes["folder"] is not None:
            if changes["folder"] not in studio.store.folders(studio.settings.workspace):
                raise HTTPException(status_code=404, detail="Folder not found in this workspace")
        if "project_id" in changes:
            if item.kind != "scenario":
                raise HTTPException(status_code=400, detail="Only scenarios can join a project")
            if changes["project_id"] is not None:
                project = studio.store.project(changes["project_id"])
                if project is None or project.workspace.resolve() != item.workspace.resolve():
                    raise HTTPException(
                        status_code=404, detail="Project not found in this workspace"
                    )
        item = item.model_copy(update=changes)
        studio.store.save_item(item)
        await studio.emit(item.id, "item.updated", json.loads(item.model_dump_json()))
        return item

    @app.get("/v1/folders")
    def folders(studio: StudioService = Depends(authorized)) -> list[str]:
        return studio.store.folders(studio.settings.workspace)

    @app.post("/v1/folders")
    async def create_folder(
        request: FolderRequest, studio: StudioService = Depends(authorized)
    ) -> dict[str, str]:
        name = clean_folder_name(request.name)
        if any(
            folder.casefold() == name.casefold()
            for folder in studio.store.folders(studio.settings.workspace)
        ):
            raise HTTPException(status_code=409, detail="A folder with this name already exists")
        studio.store.save_folder(studio.settings.workspace, name)
        await studio.emit(
            str(studio.settings.workspace), "library.refreshed", {"reason": "folder.created"}
        )
        return {"name": name}

    @app.patch("/v1/folders/{name}")
    async def rename_folder(
        name: str, request: FolderRequest, studio: StudioService = Depends(authorized)
    ) -> dict[str, str]:
        existing = studio.store.folders(studio.settings.workspace)
        if name not in existing:
            raise HTTPException(status_code=404, detail="Folder not found")
        updated = clean_folder_name(request.name)
        if any(folder.casefold() == updated.casefold() and folder != name for folder in existing):
            raise HTTPException(status_code=409, detail="A folder with this name already exists")
        studio.store.rename_folder(studio.settings.workspace, name, updated)
        await studio.emit(
            str(studio.settings.workspace), "library.refreshed", {"reason": "folder.renamed"}
        )
        return {"name": updated}

    @app.delete("/v1/folders/{name}")
    async def delete_folder(
        name: str, studio: StudioService = Depends(authorized)
    ) -> dict[str, str]:
        if name not in studio.store.folders(studio.settings.workspace):
            raise HTTPException(status_code=404, detail="Folder not found")
        studio.store.delete_folder(studio.settings.workspace, name)
        await studio.emit(
            str(studio.settings.workspace), "library.refreshed", {"reason": "folder.deleted"}
        )
        return {"status": "deleted"}

    @app.get("/v1/projects")
    def projects(studio: StudioService = Depends(authorized)) -> list[Project]:
        return studio.store.projects(studio.settings.workspace)

    @app.post("/v1/projects")
    async def create_project(
        request: ProjectRequest, studio: StudioService = Depends(authorized)
    ) -> Project:
        name = request.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="Project name cannot be blank")
        project = Project(
            workspace=studio.settings.workspace,
            name=name,
            description=request.description.strip(),
        )
        try:
            studio.store.save_project(project)
        except sqlite3.IntegrityError as error:
            raise HTTPException(
                status_code=409, detail="A project with this name already exists"
            ) from error
        await studio.emit(project.id, "project.created", json.loads(project.model_dump_json()))
        return project

    @app.patch("/v1/projects/{project_id}")
    async def update_project(
        project_id: str, update: ProjectUpdate, studio: StudioService = Depends(authorized)
    ) -> Project:
        project = studio.store.project(project_id)
        if project is None or project.workspace.resolve() != studio.settings.workspace.resolve():
            raise HTTPException(status_code=404, detail="Project not found")
        changes = update.model_dump(exclude_unset=True)
        if "name" in changes:
            if changes["name"] is None or not changes["name"].strip():
                raise HTTPException(status_code=400, detail="Project name cannot be blank")
            changes["name"] = changes["name"].strip()
        if "description" in changes:
            changes["description"] = (changes["description"] or "").strip()
        project = project.model_copy(update={**changes, "updated_at": time.time()})
        try:
            studio.store.save_project(project)
        except sqlite3.IntegrityError as error:
            raise HTTPException(
                status_code=409, detail="A project with this name already exists"
            ) from error
        await studio.emit(project.id, "project.updated", json.loads(project.model_dump_json()))
        return project

    @app.delete("/v1/projects/{project_id}")
    async def delete_project(
        project_id: str, studio: StudioService = Depends(authorized)
    ) -> dict[str, int | str]:
        project = studio.store.project(project_id)
        if project is None or project.workspace.resolve() != studio.settings.workspace.resolve():
            raise HTTPException(status_code=404, detail="Project not found")
        changed, changed_drafts, changed_views = studio.store.delete_project(project)
        for item in changed:
            await studio.emit(item.id, "item.updated", json.loads(item.model_dump_json()))
        for conversation in changed_drafts:
            await studio.emit(
                conversation.id,
                "conversation.updated",
                json.loads(conversation.model_dump_json()),
            )
        for view in changed_views:
            await studio.emit(view.name, "view.saved", json.loads(view.model_dump_json()))
        await studio.emit(project.id, "project.deleted", {})
        return {"status": "deleted", "ungrouped": len(changed)}

    @app.get("/v1/views")
    def saved_views(studio: StudioService = Depends(authorized)) -> list[SavedView]:
        return studio.store.views(studio.settings.workspace)

    @app.post("/v1/views")
    async def save_view(
        request: SavedView, studio: StudioService = Depends(authorized)
    ) -> SavedView:
        name = request.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="View name cannot be blank")
        if len(request.search) > 256:
            raise HTTPException(status_code=400, detail="Saved search is too long")
        if any(
            view.name.casefold() == name.casefold()
            for view in studio.store.views(studio.settings.workspace)
        ):
            raise HTTPException(status_code=409, detail="A view with this name already exists")
        if request.project_id:
            if request.kind != "scenario":
                raise HTTPException(
                    status_code=400, detail="Only scenario views can select a project"
                )
            project = studio.store.project(request.project_id)
            if (
                project is None
                or project.workspace.resolve() != studio.settings.workspace.resolve()
            ):
                raise HTTPException(status_code=404, detail="Project not found in this workspace")
        if request.ungrouped and (request.kind != "scenario" or request.project_id):
            raise HTTPException(status_code=400, detail="Ungrouped is a scenario-only view")
        if request.folder and request.folder not in studio.store.folders(studio.settings.workspace):
            raise HTTPException(status_code=404, detail="Folder not found in this workspace")
        view = request.model_copy(update={"name": name})
        studio.store.save_view(studio.settings.workspace, view)
        await studio.emit(name, "view.saved", json.loads(view.model_dump_json()))
        return view

    @app.delete("/v1/views/{name}")
    async def delete_view(name: str, studio: StudioService = Depends(authorized)) -> dict[str, str]:
        if not any(view.name == name for view in studio.store.views(studio.settings.workspace)):
            raise HTTPException(status_code=404, detail="Saved view not found")
        studio.store.delete_view(studio.settings.workspace, name)
        await studio.emit(name, "view.deleted", {"name": name})
        return {"status": "deleted"}

    @app.post("/v1/workspaces/select")
    async def select_workspace(
        selection: WorkspaceSelection, studio: StudioService = Depends(authorized)
    ) -> dict[str, Any]:
        previous = studio.settings.workspace
        studio.settings.workspace = ensure_workspace(selection.path)
        recent = [previous, *studio.settings.recent_workspaces]
        studio.settings.recent_workspaces = list(dict.fromkeys(recent))[:10]
        studio.settings_store.save(studio.settings)
        await studio.scan()
        await studio.emit(str(studio.settings.workspace), "workspace.selected", {})
        return studio.snapshot()

    @app.get("/v1/settings")
    def settings(studio: StudioService = Depends(authorized)) -> StudioSettings:
        return studio.settings

    @app.get("/v1/export-location")
    def export_location(studio: StudioService = Depends(authorized)) -> ExportLocation:
        return ExportLocation(directory=studio.store.export_directory(studio.settings.workspace))

    @app.put("/v1/export-location")
    def save_export_location(
        location: ExportLocation, studio: StudioService = Depends(authorized)
    ) -> ExportLocation:
        if location.directory is None or not location.directory.is_dir():
            raise HTTPException(status_code=400, detail="Export folder does not exist")
        directory = location.directory.resolve()
        studio.store.set_export_directory(studio.settings.workspace, directory)
        return ExportLocation(directory=directory)

    @app.put("/v1/settings")
    async def save_settings(
        new_settings: StudioSettings, studio: StudioService = Depends(authorized)
    ) -> StudioSettings:
        if new_settings.workspace.resolve() != studio.settings.workspace.resolve():
            raise HTTPException(
                status_code=400, detail="Use workspace selection to switch workspaces"
            )
        studio.settings = new_settings
        studio.settings_store.save(new_settings)
        studio.codex.binary = new_settings.codex_path
        studio.set_intent(
            studio.intent.model_copy(update={"settings": controller_settings(new_settings)})
        )
        await studio.emit(
            "settings", "settings.updated", json.loads(new_settings.model_dump_json())
        )
        return new_settings

    @app.post("/v1/validate")
    async def validate(
        request: ValidationRequest, studio: StudioService = Depends(authorized)
    ) -> ValidationResult:
        item = studio.store.item(request.scenario_id)
        if item is None or item.kind != "scenario":
            raise HTTPException(status_code=404, detail="Scenario not found")

        def run() -> ValidationResult:
            try:
                result = subprocess.run(
                    [
                        *_eforge_command(controller_settings(studio.settings)),
                        "validate",
                        str(item.path),
                        "--project-root",
                        str(studio.settings.workspace),
                        "--json",
                    ],
                    cwd=studio.settings.workspace,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=180,
                )
                try:
                    report = json.loads(result.stdout)
                except json.JSONDecodeError:
                    report = None
                return ValidationResult(
                    exit_code=result.returncode,
                    report=report if isinstance(report, dict) else None,
                    error=result.stderr[-2000:],
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                return ValidationResult(exit_code=-1, error=str(error))

        result = await asyncio.to_thread(run)
        studio.store.save_validation(item.id, item.source_sha256, result)
        await studio.emit(
            item.id,
            "scenario.validated",
            {"source_sha256": item.source_sha256, "result": json.loads(result.model_dump_json())},
        )
        return result

    @app.get("/v1/conversations")
    def conversations(
        item_id: str | None = None, studio: StudioService = Depends(authorized)
    ) -> list[Conversation]:
        return studio.store.conversations(studio.settings.workspace, item_id)

    @app.post("/v1/conversations")
    async def create_conversation(
        request: ConversationRequest, studio: StudioService = Depends(authorized)
    ) -> Conversation:
        if bool(request.item_id) == bool(request.draft_kind):
            raise HTTPException(status_code=400, detail="Choose one item or draft kind")
        if request.item_id:
            item = studio.store.item(request.item_id)
            if item is None or item.workspace.resolve() != studio.settings.workspace.resolve():
                raise HTTPException(status_code=404, detail="Scenario or pack not found")
        if request.project_id:
            if request.draft_kind != "scenario":
                raise HTTPException(
                    status_code=400, detail="Only scenario drafts can join projects"
                )
            project = studio.store.project(request.project_id)
            if (
                project is None
                or project.workspace.resolve() != studio.settings.workspace.resolve()
            ):
                raise HTTPException(status_code=404, detail="Project not found in this workspace")
        conversation = Conversation(
            workspace=studio.settings.workspace,
            item_id=request.item_id,
            draft_kind=request.draft_kind,
            draft_project_id=request.project_id,
            draft_name=request.name.strip() if request.name else None,
        )
        if request.draft_kind == "scenario":
            conversation.draft_path = (
                studio.settings.workspace
                / "scenarios"
                / f"studio-{conversation.id}"
                / "scenario.yaml"
            )
        elif request.draft_kind:
            conversation.draft_path = (
                studio.settings.workspace
                / ".eforge"
                / "packs"
                / f"studio-{conversation.id}"
                / "pack.yaml"
            )
        studio.store.save_conversation(conversation)
        await studio.emit(
            conversation.id, "conversation.created", json.loads(conversation.model_dump_json())
        )
        return conversation

    @app.patch("/v1/conversations/{conversation_id}")
    async def update_conversation(
        conversation_id: str,
        update: ConversationUpdate,
        studio: StudioService = Depends(authorized),
    ) -> Conversation:
        conversation = studio.store.conversation(conversation_id)
        if conversation is None or conversation.workspace != studio.settings.workspace:
            raise HTTPException(status_code=404, detail="Conversation not found")
        changes = update.model_dump(exclude_unset=True)
        if "draft_name" in changes and conversation.draft_kind != "scenario":
            raise HTTPException(status_code=400, detail="Only scenario drafts can be renamed")
        if "draft_name" in changes and changes["draft_name"] is not None:
            changes["draft_name"] = changes["draft_name"].strip()
            if not changes["draft_name"]:
                raise HTTPException(status_code=400, detail="Scenario name cannot be blank")
        if "draft_project_id" in changes:
            if conversation.draft_kind != "scenario":
                raise HTTPException(
                    status_code=400, detail="Only scenario drafts can join projects"
                )
            project_id = changes["draft_project_id"]
            if project_id is not None:
                project = studio.store.project(project_id)
                if (
                    project is None
                    or project.workspace.resolve() != studio.settings.workspace.resolve()
                ):
                    raise HTTPException(
                        status_code=404, detail="Project not found in this workspace"
                    )
        conversation = conversation.model_copy(update=changes)
        conversation.updated_at = time.time()
        if "title" in changes and conversation.thread_id and conversation.title:
            try:
                await studio.codex.call(
                    "thread/name/set",
                    {"threadId": conversation.thread_id, "name": conversation.title},
                )
            except CodexUnavailableError as error:
                raise HTTPException(status_code=503, detail=str(error)) from error
        studio.store.save_conversation(conversation)
        await studio.emit(
            conversation.id, "conversation.updated", json.loads(conversation.model_dump_json())
        )
        return conversation

    @app.delete("/v1/conversations/{conversation_id}")
    async def delete_conversation(
        conversation_id: str, studio: StudioService = Depends(authorized)
    ) -> dict[str, str]:
        conversation = studio.store.conversation(conversation_id)
        if conversation is None or conversation.workspace != studio.settings.workspace:
            raise HTTPException(status_code=404, detail="Conversation not found")
        if conversation.active:
            raise HTTPException(status_code=409, detail="Stop the active turn before deleting")
        studio.store.delete_conversation(conversation_id)
        await studio.emit(conversation_id, "conversation.deleted", {"id": conversation_id})
        return {"status": "removed from Studio"}

    @app.get("/v1/conversations/{conversation_id}/history")
    async def conversation_history(
        conversation_id: str, studio: StudioService = Depends(authorized)
    ) -> dict[str, Any]:
        conversation = studio.store.conversation(conversation_id)
        if conversation is None or conversation.workspace != studio.settings.workspace:
            raise HTTPException(status_code=404, detail="Conversation not found")
        if conversation.thread_id is None:
            return {"thread": {"turns": []}}
        try:
            result = await studio.codex.call(
                "thread/read",
                {"threadId": conversation.thread_id, "includeTurns": True},
                timeout=10,
            )
            await studio.reconcile_codex_thread(conversation, result)
            return result
        except CodexThreadNotReadyError:
            return {"thread": {"turns": []}, "history_pending": True}
        except CodexTimeoutError as error:
            await studio.set_codex_health("stalled", str(error))
            raise HTTPException(status_code=503, detail=str(error)) from error
        except CodexUnavailableError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error

    @app.get("/v1/codex/status")
    async def codex_status(studio: StudioService = Depends(authorized)) -> dict[str, Any]:
        try:
            account = await studio.codex.call("account/read", {"refreshToken": False}, timeout=10)
            if account.get("account") is None:
                return {
                    "available": True,
                    "account_ready": False,
                    "account": account,
                    "models": {"data": []},
                    "skills": {"data": []},
                }
            models, skills = await asyncio.gather(
                studio.codex.call("model/list", {"limit": 100}, timeout=10),
                studio.codex.call(
                    "skills/list",
                    {"cwds": [str(studio.settings.workspace)], "forceReload": False},
                    timeout=10,
                ),
            )
            return {
                "available": True,
                "account_ready": True,
                "account": account,
                "models": models,
                "skills": skills,
            }
        except CodexTimeoutError as error:
            await studio.set_codex_health("stalled", str(error))
            return {"available": False, "error": str(error)}
        except CodexUnavailableError as error:
            return {"available": False, "error": str(error)}

    @app.post("/v1/codex/reconnect")
    async def reconnect_codex(
        request: CodexReconnectRequest, studio: StudioService = Depends(authorized)
    ) -> CodexHealth:
        async with studio.codex_lock:
            active = studio.store.active_conversations()
            if active and not request.interrupt_active:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "message": "Reconnecting will interrupt active Codex turns.",
                        "active_conversations": [chat.id for chat in active],
                    },
                )
            await studio.set_codex_health("checking", "Reconnecting to Codex")
            await studio.codex.stop()
            await studio._clear_abandoned_turns(
                "Studio reconnected to Codex during this turn. Review its history before continuing."
            )
            try:
                await studio.codex.start()
                await studio.codex.call("thread/loaded/list", {}, timeout=10)
            except CodexUnavailableError as error:
                await studio.set_codex_health("disconnected", str(error))
                raise HTTPException(status_code=503, detail=str(error)) from error
            studio.codex_failures = 0
            await studio.set_codex_health("connected", "Codex is responding")
            return studio.codex_health

    @app.post("/v1/codex/account/login")
    async def codex_login(studio: StudioService = Depends(authorized)) -> dict[str, Any]:
        try:
            return await studio.codex.call(
                "account/login/start",
                {"type": "chatgpt", "useHostedLoginSuccessPage": True, "appBrand": "codex"},
            )
        except CodexUnavailableError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error

    @app.post("/v1/codex/account/logout")
    async def codex_logout(studio: StudioService = Depends(authorized)) -> dict[str, Any]:
        try:
            return await studio.codex.call("account/logout")
        except CodexUnavailableError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error

    @app.post("/v1/codex/skills/install")
    async def install_studio_skills(
        request: SkillInstallRequest, studio: StudioService = Depends(authorized)
    ) -> dict[str, Any]:
        if request.scope not in {"global", "workspace"} or request.agent not in {
            "all",
            "chatgpt",
            "claude",
        }:
            raise HTTPException(status_code=400, detail="Choose a valid scope and agent")

        def install() -> dict[str, Any]:
            installed: dict[str, int] = {}
            failures: dict[str, str] = {}
            for agent, target in skill_targets(
                request.scope, request.agent, studio.settings.workspace
            ):
                try:
                    files, _removed = (
                        install_skills(target)
                        if agent == "claude"
                        else install_chatgpt_skills(target)
                    )
                    installed[agent] = len(files)
                except (OSError, ValueError) as error:
                    failures[agent] = str(error)
            return {"installed": installed, "failures": failures}

        result = await asyncio.to_thread(install)
        await studio.emit("codex", "skills.installed", result)
        return result

    @app.post("/v1/conversations/{conversation_id}/turns")
    async def start_turn(
        conversation_id: str, request: TurnRequest, studio: StudioService = Depends(authorized)
    ) -> TurnSubmission:
        conversation = studio.store.conversation(conversation_id)
        if conversation is None or conversation.workspace != studio.settings.workspace:
            raise HTTPException(status_code=404, detail="Conversation not found")
        if conversation.active:
            raise HTTPException(status_code=409, detail="This conversation has an active turn")
        item = studio.store.item(conversation.item_id) if conversation.item_id else None
        if conversation.item_id and (item is None or item.workspace != conversation.workspace):
            raise HTTPException(status_code=404, detail="Conversation source is unavailable")
        first_turn = conversation.thread_id is None
        skill_name = request.skill_name
        if first_turn and skill_name is None:
            kind = item.kind if item is not None else conversation.draft_kind
            skill_name = {
                "scenario": "eforge-scenario",
                "industry_pack": "eforge-industry-pack",
                "organization_pack": "eforge-organization-pack",
            }.get(kind)
        turn_id: str | None = None
        try:
            inputs: list[dict[str, str]] = [{"type": "text", "text": request.text}]
            if skill_name:
                listing = await studio.codex.call(
                    "skills/list",
                    {"cwds": [str(conversation.workspace)], "forceReload": False},
                )
                matches = (
                    skill
                    for group in listing.get("data", [])
                    for skill in group.get("skills", [])
                    if skill.get("name") == skill_name and skill.get("enabled", True)
                )
                skill = next(matches, None)
                if skill is None or not skill.get("path"):
                    raise HTTPException(
                        status_code=409,
                        detail=f"{skill_name} is unavailable. Install EvidenceForge skills in Settings.",
                    )
                inputs.append({"type": "skill", "name": skill_name, "path": str(skill["path"])})
            if first_turn:
                context_kind = item.kind if item is not None else conversation.draft_kind
                target = (
                    str(item.path)
                    if item is not None
                    else str(conversation.draft_path or "a new draft")
                )
                draft_name_context = (
                    f"The user named this draft {conversation.draft_name!r}; use that "
                    "as the authored scenario name unless the user asks to change it. "
                    if conversation.draft_kind == "scenario" and conversation.draft_name
                    else ""
                )
                parameters: dict[str, Any] = {
                    "cwd": str(conversation.workspace),
                    "sandbox": "workspace-write",
                    "developerInstructions": (
                        f"This conversation concerns the EvidenceForge {context_kind} at {target}. "
                        "For a new draft, create its authored file at that exact path when the user "
                        "asks you to write it; keep companion files beside it. "
                        f"{draft_name_context}"
                        "Treat that path as context for the user's requests. Wait for a user "
                        "request before editing files. Keep deterministic generation in eforge."
                    ),
                }
                if conversation.model_id:
                    parameters["model"] = conversation.model_id
                started = await studio.codex.call("thread/start", parameters)
                conversation.thread_id = str(started["thread"]["id"])
                conversation.title = " ".join(request.text.strip().split()[:7])[:80]
            else:
                await studio.codex.call("thread/resume", {"threadId": conversation.thread_id})
            parameters = {"threadId": conversation.thread_id, "input": inputs}
            if conversation.model_id:
                parameters["model"] = conversation.model_id
            if conversation.reasoning_effort:
                parameters["effort"] = conversation.reasoning_effort
            conversation.active = True
            conversation.connection_note = None
            conversation.updated_at = time.time()
            studio.store.save_conversation(conversation)
            await studio.emit(
                conversation.id,
                "conversation.updated",
                json.loads(conversation.model_dump_json()),
            )
            started_turn = await studio.codex.call("turn/start", parameters)
            turn = started_turn.get("turn")
            if isinstance(turn, dict) and isinstance(turn.get("id"), str):
                turn_id = turn["id"]
        except CodexTimeoutError as error:
            await studio.set_codex_health("stalled", str(error))
            if conversation.active:
                current = studio.store.conversation(conversation.id) or conversation
                if current.active:
                    current.connection_note = (
                        "Codex did not confirm whether this turn started. "
                        "Studio is checking its status."
                    )
                    studio.store.save_conversation(current)
                    await studio.emit(
                        current.id,
                        "conversation.updated",
                        json.loads(current.model_dump_json()),
                    )
                return TurnSubmission.model_validate(
                    {**current.model_dump(), "delivery": "uncertain"}
                )
            raise HTTPException(status_code=503, detail=str(error)) from error
        except CodexUnavailableError as error:
            current = studio.store.conversation(conversation.id) or conversation
            if current.active or current.thread_id is None:
                conversation.active = False
                studio.store.save_conversation(conversation)
                await studio.emit(
                    conversation.id,
                    "conversation.updated",
                    json.loads(conversation.model_dump_json()),
                )
            raise HTTPException(status_code=503, detail=str(error)) from error
        current = studio.store.conversation(conversation.id) or conversation
        return TurnSubmission.model_validate({**current.model_dump(), "turn_id": turn_id})

    @app.post("/v1/conversations/{conversation_id}/interrupt")
    async def interrupt_turn(
        conversation_id: str, studio: StudioService = Depends(authorized)
    ) -> dict[str, str]:
        conversation = studio.store.conversation(conversation_id)
        if conversation is None or conversation.workspace != studio.settings.workspace:
            raise HTTPException(status_code=404, detail="Conversation not found")
        if conversation.thread_id:
            try:
                await studio.codex.call("turn/interrupt", {"threadId": conversation.thread_id})
            except CodexUnavailableError as error:
                raise HTTPException(status_code=503, detail=str(error)) from error
        return {"status": "interrupt requested"}

    @app.get("/v1/codex/pending")
    def pending_codex(studio: StudioService = Depends(authorized)) -> list[dict[str, Any]]:
        return [
            {"request_id": request_id, **payload}
            for request_id, payload in studio.pending_codex_requests.items()
        ]

    @app.post("/v1/codex/reply")
    async def reply_codex(
        reply: CodexReply, studio: StudioService = Depends(authorized)
    ) -> dict[str, str]:
        pending = studio.pending_codex_requests.get(reply.request_id)
        if pending is None:
            raise HTTPException(status_code=404, detail="Codex request is no longer pending")
        await studio.codex.respond(reply.request_id, reply.result)
        studio.pending_codex_requests.pop(reply.request_id)
        params = pending.get("params", {})
        thread_id = params.get("threadId") if isinstance(params, dict) else None
        conversation = (
            studio.store.conversation_for_thread(thread_id) if isinstance(thread_id, str) else None
        )
        if conversation is not None:
            still_waiting = any(
                isinstance(request.get("params"), dict)
                and request["params"].get("threadId") == thread_id
                for request in studio.pending_codex_requests.values()
            )
            if not still_waiting:
                conversation.needs_attention = False
                studio.store.save_conversation(conversation)
                await studio.emit(
                    conversation.id,
                    "conversation.updated",
                    json.loads(conversation.model_dump_json()),
                )
        await studio.emit("codex", "codex.input_answered", {"request_id": reply.request_id})
        return {"status": "answer sent"}

    @app.get("/v1/jobs")
    def jobs(studio: StudioService = Depends(authorized)) -> list[dict[str, Any]]:
        return [
            job_summary(payload) for payload in studio.store.job_payloads(studio.settings.workspace)
        ]

    @app.get("/v1/jobs/bundle-sizes")
    async def bundle_sizes(
        studio: StudioService = Depends(authorized),
    ) -> dict[str, int | None]:
        generations = [
            job
            for job in studio.jobs.load_generations()
            if job.workspace == studio.settings.workspace
        ]
        return await asyncio.to_thread(
            lambda: {job.id: _bundle_contents_size(job.output_root) for job in generations}
        )

    @app.post("/v1/jobs/{job_id}/regenerate")
    async def regenerate(
        job_id: str, studio: StudioService = Depends(authorized)
    ) -> dict[str, Any]:
        previous = next((job for job in studio.jobs.load_generations() if job.id == job_id), None)
        if previous is None or previous.workspace != studio.settings.workspace:
            raise HTTPException(status_code=404, detail="Generation not found")
        if previous.status not in {"stopped", "failed", "cancelled"}:
            raise HTTPException(
                status_code=409, detail="Only stopped generations can be regenerated"
            )
        item = next(
            (
                item
                for item in studio.store.items(studio.settings.workspace, "scenario")
                if item.path.resolve() == previous.scenario.resolve()
            ),
            None,
        )
        if item is None or not item.path.is_file():
            raise HTTPException(
                status_code=409, detail="The source scenario is no longer available"
            )
        try:
            job = await asyncio.to_thread(
                queue_studio_generation,
                studio.jobs,
                item.path,
                studio.settings.workspace,
                studio.settings,
                previous.output_root.parent.parent,
                studio.settings.checkpoint_hours,
            )
        except (OSError, ValueError) as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        summary = job_summary(json.loads(job.model_dump_json()))
        await studio.emit(job.id, "job.created", summary)
        return summary

    @app.delete("/v1/jobs/{job_id}/incomplete-bundle")
    async def delete_incomplete_bundle(
        job_id: str, studio: StudioService = Depends(authorized)
    ) -> dict[str, str]:
        job = next((entry for entry in studio.jobs.load_generations() if entry.id == job_id), None)
        if job is None or job.workspace != studio.settings.workspace:
            raise HTTPException(status_code=404, detail="Generation not found")
        if job.status not in {"paused", "stopped", "failed", "cancelled"}:
            raise HTTPException(
                status_code=409, detail="Only inactive incomplete runs can be deleted"
            )
        if any(entry.generation_id == job.id for entry in studio.jobs.load_evaluations()):
            raise HTTPException(status_code=409, detail="This run has linked evaluations")
        try:
            deleted = await asyncio.to_thread(_delete_owned_incomplete, job)
        except OSError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        if not deleted:
            raise HTTPException(
                status_code=409,
                detail="Bundle is missing, complete, active, or not verified as created by this app",
            )
        studio.store.delete_job(job.id)
        await studio.emit(job.id, "job.deleted", {"id": job.id})
        return {"status": "incomplete bundle deleted"}

    @app.delete("/v1/jobs/{job_id}/bundle")
    async def delete_completed_bundle(
        job_id: str, studio: StudioService = Depends(authorized)
    ) -> dict[str, str]:
        job = next((entry for entry in studio.jobs.load_generations() if entry.id == job_id), None)
        if job is None or job.workspace != studio.settings.workspace:
            raise HTTPException(status_code=404, detail="Generation not found")
        if job.status != "completed":
            raise HTTPException(status_code=409, detail="Only completed bundles use this action")
        evaluations = [
            entry for entry in studio.jobs.load_evaluations() if entry.generation_id == job.id
        ]
        if any(entry.status in {"queued", "running", "paused"} for entry in evaluations):
            raise HTTPException(status_code=409, detail="A linked evaluation is still active")
        try:
            deleted = await asyncio.to_thread(_delete_owned_complete, job)
        except OSError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        if not deleted:
            raise HTTPException(
                status_code=409, detail="Bundle is missing or not verified as created by this app"
            )
        for evaluation in evaluations:
            for path in (evaluation.result_file, evaluation.log_file):
                if not path.is_symlink() and path.resolve().is_relative_to(
                    (studio.paths.state / "jobs").resolve()
                ):
                    try:
                        path.unlink(missing_ok=True)
                    except OSError:
                        pass
            studio.store.delete_job(evaluation.id)
            await studio.emit(evaluation.id, "job.deleted", {"id": evaluation.id})
        studio.store.delete_job(job.id)
        await studio.emit(job.id, "job.deleted", {"id": job.id})
        return {"status": "completed bundle deleted"}

    @app.get("/v1/jobs/{job_id}/scorecard")
    def scorecard(job_id: str, studio: StudioService = Depends(authorized)) -> ScorecardDetail:
        """Read one saved evaluation without putting the full report in every snapshot."""
        payload = next(
            (
                entry
                for entry in studio.store.job_payloads(studio.settings.workspace, "evaluation")
                if entry["id"] == job_id
            ),
            None,
        )
        if payload is None:
            raise HTTPException(status_code=404, detail="Evaluation not found")
        result_file = Path(payload["result_file"])
        expected = studio.jobs.directory / "jobs" / f"{job_id}.json"
        if result_file != expected or result_file.is_symlink() or not result_file.is_file():
            raise HTTPException(status_code=404, detail="Saved evaluation report is unavailable")
        if result_file.stat().st_size > 32 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="Saved evaluation report is too large")
        try:
            report = QualityReport.model_validate_json(result_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            raise HTTPException(
                status_code=422, detail="Saved evaluation report is invalid"
            ) from exc
        return ScorecardDetail(
            scenario_name=report.scenario_name,
            evaluated_at=report.evaluated_at.isoformat(),
            overall_score=report.overall_score,
            acceptance_passed=report.acceptance_passed,
            total_records=report.total_records,
            source_counts=report.source_counts,
            pillars=[
                ScorecardPillar(
                    name=pillar.name,
                    score=pillar.score,
                    sub_scores=[
                        ScorecardSubscore(
                            name=sub.name,
                            score=sub.score,
                            details=sub.details,
                            skipped=sub.skipped,
                        )
                        for sub in pillar.sub_scores
                    ],
                )
                for pillar in report.pillars
            ],
            acceptance_criteria=[
                ScorecardCriterion(
                    name=criterion.name,
                    threshold=criterion.threshold,
                    actual=criterion.actual,
                    passed=criterion.passed,
                    level=criterion.level,
                )
                for criterion in report.acceptance_criteria
            ],
            flags=report.flags,
        )

    @app.get("/v1/jobs/{job_id}/files")
    def bundle_files(job_id: str, studio: StudioService = Depends(authorized)) -> dict[str, Any]:
        payload = next(
            (
                entry
                for entry in studio.store.job_payloads(studio.settings.workspace)
                if entry["id"] == job_id
            ),
            None,
        )
        if payload is None:
            raise HTTPException(status_code=404, detail="Job not found")
        root = Path(payload["output_root"])
        if root.is_symlink() or not root.is_dir():
            raise HTTPException(status_code=404, detail="Bundle directory is unavailable")
        files: list[dict[str, Any]] = []
        for directory, children, names in os.walk(root, followlinks=False):
            children[:] = [name for name in children if not (Path(directory) / name).is_symlink()]
            for name in names:
                path = Path(directory) / name
                if path.is_symlink() or not path.is_file():
                    continue
                files.append(
                    {"path": path.relative_to(root).as_posix(), "size": path.stat().st_size}
                )
                if len(files) >= 500:
                    return {"root": str(root), "files": files, "truncated": True}
        return {"root": str(root), "files": files, "truncated": False}

    @app.get("/v1/jobs/{job_id}/files/{relative_path:path}")
    def bundle_file(
        job_id: str, relative_path: str, studio: StudioService = Depends(authorized)
    ) -> FileResponse:
        payload = next(
            (
                entry
                for entry in studio.store.job_payloads(studio.settings.workspace)
                if entry["id"] == job_id
            ),
            None,
        )
        if payload is None:
            raise HTTPException(status_code=404, detail="Job not found")
        root = Path(payload["output_root"])
        path = root / relative_path
        if (
            root.is_symlink()
            or not path.resolve().is_relative_to(root.resolve())
            or not path.is_file()
        ):
            raise HTTPException(status_code=404, detail="Bundle file not found")
        return FileResponse(path, filename=path.name)

    @app.post("/v1/jobs/generations")
    async def create_generation(
        request: GenerationRequest, studio: StudioService = Depends(authorized)
    ) -> dict[str, Any]:
        item = studio.store.item(request.scenario_id)
        if item is None or item.kind != "scenario":
            raise HTTPException(status_code=404, detail="Scenario not found")
        try:
            job = await asyncio.to_thread(
                queue_studio_generation,
                studio.jobs,
                item.path,
                studio.settings.workspace,
                studio.settings,
                request.output_parent,
                request.checkpoint_hours
                if request.checkpoint_hours is not None
                else studio.settings.checkpoint_hours,
            )
        except (OSError, ValueError) as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        summary = job_summary(json.loads(job.model_dump_json()))
        await studio.emit(job.id, "job.created", summary)
        return summary

    @app.get("/v1/items/{item_id}/bundles/{generation_id}.zip")
    async def download_bundle(
        item_id: str, generation_id: str, studio: StudioService = Depends(authorized)
    ) -> FileResponse:
        item = studio.store.item(item_id)
        if item is None or item.workspace != studio.settings.workspace or item.kind != "scenario":
            raise HTTPException(status_code=404, detail="Scenario not found")
        generation = next(
            (job for job in studio.jobs.load_generations() if job.id == generation_id), None
        )
        if generation is None or generation.scenario.resolve() != item.path.resolve():
            raise HTTPException(status_code=404, detail="Run not found for this scenario")
        if generation.output_root.is_symlink():
            raise HTTPException(status_code=409, detail="Run directory has changed")
        root = generation.output_root.resolve()
        if generation.status != "completed" or not (root / "GENERATION_MANIFEST.json").is_file():
            raise HTTPException(status_code=409, detail="Only completed runs can be downloaded")

        def make_archive() -> Path:
            export_dir = studio.paths.cache / "exports"
            export_dir.mkdir(parents=True, exist_ok=True)
            handle, archive_name = tempfile.mkstemp(
                prefix="evidenceforge-", suffix=".zip", dir=export_dir
            )
            os.close(handle)
            archive = Path(archive_name)
            try:
                with zipfile.ZipFile(
                    archive, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True
                ) as output:
                    for source in sorted(root.rglob("*")):
                        if source.is_symlink():
                            raise ValueError("Run contains a symlink and cannot be exported safely")
                        if source.is_file():
                            output.write(source, "run/" + source.relative_to(root).as_posix())
                    if item.path.is_file():
                        output.write(item.path, "authored/" + item.path.name)
                    for name in ("ENVIRONMENT.md", "RESEARCH.md", "README.md"):
                        note = item.path.parent / name
                        if note.is_file() and not note.is_symlink():
                            output.write(note, "authored/" + name)
                    for evaluation in studio.jobs.load_evaluations():
                        if (
                            evaluation.generation_id == generation.id
                            and evaluation.status == "completed"
                            and evaluation.result_file.is_file()
                        ):
                            output.write(
                                evaluation.result_file, f"evaluations/{evaluation.id}.json"
                            )
                    output.writestr(
                        "EXPORT_README.txt",
                        "run/ contains the selected completed generation. Its RESOLVED_SCENARIO.yaml "
                        "is the authoritative input for that run. authored/ contains the current "
                        "scenario file and companion notes, which may have changed since generation. "
                        "evaluations/ contains saved reports for this run.\n",
                    )
            except (OSError, ValueError):
                archive.unlink(missing_ok=True)
                raise
            return archive

        try:
            archive = await asyncio.to_thread(make_archive)
        except (OSError, ValueError) as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        return FileResponse(
            archive,
            filename=f"{_archive_stem(item.name)}-{generation.id[:8]}.zip",
            media_type="application/zip",
            background=BackgroundTask(archive.unlink, missing_ok=True),
        )

    @app.post("/v1/jobs/{job_id}/bundle.zip/ticket")
    def bundle_download_ticket(
        job_id: str, studio: StudioService = Depends(authorized)
    ) -> dict[str, str]:
        generation = next((job for job in studio.jobs.load_generations() if job.id == job_id), None)
        if generation is None or generation.workspace != studio.settings.workspace:
            raise HTTPException(status_code=404, detail="Generation not found")
        if generation.status not in {"completed", "paused", "stopped", "failed", "cancelled"}:
            raise HTTPException(status_code=409, detail="Pause or stop this run before exporting")
        now = time.time()
        for expired, (_, deadline) in list(bundle_download_tickets.items()):
            if deadline < now:
                bundle_download_tickets.pop(expired, None)
        ticket = secrets.token_urlsafe(32)
        bundle_download_tickets[ticket] = (job_id, now + 60)
        return {"ticket": ticket}

    @app.get("/v1/jobs/{job_id}/bundle.zip")
    async def download_job_bundle(
        job_id: str,
        ticket: str | None = None,
        x_eforge_token: str | None = Header(default=None),
    ) -> FileResponse:
        if x_eforge_token != service.token:
            grant = bundle_download_tickets.pop(ticket, None) if ticket else None
            if grant is None or grant[0] != job_id or grant[1] < time.time():
                raise HTTPException(status_code=401, detail="Invalid bundle download ticket")
        studio = service
        generation = next((job for job in studio.jobs.load_generations() if job.id == job_id), None)
        if generation is None or generation.workspace != studio.settings.workspace:
            raise HTTPException(status_code=404, detail="Generation not found")
        item = next(
            (
                entry
                for entry in studio.store.items(studio.settings.workspace, "scenario")
                if entry.path.resolve() == generation.scenario.resolve()
            ),
            None,
        )
        if generation.status == "completed":
            if item is None:
                raise HTTPException(status_code=409, detail="Source scenario is unavailable")
            return await download_bundle(item.id, generation.id, studio)
        if generation.status not in {"paused", "stopped", "failed", "cancelled"}:
            raise HTTPException(status_code=409, detail="Pause or stop this run before exporting")
        root = generation.output_root
        marker = root / ".eforge-desktop-job.json"
        if not generation.owned_output or root.is_symlink() or not root.is_dir():
            raise HTTPException(status_code=409, detail="Bundle is not verified as app-owned")
        if marker.is_symlink():
            raise HTTPException(status_code=409, detail="Bundle ownership marker has changed")
        try:
            marker_id = json.loads(marker.read_text(encoding="utf-8")).get("job_id")
        except (OSError, ValueError) as error:
            raise HTTPException(
                status_code=409, detail="Bundle ownership marker is invalid"
            ) from error
        if marker_id != generation.id:
            raise HTTPException(status_code=409, detail="Bundle ownership marker has changed")

        def make_partial_archive() -> Path:
            export_dir = studio.paths.cache / "exports"
            export_dir.mkdir(parents=True, exist_ok=True)
            handle, archive_name = tempfile.mkstemp(
                prefix="evidenceforge-partial-", suffix=".zip", dir=export_dir
            )
            os.close(handle)
            archive = Path(archive_name)
            try:
                with zipfile.ZipFile(
                    archive, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True
                ) as output:
                    for source in sorted(root.rglob("*")):
                        if source.is_symlink():
                            raise ValueError("Run contains a symlink and cannot be exported safely")
                        if source.is_file():
                            output.write(source, "run/" + source.relative_to(root).as_posix())
                    if generation.scenario.is_file() and not generation.scenario.is_symlink():
                        output.write(generation.scenario, "authored/" + generation.scenario.name)
                    output.writestr(
                        "EXPORT_README.txt",
                        "This is an incomplete EvidenceForge generation. Files may be partial. "
                        "authored/ contains the current scenario, which may differ from the "
                        "scenario used when this run started.\n",
                    )
            except (OSError, ValueError):
                archive.unlink(missing_ok=True)
                raise
            return archive

        try:
            archive = await asyncio.to_thread(make_partial_archive)
        except (OSError, ValueError) as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        return FileResponse(
            archive,
            filename=f"{_archive_stem(item.name if item else generation.scenario.parent.name)}-partial-{generation.id[:8]}.zip",
            media_type="application/zip",
            background=BackgroundTask(archive.unlink, missing_ok=True),
        )

    @app.post("/v1/jobs/evaluations")
    async def create_evaluation(
        request: EvaluationRequest, studio: StudioService = Depends(authorized)
    ) -> dict[str, Any]:
        generation = next(
            (
                entry
                for entry in studio.jobs.load_generations()
                if entry.id == request.generation_id
            ),
            None,
        )
        if generation is None or generation.status != "completed":
            raise HTTPException(status_code=400, detail="Choose a completed generation")
        job = queue_studio_evaluation(studio.jobs, generation, studio.settings)
        summary = job_summary(json.loads(job.model_dump_json()))
        await studio.emit(job.id, "job.created", summary)
        return summary

    @app.post("/v1/jobs/{job_id}/suspend")
    async def suspend(job_id: str, studio: StudioService = Depends(authorized)) -> dict[str, str]:
        try:
            detail = await asyncio.to_thread(suspend_generation, studio.jobs, job_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="Generation not found") from error
        except (OSError, ValueError, RuntimeError) as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        await studio.emit(job_id, "job.pause_requested", {"detail": detail})
        return {"detail": detail}

    @app.post("/v1/jobs/resume")
    async def resume(
        request: ResumeRequest, studio: StudioService = Depends(authorized)
    ) -> dict[str, str]:
        if request.generation_id is not None:
            job = next(
                (
                    entry
                    for entry in studio.jobs.load_generations()
                    if entry.id == request.generation_id
                ),
                None,
            )
            if job is None:
                raise HTTPException(status_code=404, detail="Generation not found")
            if not can_resume(job):
                raise HTTPException(
                    status_code=409,
                    detail="No resumable checkpoint is available for this generation",
                )
        studio.set_intent(
            ControlIntent(
                action="resume",
                settings=controller_settings(studio.settings),
                resume_generation_id=request.generation_id,
            )
        )
        return {"status": "resume requested"}

    @app.post("/v1/session/close")
    async def close_window(
        request: CloseWindowRequest | None = None,
        studio: StudioService = Depends(authorized),
    ) -> dict[str, str]:
        choices = request or CloseWindowRequest()
        quit_settings = studio.settings.quit
        generations = studio.jobs.load_generations()
        if quit_settings.action == "pause":
            conflicts = [
                job for job in generations if job.status == "running" and job.checkpoint_hours == 0
            ]
            unresolved = [
                job.id
                for job in conflicts
                if choices.generation_exceptions.get(job.id) not in {"continue", "stop"}
            ]
            if unresolved:
                raise HTTPException(
                    status_code=409,
                    detail={"reason": "checkpoint_disabled", "job_ids": unresolved},
                )
        if quit_settings.action == "kill" and quit_settings.kill_incomplete_bundles == "delete":
            if not choices.confirm_delete:
                raise HTTPException(
                    status_code=409,
                    detail={"reason": "confirm_delete", "job_ids": [job.id for job in generations]},
                )
        studio.set_intent(
            ControlIntent(
                action=quit_settings.action,
                settings=controller_settings(studio.settings),
                authoring_turns=quit_settings.authoring_turns,
                generation_exceptions=choices.generation_exceptions,
            )
        )
        if quit_settings.authoring_turns == "stop":
            studio.schedule_authoring_stop()
        await studio.emit("session", "session.closed", {"action": studio.intent.action})
        waiting = quit_settings.action == "pause" and quit_settings.pause_close_timing == "wait"
        return {"status": "waiting" if waiting else "close action handed off"}

    @app.get("/v1/session/close-status")
    def close_status(studio: StudioService = Depends(authorized)) -> dict[str, Any]:
        running = [
            job
            for job in studio.jobs.load_generations()
            if job.status == "running"
            and studio.intent.generation_exceptions.get(job.id) != "continue"
        ]
        failures = [
            {"id": job.id, "detail": job.status_message}
            for job in running
            if job.status_message.startswith("Pause request failed")
        ]
        return {"ready": not running, "running": [job.id for job in running], "failures": failures}

    @app.post("/v1/session/cancel-close")
    async def cancel_close(studio: StudioService = Depends(authorized)) -> dict[str, str]:
        studio.set_intent(
            ControlIntent(action="open", settings=controller_settings(studio.settings))
        )
        return {"status": "close cancelled"}

    @app.post("/v1/session/open")
    async def open_window(studio: StudioService = Depends(authorized)) -> dict[str, str]:
        if studio.intent.action != "pause":
            studio.set_intent(
                ControlIntent(action="open", settings=controller_settings(studio.settings))
            )
        return {"status": "window attached"}

    return app
