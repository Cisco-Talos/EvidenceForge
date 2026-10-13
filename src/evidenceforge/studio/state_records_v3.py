"""Frozen database v3 chat records and settings v2 reader."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.studio.state_records_v1 import StudioSettings as StudioSettingsV1


class StudioSettings(StudioSettingsV1):
    """Settings v2 adds the active follow-up default."""

    chat_followup_mode: Literal["queue", "steer"] = "queue"


class ChatResult(BaseModel):
    """A source-local file observed changing during one turn."""

    model_config = ConfigDict(extra="forbid")
    id: str
    path: str
    kind: str = "modified"
    diff: str | None = None
    item_id: str | None = None
    item_kind: Literal["scenario", "industry_pack", "organization_pack"] | None = None


class ChatTurn(BaseModel):
    """Retained turn identity, item projection and terminal observations."""

    model_config = ConfigDict(extra="forbid")
    id: str
    conversation_id: str
    thread_id: str
    status: str = "inProgress"
    started_at: float | None = None
    completed_at: float | None = None
    duration_ms: float | None = None
    error: dict[str, Any] | None = None
    items: list[dict[str, Any]] = Field(default_factory=list)
    results: list[ChatResult] = Field(default_factory=list)
    source_path: str | None = None
    source_sha256: str | None = None


class ChatInput(BaseModel):
    """A durable dispatch claim; uncertain work must never be blindly replayed."""

    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=128)
    conversation_id: str
    text: str = Field(min_length=1)
    mode: Literal["start", "queue", "steer"]
    skill_name: str | None = None
    expected_turn_id: str | None = None
    state: Literal["queued", "dispatching", "accepted", "uncertain", "rejected"] = "queued"
    turn_id: str | None = None
    created_at: float
    error: str | None = None


class ChatAnchor(BaseModel):
    """A reading position remains valid when transcript rows change height."""

    model_config = ConfigDict(extra="forbid")
    turn_id: str
    item_id: str
    offset: float = 0


class ChatDraftSubmission(BaseModel):
    """Retain the composer's dispatch identity across navigation or lost responses."""

    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=128)
    text: str
    mode: Literal["start", "queue", "steer"]


class ChatViewState(BaseModel):
    """Private composer and reading state, independent of authored files."""

    model_config = ConfigDict(extra="forbid")
    draft: str = ""
    skill_name: str = ""
    follow_bottom: bool = True
    anchor: ChatAnchor | None = None
    answers: dict[str, dict[str, str]] = Field(default_factory=dict)
    pending_message: ChatDraftSubmission | None = None


class ChatControl(BaseModel):
    """Queue and view state for one conversation."""

    model_config = ConfigDict(extra="forbid")
    conversation_id: str
    queue_paused: bool = False
    view: ChatViewState = Field(default_factory=ChatViewState)


class ChatPreference(BaseModel):
    """Workspace-scoped conversation rail preference."""

    model_config = ConfigDict(extra="forbid")
    workspace: str
    sidebar_collapsed: bool = False
