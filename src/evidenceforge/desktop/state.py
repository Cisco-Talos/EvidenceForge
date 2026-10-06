"""Shared CLI job models and readers for retained desktop state."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ChatRecord(BaseModel):
    """One authoring tab and its Codex conversation."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    conversation_title: str | None = None
    thread_id: str | None = None
    skill_name: str = "eforge-scenario"
    context_path: Path | None = None
    context_kind: Literal["scenario", "industry pack", "organization pack"] | None = None
    model_id: str | None = None
    reasoning_effort: str | None = None
    open: bool = True


class GenerationJob(BaseModel):
    """One independently running CLI generation."""

    model_config = ConfigDict(extra="forbid")

    id: str
    scenario: Path
    output_root: Path
    progress_file: Path
    progress_history: list[Path] = Field(default_factory=list)
    log_file: Path
    pid: int = 0
    process_created_at: float = 0.0
    started_at: float
    submitted_at: float | None = None
    status: Literal[
        "queued", "running", "completed", "stopped", "paused", "failed", "cancelled"
    ] = "running"
    workspace: Path | None = None
    command: list[str] = Field(default_factory=list)
    checkpoint_hours: int = 24
    owned_output: bool = False
    status_message: str = ""
    source_sha256: str | None = None
    dependency_sha256: str | None = None
    input_snapshot: Path | None = None
    input_sha256: str | None = None
    compiled_sha256: str | None = None


class EvaluationJob(BaseModel):
    """One durable evaluation of a generated bundle."""

    model_config = ConfigDict(extra="forbid")

    id: str
    generation_id: str
    workspace: Path
    output_root: Path
    result_file: Path
    log_file: Path
    command: list[str]
    created_at: float
    pid: int = 0
    process_created_at: float = 0.0
    status: Literal["queued", "running", "completed", "paused", "failed", "cancelled"] = "queued"
    status_message: str = ""


class AppSettings(BaseModel):
    """Persistent desktop preferences with safe defaults for existing state."""

    model_config = ConfigDict(extra="forbid")

    close_action: Literal["continue", "pause", "kill"] = "continue"
    continue_queued_generations: bool = True
    continue_evaluations: Literal["continue", "hold", "manual"] = "continue"
    pause_close_timing: Literal["handoff", "wait"] = "handoff"
    pause_evaluations: Literal["finish", "restart"] = "finish"
    kill_incomplete_bundles: Literal["preserve", "delete"] = "preserve"
    skill_install_scope: Literal["global", "workspace"] = "global"
    skill_install_agent: Literal["all", "chatgpt", "claude"] = "all"
    remember_library_view: bool = True
    max_concurrent_generations: int = Field(default=2, ge=1, le=16)
    codex_path: Path | None = None
    eforge_path: Path | None = None

    @model_validator(mode="before")
    @classmethod
    def migrate_default_skill(cls, value: object) -> object:
        """Discard the redundant global skill preference in older state files."""
        if isinstance(value, dict):
            return {key: item for key, item in value.items() if key != "default_authoring_skill"}
        return value


class ScenarioFolders(BaseModel):
    """Virtual folders and scenario assignments for one workspace."""

    model_config = ConfigDict(extra="forbid")

    names: list[str] = Field(default_factory=list)
    assignments: dict[str, str] = Field(default_factory=dict)


class LibraryView(BaseModel):
    """One reusable scenario search and filter combination."""

    model_config = ConfigDict(extra="forbid")

    name: str = ""
    search: str = ""
    run_filter: str = "all"
    version_filter: str | None = None
    show_hidden: bool = False
    selected_folder: str | None = None


class WorkspaceLibraryViews(BaseModel):
    """Saved and last-used scenario views for one workspace."""

    model_config = ConfigDict(extra="forbid")

    saved: list[LibraryView] = Field(default_factory=list)
    last: LibraryView = Field(default_factory=LibraryView)


class DesktopState(BaseModel):
    """User-owned desktop library metadata; authored files remain authoritative."""

    model_config = ConfigDict(extra="forbid")

    workspace: Path
    output_directory: Path | None = None
    output_directories: dict[str, Path] = Field(default_factory=dict)
    settings: AppSettings = Field(default_factory=AppSettings)
    imported_scenarios: list[Path] = Field(default_factory=list)
    hidden_items: list[Path] = Field(default_factory=list)
    scenario_folders: dict[str, ScenarioFolders] = Field(default_factory=dict)
    library_views: dict[str, WorkspaceLibraryViews] = Field(default_factory=dict)
    chats: list[ChatRecord] = Field(default_factory=list)
    jobs: list[GenerationJob] = Field(default_factory=list)


def state_directory() -> Path:
    """Find the platform's application-data directory, with a test override."""
    override = os.environ.get("EFORGE_DESKTOP_STATE_DIR")
    if override:
        return Path(override).expanduser().resolve()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "EvidenceForge"
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", Path.home())) / "EvidenceForge"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "evidenceforge"


class StateStore:
    """Atomically load and save desktop state outside generated bundles."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory.resolve()
        self.path = self.directory / "desktop-state.json"

    def load(self, default_workspace: Path) -> DesktopState:
        """Load saved state, or create a new empty workspace record."""
        if not self.path.exists():
            return DesktopState(workspace=default_workspace.resolve())
        data = json.loads(self.path.read_text(encoding="utf-8"))
        state = DesktopState.model_validate(data)
        if state.output_directory is not None:
            state.output_directories.setdefault(str(state.workspace), state.output_directory)
        return state

    def save(self, state: DesktopState) -> None:
        """Replace saved state without exposing a partial JSON document."""
        self.directory.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".json.tmp")
        temporary.write_text(state.model_dump_json(indent=2), encoding="utf-8")
        os.replace(temporary, self.path)
