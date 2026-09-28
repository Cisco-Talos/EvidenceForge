"""Durable state for the local desktop prototype."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ChatRecord(BaseModel):
    """One authoring tab and its Codex conversation."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    thread_id: str | None = None
    skill_name: str = "eforge-scenario"


class GenerationJob(BaseModel):
    """One independently running CLI generation."""

    model_config = ConfigDict(extra="forbid")

    id: str
    scenario: Path
    output_root: Path
    progress_file: Path
    log_file: Path
    pid: int
    process_created_at: float
    started_at: float
    status: Literal["running", "completed", "stopped"] = "running"


class DesktopState(BaseModel):
    """User-owned desktop library metadata; authored files remain authoritative."""

    model_config = ConfigDict(extra="forbid")

    workspace: Path
    output_directory: Path | None = None
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
        return DesktopState.model_validate(data)

    def save(self, state: DesktopState) -> None:
        """Replace saved state without exposing a partial JSON document."""
        self.directory.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".json.tmp")
        temporary.write_text(state.model_dump_json(indent=2), encoding="utf-8")
        os.replace(temporary, self.path)
