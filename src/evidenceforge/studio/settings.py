"""Global settings for the local Studio service."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from evidenceforge.studio.paths import StudioPaths, default_workspace


class QuitSettings(BaseModel):
    """Actions selected for the next desktop-window close."""

    model_config = ConfigDict(extra="forbid")

    action: Literal["continue", "pause", "kill"] = "continue"
    continue_queued_generations: bool = True
    continue_evaluations: Literal["continue", "hold", "manual"] = "continue"
    pause_close_timing: Literal["handoff", "wait"] = "handoff"
    pause_evaluations: Literal["finish", "restart"] = "finish"
    kill_incomplete_bundles: Literal["preserve", "delete"] = "preserve"
    authoring_turns: Literal["stop", "finish"] = "stop"


class StudioSettings(BaseModel):
    """Persistent user preferences that do not belong in an authored project."""

    model_config = ConfigDict(extra="forbid")

    workspace: Path = Field(default_factory=default_workspace)
    recent_workspaces: list[Path] = Field(default_factory=list)
    output_parents: dict[str, Path] = Field(default_factory=dict)
    max_concurrent_generations: int = Field(default=2, ge=1, le=16)
    checkpoint_hours: int = Field(default=24, ge=0)
    quit: QuitSettings = Field(default_factory=QuitSettings)
    skill_install_scope: Literal["global", "workspace"] = "global"
    skill_install_agent: Literal["all", "chatgpt", "claude"] = "all"
    codex_path: Path | None = None
    eforge_path: Path | None = None

    @field_validator("output_parents")
    @classmethod
    def resolve_output_parents(cls, value: dict[str, Path]) -> dict[str, Path]:
        """Use canonical paths for both actual run destinations and cached forecasts."""
        return {
            str(Path(workspace).expanduser().resolve()): parent.expanduser().resolve()
            for workspace, parent in value.items()
        }


class SettingsStore:
    """Atomically save global settings outside the workspace."""

    def __init__(self, paths: StudioPaths) -> None:
        self.path = paths.settings_file

    def load(self) -> StudioSettings:
        """Load user preferences or return first-run defaults."""
        if not self.path.is_file():
            return StudioSettings()
        return StudioSettings.model_validate_json(self.path.read_text(encoding="utf-8"))

    def save(self, settings: StudioSettings) -> None:
        """Write validated settings without leaving a partial document."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f"{self.path.name}.{os.getpid()}.tmp")
        temporary.write_text(settings.model_dump_json(indent=2), encoding="utf-8")
        os.replace(temporary, self.path)


def settings_payload(settings: StudioSettings) -> dict[str, object]:
    """Return a JSON-compatible settings object for API responses."""
    return json.loads(settings.model_dump_json())
