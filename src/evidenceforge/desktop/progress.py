"""Interpret generation progress events without depending on Qt."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ProgressEvent(BaseModel):
    """One versioned line from ``eforge generate --progress-jsonl``."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(ge=1, le=1)
    event: str
    data: dict[str, Any]


class GenerationProgress(BaseModel):
    """Latest display state of a generation job."""

    phase: str = "Queued"
    completed_hours: int = 0
    total_hours: int = 0
    warmup_hours: int = 0
    storyline_event: int = 0
    storyline_total: int = 0
    detail: str = "Waiting for progress"

    def apply(self, event: ProgressEvent) -> None:
        """Update the GUI's bars from one canonical engine event."""
        data = event.data
        if event.event == "phase_start":
            self.phase = str(data.get("phase", "working")).replace("_", " ").title()
            self.detail = str(data.get("description", self.phase))
        elif event.event in {"warmup_progress", "hour_progress"}:
            self.completed_hours = int(data["completed_simulated_hours"])
            self.total_hours = int(data["total_simulated_hours"])
            if event.event == "warmup_progress":
                self.warmup_hours = int(data["total_hours"])
            phase = "Warm-up" if event.event == "warmup_progress" else "Collection"
            self.phase = phase
            self.detail = f"{phase} hour {data['hour']} of {data['total_hours']}"
        elif event.event == "storyline_progress":
            self.storyline_event = int(data["event_num"])
            self.storyline_total = int(data["total_events"])
            self.detail = (
                f"Storyline event {self.storyline_event} of {self.storyline_total}: "
                f"{data['actor']} on {data['system']}"
            )
        elif event.event == "phase_end":
            phase = str(data.get("phase", ""))
            if phase == "warmup" and self.warmup_hours:
                self.completed_hours = max(self.completed_hours, self.warmup_hours)
            elif phase == "baseline" and self.total_hours:
                self.completed_hours = self.total_hours
            elif phase == "storyline" and self.storyline_total:
                self.storyline_event = self.storyline_total
            self.phase = f"{phase.replace('_', ' ').title()} complete"
            self.detail = self.phase
        elif event.event == "suspension_requested":
            self.detail = "Suspending after the current simulated hour"


def parse_progress_line(line: str) -> ProgressEvent | None:
    """Ignore incomplete or unknown progress lines while tailing a live file."""
    try:
        return ProgressEvent.model_validate(json.loads(line))
    except (json.JSONDecodeError, ValueError):
        return None
