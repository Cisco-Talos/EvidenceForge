"""Atomic, per-job records shared by the desktop window and local controller."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.desktop.state import AppSettings, EvaluationJob, GenerationJob


class ControlIntent(BaseModel):
    """Durable close or resume instruction for the local controller."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: uuid4().hex)
    action: Literal["open", "continue", "pause", "kill", "resume"] = "resume"
    settings: AppSettings = Field(default_factory=AppSettings)
    authoring_turns: Literal["stop", "finish"] = "finish"
    generation_exceptions: dict[str, str] = Field(default_factory=dict)
    resume_generation_id: str | None = None


def _write_json(path: Path, value: BaseModel) -> None:
    if os.name == "nt":
        from evidenceforge.utils.windows_filesystem import mkdir_private, write_private_atomic

        mkdir_private(path.parent, parents=True, exist_ok=True)
        write_private_atomic(
            path, value.model_dump_json(indent=2).encode(), replace_open_files=True
        )
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{uuid4().hex}.tmp")
    temporary.write_text(value.model_dump_json(indent=2), encoding="utf-8")
    os.replace(temporary, path)


def _read_json(path: Path) -> str | bytes:
    if os.name == "nt":
        from evidenceforge.utils.windows_filesystem import read_private_file

        return read_private_file(path)
    return path.read_text(encoding="utf-8")


class JobStore:
    """Persist jobs independently so the controller never rewrites GUI state."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory.resolve()
        if os.name == "nt":
            from evidenceforge.utils.windows_filesystem import mkdir_private

            mkdir_private(self.directory, parents=True, exist_ok=True)
            mkdir_private(self.directory / "job-records", exist_ok=True)
        self.generations = self.directory / "job-records" / "generations"
        self.evaluations = self.directory / "job-records" / "evaluations"
        self.control_path = self.directory / "job-records" / "control.json"
        self.acknowledgement_path = self.directory / "job-records" / "ack.json"

    def save_generation(self, job: GenerationJob) -> None:
        """Atomically publish a generation record."""
        _write_json(self.generations / f"{job.id}.json", job)

    def save_evaluation(self, job: EvaluationJob) -> None:
        """Atomically publish an evaluation record."""
        _write_json(self.evaluations / f"{job.id}.json", job)

    def load_generations(self) -> list[GenerationJob]:
        """Load all app-owned generations."""
        return [
            GenerationJob.model_validate_json(_read_json(path))
            for path in sorted(self.generations.glob("*.json"))
        ]

    def load_evaluations(self) -> list[EvaluationJob]:
        """Load all app-owned evaluations."""
        return [
            EvaluationJob.model_validate_json(_read_json(path))
            for path in sorted(self.evaluations.glob("*.json"))
        ]

    def migrate_generations(self, jobs: list[GenerationJob]) -> None:
        """Copy old desktop-state jobs into independent records once."""
        for job in jobs:
            if not (self.generations / f"{job.id}.json").is_file():
                self.save_generation(job)

    def write_control(self, intent: ControlIntent) -> None:
        """Publish the next controller instruction."""
        _write_json(self.control_path, intent)

    def read_control(self) -> ControlIntent:
        """Read the current controller instruction."""
        if not self.control_path.is_file():
            return ControlIntent()
        return ControlIntent.model_validate_json(_read_json(self.control_path))

    def acknowledge(self, intent: ControlIntent) -> None:
        """Confirm that a controller has loaded the durable intent."""
        _write_json(self.acknowledgement_path, intent)

    def acknowledged(self, intent_id: str) -> bool:
        """Check whether the current intent reached the controller."""
        if not self.acknowledgement_path.is_file():
            return False
        try:
            data = json.loads(_read_json(self.acknowledgement_path))
        except (OSError, ValueError):
            return False
        return data.get("id") == intent_id
