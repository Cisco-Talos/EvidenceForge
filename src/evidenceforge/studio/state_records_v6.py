"""Frozen database version 6 project records; earlier readers remain unchanged."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.studio.state_records_v1 import Project as ProjectV1


class ProjectDefaultPack(BaseModel):
    """An exact released pack offered to new authoring in one project."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["industry", "organization"]
    publisher: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    name: str = Field(min_length=1, max_length=128)
    version: str = Field(pattern=r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


class Project(ProjectV1):
    """A project may name one default pack for scenarios authored in Studio."""

    default_pack: ProjectDefaultPack | None = None
