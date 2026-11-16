"""Frozen database v4 example-installation records."""

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class InstalledExample(BaseModel):
    """Retain exact imported identity and a restartable index-assignment intent."""

    model_config = ConfigDict(extra="forbid")

    family: str
    path: Path
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    project_id: str | None
    indexed: bool = False


class ExampleInstallation(BaseModel):
    """Per-user, per-workspace enrollment; absence never implies first run."""

    model_config = ConfigDict(extra="forbid")

    workspace: Path
    automatic: bool = False
    project_id: str
    project_created: bool = False
    manual_pending: bool = False
    regroup_pending: bool = False
    excluded: set[str] = Field(default_factory=set)
    installed: dict[str, InstalledExample] = Field(default_factory=dict)
    collection_digest: str = ""
    error: str = ""
