"""Frozen readers for unversioned/1.x Studio records. Do not replace with live models.

Validation never serializes these defaults back into retained records. Identity fields
are checked against SQL keys before decoding, so missing identities cannot be synthesized.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class SearchMatch(BaseModel):
    """One matching field or source line, with safe text highlight offsets."""

    model_config = ConfigDict(extra="forbid")

    field: str
    file: str = ""
    line: int = 0
    kind: Literal["metadata", "value", "key", "comment", "text"]
    excerpt: str
    highlights: list[tuple[int, int]] = Field(default_factory=list)


class CatalogItem(BaseModel):
    """Indexed scenario or pack; its source file remains authoritative."""

    model_config = ConfigDict(extra="forbid")

    id: str
    workspace: Path
    kind: Literal["scenario", "industry_pack", "organization_pack"]
    path: Path
    name: str
    description: str = ""
    version: str = ""
    publisher: str = ""
    publisher_display_name: str = ""
    requires_evidenceforge: str = ""
    pack_source: str = ""
    modified_at: float = 0.0
    source_sha256: str = ""
    users: int = 0
    systems: int = 0
    events: int = 0
    folder: str | None = None
    project_id: str | None = None
    hidden: bool = False
    imported: bool = False
    search_excerpt: str = ""
    search_field: str = ""
    search_matches: list[SearchMatch] = Field(default_factory=list)
    search_match_count: int = 0
    search_revision: str = ""


class Project(BaseModel):
    """A workspace-local group of scenarios and packs, independent of file paths."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default="validation-only")
    workspace: Path
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=240)
    overlay_enabled: bool = False
    updated_at: float = Field(default=0.0)


class ImportedBundle(BaseModel):
    """A complete external CLI bundle indexed for read-only inspection."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default="validation-only")
    workspace: Path
    root: Path
    scenario_name: str
    created_at: float
    size_bytes: int
    manifest_sha256: str


class Conversation(BaseModel):
    """One Codex thread associated with a scenario, pack, or draft."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default="validation-only")
    workspace: Path
    item_id: str | None = None
    draft_kind: Literal["scenario", "industry_pack", "organization_pack"] | None = None
    draft_path: Path | None = None
    draft_project_id: str | None = None
    draft_name: str | None = None
    thread_id: str | None = None
    title: str = "New conversation"
    model_id: str | None = None
    reasoning_effort: str | None = None
    active: bool = False
    needs_attention: bool = False
    connection_note: str | None = None
    updated_at: float = Field(default=0.0)


class SavedView(BaseModel):
    """A named workspace library query."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    kind: Literal["scenario", "packs", "industry_pack", "organization_pack"] = "scenario"
    search: str = ""
    folder: str | None = None
    project_id: str | None = None
    ungrouped: bool = False
    show_hidden: bool = False
    publisher: str = Field(default="", max_length=80)
    version: str = Field(default="", max_length=80)
    pack_source: Literal["", "bundled", "workspace"] = ""
    sort: Literal["name", "updated", "project"] = "name"
    expanded_groups: list[str] = Field(default_factory=list, max_length=1000)


class LibraryView(BaseModel):
    """Last selected library controls, independent of authored content."""

    model_config = ConfigDict(extra="forbid")

    search: str = Field(default="", max_length=256)
    project_id: str | None = None
    show_hidden: bool = False
    sort: Literal["name", "updated", "project"] = "name"
    pack_kind: Literal["packs", "industry_pack", "organization_pack"] = "packs"
    publisher: str = Field(default="", max_length=80)
    version: str = Field(default="", max_length=80)
    pack_source: Literal["", "bundled", "workspace"] = ""
    expanded_groups: list[str] = Field(default_factory=list, max_length=1000)


class LibraryPreferences(BaseModel):
    """Workspace-specific recall preference and independent library selections."""

    model_config = ConfigDict(extra="forbid")

    remember_view: bool = True
    scenarios: LibraryView = Field(default_factory=LibraryView)
    packs: LibraryView = Field(default_factory=LibraryView)


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


class ControlIntent(BaseModel):
    """Durable close or resume instruction for the local controller."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default="validation-only")
    action: Literal["open", "continue", "pause", "kill", "resume"] = "resume"
    settings: AppSettings = Field(default_factory=AppSettings)
    authoring_turns: Literal["stop", "finish"] = "finish"
    generation_exceptions: dict[str, str] = Field(default_factory=dict)
    resume_generation_id: str | None = None


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

    workspace: Path = Field(default=Path("."))
    recent_workspaces: list[Path] = Field(default_factory=list)
    output_parents: dict[str, Path] = Field(default_factory=dict)
    max_concurrent_generations: int = Field(default=2, ge=1, le=16)
    search_match_limit: int = Field(default=5, ge=1, le=50)
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
