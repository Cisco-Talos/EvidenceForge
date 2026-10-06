"""Immutable migration declarations and bounded, explicit historical transformations."""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from evidenceforge.studio.state_io import StudioStateError


class ContractMigration(BaseModel):
    """Reviewable declaration; changing a released declaration changes its checksum."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(pattern=r"^[a-z0-9-]+$")
    family: Literal["database", "settings", "private_layout", "workspace_layout"]
    source: int = Field(ge=0)
    target: int = Field(ge=1)
    description: str
    incompatible: bool = True
    preconditions: tuple[str, ...] = ("Recognized source version; exclusive ownership",)
    affected: tuple[str, ...] = ()
    postconditions: tuple[str, ...] = ("Target reader accepts every authoritative record",)
    recovery: Literal["verified-images"] = "verified-images"

    @property
    def checksum(self) -> str:
        """Fingerprint all declared behavior, including SQL and JSON transformations."""
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()


class JsonChange(BaseModel):
    """Explicit field operations with frozen literal defaults; no current-model factories."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    action: Literal["rename", "default", "wrap"]
    field: str
    target: str = ""
    literal: str = "null"

    def apply(self, record: dict[str, object]) -> dict[str, object]:
        """Transform one object without regenerating IDs, timestamps or unspecified fields."""
        result = dict(record)
        if self.action == "rename" and self.field in result:
            if self.target in result:
                raise StudioStateError("Historical JSON rename would overwrite an existing field")
            result[self.target] = result.pop(self.field)
        elif self.action == "default":
            result.setdefault(self.field, json.loads(self.literal))
        elif self.action == "wrap":
            envelope = json.loads(self.literal)
            if not isinstance(envelope, dict) or self.field in envelope:
                raise StudioStateError("Invalid frozen settings envelope declaration")
            result = {**envelope, self.field: result}
        return result


class RecordChange(BaseModel):
    """A bounded row-by-row JSON transformation inside the database transaction."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    table: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    column: str = Field(default="payload", pattern=r"^[a-z][a-z0-9_]*$")
    changes: tuple[JsonChange, ...]


class SettingsMigration(ContractMigration):
    """Frozen transformations for the disk envelope, independent of API response shape."""

    family: Literal["settings"] = "settings"
    changes: tuple[JsonChange, ...]

    def apply(self, values: dict[str, object]) -> dict[str, object]:
        """Apply the declared operations in order."""
        for change in self.changes:
            values = change.apply(values)
        return values


SETTINGS_MIGRATIONS = (
    SettingsMigration(
        id="studio-settings-0001",
        source=0,
        target=1,
        description="Wrap preserved preferences in the Studio settings version envelope",
        affected=("settings",),
        changes=(JsonChange(action="wrap", field="settings", literal='{"schema_version":1}'),),
    ),
)
LAYOUT_MIGRATIONS = tuple(
    ContractMigration(
        id=f"studio-{family.replace('_', '-')}-0001",
        family=family,
        source=0,
        target=1,
        description="Adopt existing Studio conventions without relocating engine content",
        incompatible=False,
        affected=("layout",),
        postconditions=("Stable identity and versioned manifest published after declared steps",),
    )
    for family in ("private_layout", "workspace_layout")
)


class FileMove(BaseModel):
    """Exact Studio-owned paths; manifests cannot supply additional destinations."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    source: str
    target: str

    @field_validator("source", "target")
    @classmethod
    def studio_relative(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or ".." in path.parts
            or "\\" in value
            or not value.startswith(".eforge/studio/")
            or path.name in {"layout.json", "owner.lock"}
            or str(path) != value
        ):
            raise ValueError("File moves must name canonical relative Studio-managed files")
        return value


class FilesystemMigration(ContractMigration):
    """Explicit file relocation, staged before publication and recovered by observed images."""

    family: Literal["workspace_layout"] = "workspace_layout"
    moves: tuple[FileMove, ...]

    def stage[T](self, files: dict[str, T | None]) -> dict[str, T | None]:
        """Return a proposed image map; refuse missing sources and occupied destinations."""
        proposed = dict(files)
        for move in self.moves:
            if proposed.get(move.source) is None:
                raise StudioStateError("Declared Studio relocation source is missing")
            if proposed.get(move.target) is not None:
                raise StudioStateError("Declared Studio relocation destination is occupied")
            proposed[move.target], proposed[move.source] = proposed[move.source], None
        return proposed


def ordered_chain(
    migrations: tuple[ContractMigration, ...], family: str, source: int, target: int
) -> tuple[ContractMigration, ...]:
    """Validate a complete, unambiguous consecutive chain, including skipped releases."""
    selected = tuple(entry for entry in migrations if entry.family == family)
    if len({entry.id for entry in migrations}) != len(migrations):
        raise StudioStateError("Studio migration identifiers are duplicated")
    steps: list[ContractMigration] = []
    version = source
    while version < target:
        candidates = [entry for entry in selected if entry.source == version]
        if len(candidates) != 1 or candidates[0].target != version + 1:
            raise StudioStateError("Studio migration chain has a gap or ambiguous transition")
        step = candidates[0]
        steps.append(step)
        version = step.target
    if version != target:
        raise StudioStateError("Unsupported Studio downgrade")
    return tuple(steps)
