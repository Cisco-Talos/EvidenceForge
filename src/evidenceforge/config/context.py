# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit, portable configuration contexts shared by every EvidenceForge client."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from evidenceforge.models.exceptions import ConfigurationError


class ConfigurationContextError(ConfigurationError):
    """An explicitly selected configuration context is invalid or unavailable."""


class OverlayReference(BaseModel):
    """One directory of partial configuration YAML, applied after the base overlay."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str = Field(min_length=1, max_length=80, pattern=r"^[^\r\n]+$")
    path: Path


class ConfigurationContext(BaseModel):
    """Versioned file contract; all paths are relative to the declaring context file."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    context_version: Literal["1.0"] = "1.0"
    project_root: Path
    overlays: list[OverlayReference] = Field(default_factory=list, max_length=16)

    @model_validator(mode="after")
    def unique_names(self) -> ConfigurationContext:
        """Require useful, unambiguous provenance labels."""
        names = [layer.name.casefold().strip() for layer in self.overlays]
        if any(not name for name in names) or len(set(names)) != len(names):
            raise ValueError("Overlay names must be nonblank and unique")
        return self


class SelectedContext(BaseModel):
    """Resolved paths for one explicit invocation; never discovered from Studio state."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    project_root: Path
    path: Path | None = None
    overlays: list[OverlayReference] = Field(default_factory=list)


def select_context(
    project_root: Path | None = None, context: Path | None = None
) -> SelectedContext:
    """Select CWD/explicit root as before, or resolve one explicitly supplied context file."""
    if context is None:
        return SelectedContext(project_root=(project_root or Path.cwd()).resolve())
    path = context.expanduser().absolute()
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024**2:
            raise ConfigurationContextError("Choose a regular context YAML file smaller than 1 MiB")
        path = path.resolve()
        document = ConfigurationContext.model_validate(
            yaml.safe_load(path.read_text(encoding="utf-8"))
        )
        root = (path.parent / document.project_root.expanduser()).resolve()
        if not root.is_dir():
            raise ConfigurationContextError(f"Context project_root is not a directory: {root}")
        if project_root is not None and project_root.expanduser().resolve() != root:
            raise ConfigurationContextError(
                "--project-root conflicts with the context's project_root; select one root"
            )
        layers: list[OverlayReference] = []
        seen = {root / ".eforge" / "config"}
        for reference in document.overlays:
            directory = path.parent / reference.path.expanduser()
            if any(part.is_symlink() for part in (directory, *directory.parents)):
                raise ConfigurationContextError(
                    f"Overlay directory cannot be a symlink: {directory}"
                )
            directory = directory.resolve()
            if not directory.is_dir():
                raise ConfigurationContextError(
                    f"Overlay '{reference.name}' is missing: {directory}. Restore it or edit the context"
                )
            if directory in seen:
                raise ConfigurationContextError(f"Overlay directory is selected twice: {directory}")
            seen.add(directory)
            layers.append(reference.model_copy(update={"path": directory}))
        return SelectedContext(project_root=root, path=path, overlays=layers)
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError) as exc:
        raise ConfigurationContextError(f"Cannot read configuration context {path}: {exc}") from exc


def context_fingerprint(selection: SelectedContext) -> str:
    """Fingerprint the selected file and ordered layer bytes, including empty-directory identity."""
    entries: list[tuple[str, str]] = []
    if selection.path is not None:
        entries.append(("context", hashlib.sha256(selection.path.read_bytes()).hexdigest()))
    for reference in selection.overlays:
        entries.append((reference.name, str(reference.path)))
        for path in sorted(reference.path.rglob("*.yaml")):
            if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
                raise ConfigurationContextError(
                    f"Overlay file escapes its selected directory: {path}"
                )
            entries.append(
                (
                    f"{reference.name}/{path.relative_to(reference.path).as_posix()}",
                    _file_digest(path),
                )
            )
    return hashlib.sha256(json.dumps(entries).encode()).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            digest.update(chunk)
    return digest.hexdigest()
