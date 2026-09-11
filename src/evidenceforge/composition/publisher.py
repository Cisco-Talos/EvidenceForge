# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit publisher identity configuration for pack authoring."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.models.exceptions import PackError

from .models import PUBLISHER_ID_PATTERN

PublisherScope = Literal["user", "project"]


class PublisherIdentity(BaseModel):
    """One configured, non-cryptographic publisher namespace."""

    publisher_schema_version: Literal["1.0"] = "1.0"
    publisher: str = Field(pattern=PUBLISHER_ID_PATTERN)
    publisher_display_name: str = Field(min_length=1, max_length=120)

    model_config = ConfigDict(extra="forbid", frozen=True)


class PublisherIdentityRequiredError(PackError):
    """Pack authoring requires an explicitly configured publisher identity."""


def publisher_path(project_root: Path, scope: PublisherScope) -> Path:
    """Return the configured publisher path for a scope."""

    if scope == "project":
        return project_root.resolve() / ".eforge" / "publisher.yaml"
    return Path.home() / ".eforge" / "publisher.yaml"


def _read_identity(path: Path) -> PublisherIdentity | None:
    if path.is_symlink():
        raise PackError(f"publisher configuration cannot be a symlink: {path}")
    if not path.exists():
        return None
    if not path.is_file():
        raise PackError(f"publisher configuration is not a regular file: {path}")
    try:
        return PublisherIdentity.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise PackError(f"invalid publisher configuration {path}: {exc}") from exc


def effective_publisher(
    project_root: Path, *, required: bool = False
) -> tuple[PublisherIdentity | None, PublisherScope | None]:
    """Load project-over-user publisher identity without deriving a fallback."""

    project = _read_identity(publisher_path(project_root, "project"))
    if project is not None:
        return project, "project"
    user = _read_identity(publisher_path(project_root, "user"))
    if user is not None:
        return user, "user"
    if required:
        raise PublisherIdentityRequiredError(
            "publisher identity is required; run 'eforge pack publisher set <id> "
            "--display-name <name> --scope user|project'"
        )
    return None, None


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or path.is_symlink():
        raise PackError(f"publisher configuration path cannot contain a symlink: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    except OSError as exc:
        temporary_path.unlink(missing_ok=True)
        raise PackError(f"unable to write publisher configuration {path}: {exc}") from exc


def set_publisher(
    project_root: Path,
    identity: PublisherIdentity,
    *,
    scope: PublisherScope,
    force: bool,
) -> Path:
    """Atomically set one publisher identity, requiring force for replacement."""

    path = publisher_path(project_root, scope)
    existing = _read_identity(path)
    if existing is not None and existing != identity and not force:
        raise PackError(f"publisher identity already exists at {path}; use --force to replace it")
    _atomic_write(
        path,
        yaml.safe_dump(identity.model_dump(mode="json"), sort_keys=False).encode("utf-8"),
    )
    return path


def clear_publisher(project_root: Path, *, scope: PublisherScope) -> tuple[Path, bool]:
    """Clear one exact publisher scope without touching its fallback scope."""

    path = publisher_path(project_root, scope)
    if path.is_symlink():
        raise PackError(f"publisher configuration cannot be a symlink: {path}")
    existed = path.is_file()
    if existed:
        path.unlink()
    return path, existed
