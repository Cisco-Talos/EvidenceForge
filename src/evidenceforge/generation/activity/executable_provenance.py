# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Decide whether an executable already exists before a storyline launches it."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_PROVENANCE_PATH = get_activity_directory() / "executable_provenance.yaml"
_CACHED_EXECUTABLE_PROVENANCE: ExecutableProvenance | None = None


class PreinstalledPrefixes(BaseModel):
    """Per-platform path prefixes whose executables predate the window."""

    windows: tuple[str, ...] = ()
    linux: tuple[str, ...] = ()
    macos: tuple[str, ...] = ()

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("windows", "linux", "macos")
    @classmethod
    def normalize(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Compare case-insensitively and reject empty prefixes."""
        if any(not value.strip() for value in values):
            raise ValueError("preinstalled prefixes must be non-empty")
        return tuple(value.casefold() for value in values)


class ExecutableProvenance(BaseModel):
    """Validated executable-provenance policy."""

    schema_version: str = Field(min_length=1)
    preinstalled_prefixes: PreinstalledPrefixes

    model_config = ConfigDict(frozen=True, extra="forbid")


def load_executable_provenance() -> ExecutableProvenance:
    """Load the provenance policy merged with overlays. Cached after first call."""
    global _CACHED_EXECUTABLE_PROVENANCE
    if _CACHED_EXECUTABLE_PROVENANCE is None:
        data = load_with_overlay(
            _PROVENANCE_PATH, "activity/executable_provenance.yaml", deep_merge_dict
        )
        _CACHED_EXECUTABLE_PROVENANCE = ExecutableProvenance.model_validate(data)
    return _CACHED_EXECUTABLE_PROVENANCE


def _comparable(path: str, os_category: str) -> str:
    return path.replace("/", "\\").casefold() if os_category == "windows" else path.casefold()


def executable_preexists(image: str, os_category: str, username: str = "") -> bool:
    """Return whether an image is installed before the simulated window.

    True for images under a preinstalled prefix, catalogued application installs
    and catalogued system binaries. A bare (pathless) name is resolved by the
    launcher from the search path, so it is treated as installed as well.
    """
    if os_category not in {"windows", "linux", "macos"}:
        return True
    separator = "\\" if os_category == "windows" else "/"
    normalized = image.replace("/", "\\") if os_category == "windows" else image
    if separator not in normalized:
        return True
    comparable = _comparable(normalized, os_category)
    prefixes: tuple[str, ...] = getattr(
        load_executable_provenance().preinstalled_prefixes, os_category
    )
    if comparable.startswith(prefixes):
        return True
    basename = normalized.rsplit(separator, 1)[-1]
    from evidenceforge.generation.activity.application_catalog import resolve_image_path
    from evidenceforge.generation.activity.system_processes import get_system_binary_path

    try:
        catalogued = resolve_image_path(
            basename, os_category, username=username, allow_fallback=False
        )
    except ValueError:
        catalogued = ""
    if catalogued and _comparable(catalogued, os_category) == comparable:
        return True
    system_path = get_system_binary_path(basename, username=username or None)
    return bool(system_path) and _comparable(system_path, os_category) == comparable


__all__ = [
    "ExecutableProvenance",
    "PreinstalledPrefixes",
    "executable_preexists",
    "load_executable_provenance",
]
