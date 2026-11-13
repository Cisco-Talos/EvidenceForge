# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Windows filesystem spelling beyond the legacy path limit."""

import os
from pathlib import Path


def filesystem_path(path: Path) -> Path:
    """Spell a physical I/O path without changing its logical/public identity.

    Use only at filesystem boundaries, after the caller's normal path validation.
    This does not validate containment, permissions, links or component lengths.
    POSIX paths retain their existing spelling and relative-path behavior.
    """
    if os.name != "nt":
        return path
    absolute = os.path.abspath(path)
    if absolute.startswith("\\\\?\\"):
        return Path(absolute)
    if absolute.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + absolute[2:])
    return Path("\\\\?\\" + absolute)


def package_resource_path(path: Path) -> Path:
    """Keep bundled data readable without requiring Windows long-path policy changes."""
    return filesystem_path(path)


def resolve_path(path: Path, *, strict: bool = False) -> Path:
    """Resolve through Windows long-path I/O while retaining the caller's namespace."""
    resolved = filesystem_path(path).resolve(strict=strict)
    if os.name != "nt" or str(path).startswith("\\\\?\\"):
        return resolved
    spelling = str(resolved)
    if spelling.startswith("\\\\?\\UNC\\"):
        return Path("\\\\" + spelling[8:])
    if spelling.startswith("\\\\?\\"):
        return Path(spelling[4:])
    return resolved
