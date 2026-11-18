# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""The one way EvidenceForge opens SQLite database files.

SQLite's Windows VFS opens files by path and cannot open a path longer than MAX_PATH unless it is
spelled in the extended-length ``\\\\?\\`` form, which deep workspaces, drafts and private journals
routinely exceed. Every database open goes through :func:`connect_sqlite` so the physical spelling
is applied in one place; POSIX opens are unchanged.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

from evidenceforge._windows_paths import filesystem_path

SqliteOpenMode = Literal["ro", "rw", "rwc"]
MEMORY_DATABASE = ":memory:"


def sqlite_target(path: Path | str, mode: SqliteOpenMode | None = None) -> tuple[str, bool]:
    """Return the SQLite filename and whether it is a URI for one database path.

    ``mode`` restricts how the file may be opened (``rw`` never creates a missing file). With no
    mode the default read/write/create semantics apply. ``:memory:`` is returned unchanged.
    """
    if str(path) == MEMORY_DATABASE:
        return MEMORY_DATABASE, False
    query = f"?mode={mode}" if mode is not None else ""
    if os.name == "nt":
        # The extended-length spelling bypasses MAX_PATH; quoting keeps "?" and "\" literal.
        return f"file:{quote(str(filesystem_path(Path(path))))}{query}", True
    if mode is None:
        return str(path), False
    return f"{Path(path).absolute().as_uri()}{query}", True


def connect_sqlite(
    path: Path | str, *, mode: SqliteOpenMode | None = None, **options: Any
) -> sqlite3.Connection:
    """Open one SQLite database with long-path-safe Windows spelling.

    Args:
        path: Database file path, or ``:memory:``.
        mode: Optional SQLite URI open mode; ``rw`` requires an existing file.
        **options: Other ``sqlite3.connect`` keyword arguments, such as ``timeout``.
    """
    target, uri = sqlite_target(path, mode)
    return sqlite3.connect(target, uri=uri, **options)
