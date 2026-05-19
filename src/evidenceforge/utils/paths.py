# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Centralized path safety utilities for EvidenceForge.

Provides sanitization and containment validation for filesystem paths
constructed from external data (scenario YAML, overlay configs, etc.).
Prevents path traversal, symlink attacks, and arbitrary file writes.
"""

import logging
import os
import re
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Valid hostname/component pattern: alphanumeric, dots, hyphens, underscores
_SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def sanitize_path_component(name: str) -> str:
    """Sanitize a single path component (hostname, username, sensor name, etc.).

    Returns the sanitized name, or empty string if the input is unsafe.
    An empty return signals the caller to fall back to a safe default
    (e.g., flat-file output instead of per-host directories).

    Rejects:
    - Empty/whitespace-only strings
    - Path separators (/ or \\)
    - Traversal sequences (..)
    - Characters outside [A-Za-z0-9._-]
    """
    candidate = name.strip()
    if not candidate:
        return ""
    if "/" in candidate or "\\" in candidate:
        logger.warning("Path component rejected (contains separator): %r", name)
        return ""
    if ".." in candidate:
        logger.warning("Path component rejected (contains traversal): %r", name)
        return ""
    if not _SAFE_COMPONENT_RE.fullmatch(candidate):
        logger.warning("Path component rejected (invalid characters): %r", name)
        return ""
    return candidate


def safe_path_join(base: Path, *components: str) -> Path | None:
    """Join path components onto a base directory with containment validation.

    Returns the resolved path if it's safely contained within base.
    Returns None if any component is unsafe or the result escapes base.

    Each component is sanitized individually before joining.
    """
    parts = []
    for comp in components:
        safe = sanitize_path_component(comp)
        if not safe:
            return None
        parts.append(safe)

    result = base
    for part in parts:
        result = result / part

    # Verify containment: resolved path must be inside resolved base
    try:
        result_resolved = result.resolve()
        base_resolved = base.resolve()
        result_resolved.relative_to(base_resolved)
    except (ValueError, OSError):
        logger.warning("Path containment check failed: %s is not inside %s", result, base)
        return None

    return result


def reject_symlink(path: Path) -> None:
    """Raise PermissionError if path is a symlink.

    Checks is_symlink() first (works for dangling symlinks where
    exists() returns False).
    """
    if path.is_symlink():
        raise PermissionError(f"Refusing to use symlinked path: {path}")


def safe_write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    """Atomically write text to a regular file without following target symlinks.

    The destination path itself is never opened for writing, so a symlink at
    that location cannot redirect output outside the intended directory. A
    temporary regular file is created in the destination directory and then
    atomically replaces the destination path. Dangling symlinks are rejected
    before the temporary file is created; if a symlink appears before the final
    replace, the replace unlinks the symlink rather than following it.

    Args:
        path: Destination file path.
        content: Text content to write.
        encoding: Text encoding to use.

    Raises:
        PermissionError: If the destination path is a symlink.
        OSError: If the temporary file cannot be created, written, or moved.
    """
    reject_symlink(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding=encoding,
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_name = temp_file.name
            temp_file.write(content)
            temp_file.flush()
            os.fsync(temp_file.fileno())

        os.replace(temp_name, path)
        temp_name = None
    finally:
        if temp_name is not None:
            try:
                Path(temp_name).unlink()
            except FileNotFoundError:
                pass
