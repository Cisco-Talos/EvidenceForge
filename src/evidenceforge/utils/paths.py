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
import stat
import tempfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from io import BufferedReader
from pathlib import Path

from evidenceforge.models.exceptions import PathSafetyError

logger = logging.getLogger(__name__)

# Valid hostname/component pattern: alphanumeric, dots, hyphens, underscores
_SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


def _validated_relative_parts(reference: Path | str, *, label: str) -> tuple[str, ...]:
    """Normalize a relative reference without resolving attacker-controlled links."""

    candidate = Path(reference)
    parts = candidate.parts
    if candidate.is_absolute() or not parts or any(part in {"", ".", ".."} for part in parts):
        raise PathSafetyError(
            f"Unsafe {label}: expected a contained relative path, got {reference!r}"
        )
    return parts


def _validate_open_regular_file(
    file_descriptor: int,
    *,
    path: Path,
    max_bytes: int | None,
    label: str,
) -> None:
    """Validate an already-open descriptor before any bytes are consumed."""

    metadata = os.fstat(file_descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise PathSafetyError(f"Unsafe {label}: expected a regular file: {path}")
    if max_bytes is not None and metadata.st_size > max_bytes:
        raise PathSafetyError(
            f"Unsafe {label}: file exceeds {max_bytes} bytes: {path} ({metadata.st_size} bytes)"
        )


@contextmanager
def open_regular_file_beneath(
    root: Path,
    reference: Path | str,
    *,
    max_bytes: int | None = None,
    label: str = "input file",
) -> Iterator[BufferedReader]:
    """Open a regular file beneath ``root`` without following path-component symlinks."""

    parts = _validated_relative_parts(reference, label=label)
    resolved_root = root.resolve(strict=True)
    display_path = resolved_root.joinpath(*parts)
    descriptors: list[int] = []
    file_descriptor: int | None = None
    try:
        if os.open in os.supports_dir_fd:
            current = os.open(resolved_root, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
            descriptors.append(current)
            for part in parts[:-1]:
                current = os.open(
                    part,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                    dir_fd=current,
                )
                descriptors.append(current)
            file_descriptor = os.open(parts[-1], os.O_RDONLY | _NOFOLLOW, dir_fd=current)
        else:  # pragma: no cover - platforms without openat support
            current_path = resolved_root
            for part in parts:
                current_path /= part
                if current_path.is_symlink():
                    raise PathSafetyError(
                        f"Unsafe {label}: symlinks are not allowed: {current_path}"
                    )
            resolved = current_path.resolve(strict=True)
            if not resolved.is_relative_to(resolved_root):
                raise PathSafetyError(f"Unsafe {label}: path escapes input root: {reference!r}")
            file_descriptor = os.open(resolved, os.O_RDONLY | _NOFOLLOW)

        _validate_open_regular_file(
            file_descriptor,
            path=display_path,
            max_bytes=max_bytes,
            label=label,
        )
        with os.fdopen(file_descriptor, "rb", closefd=True) as handle:
            file_descriptor = None
            yield handle
    except (FileNotFoundError, NotADirectoryError, OSError) as exc:
        raise PathSafetyError(f"Unsafe {label}: cannot open {display_path}: {exc}") from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def read_text_file_beneath(
    root: Path,
    reference: Path | str,
    *,
    max_bytes: int,
    encoding: str = "utf-8",
    label: str = "input file",
) -> str:
    """Read one bounded, regular, non-symlink file below an explicit root."""

    with open_regular_file_beneath(root, reference, max_bytes=max_bytes, label=label) as handle:
        content = handle.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise PathSafetyError(f"Unsafe {label}: content exceeds {max_bytes} bytes")
    try:
        return content.decode(encoding)
    except UnicodeDecodeError as exc:
        raise PathSafetyError(f"Unsafe {label}: content is not valid {encoding}") from exc


def write_exclusive_child_bytes(
    root: Path,
    filename: str,
    content: bytes,
    *,
    label: str = "output artifact",
) -> Path:
    """Create one new regular file below ``root`` without following or replacing links."""

    return write_exclusive_child_stream(root, filename, (content,), label=label)


def write_exclusive_child_stream(
    root: Path,
    filename: str,
    chunks: Iterable[bytes],
    *,
    label: str = "output artifact",
    max_bytes: int | None = None,
) -> Path:
    """Stream one new regular child file and remove partial output after any failure."""

    parts = _validated_relative_parts(filename, label=label)
    if len(parts) != 1:
        raise PathSafetyError(f"Unsafe {label}: expected one filename component, got {filename!r}")
    root_path = root.absolute()
    if max_bytes is not None and max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW
    root_descriptor: int | None = None
    file_descriptor: int | None = None
    created = False
    completed = False
    written = 0
    try:
        root.mkdir(parents=True, exist_ok=True)
        if os.open in os.supports_dir_fd:
            root_descriptor = os.open(root_path, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
            file_descriptor = os.open(
                parts[0],
                flags,
                0o600,
                dir_fd=root_descriptor,
            )
            created = True
        else:  # pragma: no cover - platforms without openat support
            if root_path.is_symlink():
                raise PathSafetyError(f"Unsafe {label}: output directory cannot be a symlink")
            destination = root_path / parts[0]
            file_descriptor = os.open(destination, flags, 0o600)
            created = True
        with os.fdopen(file_descriptor, "wb", closefd=True) as handle:
            file_descriptor = None
            for chunk in chunks:
                written += len(chunk)
                if max_bytes is not None and written > max_bytes:
                    raise PathSafetyError(
                        f"Unsafe {label}: streamed content exceeds {max_bytes} bytes"
                    )
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        completed = True
    except FileExistsError as exc:
        raise PathSafetyError(f"Unsafe {label}: refusing to overwrite {filename!r}") from exc
    except OSError as exc:
        raise PathSafetyError(f"Unsafe {label}: cannot create {filename!r}: {exc}") from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if created and not completed:
            try:
                if root_descriptor is not None and os.unlink in os.supports_dir_fd:
                    os.unlink(parts[0], dir_fd=root_descriptor)
                else:  # pragma: no cover - platforms without unlinkat support
                    (root_path / parts[0]).unlink()
            except FileNotFoundError:
                pass
        if root_descriptor is not None:
            os.close(root_descriptor)
    return root_path / parts[0]


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
