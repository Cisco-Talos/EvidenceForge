"""Bounded filesystem, hashing, and serialization helpers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

MAX_TEXT_BYTES = 2_000_000
REDACTION_PATTERNS = (
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/-]+"),
    re.compile(r"(?i)(api[_-]?key|token|authorization|password)(\s*[=:]\s*)([^\s,;]+)"),
)


def sha256_bytes(value: bytes) -> str:
    """Return a lowercase SHA-256 digest."""

    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    """Hash a regular file without following a symlink."""

    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected a regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def digest_tree(root: Path, *, include: tuple[str, ...] = ("*",)) -> str:
    """Hash relative names and contents for a bounded regular-file tree."""

    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"expected a regular directory: {root}")
    digest = hashlib.sha256()
    files = sorted({path for pattern in include for path in root.rglob(pattern) if path.is_file()})
    for path in files:
        if path.is_symlink():
            raise ValueError(f"refusing to hash symlink: {path}")
        relative = path.relative_to(root).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        content = path.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def redact_text(value: str) -> str:
    """Remove common credential forms and bound captured provider output."""

    bounded = value.encode("utf-8", errors="replace")[:MAX_TEXT_BYTES].decode(
        "utf-8", errors="replace"
    )
    for pattern in REDACTION_PATTERNS:
        if "bearer" in pattern.pattern.lower():
            bounded = pattern.sub("Bearer [REDACTED]", bounded)
        else:
            bounded = pattern.sub(r"\1\2[REDACTED]", bounded)
    return bounded.encode("utf-8", errors="replace")[:MAX_TEXT_BYTES].decode(
        "utf-8", errors="ignore"
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON deterministically."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def atomic_write_json(path: Path, value: Any) -> None:
    """Atomically replace a JSON file without traversing a symlink."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError(f"refusing to replace symlink: {path}")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, default=str)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def contained_path(root: Path, candidate: Path) -> Path:
    """Resolve a path and require it to remain beneath root."""

    resolved_root = root.resolve()
    resolved = candidate.resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ValueError(f"path escapes controlled root: {candidate}")
    return resolved
