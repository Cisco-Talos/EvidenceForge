"""Bounded, read-only diagnostics from an app-owned job's captured CLI log."""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict

_TAIL_BYTES = 32 * 1024
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ERROR_START = re.compile(r"^(?:Fatal error:|Error:|Generation failed:)", re.IGNORECASE)


class JobDiagnostics(BaseModel):
    """A bounded log preview and the last explicit CLI error, when recorded."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    available: bool = False
    message: str = ""
    log_path: Path
    tail: str = ""
    truncated: bool = False


def read_job_diagnostics(path: Path, directory: Path, job_id: str) -> JobDiagnostics:
    """Read only the canonical private log for this job, without following symlinks."""
    expected = directory / f"{job_id}.log"
    if (
        path != expected
        or path.parent != directory
        or directory.is_symlink()
        or path.is_symlink()
        or not path.is_file()
    ):
        return JobDiagnostics(log_path=expected)
    try:
        with path.open("rb") as stream:
            size = stream.seek(0, 2)
            stream.seek(max(0, size - _TAIL_BYTES))
            payload = stream.read(_TAIL_BYTES)
    except OSError:
        return JobDiagnostics(log_path=expected)
    tail = _ANSI_ESCAPE.sub("", payload.decode("utf-8", errors="replace")).replace("\r", "\n")
    # Rich wraps CLI errors onto multiple lines. Retain their paragraph, not an
    # arbitrary last line (which may be a resource warning or progress update).
    lines = tail.splitlines()
    start = next(
        (index for index in range(len(lines) - 1, -1, -1) if _ERROR_START.match(lines[index])),
        None,
    )
    message = ""
    if start is not None:
        paragraph: list[str] = []
        for line in lines[start:]:
            if not line.strip() or line.startswith("Traceback (most recent call last):"):
                break
            paragraph.append(line.strip())
        message = " ".join(paragraph)[:2000]
    return JobDiagnostics(
        available=True,
        message=message,
        log_path=path,
        tail=tail,
        truncated=size > _TAIL_BYTES,
    )
