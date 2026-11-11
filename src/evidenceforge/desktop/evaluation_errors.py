"""Bounded CLI failure diagnostics for evaluation jobs without a readable report."""

from __future__ import annotations

import re
from pathlib import Path

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_CLI_ERROR = re.compile(r"(?m)^\s*(?:Error:|Fatal error:)\s*")


def evaluation_failure_message(log_file: Path, fallback: str) -> str:
    """Prefer the CLI's terminal error over a secondary empty-report parse error."""
    try:
        with log_file.open("rb") as stream:
            stream.seek(0, 2)
            stream.seek(max(0, stream.tell() - 16_384))
            tail = _ANSI_ESCAPE.sub("", stream.read(16_384).decode("utf-8", errors="replace"))
    except OSError:
        return fallback
    errors = list(_CLI_ERROR.finditer(tail))
    if not errors:
        return fallback
    paragraph = tail[errors[-1].end() :].split("\n\n", 1)[0]
    return " ".join(paragraph.split())[:500] or fallback
