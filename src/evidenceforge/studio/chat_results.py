"""Read-only presentation metadata for the frozen chat result records."""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from evidenceforge.artifacts.lifecycle import _safe_path
from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.studio.state_records_v3 import ChatResult, ChatTurn

ResultOperation = Literal["edited", "created", "removed", "renamed", "changed"]
SOURCE_PREVIEW_LIMIT = 2 * 1024 * 1024
_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")
logger = logging.getLogger(__name__)


class RecordedFileChange(BaseModel):
    """One completed native file operation, without inferred prose claims."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    path: str
    operation: ResultOperation
    previous_path: str | None = None
    diff: str | None = None


class ChatResultSummary(ChatResult):
    """Additive API presentation; never written into the frozen database payload."""

    operation: ResultOperation
    relative_path: str
    previous_path: str | None = None
    previous_relative_path: str | None = None
    lines_added: int | None = None
    lines_removed: int | None = None
    current_lines: int | None = None
    current_characters: int | None = None
    current_bytes: int | None = None
    available: bool = False
    metadata_only: bool = False


class ChatTurnSummary(ChatTurn):
    """Present saved turns using derived result summaries, preserving their stored contract."""

    results: list[ChatResultSummary]


def result_operation(kind: str) -> ResultOperation:
    """Normalize current protocol names and older stored result labels."""
    if kind in {"add", "created"}:
        return "created"
    if kind in {"delete", "deleted", "removed"}:
        return "removed"
    if kind in {"update", "modified", "edited"}:
        return "edited"
    if kind in {"rename", "renamed", "move", "moved"}:
        return "renamed"
    return "changed"


def recorded_changes(items: list[dict[str, Any]]) -> Iterator[RecordedFileChange]:
    """Read completed operations including Codex's update-with-move destination."""
    for item in items:
        if item.get("type") != "fileChange" or item.get("status") != "completed":
            continue
        changes = item.get("changes")
        if not isinstance(changes, list):
            continue
        for change in changes:
            if not isinstance(change, dict) or not isinstance(change.get("path"), str):
                continue
            kind = change.get("kind", "modified")
            operation = result_operation(
                str(kind.get("type", "modified") if isinstance(kind, dict) else kind)
            )
            move = kind.get("move_path") if isinstance(kind, dict) else None
            previous = change["path"] if isinstance(move, str) and move else None
            yield RecordedFileChange(
                path=move if previous else change["path"],
                operation="renamed" if previous else operation,
                previous_path=previous,
                diff=change.get("diff") if isinstance(change.get("diff"), str) else None,
            )


def result_path(raw: str, directory: Path) -> Path:
    """Verify even absent paths against the source boundary, rejecting symbolic links."""
    path = Path(raw)
    path = _safe_path(path if path.is_absolute() else directory / path).resolve()
    if not path.is_relative_to(directory):
        raise ValueError("Chat result is outside its permitted source directory")
    return path


def source_text(path: Path) -> str | None:
    """Read bounded UTF-8 contents without changing newline or character counts."""
    try:
        with path.open("rb") as stream:
            payload = stream.read(SOURCE_PREVIEW_LIMIT + 1)
        return payload.decode("utf-8") if len(payload) <= SOURCE_PREVIEW_LIMIT else None
    except (OSError, UnicodeError):
        return None


def diff_line_counts(diff: str | None) -> tuple[int | None, int | None]:
    """Count only complete unified diff hunks, excluding headers and raw file text."""
    if not diff:
        return None, None
    added = removed = 0
    old_left = new_left = 0
    found = False
    for line in diff.splitlines():
        hunk = _HUNK.match(line)
        if hunk:
            if old_left or new_left:
                return None, None
            old_left = int(hunk[1]) if hunk[1] is not None else 1
            new_left = int(hunk[2]) if hunk[2] is not None else 1
            found = True
        elif old_left or new_left:
            if line.startswith("\\ No newline"):
                continue
            if line.startswith("+"):
                added += 1
                new_left -= 1
            elif line.startswith("-"):
                removed += 1
                old_left -= 1
            elif line.startswith(" "):
                old_left -= 1
                new_left -= 1
            else:
                return None, None
            if old_left < 0 or new_left < 0:
                return None, None
    return (added, removed) if found and not (old_left or new_left) else (None, None)


def summarize_turn(
    turn: ChatTurn,
    directory: Path | None,
    sizes: dict[Path, tuple[int | None, int | None, int | None]],
) -> ChatTurnSummary:
    """Derive stable patch counts and explicitly current sizes without changing saved records."""
    summaries: list[ChatResultSummary] = []
    changes = list(recorded_changes(turn.items))
    for result in turn.results:
        summary = ChatResultSummary(
            **result.model_dump(),
            operation=result_operation(result.kind),
            relative_path=Path(result.path).name,
        )
        summary.lines_added, summary.lines_removed = diff_line_counts(result.diff)
        summary.metadata_only = bool(
            result.diff
            and summary.lines_added is None
            and "old mode " in result.diff
            and "new mode " in result.diff
        )
        try:
            if directory is None:
                raise ValueError("Source permissions are unavailable")
            path = result_path(result.path, directory)
            summary.relative_path = path.relative_to(directory).as_posix()
            for change in changes:
                if not change.previous_path:
                    continue
                try:
                    if result_path(change.path, directory) != path:
                        continue
                    previous = result_path(change.previous_path, directory)
                except (OSError, ValueError, EvidenceForgeError):
                    continue
                if summary.operation not in {"created", "removed"}:
                    summary.operation = "renamed"
                summary.previous_path = str(previous)
                summary.previous_relative_path = previous.relative_to(directory).as_posix()
                break
            summary.available = summary.operation != "removed" and path.is_file()
            if summary.available:
                if path not in sizes:
                    text = source_text(path)
                    sizes[path] = (
                        len(text.splitlines()) if text is not None else None,
                        len(text) if text is not None else None,
                        path.stat().st_size,
                    )
                summary.current_lines, summary.current_characters, summary.current_bytes = sizes[
                    path
                ]
        except (OSError, ValueError, EvidenceForgeError):
            summary.available = False
        summaries.append(summary)
    return ChatTurnSummary(**{**turn.model_dump(), "results": summaries})
