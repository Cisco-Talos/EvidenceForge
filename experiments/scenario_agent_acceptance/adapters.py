"""Strict adapters for Codex and Claude JSONL transcript streams."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import AgentName, NormalizedEvent


class UnsupportedTranscriptError(ValueError):
    """Provider output cannot be interpreted without guessing."""


def _read_json_lines(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise UnsupportedTranscriptError(
                f"malformed JSONL at line {line_number}: {exc.msg}"
            ) from exc
        if not isinstance(value, dict) or not isinstance(value.get("type"), str):
            raise UnsupportedTranscriptError(f"invalid event envelope at line {line_number}")
        records.append(value)
    if not records:
        raise UnsupportedTranscriptError("provider emitted no transcript events")
    return records


def _codex_item(sequence: int, item: dict[str, Any]) -> NormalizedEvent:
    item_type = item.get("type")
    if item_type in {"agent_message", "reasoning"}:
        return NormalizedEvent(
            sequence=sequence,
            kind="message",
            output=str(item.get("text", "")),
        )
    if item_type == "command_execution":
        return NormalizedEvent(
            sequence=sequence,
            kind="tool_call",
            tool="shell",
            input={"command": item.get("command", "")},
            output=str(item.get("aggregated_output", "")),
        )
    if item_type == "file_change":
        return NormalizedEvent(
            sequence=sequence,
            kind="tool_call",
            tool="file_change",
            input={"changes": item.get("changes", [])},
        )
    if item_type in {"mcp_tool_call", "web_search"}:
        return NormalizedEvent(
            sequence=sequence,
            kind="tool_call",
            tool=str(item.get("tool", item_type)),
            input=item.get("arguments", {}) if isinstance(item.get("arguments", {}), dict) else {},
        )
    if item_type in {"todo_list", "error"}:
        return NormalizedEvent(sequence=sequence, kind="message", output=json.dumps(item))
    raise UnsupportedTranscriptError(f"unrecognized Codex item type: {item_type!r}")


def parse_codex(path: Path) -> list[NormalizedEvent]:
    """Normalize the documented Codex exec JSONL event families."""

    events: list[NormalizedEvent] = []
    known = {
        "thread.started",
        "turn.started",
        "turn.completed",
        "turn.failed",
        "item.started",
        "item.updated",
        "item.completed",
        "error",
    }
    for sequence, record in enumerate(_read_json_lines(path)):
        event_type = record["type"]
        if event_type not in known:
            raise UnsupportedTranscriptError(f"unrecognized Codex event type: {event_type}")
        if event_type == "thread.started":
            events.append(
                NormalizedEvent(
                    sequence=sequence,
                    kind="session",
                    session_id=str(record.get("thread_id", "")),
                )
            )
        elif event_type == "item.completed":
            item = record.get("item")
            if not isinstance(item, dict):
                raise UnsupportedTranscriptError("Codex item.completed omitted item object")
            events.append(_codex_item(sequence, item))
        elif event_type == "turn.completed":
            usage = record.get("usage", {})
            if not isinstance(usage, dict):
                raise UnsupportedTranscriptError("Codex turn usage is not an object")
            events.append(NormalizedEvent(sequence=sequence, kind="usage", usage=usage))
        elif event_type in {"turn.failed", "error"}:
            events.append(
                NormalizedEvent(sequence=sequence, kind="message", output=json.dumps(record))
            )
    return events


def _claude_content(sequence: int, content: Iterable[Any]) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    for block in content:
        if not isinstance(block, dict) or not isinstance(block.get("type"), str):
            raise UnsupportedTranscriptError("Claude message contains an invalid content block")
        block_type = block["type"]
        if block_type in {"text", "thinking"}:
            events.append(
                NormalizedEvent(
                    sequence=sequence,
                    kind="message",
                    output=str(block.get("text", block.get("thinking", ""))),
                )
            )
        elif block_type == "tool_use":
            tool_input = block.get("input", {})
            if not isinstance(tool_input, dict):
                raise UnsupportedTranscriptError("Claude tool_use input is not an object")
            events.append(
                NormalizedEvent(
                    sequence=sequence,
                    kind="tool_call",
                    tool=str(block.get("name", "")),
                    input=tool_input,
                )
            )
        elif block_type == "tool_result":
            events.append(
                NormalizedEvent(
                    sequence=sequence,
                    kind="tool_result",
                    output=str(block.get("content", "")),
                )
            )
        else:
            raise UnsupportedTranscriptError(f"unrecognized Claude content type: {block_type}")
    return events


def parse_claude(path: Path) -> list[NormalizedEvent]:
    """Normalize Claude Code stream-json output without accepting silent drift."""

    events: list[NormalizedEvent] = []
    known = {"system", "assistant", "user", "result", "rate_limit_event", "stream_event"}
    for sequence, record in enumerate(_read_json_lines(path)):
        event_type = record["type"]
        if event_type not in known:
            raise UnsupportedTranscriptError(f"unrecognized Claude event type: {event_type}")
        if event_type == "system":
            events.append(
                NormalizedEvent(
                    sequence=sequence,
                    kind="session",
                    session_id=str(record.get("session_id", "")),
                )
            )
        elif event_type in {"assistant", "user"}:
            message = record.get("message", {})
            content = message.get("content", []) if isinstance(message, dict) else []
            if not isinstance(content, list):
                raise UnsupportedTranscriptError("Claude message content is not a list")
            events.extend(_claude_content(sequence, content))
        elif event_type == "result":
            usage = record.get("usage", {})
            if not isinstance(usage, dict):
                raise UnsupportedTranscriptError("Claude result usage is not an object")
            numeric_usage = {
                key: value for key, value in usage.items() if isinstance(value, (int, float))
            }
            if isinstance(record.get("total_cost_usd"), (int, float)):
                numeric_usage["total_cost_usd"] = record["total_cost_usd"]
            events.append(NormalizedEvent(sequence=sequence, kind="usage", usage=numeric_usage))
    return events


def parse_transcript(agent: AgentName, path: Path) -> list[NormalizedEvent]:
    """Dispatch strict provider parsing."""

    return parse_codex(path) if agent is AgentName.CODEX else parse_claude(path)
