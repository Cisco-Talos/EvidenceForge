"""Surgical YAML envelope edits preserving authored comments and unrelated bytes."""

from __future__ import annotations

from typing import Any

import yaml

from evidenceforge.models.exceptions import SchemaValidationError


def update_top_level(
    content: bytes, changes: dict[str, Any], remove: set[str] | None = None
) -> bytes:
    """Replace complete top-level YAML nodes, retaining all other text and comments."""

    text = content.decode("utf-8")
    node = yaml.compose(text)
    if not isinstance(node, yaml.MappingNode):
        raise SchemaValidationError("document must be a YAML mapping")
    edits: list[tuple[int, int, str]] = []
    remaining = dict(changes)
    seen: set[str] = set()
    for key, value in node.value:
        if not isinstance(key, yaml.ScalarNode) or key.value in seen:
            raise SchemaValidationError(
                "duplicate or complex YAML envelope keys cannot be upgraded safely"
            )
        seen.add(key.value)
        if key.value not in changes and key.value not in (remove or set()):
            continue
        start = key.start_mark.index
        end = value.end_mark.index
        replacement = ""
        if key.value in changes:
            replacement = yaml.safe_dump(
                {key.value: remaining.pop(key.value)}, sort_keys=False
            ).rstrip("\n")
            if text[start:end].endswith("\n"):
                replacement += "\n"
        # Consume only whitespace up to the next newline, retaining any trailing comment.
        edits.append((start, end, replacement))
    for start, end, replacement in reversed(edits):
        text = text[:start] + replacement + text[end:]
    if remaining:
        text = text.rstrip("\n") + "\n" + yaml.safe_dump(remaining, sort_keys=False)
    return text.encode("utf-8")


def upgrade_sources(
    sources: dict[str, bytes], root: str, family: str, source_names: set[str] | None = None
) -> dict[str, bytes]:
    """Remove historical markers from all includes; the caller supplies a new draft envelope."""

    result = dict(sources)
    for name, content in sources.items():
        if source_names is not None and name not in source_names:
            continue
        if not name.endswith((".yaml", ".yml")):
            continue
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            continue
        remove = (
            {"version", "scenario_version", "schema_version"} if family == "scenario" else set()
        )
        if family == "pack" and name != root:
            continue
        result[name] = update_top_level(content, {}, remove=remove)
    return result
