"""Deterministic, contextual excerpts from indexed authored YAML."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.tokens import ScalarToken

from evidenceforge.models.exceptions import ConfigurationError
from evidenceforge.utils import load_scenario_source_graph


class SearchMatch(BaseModel):
    """One matching field or source line, with safe text highlight offsets."""

    model_config = ConfigDict(extra="forbid")

    field: str
    file: str = ""
    line: int = 0
    kind: Literal["metadata", "value", "key", "comment", "text"]
    excerpt: str
    highlights: list[tuple[int, int]] = Field(default_factory=list)


def index_sources(path: Path, content: str, scenario: bool) -> dict[str, str]:
    """Capture includes at indexing time; searching never rereads live files."""
    if scenario:
        try:
            graph = load_scenario_source_graph(path)
        except (ConfigurationError, OSError, ValueError):
            pass
        else:
            return {
                str(source.path.relative_to(path.parent))
                if source.path.is_relative_to(path.parent)
                else str(source.path): source.content.decode("utf-8")
                for source in graph.sources
            }
    return {path.name: content}


def yaml_entries(sources: dict[str, str]) -> list[SearchMatch]:
    """Index scalar values and keys separately, retaining source and YAML paths."""
    entries: list[SearchMatch] = []
    for file, content in sources.items():
        lines = content.splitlines()
        covered: set[int] = set()
        try:
            root = yaml.compose(content, Loader=yaml.SafeLoader)
        except yaml.YAMLError:
            root = None
        scalar_ranges: dict[int, list[tuple[int, int]]] = {}
        if root is not None:
            for token in yaml.scan(content, Loader=yaml.SafeLoader):
                if isinstance(token, ScalarToken):
                    for row in range(token.start_mark.line, token.end_mark.line + 1):
                        left = token.start_mark.column if row == token.start_mark.line else 0
                        right = (
                            token.end_mark.column if row == token.end_mark.line else len(lines[row])
                        )
                        scalar_ranges.setdefault(row, []).append((left, right))
        visited: set[int] = set()

        def walk(
            node: Node,
            path: str,
            *,
            key: bool = False,
            depth: int = 0,
            visited: set[int] = visited,
            covered: set[int] = covered,
            file: str = file,
        ) -> None:
            if id(node) in visited or depth > 64:
                return
            visited.add(id(node))
            if isinstance(node, ScalarNode):
                covered.update(range(node.start_mark.line, node.end_mark.line + 1))
                if node.value:
                    entries.append(
                        SearchMatch(
                            field=path or "YAML",
                            file=file,
                            line=node.start_mark.line + 1,
                            kind="key" if key else "value",
                            excerpt=" ".join(node.value.split()),
                        )
                    )
            elif isinstance(node, MappingNode):
                for label, value in node.value:
                    name = label.value if isinstance(label, ScalarNode) else "?"
                    child = f"{path}.{name}" if path else name
                    walk(label, child, key=True, depth=depth + 1)
                    walk(value, child, depth=depth + 1)
            elif isinstance(node, SequenceNode):
                for index, value in enumerate(node.value):
                    walk(value, f"{path}[{index}]", depth=depth + 1)

        if root is not None:
            walk(root, "")
        for number, text in enumerate(lines, start=1):
            # Comments remain searchable, including comments following a scalar.
            comment_start = next(
                (
                    index
                    for index, character in enumerate(text)
                    if character == "#"
                    and (index == 0 or text[index - 1].isspace())
                    and not any(
                        left <= index < right for left, right in scalar_ranges.get(number - 1, [])
                    )
                ),
                None,
            )
            comment = text[comment_start + 1 :] if comment_start is not None else ""
            if comment or number - 1 not in covered:
                entries.append(
                    SearchMatch(
                        field="Comment" if comment else "YAML",
                        file=file,
                        line=number,
                        kind="comment" if comment else "text",
                        excerpt=(comment or text).strip(),
                    )
                )
    return entries


def matching_excerpts(
    entries: list[SearchMatch], terms: list[tuple[str, str]], limit: int
) -> tuple[list[SearchMatch], int]:
    """Rank informative values ahead of keys; count matching fields, not occurrences."""
    ranked: list[tuple[tuple[int, int, str, int], SearchMatch]] = []
    for entry in entries:
        needles = [
            value
            for scope, value in terms
            if not scope
            or (scope == "yaml" and entry.kind != "metadata")
            or (scope == entry.field.casefold() and entry.kind == "metadata")
        ]
        needles = list(dict.fromkeys(value for value in needles if value))
        if not needles:
            continue
        pattern = re.compile("|".join(re.escape(value) for value in needles), re.IGNORECASE)
        matches = list(pattern.finditer(entry.excerpt))
        if not matches:
            continue
        # Metadata, then values, then field keys and comments. Within a group,
        # prefer word/prefix occurrences over matches buried inside another word.
        prefix = any(
            match.start() == 0 or not entry.excerpt[match.start() - 1].isalnum()
            for match in matches
        )
        rank = {"metadata": 0, "value": 1, "text": 2, "key": 3, "comment": 4}[entry.kind]
        start = max(0, matches[0].start() - 55)
        excerpt = entry.excerpt[start : start + 160]
        if start:
            excerpt = "…" + excerpt
        if len(entry.excerpt) > start + 160:
            excerpt += "…"
        result = entry.model_copy(
            update={
                "excerpt": excerpt,
                "highlights": [(match.start(), match.end()) for match in pattern.finditer(excerpt)],
            }
        )
        ranked.append(((rank, 0 if prefix else 1, entry.file, entry.line), result))
    ranked.sort(key=lambda pair: pair[0])
    unique: list[SearchMatch] = []
    seen: set[tuple[str, str, int]] = set()
    for _, entry in ranked:
        key = (entry.file, entry.field, 0 if entry.kind in {"value", "key"} else entry.line)
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    return unique[:limit], len(unique)
