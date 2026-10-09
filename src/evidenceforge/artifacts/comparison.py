"""Bounded authored-source comparisons against exact recorded ancestors."""

from __future__ import annotations

import difflib
import json
import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.artifacts.lifecycle import (
    _capture_sources,
    artifact_root,
    inspect_artifact,
    resolve_reference,
    safe_relative,
)
from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.naming import storage_name
from evidenceforge.schema import ParentReference

logger = logging.getLogger(__name__)


class ParentComparison(BaseModel):
    """Exact-parent availability and bounded source changes, without merging."""

    parent: ParentReference
    status: Literal["available", "unavailable"]
    changed_files: list[str] = Field(default_factory=list)
    changes: dict[str, str] = Field(default_factory=dict)
    truncated: bool = False
    model_config = ConfigDict(extra="forbid", frozen=True)


def compare_parent(
    source: Path,
    parent: ParentReference,
    project_root: Path,
    candidates: Iterable[Path],
    *,
    character_budget: int = 12000,
) -> ParentComparison:
    """Compare only an ancestor matching its recorded identity and complete digest."""
    paths = list(candidates)
    try:
        if parent.version and parent.publisher:
            reference = (
                f"{parent.publisher}:{parent.kind}:{quote(parent.name, safe='')}@{parent.version}"
            )
            paths.insert(0, resolve_reference(reference, project_root))
        elif parent.draft_id:
            root = (
                artifact_root(project_root)
                / "drafts"
                / parent.kind
                / storage_name(parent.name)
                / str(parent.draft_id)
            )
            entry = json.loads((root / "draft.json").read_bytes())["entrypoint"]
            paths.insert(0, root / safe_relative(entry))
    except (EvidenceForgeError, OSError, ValueError, KeyError):
        pass
    for path in dict.fromkeys(paths):
        if path.suffix not in {".yaml", ".yml"}:
            # Archives are not authored entrypoints; never compare their containing directory.
            continue
        try:
            info = inspect_artifact(path)
            metadata = info.get("lifecycle") or {}
            if (
                info.get("kind") != parent.kind
                or info.get("name") != parent.name
                or info.get("digest") != parent.digest
                or (parent.publisher is not None and metadata.get("publisher") != parent.publisher)
                or (parent.version is not None and metadata.get("version") != parent.version)
                or (
                    parent.draft_id is not None and metadata.get("draft_id") != str(parent.draft_id)
                )
            ):
                continue
            family = "scenario" if parent.kind == "scenario" else "pack"
            before, _, _ = _capture_sources(path, family)
            current = inspect_artifact(source)
            after, _, _ = _capture_sources(
                source, "scenario" if current["kind"] == "scenario" else "pack"
            )
            if inspect_artifact(path)["digest"] != parent.digest:
                continue
        except (EvidenceForgeError, OSError, ValueError):
            continue
        changed = sorted(
            name for name in before.keys() | after.keys() if before.get(name) != after.get(name)
        )
        changes: dict[str, str] = {}
        truncated = False
        remaining = max(0, character_budget)
        for name in changed[:80]:
            if remaining <= 0:
                truncated = True
                break
            left, right = before.get(name, b""), after.get(name, b"")
            if max(len(left), len(right)) > 1024 * 1024:
                difference = "Large asset changed; content comparison omitted."
                truncated = True
            else:
                try:
                    difference = ""
                    for line in difflib.unified_diff(
                        left.decode().splitlines(True),
                        right.decode().splitlines(True),
                        fromfile=f"parent/{name}",
                        tofile=f"draft/{name}",
                    ):
                        if len(difference) + len(line) > remaining:
                            difference += line[: max(0, remaining - len(difference))]
                            truncated = True
                            break
                        difference += line
                except UnicodeError:
                    difference = "Binary asset changed; content comparison omitted."
                    truncated = True
            if len(difference) > remaining:
                truncated = True
            changes[name] = difference[:remaining]
            remaining -= len(changes[name])
        return ParentComparison(
            parent=parent,
            status="available",
            changed_files=changed[:80],
            changes=changes,
            truncated=truncated or len(changed) > 80,
        )
    return ParentComparison(parent=parent, status="unavailable")
