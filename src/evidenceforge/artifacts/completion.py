"""Completed drafts are established by immutable publication receipts."""

import json
from pathlib import Path

from evidenceforge.models.exceptions import EvidenceForgeError

from .discovery import discover_publications
from .lifecycle import (
    _safe_path,
    artifact_root,
    inspect_artifact,
    safe_relative,
)


def published_draft_sources(
    project_root: Path, candidates: list[Path] | None = None
) -> dict[Path, Path]:
    """Map unchanged finalized drafts to releases, preserving unrelated or edited drafts.

    The last parent is the exact draft snapshot captured by publication. Earlier parents
    are ancestry only: publishing a fork must never consume its still-active parent.
    A failed or interrupted publication has no verified release and consumes nothing.
    """
    artifacts = artifact_root(project_root)
    sources = set(candidates or [])
    for marker in artifacts.glob("drafts/*/*/*/draft.json") if candidates is None else []:
        try:
            sources.add(
                marker.parent / safe_relative(json.loads(marker.read_bytes())["entrypoint"])
            )
        except (OSError, ValueError, KeyError):
            continue
    releases: dict[tuple[str, str, str, str], tuple[tuple[int, ...], Path]] = {}
    publications, _issues = discover_publications(project_root)
    for publication in publications:
        receipt = publication.receipt
        if not receipt.lifecycle.parents:
            continue
        parent = receipt.lifecycle.parents[-1]
        if not parent.draft_id or (parent.kind, parent.name) != (receipt.kind, receipt.name):
            continue
        key = (parent.kind, parent.name, str(parent.draft_id), parent.digest)
        version = tuple(int(part) for part in str(receipt.lifecycle.version).split("."))
        if key not in releases or version > releases[key][0]:
            releases[key] = (version, publication.source)
    completed: dict[Path, Path] = {}
    from .removal import retired_draft_publications

    retired = retired_draft_publications(project_root)
    for source in sources:
        try:
            info = inspect_artifact(source)
            metadata = info.get("lifecycle") or {}
            if metadata.get("status") != "draft":
                continue
            key = (info["kind"], info["name"], metadata.get("draft_id"), info["digest"])
            if key in releases:
                completed[source.resolve()] = releases[key][1].resolve()
            elif key in retired:
                completed[source.resolve()] = retired[key]
        except (EvidenceForgeError, OSError, ValueError, TypeError, AttributeError):
            continue
    return completed


def completed_draft_release(source: Path, project_root: Path | None = None) -> Path | None:
    """Locate a managed draft's verified publication without a Studio database."""
    # Include/catalog edits must respect completion of the owning artifact, too.
    for parent in source.absolute().parents:
        marker = parent / "draft.json"
        if not marker.is_file():
            continue
        try:
            _safe_path(marker)
            source = parent / safe_relative(json.loads(marker.read_bytes())["entrypoint"])
        except (EvidenceForgeError, OSError, ValueError, KeyError):
            return None
        break
    if project_root is None:
        project_root = next(
            (
                parent.parent.parent
                for parent in source.absolute().parents
                if parent.name == "artifacts" and parent.parent.name == ".eforge"
            ),
            None,
        )
    if project_root is None:
        return None
    return published_draft_sources(project_root, [source]).get(source.resolve())
