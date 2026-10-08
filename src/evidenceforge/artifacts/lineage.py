"""Derived library families from exact file ancestry, without changing artifact identity."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.schema import LifecycleMetadata, ParentReference
from evidenceforge.utils import load_scenario_source_graph

from .lifecycle import ArtifactKind, canonical_bytes, inspect_artifact


class ArtifactGroup(BaseModel):
    """A presentation group; its publisher never replaces a member's recorded publisher."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str
    name: str
    publisher: str | None = None


class ArtifactLineage(BaseModel):
    """Exact self and parent references captured from one authored artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ArtifactKind
    name: str
    publisher: str | None = None
    reference: ParentReference
    parents: list[ParentReference] = Field(default_factory=list)


def inspect_lineage(path: Path) -> ArtifactLineage:
    """Read portable ancestry through the canonical integrity and envelope contracts."""
    info = inspect_artifact(path)
    metadata = (
        LifecycleMetadata.model_validate(info["lifecycle"]) if info.get("lifecycle") else None
    )
    publisher = (
        metadata.publisher if metadata else load_scenario_source_graph(path).data.get("publisher")
    )
    reference = ParentReference(
        kind=info["kind"],
        name=info["name"],
        publisher=metadata.publisher if metadata else None,
        version=metadata.version if metadata else None,
        draft_id=metadata.draft_id if metadata else None,
        source_schema_version=info["schema_version"] if metadata is None else None,
        digest=info["digest"],
    )
    return ArtifactLineage(
        kind=reference.kind,
        name=reference.name,
        publisher=publisher,
        reference=reference,
        parents=metadata.parents if metadata else [],
    )


def group_lineage(records: dict[str, ArtifactLineage]) -> dict[str, ArtifactGroup]:
    """Connect unassigned sources to an unambiguous publisher through exact ancestry.

    Named publishers and renamed forks retain separate identities. Shared parent receipts
    also link a retained draft to its release when their ancestor is no longer available.
    An ancestor used by multiple publishers stays unassigned rather than selecting an owner.
    """
    roots = {identifier: identifier for identifier in records}

    def root(identifier: str) -> str:
        while roots[identifier] != identifier:
            roots[identifier] = roots[roots[identifier]]
            identifier = roots[identifier]
        return identifier

    anchors: dict[bytes, str] = {}
    for identifier, record in records.items():
        for reference in [record.reference, *record.parents]:
            if (reference.kind, reference.name) != (record.kind, record.name):
                continue
            identity = reference.model_dump(mode="json", exclude_none=True)
            # A mutable draft keeps its identity through edits. Its recorded publication
            # parent still seals an exact digest, but grouping follows the stable draft ID.
            # Legacy originals and immutable releases require the exact digest to match.
            if reference.draft_id is not None:
                identity.pop("digest")
            key = canonical_bytes(identity)
            if key in anchors:
                left, right = root(identifier), root(anchors[key])
                roots[max(left, right)] = min(left, right)
            else:
                anchors[key] = identifier

    publishers: dict[str, set[str]] = {}
    for identifier, record in records.items():
        if record.publisher:
            publishers.setdefault(root(identifier), set()).add(record.publisher)

    groups: dict[str, ArtifactGroup] = {}
    for identifier, record in records.items():
        component = root(identifier)
        candidates = publishers.get(component, set())
        publisher = record.publisher
        if publisher is None and len(candidates) == 1:
            publisher = next(iter(candidates))
        # Unrelated anonymous sources with equal names must not become a single artifact.
        identity = publisher if publisher else f"unassigned:{component}"
        groups[identifier] = ArtifactGroup(
            key=canonical_bytes([record.kind, record.name, identity]).decode(),
            name=record.name,
            publisher=publisher,
        )
    return groups
