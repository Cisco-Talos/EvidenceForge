"""Read-only discovery of canonical, verified local artifact publications."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.artifacts.lifecycle import (
    ArtifactError,
    ArtifactKind,
    ReleaseReceipt,
    _safe_path,
    artifact_root,
    storage_name,
    verify_release,
)
from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.schema.contracts import VERSION_PATTERN

logger = logging.getLogger(__name__)


class PublishedArtifact(BaseModel):
    """A verified publication at its canonical publisher/kind/name/version location."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    root: Path = Field(description="Canonical publication directory")
    receipt: ReleaseReceipt = Field(description="Verified immutable release authority")

    @property
    def source(self) -> Path:
        """Return the receipt's verified source entrypoint."""
        return self.root / self.receipt.entrypoint


class ArtifactDiscoveryIssue(BaseModel):
    """One invalid entry does not discard unrelated publications."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    location: Path = Field(description="Directory that could not be safely discovered")
    error: str = Field(description="Actionable integrity or discovery failure")


def publication_roots(
    project_root: Path,
    *,
    kinds: tuple[ArtifactKind, ...] = ("scenario", "industry", "organization"),
) -> tuple[list[Path], list[ArtifactDiscoveryIssue]]:
    """Enumerate only the selected repository, without directory creation or link traversal."""
    roots: list[Path] = []
    issues: list[ArtifactDiscoveryIssue] = []
    try:
        library = _safe_path(artifact_root(project_root) / "releases")
    except (EvidenceForgeError, OSError, ValueError) as error:
        return [], [
            ArtifactDiscoveryIssue(location=project_root / ".eforge/artifacts", error=str(error))
        ]

    def directories(parent: Path, *, versions: bool = False) -> list[Path]:
        try:
            _safe_path(parent)
            if not parent.exists():
                return []
            if not parent.is_dir():
                raise ArtifactError(f"publication repository entry is not a directory: {parent}")
            result: list[Path] = []
            for child in sorted(parent.iterdir()):
                if child.name.startswith("."):
                    continue  # In-flight publication staging is not a release.
                if child.is_symlink():
                    issues.append(
                        ArtifactDiscoveryIssue(
                            location=child,
                            error=f"artifact paths cannot contain symbolic links: {child}",
                        )
                    )
                elif child.is_dir():
                    result.append(child)
                elif versions and re.fullmatch(VERSION_PATTERN, child.name):
                    issues.append(
                        ArtifactDiscoveryIssue(
                            location=child, error=f"publication version is not a directory: {child}"
                        )
                    )
            return result
        except (EvidenceForgeError, OSError, ValueError) as error:
            issues.append(ArtifactDiscoveryIssue(location=parent, error=str(error)))
            return []

    for publisher in directories(library):
        for kind in kinds:
            for name in directories(publisher / kind):
                for version in directories(name, versions=True):
                    roots.append(version)
    return roots, issues


def discover_publications(
    project_root: Path,
    *,
    kinds: tuple[ArtifactKind, ...] = ("scenario", "industry", "organization"),
) -> tuple[list[PublishedArtifact], list[ArtifactDiscoveryIssue]]:
    """Verify each candidate separately, retaining valid peers and isolated findings."""
    roots, issues = publication_roots(project_root, kinds=kinds)
    publications: list[PublishedArtifact] = []
    library = project_root.absolute() / ".eforge/artifacts/releases"
    for root in roots:
        try:
            receipt = verify_release(root)
            expected = (
                library
                / str(receipt.lifecycle.publisher)
                / receipt.kind
                / storage_name(receipt.name)
                / str(receipt.lifecycle.version)
            )
            if root != expected or receipt.kind not in kinds:
                raise ArtifactError("stored release does not match its repository identity")
            publications.append(PublishedArtifact(root=root, receipt=receipt))
        except (EvidenceForgeError, OSError, ValueError) as error:
            issues.append(ArtifactDiscoveryIssue(location=root, error=str(error)))
    return publications, issues
