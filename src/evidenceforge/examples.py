"""Discover the same portable, offline example collection in source and installed builds."""

from __future__ import annotations

import logging
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from evidenceforge.artifacts.lifecycle import (
    ArtifactError,
    ReleaseReceipt,
    canonical_bytes,
    sha256,
    storage_name,
    verify_release,
)

logger = logging.getLogger(__name__)


class ExampleRelease(BaseModel):
    """An exact published scenario in the distribution's example collection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    root: Path
    receipt: ReleaseReceipt

    @property
    def family(self) -> str:
        """Return the publisher-qualified scenario identity."""
        return f"{self.receipt.lifecycle.publisher}/{self.receipt.name}"

    @property
    def identity(self) -> str:
        """Return the immutable release identity."""
        return f"{self.family}@{self.receipt.lifecycle.version}"


def examples_directory() -> Path:
    """Locate browsable files without requiring Studio or a running helper."""
    package = Path(__file__).resolve().parent
    installed = package / "_data" / "examples"
    if installed.is_dir():
        return installed
    source = package.parents[1] / "examples"
    if source.is_dir() and (source.parent / "pyproject.toml").is_file():
        return source
    raise ArtifactError("Bundled examples are missing; reinstall EvidenceForge")


def discover_examples(directory: Path | None = None) -> list[ExampleRelease]:
    """Verify every release, accepting an intentionally empty collection."""
    root = directory if directory is not None else examples_directory()
    examples: list[ExampleRelease] = []
    for scenario in sorted(root.iterdir()):
        if not scenario.is_dir():
            continue
        if scenario.is_symlink():
            raise ArtifactError("Example directories cannot be symbolic links")
        for release in sorted(scenario.iterdir()):
            if not release.is_dir():
                continue
            # Package managers may hardlink immutable wheel resources into their cache.
            # Receipts still seal every byte; installation writes independent regular files.
            receipt = verify_release(release, allow_hardlinks=True)
            if (
                receipt.kind != "scenario"
                or receipt.lifecycle.publisher != "evidenceforge"
                or scenario.name != storage_name(receipt.name)
                or release.name != receipt.lifecycle.version
            ):
                raise ArtifactError(
                    f"Example {release} must be an evidenceforge scenario under its name/version"
                )
            examples.append(ExampleRelease(root=release, receipt=receipt))
    return examples


def collection_digest(examples: list[ExampleRelease]) -> str:
    """Identify an exact collection independently of installation paths."""
    return sha256(canonical_bytes({item.identity: item.receipt.digest for item in examples}))
