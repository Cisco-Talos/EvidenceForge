# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Central ownership and transactional installation for generated bundle sidecars."""

from __future__ import annotations

import hashlib
import logging
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from evidenceforge.events.artifacts_manifest import ARTIFACTS_MANIFEST_FILENAME
from evidenceforge.events.collection_profile import COLLECTION_PROFILE_FILENAME
from evidenceforge.events.ground_truth import GROUND_TRUTH_JSON_FILENAME
from evidenceforge.events.observation_manifest import OBSERVATION_MANIFEST_FILENAME
from evidenceforge.output_targets import OUTPUT_TARGET_FILENAME

from .artifacts import GENERATION_MANIFEST_FILENAME, RESOLVED_SCENARIO_FILENAME

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SidecarSpec:
    """One engine-owned path in a generated bundle."""

    relative_path: str
    required: bool = False
    directory: bool = False


class SidecarRegistry:
    """Select, protect, validate, and atomically replace one complete bundle."""

    def __init__(self) -> None:
        self.specs = (
            SidecarSpec("data", required=True, directory=True),
            SidecarSpec("GROUND_TRUTH.md", required=True),
            SidecarSpec(GROUND_TRUTH_JSON_FILENAME, required=True),
            SidecarSpec(OBSERVATION_MANIFEST_FILENAME, required=True),
            SidecarSpec(ARTIFACTS_MANIFEST_FILENAME),
            SidecarSpec(COLLECTION_PROFILE_FILENAME),
            SidecarSpec(OUTPUT_TARGET_FILENAME, required=True),
            SidecarSpec("STORAGE_MANIFEST.json"),
            SidecarSpec("artifacts", directory=True),
            SidecarSpec(RESOLVED_SCENARIO_FILENAME, required=True),
            # The run manifest is deliberately installed last.
            SidecarSpec(GENERATION_MANIFEST_FILENAME, required=True),
        )

    def paths(self, root: Path) -> tuple[Path, ...]:
        """Return every registered path under one output root."""

        return tuple(root / spec.relative_path for spec in self.specs)

    def reject_symlinks(self, root: Path) -> None:
        """Reject final-component symlinks, including dangling ones."""

        symlinks = [path for path in self.paths(root) if path.is_symlink()]
        if symlinks:
            joined = ", ".join(str(path) for path in symlinks)
            raise PermissionError(f"Refusing to write generated sidecar through symlink: {joined}")

    def existing(self, root: Path) -> tuple[SidecarSpec, ...]:
        """Return registered paths already present in a destination."""

        return tuple(
            spec
            for spec in self.specs
            if (root / spec.relative_path).exists() or (root / spec.relative_path).is_symlink()
        )

    def validate_staged(self, root: Path) -> None:
        """Require the complete authoritative subset before installation."""

        self._validate_required(root, description="Staged")

    def validate_generated(self, root: Path) -> None:
        """Require the complete authoritative subset after generation."""

        self._validate_required(root, description="Generated")

    def _validate_required(self, root: Path, *, description: str) -> None:
        """Validate required bundle members with a context-specific description."""

        self.reject_symlinks(root)
        for spec in self.specs:
            if not spec.required:
                continue
            path = root / spec.relative_path
            valid = path.is_dir() if spec.directory else path.is_file()
            if not valid:
                raise RuntimeError(f"{description} {spec.relative_path} missing after generation")

    def hashes(self, root: Path) -> dict[str, str]:
        """Hash the registered bundle payload without following symlinks.

        The generation manifest is excluded because it owns these hashes and is
        deliberately written last. Unregistered author collateral in the output
        directory is not part of the authoritative bundle.
        """

        hashes: dict[str, str] = {}
        for spec in self.specs:
            if spec.relative_path == GENERATION_MANIFEST_FILENAME:
                continue
            path = root / spec.relative_path
            if path.is_symlink():
                raise PermissionError(f"generated bundle contains a symlink: {path}")
            if not path.exists():
                continue
            candidates = sorted(path.rglob("*"), key=str) if spec.directory else [path]
            for candidate in candidates:
                if candidate.is_symlink():
                    raise PermissionError(f"generated bundle contains a symlink: {candidate}")
                if candidate.is_file():
                    relative = str(candidate.relative_to(root))
                    hashes[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
        return dict(sorted(hashes.items()))

    def replace(self, staged_root: Path, destination_root: Path) -> None:
        """Atomically install a staged matched set, restoring the old set on failure."""

        self.validate_staged(staged_root)
        self.reject_symlinks(destination_root)
        for stale in destination_root.glob(".eforge_rollback_*"):
            if stale.is_symlink():
                stale.unlink()
            elif stale.is_dir():
                logger.warning("Cleaning stale rollback directory: %s", stale)
                shutil.rmtree(stale, ignore_errors=True)

        rollback_root = Path(tempfile.mkdtemp(prefix=".eforge_rollback_", dir=destination_root))
        succeeded = False
        try:
            for spec in self.specs:
                destination = destination_root / spec.relative_path
                if destination.exists() or destination.is_symlink():
                    destination.rename(rollback_root / spec.relative_path)
            for spec in self.specs:
                staged = staged_root / spec.relative_path
                if staged.exists():
                    staged.rename(destination_root / spec.relative_path)
            succeeded = True
        except BaseException:
            try:
                for spec in reversed(self.specs):
                    installed = destination_root / spec.relative_path
                    self._remove(installed)
                for spec in self.specs:
                    backup = rollback_root / spec.relative_path
                    if backup.exists() or backup.is_symlink():
                        backup.rename(destination_root / spec.relative_path)
            except OSError:
                logger.error("Rollback failed; old output may remain in %s", rollback_root)
            raise
        finally:
            if succeeded:
                shutil.rmtree(rollback_root, ignore_errors=True)

    @staticmethod
    def _remove(path: Path) -> None:
        """Remove one precisely registered installed path during rollback."""

        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)


SIDECAR_REGISTRY = SidecarRegistry()
