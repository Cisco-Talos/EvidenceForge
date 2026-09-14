"""Windows-only durability adoption and index-authorized checkpoint reclamation."""

from __future__ import annotations

import stat
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import ValidationError

from evidenceforge.utils import windows_filesystem as filesystem

from .errors import CheckpointCorruptionError
from .models import CheckpointManifest, SegmentCatalogNode, SegmentCatalogReference

if TYPE_CHECKING:
    from .store import IncrementalCheckpointStore


def prepare_dependencies(store: IncrementalCheckpointStore, manifest: CheckpointManifest) -> None:
    """Establish barriers for newly referenced and pre-existing immutable dependencies."""
    operations = store._windows_io
    operations.require_healthy()
    resolved = store.workspace / manifest.resolved_scenario_relative_path
    operations.ensure_file(
        resolved, size=resolved.stat().st_size, digest=manifest.resolved_scenario_sha256
    )
    visiting: set[str] = set()

    def adopt(reference: SegmentCatalogReference) -> None:
        if reference.sha256 in operations.durable_catalogs:
            return
        if reference.sha256 in visiting:
            raise CheckpointCorruptionError("checkpoint segment catalog contains a cycle")
        visiting.add(reference.sha256)
        payload = store._validate_file(reference.relative_path, reference.size, reference.sha256)
        try:
            node = SegmentCatalogNode.model_validate_json(payload)
        except ValidationError as error:
            raise CheckpointCorruptionError("checkpoint segment catalog is corrupt") from error
        if node.level != reference.level:
            raise CheckpointCorruptionError("checkpoint segment catalog level changed")
        if node.kind == "leaf":
            for segment in node.segments:
                operations.ensure_file(
                    store.workspace / segment.relative_path,
                    size=segment.size,
                    digest=segment.sha256,
                )
        else:
            for child in node.children:
                adopt(child)
        operations.ensure_file(
            store.workspace / reference.relative_path, size=len(payload), digest=reference.sha256
        )
        visiting.remove(reference.sha256)
        operations.durable_catalogs.add(reference.sha256)

    for catalog in manifest.segment_catalogs:
        adopt(catalog)


def rotate_recoveries(store: IncrementalCheckpointStore) -> None:
    """Remove only recovery directories absent from the confirmed recovery index."""
    store._windows_io.require_healthy()
    entries = store.recovery_index_entries(read_only=True)
    retained = {sequence for sequence, _digest in entries}
    for path in store._recovery_directories():
        if int(path.name) not in retained:
            store._windows_io.remove_tree(path)


def collect_garbage(store: IncrementalCheckpointStore) -> None:
    """Use the authenticated index, not directory sorting, to retain dependencies."""
    store.initialize()
    operations = store._windows_io
    operations.require_healthy()
    retained: set[str] = set()
    entries = store.recovery_index_entries(read_only=True)
    if not entries:
        return
    for sequence, digest in entries:
        recovery = store.validate_recovery_entry(sequence, digest)
        manifest = recovery.manifest
        retained.add(manifest.resolved_scenario_relative_path)
        retained.update(
            segment.relative_path
            for segment in store.segment_references(manifest, retained_paths=retained)
        )

    def reclaim(directory: Path) -> None:
        for name, metadata in filesystem.directory_entries(directory):
            path = directory / name
            if stat.S_ISREG(metadata.st_mode):
                relative = path.relative_to(store.workspace).as_posix()
                if relative not in retained:
                    operations.unlink(path)
            elif stat.S_ISDIR(metadata.st_mode):
                reclaim(path)
            else:
                raise CheckpointCorruptionError(
                    f"unsafe checkpoint object during reclamation: {path}"
                )

    reclaim(store.objects)
