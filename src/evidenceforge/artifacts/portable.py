"""Deterministic portable scenario and lifecycle pack release archives."""

from __future__ import annotations

import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from .lifecycle import (
    MAX_BYTES,
    MAX_FILES,
    RECEIPT,
    ArtifactError,
    ReleaseReceipt,
    _publication_lock,
    _publish_directory,
    _safe_path,
    _used_versions,
    _write_files,
    artifact_root,
    safe_relative,
    snapshot_tree,
    storage_name,
    verify_release,
)


def export_release(source: Path, destination: Path) -> Path:
    """Export an immutable release with all sources, dependencies and integrity receipts."""
    from .lifecycle import _receipt_root

    root = _receipt_root(source)
    if root is None:
        raise ArtifactError("export requires a published release with an integrity receipt")
    receipt = verify_release(root)
    extension = ".efscenario" if receipt.kind == "scenario" else ".efpack"
    if destination.suffix != extension:
        raise ArtifactError(f"use {extension} for this artifact")
    files = snapshot_tree(root)
    destination = _safe_path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise ArtifactError(f"refusing to overwrite export: {destination}")
    temporary = Path(tempfile.mkdtemp(prefix=".export-", dir=destination.parent))
    try:
        archive_path = temporary / destination.name
        with zipfile.ZipFile(archive_path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in sorted(files.items()):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100600 << 16
                archive.writestr(info, content)
        # Exclusive creation never overwrites a concurrently selected export destination.
        with destination.open("xb") as stream:
            stream.write(archive_path.read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
        return destination
    finally:
        shutil.rmtree(temporary)


def read_archive(path: Path) -> tuple[ReleaseReceipt, dict[str, bytes]]:
    """Bound, inventory and validate every member before writing an import."""
    _safe_path(path)
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if len(entries) > MAX_FILES or sum(entry.file_size for entry in entries) > MAX_BYTES:
                raise ArtifactError("release archive exceeds portable limits")
            if len(names) != len(set(names)):
                raise ArtifactError("release archive contains duplicate members")
            for entry in entries:
                safe_relative(entry.filename)
                if entry.is_dir() or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ArtifactError(
                        "release archive contains a directory or symbolic link member"
                    )
            if RECEIPT not in names:
                raise ArtifactError("release archive has no integrity receipt")
            files = {entry.filename: archive.read(entry) for entry in entries}
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise ArtifactError(f"unable to read portable release: {exc}") from exc
    staging = Path(tempfile.mkdtemp(prefix="efartifact-verify-")).resolve()
    try:
        _write_files(staging, files)
        receipt = verify_release(staging)
    finally:
        shutil.rmtree(staging)
    return receipt, files


def import_release(path: Path, *, project_root: Path) -> Path:
    """Idempotently import exact contents; reject identity/version conflicts."""
    receipt, files = read_archive(path)
    lifecycle = receipt.lifecycle
    with _publication_lock(project_root):
        target = (
            artifact_root(project_root)
            / "releases"
            / str(lifecycle.publisher)
            / receipt.kind
            / storage_name(receipt.name)
            / str(lifecycle.version)
        )
        if target.exists():
            existing = verify_release(target)
            if existing.digest != receipt.digest:
                raise ArtifactError(
                    "different contents already exist under this publisher/name/version"
                )
            return target / existing.entrypoint
        if lifecycle.version in _used_versions(
            project_root, kind=receipt.kind, name=receipt.name, publisher=str(lifecycle.publisher)
        ):
            raise ArtifactError("release identity/version conflicts with an existing legacy pack")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        staging = Path(tempfile.mkdtemp(prefix=".import-", dir=target.parent))
        try:
            _write_files(staging, files)
            verify_release(staging)
            _publish_directory(staging, target)
        finally:
            if staging.exists():
                shutil.rmtree(staging)
    return target / receipt.entrypoint
