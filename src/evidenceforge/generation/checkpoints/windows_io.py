"""Windows-only checkpoint publication using NTFS write-through namespace operations.

File flushes and write-through renames are separate barriers. A flush of an
unrelated directory or merely closing a handle is never treated as a barrier.
The guarantee assumes NTFS and storage honor the requested flushes; it does not
certify physical hardware against power loss. Ordinary emitter I/O does not use
this module.
"""

from __future__ import annotations

import hashlib
import os
import stat
import uuid
from collections.abc import Iterable, Iterator
from pathlib import Path

from evidenceforge.utils import windows_filesystem as filesystem

from .errors import CheckpointCorruptionError, CheckpointFilesystemError

_COPY_CHUNK_BYTES = 1024 * 1024


class WindowsCheckpointIO:
    """Own publication barriers and the known-durable dependency set for a store."""

    def __init__(self) -> None:
        self._durable: set[tuple[Path, str]] = set()
        self.durable_catalogs: set[str] = set()
        self._uncertain = False

    def require_healthy(self) -> None:
        """Prevent publication and reclamation after an uncertain index update."""
        if self._uncertain:
            raise CheckpointFilesystemError(
                "Windows checkpoint publication could not confirm durability; "
                "stop this generation and verify/resume in a fresh process"
            )

    def _create_file(self, path: Path, mode: int) -> int:
        return filesystem.open_file(
            path, os.O_RDWR | os.O_CREAT | os.O_EXCL, mode, write_through=True
        )

    def _write(self, descriptor: int, payload: memoryview) -> int:
        return os.write(descriptor, payload)

    def _flush(self, descriptor: int) -> None:
        filesystem.flush_file(descriptor)

    def _create_directory(self, path: Path, *, private: bool) -> None:
        parent = filesystem.open_directory(path.parent)
        try:
            descriptor = filesystem.open_child(
                parent,
                path.name,
                os.O_CREAT | os.O_EXCL,
                0o700 if private else 0o777,
                directory=True,
                write_through=True,
            )
            os.close(descriptor)
        finally:
            os.close(parent)

    def _rename(
        self,
        source: Path,
        target: Path,
        *,
        replace: bool,
        directory: bool,
        identity: tuple[int, int] | None = None,
    ) -> None:
        source_parent = filesystem.open_directory(source.parent)
        try:
            target_parent = filesystem.open_directory(target.parent)
            try:
                filesystem.replace_child(
                    source_parent,
                    source.name,
                    target_parent,
                    target.name,
                    replace=replace,
                    directory=directory,
                    write_through=True,
                    expected_identity=identity,
                )
            finally:
                os.close(target_parent)
        finally:
            os.close(source_parent)

    def unlink(self, path: Path, *, directory: bool = False) -> None:
        """Remove a no-follow entry; delayed persistence of reclamation is harmless."""
        self.require_healthy()
        parent = filesystem.open_directory(path.parent)
        try:
            try:
                filesystem.remove_child(parent, path.name, directory=directory)
            except FileNotFoundError:
                pass
        finally:
            os.close(parent)

    def mkdir(
        self,
        path: Path,
        *,
        parents: bool = False,
        exist_ok: bool = False,
        private: bool = True,
    ) -> None:
        """Publish new directory entries by write-through rename, including parents."""
        self.require_healthy()
        path = Path(os.path.abspath(path))
        try:
            descriptor = filesystem.open_directory(path)
        except FileNotFoundError:
            descriptor = None
        if descriptor is not None:
            try:
                if private:
                    filesystem.require_private(descriptor)
            finally:
                os.close(descriptor)
            if not exist_ok:
                raise FileExistsError(path)
            return
        if parents:
            self.mkdir(path.parent, parents=True, exist_ok=True, private=False)
        parent = filesystem.open_directory(path.parent)
        temporary = path.with_name(f".{path.name}.pending-{uuid.uuid4().hex}")
        try:
            self._create_directory(temporary, private=private)
            try:
                self._rename(temporary, path, replace=False, directory=True)
            except FileExistsError:
                if not exist_ok:
                    raise
                self.mkdir(path, exist_ok=True, private=private)
        finally:
            try:
                self.unlink(temporary, directory=True)
            finally:
                os.close(parent)

    def write_atomic(
        self,
        path: Path,
        payloads: Iterable[bytes],
        *,
        replace: bool = True,
        mode: int = 0o600,
        commit_point: bool = False,
    ) -> None:
        """Flush private bytes, publish their name, and confirm publication metadata."""
        self.require_healthy()
        path = Path(os.path.abspath(path))
        parent = filesystem.open_directory(path.parent)
        temporary = path.with_name(f".{path.name}.pending-{uuid.uuid4().hex}")
        descriptor: int | None = None
        publication_started = False
        try:
            descriptor = self._create_file(temporary, mode)
            metadata = os.fstat(descriptor)
            identity = (int(metadata.st_dev), int(metadata.st_ino))
            for payload in payloads:
                view = memoryview(payload)
                while view:
                    written = self._write(descriptor, view)
                    if written <= 0:
                        raise OSError("Windows checkpoint write made no progress")
                    view = view[written:]
            self._flush(descriptor)
            os.close(descriptor)
            descriptor = None
            publication_started = True
            self._rename(temporary, path, replace=replace, directory=False, identity=identity)
        except OSError:
            if commit_point and publication_started:
                self._uncertain = True
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                # An uncertain rename may already have consumed this name. Do not
                # remove either public name or any recovery dependencies here.
                if not self._uncertain:
                    self.unlink(temporary)
            finally:
                os.close(parent)

    def write_new(self, path: Path, payload: bytes, *, mode: int = 0o600) -> None:
        """Exclusively publish complete bytes without exposing a partial record."""
        self.write_atomic(path, (payload,), replace=False, mode=mode)

    def replace_directory(self, source: Path, target: Path) -> None:
        """Publish a complete recovery after its descendants' handles have closed."""
        self.require_healthy()
        self._rename(source, target, replace=False, directory=True)

    def content_object(self, path: Path, payload: bytes) -> bool:
        """Publish or authenticate an immutable object, remembering its barrier."""
        digest = hashlib.sha256(payload).hexdigest()
        self.mkdir(path.parent, parents=True, exist_ok=True)
        try:
            self.write_new(path, payload)
        except FileExistsError:
            self.ensure_file(path, size=len(payload), digest=digest)
            return False
        self._durable.add((path, digest))
        return True

    def ensure_file(self, path: Path, *, size: int, digest: str) -> None:
        """Authenticate and republish an existing dependency once, with bounded I/O."""
        self.require_healthy()
        if (path, digest) in self._durable:
            return
        descriptor = filesystem.open_file(path, os.O_RDONLY)
        try:
            filesystem.require_private(descriptor)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != size:
                raise CheckpointCorruptionError(f"checkpoint dependency changed: {path}")

            def chunks() -> Iterator[bytes]:
                checksum = hashlib.sha256()
                total = 0
                while payload := os.read(descriptor, _COPY_CHUNK_BYTES):
                    total += len(payload)
                    checksum.update(payload)
                    yield payload
                if total != size or checksum.hexdigest() != digest:
                    raise CheckpointCorruptionError(
                        f"checkpoint dependency failed integrity: {path}"
                    )

            self.write_atomic(path, chunks())
        finally:
            os.close(descriptor)
        self._durable.add((path, digest))

    def remove_tree(self, path: Path) -> None:
        """Reclaim an unreferenced tree without following junctions or symlinks."""
        self.require_healthy()
        try:
            entries = filesystem.directory_entries(path)
        except FileNotFoundError:
            return
        for name, metadata in entries:
            child = path / name
            if stat.S_ISDIR(metadata.st_mode):
                self.remove_tree(child)
            else:
                self.unlink(child)
        self.unlink(path, directory=True)
