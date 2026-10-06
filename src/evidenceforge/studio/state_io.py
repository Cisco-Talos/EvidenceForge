"""Private, durable state publication and cross-platform ownership locks."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

from evidenceforge.models.exceptions import EvidenceForgeError


class StudioStateError(EvidenceForgeError):
    """State cannot be opened or changed safely; never implies permission to reset it."""


def canonical_path(path: Path) -> Path:
    """Normalize only macOS system aliases, without resolving user-controlled links."""
    absolute = path.absolute()
    if sys.platform == "darwin":
        for alias in ("/var", "/tmp", "/etc"):
            if absolute.is_relative_to(alias):
                return Path("/private") / absolute.relative_to("/")
    return absolute


def safe_path(path: Path) -> None:
    """Reject links, reparse points and aliased leaves without resolving them away."""
    path = canonical_path(path)
    for part in (path, *path.parents):
        try:
            metadata = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 1024:
            raise StudioStateError(f"State path is a link or reparse point: {part}")
        if part == path and stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
            raise StudioStateError(f"State file has multiple links: {part}")
        if part == path:
            from evidenceforge.studio.ownership import require_owned

            require_owned(metadata)


def private_directory(path: Path) -> None:
    """Create a private directory without traversing linked components."""
    safe_path(path)
    if os.name == "nt":
        from evidenceforge.utils.windows_filesystem import mkdir_private

        mkdir_private(path, parents=True, exist_ok=True)
    else:
        absolute = canonical_path(path)
        descriptor = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in absolute.parts[1:]:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                    os.fsync(descriptor)
                except FileExistsError:
                    pass
                child = os.open(
                    component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
                )
                os.close(descriptor)
                descriptor = child
        finally:
            os.close(descriptor)
    safe_path(path)


def parent_handle(path: Path) -> int:
    """Walk POSIX ancestry through no-follow directory handles."""
    absolute = canonical_path(path)
    descriptor = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in absolute.parent.parts[1:]:
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except (OSError, StudioStateError):
        os.close(descriptor)
        raise


def atomic_write(path: Path, content: bytes, mode: int = 0o600) -> None:
    """Flush bytes before publishing a namespace entry; never follow the destination."""
    private_directory(path.parent)
    safe_path(path)
    if os.name == "nt":
        from evidenceforge.utils.windows_filesystem import write_private_atomic

        write_private_atomic(path, content)
        return
    parent = parent_handle(path)
    temporary = f".{path.name}.{uuid4().hex}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent
        )
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("State publication made no write progress")
            remaining = remaining[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        safe_path(path)
        os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def durable_remove(path: Path, *, precondition: Callable[[], None] | None = None) -> None:
    """Remove a regular entry and persist its absence."""
    safe_path(path)
    if not path.exists():
        return
    if os.name == "nt":
        from evidenceforge.utils import windows_filesystem as filesystem

        parent = filesystem.open_directory(path.parent)
        try:
            if precondition:
                precondition()
            filesystem.remove_child(parent, path.name)
        finally:
            os.close(parent)
        return
    parent = parent_handle(path)
    try:
        if precondition:
            precondition()
        os.unlink(path.name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


class StateLock:
    """Nonblocking OS ownership lock, released even when its process crashes."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.descriptor: int | None = None

    def acquire(self) -> None:
        """Acquire ownership or refuse concurrent mutation."""
        if self.descriptor is not None:
            return
        private_directory(self.path.parent)
        safe_path(self.path)
        descriptor = open_regular(self.path, os.O_RDWR | os.O_CREAT)
        try:
            if os.name == "nt":
                import msvcrt

                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            os.close(descriptor)
            raise StudioStateError(
                "Another Studio process owns this state; retry after it exits"
            ) from error
        self.descriptor = descriptor

    def close(self) -> None:
        """Release ownership."""
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None

    def __enter__(self) -> StateLock:
        self.acquire()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def sync_file(path: Path) -> None:
    """Flush an already materialized SQLite image without loading it into memory."""
    safe_path(path)
    descriptor = open_regular(path, os.O_RDWR)
    try:
        if os.name == "nt":
            from evidenceforge.utils.windows_filesystem import flush_file

            flush_file(descriptor)
        else:
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_copy(
    path: Path, source: Path, mode: int = 0o600, *, precondition: Callable[[], None] | None = None
) -> None:
    """Publish a large verified image in bounded chunks."""
    private_directory(path.parent)
    safe_path(source)
    safe_path(path)
    temporary = f".{path.name}.{uuid4().hex}.tmp"
    if os.name == "nt":
        from evidenceforge.utils import windows_filesystem as filesystem

        parent = filesystem.open_directory(path.parent)
        descriptor = filesystem.open_child(parent, temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    else:
        parent = parent_handle(path)
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent
        )
    try:
        with os.fdopen(open_regular(source, os.O_RDONLY), "rb") as stream:
            while content := stream.read(1024 * 1024):
                remaining = memoryview(content)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise OSError("State copy made no write progress")
                    remaining = remaining[written:]
        if os.name == "nt":
            filesystem.flush_file(descriptor)
        else:
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        safe_path(path)
        if precondition:
            precondition()
        if os.name == "nt":
            filesystem.replace_child(parent, temporary, parent, path.name)
        else:
            os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
    finally:
        if descriptor != -1:
            os.close(descriptor)
        try:
            if os.name == "nt":
                filesystem.remove_child(parent, temporary)
            else:
                os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def open_regular(path: Path, flags: int) -> int:
    """Open a regular single-link file through pinned, no-follow ancestry."""
    safe_path(path)
    expected: tuple[int, int] | None = None
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(metadata.st_mode):
            raise StudioStateError("State entry must be a regular file with one link")
        expected = (metadata.st_dev, metadata.st_ino)
    if os.name == "nt":
        from evidenceforge.utils.windows_filesystem import open_file

        descriptor = open_file(path, flags)
    else:
        parent = parent_handle(path)
        try:
            if flags & os.O_CREAT and not flags & os.O_EXCL:
                # Separate atomic creation from attachment to an existing inode.
                # Concurrent O_CREAT|O_NOFOLLOW calls were observed to fail with ENOENT on macOS.
                try:
                    descriptor = os.open(
                        path.name, flags | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
                    )
                except FileExistsError:
                    descriptor = os.open(
                        path.name, (flags & ~os.O_CREAT) | os.O_NOFOLLOW, dir_fd=parent
                    )
            else:
                descriptor = os.open(path.name, flags | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        finally:
            os.close(parent)
    metadata = os.fstat(descriptor)
    if expected is not None and (metadata.st_dev, metadata.st_ino) != expected:
        os.close(descriptor)
        raise StudioStateError("State entry changed while opening; reopen to inspect it again")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        os.close(descriptor)
        raise StudioStateError("State entry must be a regular file with one link")
    try:
        from evidenceforge.studio.ownership import require_owned

        require_owned(metadata)
    except StudioStateError:
        os.close(descriptor)
        raise
    return descriptor


def read_bytes(path: Path, limit: int | None = None) -> bytes:
    """Read through verified handles, optionally enforcing a bounded document size."""
    with os.fdopen(open_regular(path, os.O_RDONLY), "rb") as stream:
        content = stream.read() if limit is None else stream.read(limit + 1)
    if limit is not None and len(content) > limit:
        raise StudioStateError("Studio state document exceeds its supported size")
    return content


def file_checksum(path: Path) -> str:
    """Hash every byte in bounded chunks, including all SQLite pages."""
    digest = hashlib.sha256()
    with os.fdopen(open_regular(path, os.O_RDONLY), "rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


class StateIO:
    """Injectable persistence boundary; normal applications use native durable operations."""

    def write(self, path: Path, content: bytes, mode: int = 0o600) -> None:
        """Publish a small document."""
        atomic_write(path, content, mode)

    def copy(
        self,
        path: Path,
        source: Path,
        mode: int = 0o600,
        *,
        precondition: Callable[[], None] | None = None,
    ) -> None:
        """Publish a bounded large-file image."""
        atomic_copy(path, source, mode, precondition=precondition)

    def remove(self, path: Path, *, precondition: Callable[[], None] | None = None) -> None:
        """Publish original absence."""
        durable_remove(path, precondition=precondition)

    def flush(self, path: Path) -> None:
        """Persist an already-created image."""
        sync_file(path)

    def backup(self, source: sqlite3.Connection, target: sqlite3.Connection) -> None:
        """Copy committed SQLite pages, including WAL, through SQLite's snapshot API."""
        source.backup(target, pages=256)
