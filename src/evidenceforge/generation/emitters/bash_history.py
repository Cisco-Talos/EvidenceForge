# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Bash history emitter with durable, retryable per-user journals."""

from __future__ import annotations

import errno
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import stat
import tempfile
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from queue import Empty, Full
from threading import Event, Lock, RLock, get_ident
from typing import Any

from jinja2 import Template

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import (
    _EXACT_PUBLICATION_ATTEMPT,
    ExactPublicationError,
    ExactPublicationKey,
    LogEmitter,
    _ExactPublicationAttempt,
    _ExactQueuedPublication,
    complete_exact_publication_queue_item,
    exact_publication_queue_payload,
    exact_publication_worker_attempt,
    stage_exact_publication_row,
)
from evidenceforge.utils.paths import sanitize_path_component

logger = logging.getLogger(__name__)

_DEFAULT_JOURNAL_ROW_CAPACITY = 1_000_000
_DEFAULT_JOURNAL_BYTE_CAPACITY = 512 * 1024 * 1024
_DEFAULT_JOURNAL_ROUTE_CAPACITY = 10_000
_EXACT_HISTORY_RESERVATION_ROUTE: ContextVar[tuple[str, str] | None] = ContextVar(
    "exact_history_reservation_route",
    default=None,
)
_EXACT_HISTORY_REGISTRATION_READY: ContextVar[tuple[str, int] | None] = ContextVar(
    "exact_history_registration_ready",
    default=None,
)
_EXACT_HISTORY_ENVELOPE_VERSION = 1
_PREPARED_HISTORY_EVENT_VERSION = 1
_EXACT_METADATA_BYTES = 256
_EXACT_RESERVATION_ROWS = 3
_STREAM_CHUNK_BYTES = 64 * 1024
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_PRIVATE_ROUTE_DOMAIN = b"evidenceforge\0bash-history\0private-route\0v1\0"
_PRIVATE_NONCE_HEX_LENGTH = 32
_JOURNAL_PRIVATE_SUFFIX = ".sqlite3"
_EXPORT_PRIVATE_SUFFIX = ".tmp"
_SQLITE_COMPANION_SUFFIXES = ("-journal", "-wal", "-shm")
_SPOOL_DIRECTORY_ENVIRONMENT = "EFORGE_SPOOL_DIR"
_SPOOL_DIRECTORY_PREFIX = ".evidenceforge-bash-journal-"

# A matching command erases itself and every history entry ordered before it.
_CLEAR_PATTERNS = (
    re.compile(r"history\s+-c"),
    re.compile(r">\s*~/\.bash_history"),
    re.compile(r"cat\s+/dev/null\s*>\s*~/\.bash_history"),
    re.compile(r"truncate\s+-s\s+0\s+.*\.bash_history"),
    re.compile(r"rm\s+((-[rf]+\s+)?.*)?\.bash_history"),
    re.compile(r"shred\s+.*(-u|--remove).*\.bash_history"),
)


@dataclass(frozen=True, slots=True)
class BashHistoryJournalCensus:
    """Bounded-memory and durable-pending counts for all history writers."""

    writers: int
    pending_operations: int
    pending_bytes: int
    reserved_rows: int
    reserved_bytes: int
    admission_receipts: int
    export_receipts: int
    retained_rows: int
    retained_bytes: int
    row_capacity_per_writer: int
    byte_capacity_per_writer: int
    high_water_rows: int
    high_water_bytes: int
    routes: int = 0
    route_capacity: int = _DEFAULT_JOURNAL_ROUTE_CAPACITY

    @property
    def row_capacity(self) -> int:
        """Global retained-row ceiling (compatibility-safe explicit name)."""

        return self.row_capacity_per_writer

    @property
    def byte_capacity(self) -> int:
        """Global retained-byte ceiling (compatibility-safe explicit name)."""

        return self.byte_capacity_per_writer

    @property
    def pending_rows(self) -> int:
        """Compatibility name for callers that count pending journal rows."""

        return self.pending_operations

    @property
    def active_receipts(self) -> int:
        """Compatibility name for live durable-admission receipts."""

        return self.admission_receipts


@dataclass(frozen=True, slots=True)
class _HistoryJournalCensus:
    pending_rows: int
    pending_bytes: int
    total_events: int
    high_water_rows: int
    high_water_bytes: int
    reserved_rows: int
    reserved_bytes: int
    receipt_rows: int
    admission_receipts: int
    export_receipts: int
    plan_rows: int
    plan_bytes: int

    @property
    def retained_rows(self) -> int:
        return (
            self.pending_rows
            + self.receipt_rows
            + self.admission_receipts
            + self.export_receipts
            + self.plan_rows
        )

    @property
    def retained_bytes(self) -> int:
        metadata_rows = self.retained_rows
        return self.pending_bytes + self.plan_bytes + metadata_rows * _EXACT_METADATA_BYTES


@dataclass(slots=True)
class _ExactDrainRequest:
    """FIFO acknowledgement that drains worker work without exporting it."""

    completed: Event = field(default_factory=Event)
    error: BaseException | None = None


def _publication_key(key: ExactPublicationKey) -> str:
    return f"{key[0]}:{key[1]}:{key[2]}"


def _lexical_absolute(path: Path) -> Path:
    """Return a normalized absolute path without following any symlink."""

    return Path(os.path.abspath(os.fspath(path)))


def _require_contained(base_dir: Path, path: Path) -> tuple[Path, Path]:
    """Validate lexical containment without resolving attacker-controlled links."""

    base = _lexical_absolute(base_dir)
    candidate = _lexical_absolute(path)
    try:
        candidate.relative_to(base)
    except ValueError as error:
        raise ExactPublicationError(
            f"Unsafe Bash history path escapes its output root: {candidate}"
        ) from error
    return base, candidate


def _private_route_stem(base_dir: Path, output_path: Path) -> str:
    """Return one full, domain-separated SHA-256 identifier for a public route."""

    base, candidate = _require_contained(base_dir, output_path)
    relative_parts = candidate.relative_to(base).parts
    digest = hashlib.sha256()
    digest.update(_PRIVATE_ROUTE_DOMAIN)
    digest.update(len(relative_parts).to_bytes(4, "big"))
    for part in relative_parts:
        encoded = os.fsencode(part)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _journal_file_prototypes(base_dir: Path, output_path: Path) -> tuple[str, ...]:
    """Return every SQLite component derived for one output route."""

    stem = _private_route_stem(base_dir, output_path)
    nonce = "0" * _PRIVATE_NONCE_HEX_LENGTH
    journal = f".{stem}.journal-{nonce}{_JOURNAL_PRIVATE_SUFFIX}"
    return (journal, *(f"{journal}{suffix}" for suffix in _SQLITE_COMPANION_SUFFIXES))


def _export_file_prototype(base_dir: Path, output_path: Path) -> str:
    """Return the maximum atomic-export component for one output route."""

    stem = _private_route_stem(base_dir, output_path)
    nonce = "0" * _PRIVATE_NONCE_HEX_LENGTH
    return f".{stem}.export-{nonce}{_EXPORT_PRIVATE_SUFFIX}"


def _private_file_prototypes(base_dir: Path, output_path: Path) -> tuple[str, ...]:
    """Return every maximum private component derived for one output route."""

    return (
        *_journal_file_prototypes(base_dir, output_path),
        _export_file_prototype(base_dir, output_path),
    )


def _directory_path_limits(directory_descriptor: int) -> tuple[int | None, int | None]:
    """Read bounded filesystem limits from one safely opened directory."""

    fpathconf = getattr(os, "fpathconf", None)
    if fpathconf is None:  # pragma: no cover - non-POSIX fallback
        raise ExactPublicationError("Bash history cannot safely determine filesystem path limits")
    try:
        name_max = int(fpathconf(directory_descriptor, "PC_NAME_MAX"))
        path_max = int(fpathconf(directory_descriptor, "PC_PATH_MAX"))
    except (OSError, ValueError) as error:  # pragma: no cover - platform-specific failure
        raise ExactPublicationError(
            "Bash history cannot safely determine filesystem path limits"
        ) from error
    if name_max <= 0 or path_max <= 0:  # pragma: no cover - indeterminate platform limit
        raise ExactPublicationError("Bash history filesystem path limits are not bounded")
    return name_max, path_max


def _validate_component_capacity(component: str, name_max: int | None, *, label: str) -> None:
    """Reject a derived directory entry that cannot fit on its target filesystem."""

    if (
        not component
        or component in {".", ".."}
        or "\x00" in component
        or "/" in component
        or (os.altsep is not None and os.altsep in component)
    ):
        raise ExactPublicationError(f"Unsafe Bash history {label} component")
    encoded_bytes = len(os.fsencode(component))
    if name_max is not None and encoded_bytes > name_max:
        raise ExactPublicationError(
            f"Bash history {label} component exceeds NAME_MAX ({encoded_bytes} > {name_max})"
        )


def _validate_path_capacity(path: Path, path_max: int | None, *, label: str) -> None:
    """Reject a derived absolute pathname that cannot include its terminating NUL."""

    encoded_bytes = len(os.fsencode(os.fspath(_lexical_absolute(path)))) + 1
    if path_max is not None and encoded_bytes > path_max:
        raise ExactPublicationError(
            f"Bash history {label} path exceeds PATH_MAX ({encoded_bytes} > {path_max})"
        )


def _validate_capacity_from_descriptor(
    directory_descriptor: int,
    *,
    base_dir: Path,
    output_path: Path,
    relative_components: tuple[str, ...],
) -> None:
    """Validate every public and private component/path against one filesystem."""

    name_max, path_max = _directory_path_limits(directory_descriptor)
    for component in relative_components:
        _validate_component_capacity(component, name_max, label="public output")
    export_name = _export_file_prototype(base_dir, output_path)
    _validate_component_capacity(export_name, name_max, label="private export")
    _validate_path_capacity(output_path, path_max, label="public output")
    _validate_path_capacity(
        output_path.parent / export_name,
        path_max,
        label="private export",
    )


def _validate_derived_path_capacity(base_dir: Path, output_path: Path) -> None:
    """Preflight a future route from its deepest safely opened ancestor."""

    base, candidate = _require_contained(base_dir, output_path)
    # Validate from the output root (or its nearest existing ancestor) before
    # attempting any syscall with a potentially oversized derived component.
    existing = base
    descriptor: int | None = None
    while descriptor is None:
        try:
            descriptor = _open_directory_nofollow(existing, create=False)
        except FileNotFoundError as error:
            parent = existing.parent
            if parent == existing:  # pragma: no cover - filesystem root must exist
                raise ExactPublicationError(
                    "Bash history output has no existing filesystem ancestor"
                ) from error
            existing = parent
    try:
        relative_components = candidate.relative_to(existing).parts
        _validate_capacity_from_descriptor(
            descriptor,
            base_dir=base,
            output_path=candidate,
            relative_components=relative_components,
        )
    finally:
        os.close(descriptor)

    # A deeper existing directory may be a mount with stricter limits. All
    # route components are now known to fit the outer filesystem, so probing
    # the deepest present parent cannot itself cross its component ceiling.
    existing = candidate.parent
    descriptor = None
    while descriptor is None:
        try:
            descriptor = _open_directory_nofollow(existing, create=False)
        except FileNotFoundError:
            existing = existing.parent
    try:
        relative_components = candidate.relative_to(existing).parts
        _validate_capacity_from_descriptor(
            descriptor,
            base_dir=base,
            output_path=candidate,
            relative_components=relative_components,
        )
    finally:
        os.close(descriptor)


def _validate_parent_capacity(
    directory_descriptor: int,
    *,
    base_dir: Path,
    output_path: Path,
) -> None:
    """Recheck final-parent limits immediately before private mutation."""

    base, candidate = _require_contained(base_dir, output_path)
    _validate_capacity_from_descriptor(
        directory_descriptor,
        base_dir=base,
        output_path=candidate,
        relative_components=(candidate.name,),
    )


def _open_directory_nofollow(path: Path, *, create: bool) -> int:
    """Open a directory by walking every component with no-follow semantics."""

    absolute = _lexical_absolute(path)
    if os.open not in os.supports_dir_fd:
        current = Path(absolute.anchor)
        for component in absolute.parts[1:]:  # pragma: no cover - fallback platforms
            current /= component
            try:
                metadata = os.lstat(current)
            except FileNotFoundError:
                if not create:
                    raise
                current.mkdir(mode=0o755)
                metadata = os.lstat(current)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ExactPublicationError(f"Unsafe Bash history directory ancestry: {current}")
        return os.open(absolute, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)

    descriptor = os.open(absolute.anchor, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
    try:
        for component in absolute.parts[1:]:
            try:
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, mode=0o755, dir_fd=descriptor)
                except FileExistsError:
                    pass
                else:
                    os.fsync(descriptor)
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                    dir_fd=descriptor,
                )
            except OSError as error:
                raise ExactPublicationError(
                    f"Unsafe Bash history directory ancestry: {absolute}"
                ) from error
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validate_future_output_path(base_dir: Path, output_path: Path) -> None:
    """Reject existing symlink ancestry or a non-regular final output."""

    base, candidate = _require_contained(base_dir, output_path)
    _validate_derived_path_capacity(base, candidate)
    relative_parent = candidate.parent.relative_to(base)
    current = base
    try:
        descriptor = _open_directory_nofollow(base, create=False)
    except FileNotFoundError:
        # Once an ancestor is absent, no deeper symlink can presently redirect us.
        parent = base.parent
        while parent != parent.parent:
            try:
                descriptor = _open_directory_nofollow(parent, create=False)
                os.close(descriptor)
                break
            except FileNotFoundError:
                parent = parent.parent
        return
    try:
        for component in relative_parent.parts:
            current /= component
            try:
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                return
            except OSError as error:
                raise ExactPublicationError(
                    f"Unsafe Bash history route ancestry: {current}"
                ) from error
            os.close(descriptor)
            descriptor = next_descriptor
        try:
            metadata = os.stat(candidate.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ExactPublicationError(f"Unsafe Bash history output path: {candidate}")
    finally:
        os.close(descriptor)


def _safe_file_metadata(
    directory_descriptor: int, name: str, *, label: str
) -> os.stat_result | None:
    try:
        metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ExactPublicationError(f"Unsafe Bash history {label}: {name}")
    return metadata


def _open_regular_nofollow(directory_descriptor: int, name: str, flags: int) -> int:
    descriptor = os.open(name, flags | _NOFOLLOW, dir_fd=directory_descriptor)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise ExactPublicationError(f"Unsafe Bash history regular file: {name}")
    return descriptor


def _create_private_file(directory_descriptor: int, prefix: str, suffix: str) -> tuple[int, str]:
    """Create one private regular file relative to an already-safe directory."""

    name_max, _path_max = _directory_path_limits(directory_descriptor)
    for _attempt in range(128):
        name = f"{prefix}{secrets.token_hex(16)}{suffix}"
        _validate_component_capacity(name, name_max, label="private")
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                0o600,
                dir_fd=directory_descriptor,
            )
        except FileExistsError:
            continue
        except OSError as error:
            if error.errno == errno.ENAMETOOLONG:
                raise ExactPublicationError(
                    "Bash history private filename exceeds the filesystem limit"
                ) from error
            raise
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            raise ExactPublicationError(f"Unsafe Bash history private file: {name}")
        return descriptor, name
    raise ExactPublicationError("Unable to allocate a unique Bash history private file")


def _hash_descriptor(descriptor: int, *, expected_size: int) -> tuple[str, int]:
    """Hash exactly one stat-sealed size and reject growth or truncation promptly."""

    digest = hashlib.sha256()
    size = 0
    os.lseek(descriptor, 0, os.SEEK_SET)
    while size < expected_size:
        chunk = os.read(descriptor, min(_STREAM_CHUNK_BYTES, expected_size - size))
        if not chunk:
            raise ExactPublicationError("Bash history file shrank while hashing")
        digest.update(chunk)
        size += len(chunk)
    if os.read(descriptor, 1):
        raise ExactPublicationError("Bash history file grew while hashing")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest(), size


def _copy_descriptor(
    source: int,
    destination: int,
    digest: Any,
    *,
    expected_size: int,
    expected_digest: str,
) -> int:
    """Copy one sealed regular-file snapshot without reading beyond its charge."""

    copied = 0
    copied_digest = hashlib.sha256()
    os.lseek(source, 0, os.SEEK_SET)
    while copied < expected_size:
        chunk = os.read(source, min(_STREAM_CHUNK_BYTES, expected_size - copied))
        if not chunk:
            raise ExactPublicationError(
                "Bash history output shrank while copying its sealed baseline"
            )
        view = memoryview(chunk)
        while view:
            written = os.write(destination, view)
            view = view[written:]
        digest.update(chunk)
        copied_digest.update(chunk)
        copied += len(chunk)
    if os.read(source, 1):
        raise ExactPublicationError("Bash history output grew while copying its sealed baseline")
    if copied_digest.hexdigest() != expected_digest:
        raise ExactPublicationError("Bash history output changed while copying its sealed baseline")
    return copied


def _connect_existing_journal(journal_path: Path) -> sqlite3.Connection:
    """Open only an existing private journal before any SQLite mutation."""

    return sqlite3.connect(
        f"{journal_path.as_uri()}?mode=rw",
        uri=True,
        check_same_thread=False,
    )


def _real_absolute(path: Path) -> Path:
    """Return one canonical absolute path for trusted private-spool selection."""

    return _lexical_absolute(Path(os.path.realpath(os.fspath(path))))


def _effective_user_id() -> int | None:
    """Return the POSIX effective user id when the platform exposes one."""

    getter = getattr(os, "geteuid", None)
    if getter is None:
        return None
    return int(getter())


def _verify_directory_fsync(descriptor: int) -> None:
    """Probe durable directory-fsync support for exact journal admission."""

    os.fsync(descriptor)


def _verify_descriptor_listing(descriptor: int) -> None:
    """Probe listdir(fd) support without changing private-spool contents."""

    os.listdir(descriptor)


def _verify_descriptor_relative_access(descriptor: int) -> None:
    """Probe actual openat/statat support without mutating the spool filesystem."""

    reopened = os.open(
        ".",
        os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
        dir_fd=descriptor,
    )
    try:
        metadata = os.stat(".", dir_fd=descriptor, follow_symlinks=False)
        retained = os.fstat(reopened)
        if not stat.S_ISDIR(metadata.st_mode) or (int(metadata.st_dev), int(metadata.st_ino)) != (
            int(retained.st_dev),
            int(retained.st_ino),
        ):
            raise ExactPublicationError(
                "Exact Bash history descriptor-relative capability probe changed identity"
            )
    finally:
        os.close(reopened)


def _require_exact_journal_capabilities() -> None:
    """Fail exact admission closed without the required POSIX filesystem contract."""

    supports_dir_fd = getattr(os, "supports_dir_fd", frozenset())
    required_dir_fd = (os.open, os.mkdir, os.stat, os.unlink, os.rmdir, os.rename)
    supports_follow_symlinks = getattr(os, "supports_follow_symlinks", frozenset())
    if (
        os.name != "posix"
        or _NOFOLLOW == 0
        or _DIRECTORY == 0
        or _effective_user_id() is None
        or not callable(getattr(os, "fpathconf", None))
        or not callable(getattr(os, "fsync", None))
        or not callable(getattr(os, "listdir", None))
        or any(operation not in supports_dir_fd for operation in required_dir_fd)
        or os.stat not in supports_follow_symlinks
    ):
        raise ExactPublicationError(
            "Exact Bash history publication requires POSIX directory-descriptor, "
            "no-follow, and effective-owner support"
        )

    configured = os.environ.get(_SPOOL_DIRECTORY_ENVIRONMENT)
    probe_path = _real_absolute(
        Path(configured).expanduser() if configured else Path(tempfile.gettempdir())
    )
    try:
        while True:
            try:
                descriptor = _open_directory_nofollow(probe_path, create=False)
            except FileNotFoundError as error:
                parent = probe_path.parent
                if parent == probe_path:  # pragma: no cover - filesystem root must exist
                    raise ExactPublicationError(
                        "Exact Bash history private spool has no existing capability probe root"
                    ) from error
                probe_path = parent
                continue
            break
    except (NotImplementedError, TypeError) as error:
        raise ExactPublicationError(
            "Exact Bash history publication requires working directory-descriptor operations"
        ) from error
    try:
        # listdir(fd) and directory fsync have no stdlib capability registry, so
        # exercise them plus the registry-backed operations against the actual
        # spool filesystem without mutating it.
        _verify_descriptor_relative_access(descriptor)
        _verify_descriptor_listing(descriptor)
        _verify_directory_fsync(descriptor)
    except (OSError, TypeError, NotImplementedError) as error:
        raise ExactPublicationError(
            "Exact Bash history publication requires descriptor listing and directory fsync"
        ) from error
    finally:
        os.close(descriptor)


def _validate_private_spool_ancestry(path: Path) -> None:
    """Require a no-follow spool ancestry controlled by root or this process user."""

    effective_user = _effective_user_id()
    current = path
    while True:
        descriptor = _open_directory_nofollow(current, create=False)
        try:
            metadata = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):  # pragma: no cover - guarded by open
            raise ExactPublicationError(f"Unsafe Bash history private spool directory: {current}")
        if effective_user is not None and int(metadata.st_uid) not in {0, effective_user}:
            raise ExactPublicationError(
                f"Bash history private spool ancestry is not emitter-controlled: {current}"
            )
        permissions = stat.S_IMODE(metadata.st_mode)
        if permissions & 0o022 and not metadata.st_mode & stat.S_ISVTX:
            raise ExactPublicationError(
                f"Bash history private spool ancestry is externally writable: {current}"
            )
        if current == current.parent:
            return
        current = current.parent


def _validate_existing_private_spool_ancestor(path: Path) -> None:
    """Validate the deepest existing ancestor before creating a configured spool."""

    current = path
    while True:
        try:
            descriptor = _open_directory_nofollow(current, create=False)
        except FileNotFoundError as error:
            parent = current.parent
            if parent == current:  # pragma: no cover - filesystem root must exist
                raise ExactPublicationError(
                    "Bash history private spool has no existing filesystem ancestor"
                ) from error
            current = parent
            continue
        else:
            os.close(descriptor)
            _validate_private_spool_ancestry(current)
            return


def _open_private_spool_root(base_dir: Path) -> tuple[Path, int]:
    """Open a trusted spool root that is disjoint from the public output tree."""

    configured = os.environ.get(_SPOOL_DIRECTORY_ENVIRONMENT)
    if configured:
        spool_root = _real_absolute(Path(configured).expanduser())
    else:
        # Resolve only the platform-owned temporary root. On Darwin the public
        # spelling commonly starts with /var, which is itself a system symlink.
        spool_root = _real_absolute(Path(tempfile.gettempdir()))
    real_base_dir = _real_absolute(base_dir)
    try:
        spool_root.relative_to(real_base_dir)
    except ValueError:
        pass
    else:
        raise ExactPublicationError(
            "Bash history private spool must be outside its public output root; "
            f"configure {_SPOOL_DIRECTORY_ENVIRONMENT} to a disjoint trusted directory"
        )
    if configured:
        _validate_existing_private_spool_ancestor(spool_root)
    descriptor = _open_directory_nofollow(spool_root, create=configured is not None)
    try:
        _validate_private_spool_ancestry(spool_root)
        real_spool_root = _real_absolute(spool_root)
        try:
            real_spool_root.relative_to(real_base_dir)
        except ValueError:
            pass
        else:
            raise ExactPublicationError(
                "Bash history private spool must be outside its public output root; "
                f"configure {_SPOOL_DIRECTORY_ENVIRONMENT} to a disjoint trusted directory"
            )
        return real_spool_root, descriptor
    except BaseException:
        os.close(descriptor)
        raise


class _PrivateJournalDirectory:
    """Own one protected SQLite directory outside attacker-controlled output paths."""

    def __init__(self, *, base_dir: Path, output_path: Path) -> None:
        self._base_dir, self._output_path = _require_contained(base_dir, output_path)
        self._journal_prefix = f".{_private_route_stem(base_dir, output_path)}.journal-"
        self.path: Path | None = None
        self._parent_descriptor: int | None = None
        self._directory_descriptor: int | None = None
        self._directory_name: str | None = None
        self._identity: tuple[int, int] | None = None
        self._unlinked = False
        self._closed = False
        self._strict_exact = False
        self._initialization_pending = False
        self._initialization_error: BaseException | None = None

        spool_root, parent_descriptor = _open_private_spool_root(self._base_dir)
        try:
            created_path = Path(tempfile.mkdtemp(prefix=_SPOOL_DIRECTORY_PREFIX, dir=spool_root))
        except BaseException:
            os.close(parent_descriptor)
            raise
        if created_path.parent != spool_root:  # pragma: no cover - tempfile contract
            os.close(parent_descriptor)
            raise ExactPublicationError("Bash history private spool escaped its trusted root")
        self.path = created_path
        self._parent_descriptor = parent_descriptor
        self._directory_name = created_path.name
        self._initialization_pending = True
        try:
            self._finish_initialization()
        except BaseException as error:
            # The writer must retain this allocation as the sole retry/cleanup
            # owner. The first admission surfaces the original failure; a later
            # retry can reconcile a lost return without orphaning the directory.
            self._initialization_error = error

    def _retained_identity(self) -> tuple[os.stat_result, os.stat_result, os.stat_result]:
        """Open or revalidate every retained spelling of the private directory."""

        if self._closed or self._unlinked:
            raise ExactPublicationError("Bash history private spool is already terminal")
        path = self.path
        parent_descriptor = self._parent_descriptor
        directory_name = self._directory_name
        if path is None or parent_descriptor is None or directory_name is None:
            raise ExactPublicationError("Bash history private spool lost its identity")
        current = os.stat(
            directory_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISDIR(current.st_mode):
            raise ExactPublicationError("Bash history private spool identity changed")
        directory_descriptor = self._directory_descriptor
        if directory_descriptor is None:
            directory_descriptor = os.open(
                directory_name,
                os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                dir_fd=parent_descriptor,
            )
            self._directory_descriptor = directory_descriptor
        retained = os.fstat(directory_descriptor)
        reopened_descriptor = _open_directory_nofollow(path, create=False)
        try:
            reopened = os.fstat(reopened_descriptor)
        finally:
            os.close(reopened_descriptor)
        identity = self._identity
        retained_identity = (int(retained.st_dev), int(retained.st_ino))
        if identity is None:
            identity = retained_identity
            self._identity = identity
        if (
            not stat.S_ISDIR(retained.st_mode)
            or not stat.S_ISDIR(reopened.st_mode)
            or (int(current.st_dev), int(current.st_ino)) != identity
            or retained_identity != identity
            or (int(reopened.st_dev), int(reopened.st_ino)) != identity
        ):
            raise ExactPublicationError("Bash history private spool identity changed")
        return current, retained, reopened

    def _finish_initialization(self) -> None:
        """Complete or retry validation of a newly allocated private directory."""

        _current, retained, _reopened = self._retained_identity()
        effective_user = _effective_user_id()
        if effective_user is not None and int(retained.st_uid) != effective_user:
            raise ExactPublicationError("Bash history private spool has an unsafe owner")
        if effective_user is not None and stat.S_IMODE(retained.st_mode) != 0o700:
            raise ExactPublicationError("Bash history private spool is not mode 0700")
        directory_descriptor = self._directory_descriptor
        parent_descriptor = self._parent_descriptor
        path = self.path
        if directory_descriptor is None or parent_descriptor is None or path is None:
            raise ExactPublicationError("Bash history private spool lost its descriptors")
        if os.listdir(directory_descriptor):
            raise ExactPublicationError("Bash history private spool was not created empty")
        name_max, path_max = _directory_path_limits(directory_descriptor)
        for private_name in _journal_file_prototypes(self._base_dir, self._output_path):
            _validate_component_capacity(private_name, name_max, label="private journal")
            _validate_path_capacity(path / private_name, path_max, label="private journal")
        self._fsync_parent(parent_descriptor)
        self._initialization_pending = False

    @property
    def directory_descriptor(self) -> int:
        """Return the pinned journal directory after revalidating its identity."""

        self.validate()
        if self._directory_descriptor is None:  # pragma: no cover - validate fails first
            raise ExactPublicationError("Bash history private spool lost its descriptor")
        return self._directory_descriptor

    def validate(self) -> None:
        """Fail closed if the protected journal directory identity changes."""

        initialization_error = self._initialization_error
        if initialization_error is not None:
            self._initialization_error = None
            raise initialization_error
        if self._initialization_pending:
            self._finish_initialization()
        path = self.path
        if path is None:
            raise ExactPublicationError("Bash history private spool lost its identity")
        current, retained, reopened = self._retained_identity()
        if self._strict_exact:
            effective_user = _effective_user_id()
            if effective_user is None:
                raise ExactPublicationError("Bash history private spool lost POSIX owner support")
            _validate_private_spool_ancestry(path.parent)
            for metadata in (current, retained, reopened):
                if (
                    int(metadata.st_uid) != effective_user
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                ):
                    raise ExactPublicationError(
                        "Bash history exact private spool lost owner or mode 0700"
                    )

    def require_exact_guarantees(self) -> None:
        """Upgrade this route to repeated exact-publication trust validation."""

        if self._strict_exact:
            self.validate()
            return
        self.validate()
        path = self.path
        parent_descriptor = self._parent_descriptor
        directory_descriptor = self._directory_descriptor
        if path is None or parent_descriptor is None or directory_descriptor is None:
            raise ExactPublicationError("Bash history exact private spool lost its descriptors")
        effective_user = _effective_user_id()
        if effective_user is None:
            raise ExactPublicationError("Bash history exact publication requires POSIX ownership")
        _validate_private_spool_ancestry(path.parent)
        metadata = os.fstat(directory_descriptor)
        if int(metadata.st_uid) != effective_user or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise ExactPublicationError(
                "Bash history exact private spool requires owner-only mode 0700"
            )
        try:
            _verify_directory_fsync(directory_descriptor)
            _verify_directory_fsync(parent_descriptor)
        except (OSError, TypeError, NotImplementedError) as error:
            raise ExactPublicationError(
                "Bash history exact private spool requires durable directory fsync"
            ) from error
        self._strict_exact = True
        self.validate()

    def fsync(self) -> None:
        """Durably persist private journal directory changes."""

        os.fsync(self.directory_descriptor)

    def close(self) -> None:
        """Retryably unlink one empty private directory and fsync its parent."""

        if self._closed:
            return
        self._initialization_error = None
        if not self._unlinked:
            self._retained_identity()
        parent_descriptor = self._parent_descriptor
        directory_descriptor = self._directory_descriptor
        directory_name = self._directory_name
        identity = self._identity
        path = self.path
        if (
            parent_descriptor is None
            or directory_descriptor is None
            or directory_name is None
            or identity is None
            or path is None
        ):
            raise ExactPublicationError("Bash history private spool lost its cleanup identity")
        if not self._unlinked:
            self._retained_identity()
            removed_stale = False
            for retained_name in os.listdir(directory_descriptor):
                if not self._is_owned_journal_component(retained_name):
                    raise ExactPublicationError(
                        "Bash history private spool retained an unowned file"
                    )
                metadata = os.stat(
                    retained_name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                if stat.S_ISDIR(metadata.st_mode):
                    raise ExactPublicationError(
                        "Bash history private spool retained an unsafe directory"
                    )
                self._unlink_retained_component(directory_descriptor, retained_name)
                removed_stale = True
            if removed_stale:
                os.fsync(directory_descriptor)
            try:
                self._remove_directory(parent_descriptor, directory_name, path)
            except BaseException:
                try:
                    current = os.stat(
                        directory_name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    self._unlinked = True
                else:
                    if (
                        not stat.S_ISDIR(current.st_mode)
                        or (int(current.st_dev), int(current.st_ino)) != identity
                    ):
                        raise ExactPublicationError(
                            "Bash history private spool changed during cleanup"
                        )
                raise
            else:
                self._unlinked = True
        self._fsync_parent(parent_descriptor)
        os.close(directory_descriptor)
        os.close(parent_descriptor)
        self._directory_descriptor = None
        self._parent_descriptor = None
        self._initialization_pending = False
        self._closed = True

    def _is_owned_journal_component(self, name: str) -> bool:
        """Return whether a stale component belongs to this route's private journal."""

        if not name.startswith(self._journal_prefix):
            return False
        remainder = name.removeprefix(self._journal_prefix)
        suffixes = (
            _JOURNAL_PRIVATE_SUFFIX,
            *(f"{_JOURNAL_PRIVATE_SUFFIX}{suffix}" for suffix in _SQLITE_COMPANION_SUFFIXES),
        )
        for suffix in suffixes:
            if not remainder.endswith(suffix):
                continue
            nonce = remainder[: -len(suffix)]
            return len(nonce) == _PRIVATE_NONCE_HEX_LENGTH and all(
                character in "0123456789abcdef" for character in nonce
            )
        return False

    def _remove_directory(
        self,
        parent_descriptor: int,
        directory_name: str,
        path: Path,
    ) -> None:
        """Fault-injection seam for private-directory removal."""

        if os.rmdir in os.supports_dir_fd:
            os.rmdir(directory_name, dir_fd=parent_descriptor)
        else:  # pragma: no cover - non-POSIX fallback
            os.rmdir(path)

    def _unlink_retained_component(self, directory_descriptor: int, name: str) -> None:
        """Fault-injection seam for a route-owned residual SQLite component."""

        os.unlink(name, dir_fd=directory_descriptor)

    def _fsync_parent(self, parent_descriptor: int) -> None:
        """Fault-injection seam for private-directory durability."""

        os.fsync(parent_descriptor)


def _extract_epoch(entry: str) -> int:
    for line in entry.splitlines():
        if line.startswith("#") and line[1:].strip().isdigit():
            return int(line[1:].strip())
    return 0


def _is_clear_entry(entry: str) -> bool:
    command = " ".join(line for line in entry.splitlines() if not line.startswith("#")).strip()
    return any(pattern.search(command) for pattern in _CLEAR_PATTERNS)


@dataclass(frozen=True, slots=True)
class _BudgetSnapshot:
    writers: int
    routes: int
    pending_operations: int
    pending_bytes: int
    reserved_rows: int
    reserved_bytes: int
    receipt_rows: int
    admission_receipts: int
    export_receipts: int
    plan_rows: int
    plan_bytes: int
    retained_rows: int
    retained_bytes: int
    high_water_rows: int
    high_water_bytes: int
    total_events: int


class _GlobalHistoryBudget:
    """One scalar, constant-time capacity ledger shared by every route."""

    def __init__(self, *, route_capacity: int, row_capacity: int, byte_capacity: int) -> None:
        self.route_capacity = route_capacity
        self.row_capacity = row_capacity
        self.byte_capacity = byte_capacity
        self._lock = RLock()
        self._writers = 0
        self._routes = 0
        self._pending_operations = 0
        self._pending_bytes = 0
        self._reserved_rows = 0
        self._reserved_bytes = 0
        self._receipt_rows = 0
        self._admission_receipts = 0
        self._export_receipts = 0
        self._plan_rows = 0
        self._plan_bytes = 0
        self._high_water_rows = 0
        self._high_water_bytes = 0
        self._total_events = 0

    def _retained_rows_unlocked(self) -> int:
        return (
            self._writers
            + self._pending_operations
            + self._receipt_rows
            + self._admission_receipts
            + self._export_receipts
            + self._plan_rows
        )

    def _retained_bytes_unlocked(self) -> int:
        return (
            self._pending_bytes
            + self._plan_bytes
            + self._retained_rows_unlocked() * _EXACT_METADATA_BYTES
        )

    def _validate_unlocked(self) -> None:
        scalars = (
            self._writers,
            self._routes,
            self._pending_operations,
            self._pending_bytes,
            self._reserved_rows,
            self._reserved_bytes,
            self._receipt_rows,
            self._admission_receipts,
            self._export_receipts,
            self._plan_rows,
            self._plan_bytes,
        )
        if any(value < 0 for value in scalars) or self._writers > self._routes:
            raise RuntimeError("Bash history global journal accounting underflowed")
        rows = self._retained_rows_unlocked() + self._reserved_rows
        retained_bytes = self._retained_bytes_unlocked() + self._reserved_bytes
        if self._routes > self.route_capacity:
            raise ExactPublicationError("Bash history route capacity is exhausted")
        if rows > self.row_capacity:
            raise ExactPublicationError("Bash history journal row capacity is exhausted")
        if retained_bytes > self.byte_capacity:
            raise ExactPublicationError("Bash history journal byte capacity is exhausted")
        self._high_water_rows = max(self._high_water_rows, rows)
        self._high_water_bytes = max(self._high_water_bytes, retained_bytes)

    def _mutate(self, **deltas: int) -> None:
        with self._lock:
            originals: dict[str, int] = {}
            for name, delta in deltas.items():
                attribute = f"_{name}"
                originals[attribute] = int(getattr(self, attribute))
                setattr(self, attribute, originals[attribute] + delta)
            try:
                self._validate_unlocked()
            except BaseException:
                for attribute, original in originals.items():
                    setattr(self, attribute, original)
                raise

    def preflight_exact_upgrade(
        self,
        *,
        retained_bytes: int,
        add_route: bool,
        migration_rows: int,
        migration_bytes: int,
    ) -> None:
        """Validate one complete exact upgrade without mutating census/high-water state."""

        route_rows = int(add_route)
        prospective_rows = route_rows + _EXACT_RESERVATION_ROWS + migration_rows
        prospective_bytes = (
            retained_bytes + migration_bytes + prospective_rows * _EXACT_METADATA_BYTES
        )
        with self._lock:
            if self._routes + route_rows > self.route_capacity:
                raise ExactPublicationError("Bash history route capacity is exhausted")
            if (
                self._retained_rows_unlocked() + self._reserved_rows + prospective_rows
                > self.row_capacity
            ):
                raise ExactPublicationError("Bash history journal row capacity is exhausted")
            if (
                self._retained_bytes_unlocked() + self._reserved_bytes + prospective_bytes
                > self.byte_capacity
            ):
                raise ExactPublicationError("Bash history journal byte capacity is exhausted")

    def reserve_route(self) -> None:
        self._mutate(routes=1, reserved_rows=1, reserved_bytes=_EXACT_METADATA_BYTES)

    def release_reserved_route(self) -> None:
        self._mutate(routes=-1, reserved_rows=-1, reserved_bytes=-_EXACT_METADATA_BYTES)

    def commit_reserved_route(self) -> None:
        self._mutate(writers=1, reserved_rows=-1, reserved_bytes=-_EXACT_METADATA_BYTES)

    def charge_writer_route(self) -> None:
        self._mutate(writers=1, routes=1)

    def release_writer_route(self) -> None:
        self._mutate(writers=-1, routes=-1)

    def reserve_exact(self, retained_bytes: int) -> None:
        self._mutate(
            reserved_rows=_EXACT_RESERVATION_ROWS,
            reserved_bytes=retained_bytes + _EXACT_RESERVATION_ROWS * _EXACT_METADATA_BYTES,
        )

    def release_exact_reservation(self, retained_bytes: int) -> None:
        self._mutate(
            reserved_rows=-_EXACT_RESERVATION_ROWS,
            reserved_bytes=-(retained_bytes + _EXACT_RESERVATION_ROWS * _EXACT_METADATA_BYTES),
        )

    def commit_exact(self, retained_bytes: int) -> None:
        self._mutate(
            reserved_rows=-_EXACT_RESERVATION_ROWS,
            reserved_bytes=-(retained_bytes + _EXACT_RESERVATION_ROWS * _EXACT_METADATA_BYTES),
            pending_operations=1,
            pending_bytes=retained_bytes,
            receipt_rows=1,
            admission_receipts=1,
            total_events=1,
        )

    def rollback_exact_commit(self, retained_bytes: int) -> None:
        self._mutate(
            reserved_rows=_EXACT_RESERVATION_ROWS,
            reserved_bytes=retained_bytes + _EXACT_RESERVATION_ROWS * _EXACT_METADATA_BYTES,
            pending_operations=-1,
            pending_bytes=-retained_bytes,
            receipt_rows=-1,
            admission_receipts=-1,
            total_events=-1,
        )

    def charge_ordinary(self, retained_bytes: int) -> None:
        self._mutate(pending_operations=1, pending_bytes=retained_bytes)

    def rollback_ordinary(self, retained_bytes: int) -> None:
        self._mutate(pending_operations=-1, pending_bytes=-retained_bytes)

    def reserve_ordinary_migration(self, rows: int, retained_bytes: int) -> None:
        self._mutate(
            reserved_rows=rows,
            reserved_bytes=retained_bytes + rows * _EXACT_METADATA_BYTES,
        )

    def commit_ordinary_migration(self, rows: int, retained_bytes: int) -> None:
        self._mutate(
            reserved_rows=-rows,
            reserved_bytes=-(retained_bytes + rows * _EXACT_METADATA_BYTES),
            pending_operations=rows,
            pending_bytes=retained_bytes,
        )

    def rollback_ordinary_migration(self, rows: int, retained_bytes: int) -> None:
        self._mutate(
            reserved_rows=-rows,
            reserved_bytes=-(retained_bytes + rows * _EXACT_METADATA_BYTES),
        )

    def rollback_ordinary_migration_and_writer_route(
        self,
        rows: int,
        retained_bytes: int,
    ) -> None:
        """Atomically release a proved-absent migration and its exact route."""

        self._mutate(
            writers=-1,
            routes=-1,
            reserved_rows=-rows,
            reserved_bytes=-(retained_bytes + rows * _EXACT_METADATA_BYTES),
        )

    def record_ordinary_commit(self) -> None:
        self._mutate(total_events=1)

    def release_admission(self) -> None:
        self._mutate(admission_receipts=-1)

    def release_exported_receipt(self) -> None:
        self._mutate(receipt_rows=-1, admission_receipts=-1, export_receipts=-1)

    def reserve_export_plan(self, working_bytes: int) -> None:
        self._mutate(plan_rows=1, plan_bytes=working_bytes)

    def rollback_export_plan(self, working_bytes: int) -> None:
        self._mutate(plan_rows=-1, plan_bytes=-working_bytes)

    def complete_export(
        self,
        *,
        pending_rows: int,
        pending_bytes: int,
        inactive_receipts: int,
        active_receipts: int,
        working_bytes: int,
    ) -> None:
        self._mutate(
            pending_operations=-pending_rows,
            pending_bytes=-pending_bytes,
            receipt_rows=-inactive_receipts,
            export_receipts=active_receipts,
            plan_rows=-1,
            plan_bytes=-working_bytes,
        )

    def snapshot(self) -> _BudgetSnapshot:
        with self._lock:
            return _BudgetSnapshot(
                writers=self._writers,
                routes=self._routes,
                pending_operations=self._pending_operations,
                pending_bytes=self._pending_bytes,
                reserved_rows=self._reserved_rows,
                reserved_bytes=self._reserved_bytes,
                receipt_rows=self._receipt_rows,
                admission_receipts=self._admission_receipts,
                export_receipts=self._export_receipts,
                plan_rows=self._plan_rows,
                plan_bytes=self._plan_bytes,
                retained_rows=self._retained_rows_unlocked(),
                retained_bytes=self._retained_bytes_unlocked(),
                high_water_rows=self._high_water_rows,
                high_water_bytes=self._high_water_bytes,
                total_events=self._total_events,
            )


@dataclass(frozen=True, slots=True)
class _ExportPlan:
    max_sequence: int
    baseline_exists: bool
    baseline_digest: str
    baseline_size: int
    expected_exists: bool
    expected_digest: str
    expected_size: int
    temporary_name: str
    temporary_device: int
    temporary_inode: int
    working_bytes: int


@dataclass(frozen=True, slots=True)
class _ExportCompletion:
    """Retry-local ownership of one possibly committed export cleanup transaction."""

    plan: _ExportPlan
    removed_rows: int
    removed_bytes: int
    active_exact: int
    inactive_exact: int


@dataclass(frozen=True, slots=True)
class _OrdinaryMigration:
    """One all-or-nothing ordinary-buffer transfer into a private journal."""

    start_sequence: int
    rows: tuple[tuple[int, str, int], ...]
    retained_bytes: int


class _SingleHistoryWriter:
    """Own one history file and its durable pending-row journal."""

    def __init__(
        self,
        output_path: Path,
        template: Template,
        buffer_size: int = 10_000,
        *,
        base_dir: Path,
        budget: _GlobalHistoryBudget,
    ) -> None:
        self._base_dir, self.output_path = _require_contained(base_dir, output_path)
        self._template = template
        self.buffer_size = buffer_size
        self._budget = budget
        self._lock = RLock()
        self._ordinary_buffer: list[str] = []
        self._journal_mode = False
        self._exact_route_active = False
        self._connection: sqlite3.Connection | None = None
        self._journal_path: Path | None = None
        self._journal_name: str | None = None
        self._journal_identity: tuple[int, int] | None = None
        self._journal_unlinked = False
        self._close_requested = False
        self._terminal = False
        self._closed = False
        self._exact_receipts: dict[ExactPublicationKey, str] = {}
        self._exact_release_receipts: dict[ExactPublicationKey, tuple[int, int]] = {}
        self._unreconciled_export_plan: _ExportPlan | None = None
        self._export_completion: _ExportCompletion | None = None
        self._ordinary_migration: _OrdinaryMigration | None = None
        self._ordinary_migration_reservation: tuple[int, int] | None = None
        self._ordinary_migration_started = False
        self._ordinary_migration_rollback_proved = False
        self._pending_rows = 0
        self._pending_bytes = 0
        self._receipt_rows = 0
        self._admission_receipts = 0
        self._export_receipts = 0
        self._plan_rows = 0
        self._plan_bytes = 0
        self._retained_event_count = 0
        self._journal_directory: _PrivateJournalDirectory | None = None

    def render(self, event_data: dict[str, Any]) -> str:
        """Freeze the source-native two-line history representation."""

        return self._template.render(
            timestamp=event_data.get("timestamp"),
            command=event_data.get("command"),
        ).strip()

    def write(self, event_data: dict[str, Any]) -> None:
        """Journal one ordinary event and publish at the configured threshold."""

        self.write_rendered(self.render(event_data))

    def write_rendered(self, rendered: str) -> None:
        if type(rendered) is not str:
            raise TypeError("Bash history rows must be exact strings")
        with self._lock:
            self._require_open_unlocked()
            self._reconcile_ordinary_migration_unlocked()
            if not self._journal_mode:
                self._ordinary_buffer.append(rendered)
                self._retained_event_count += 1
                self._budget.record_ordinary_commit()
                if len(self._ordinary_buffer) >= self.buffer_size:
                    self._flush_ordinary_unlocked()
                return
            self._journal_ordinary_unlocked(rendered, record_event=True)
            if self._pending_rows >= self.buffer_size:
                self._export_unlocked()

    def activate_exact_route(self) -> None:
        """Record that this writer owns one globally charged exact route."""

        with self._lock:
            self._exact_route_active = True

    def deactivate_exact_route(self) -> None:
        """Drop a failed upgrade's exact-route ownership after full rollback."""

        with self._lock:
            if not self._terminal and (self._journal_mode or self._journal_directory is not None):
                raise ExactPublicationError(
                    "Bash history cannot deactivate a route with retained exact storage"
                )
            self._exact_route_active = False

    @property
    def exact_route_active(self) -> bool:
        """Return whether this writer owns an exact-route budget charge."""

        with self._lock:
            return self._exact_route_active

    def ordinary_migration_requirements(self) -> tuple[int, int]:
        """Return the complete legacy buffer charge without changing its state."""

        rows, retained_bytes, _reserved = self.ordinary_migration_preflight()
        return rows, retained_bytes

    def ordinary_migration_preflight(self) -> tuple[int, int, bool]:
        """Return migration size and whether a prior failed upgrade already owns it."""

        with self._lock:
            self._reconcile_ordinary_migration_unlocked()
            if self._journal_mode:
                if self._ordinary_buffer:
                    raise ExactPublicationError(
                        "Bash history journal mode retained an ordinary buffer"
                    )
                return 0, 0, False
            current = (
                len(self._ordinary_buffer),
                sum(len(rendered.encode("utf-8")) for rendered in self._ordinary_buffer),
            )
            reservation = self._ordinary_migration_reservation
            if reservation is not None and reservation != current:
                raise ExactPublicationError(
                    "Bash history retained ordinary migration changed before retry"
                )
            return *current, reservation is not None

    def reserve_ordinary_migration(self, rows: int, retained_bytes: int) -> None:
        """Charge one whole legacy-buffer migration before allocating its owner."""

        with self._lock:
            if self._ordinary_migration_reservation is not None:
                raise ExactPublicationError(
                    "Bash history ordinary migration already owns a capacity reservation"
                )
            current = self.ordinary_migration_requirements()
            if current != (rows, retained_bytes):
                raise ExactPublicationError(
                    "Bash history ordinary migration changed after preflight"
                )
            self._budget.reserve_ordinary_migration(rows, retained_bytes)
            self._ordinary_migration_reservation = (rows, retained_bytes)

    def enable_exact_journal(self, migration_rows: int, migration_bytes: int) -> None:
        """Allocate and initialize the private journal only for exact publication."""

        with self._lock:
            self._require_open_unlocked()
            self._reconcile_ordinary_migration_unlocked()
            if self._journal_mode:
                if (migration_rows, migration_bytes) != (0, 0):
                    raise ExactPublicationError(
                        "Bash history exact journal received a duplicate migration"
                    )
                journal_directory = self._journal_directory
                if journal_directory is None:
                    raise ExactPublicationError(
                        "Bash history exact journal lost its private directory"
                    )
                journal_directory.require_exact_guarantees()
                return
            reservation = self._ordinary_migration_reservation
            if migration_rows == 0:
                if migration_bytes or reservation is not None or self._ordinary_buffer:
                    raise ExactPublicationError(
                        "Bash history empty ordinary migration changed after preflight"
                    )
            elif reservation != (migration_rows, migration_bytes):
                raise ExactPublicationError("Bash history ordinary migration lost its reservation")
            journal_directory = self._journal_directory
            if journal_directory is None:
                journal_directory = _PrivateJournalDirectory(
                    base_dir=self._base_dir,
                    output_path=self.output_path,
                )
                self._journal_directory = journal_directory
            journal_directory.require_exact_guarantees()
            self._open_journal_unlocked()
            if migration_rows:
                self._migrate_ordinary_buffer_unlocked()
            self._journal_mode = True

    def reconcile_ordinary_migration(self) -> None:
        """Resolve a retained durable migration before any later public operation."""

        with self._lock:
            self._reconcile_ordinary_migration_unlocked()

    def _reconcile_ordinary_migration_unlocked(self) -> None:
        """Adopt an exact whole-buffer owner or fail before touching later state."""

        if self._ordinary_migration is None:
            return
        if self._journal_mode:
            raise ExactPublicationError(
                "Bash history journal mode conflicts with a retained ordinary migration"
            )
        if self._migrate_ordinary_buffer_unlocked():
            self._journal_mode = True

    def _migrate_ordinary_buffer_unlocked(self) -> bool:
        """Move the complete legacy buffer in one reconciled SQLite transaction."""

        reservation = self._ordinary_migration_reservation
        if reservation is None:
            raise ExactPublicationError("Bash history ordinary migration lost its capacity owner")
        reserved_rows, reserved_bytes = reservation
        if reserved_rows == 0:
            if self._ordinary_buffer or reserved_bytes:
                raise ExactPublicationError("Bash history empty migration changed after preflight")
            self._ordinary_migration_reservation = None
            return True
        owner = self._ordinary_migration
        if owner is not None and self._ordinary_migration_rollback_proved:
            self._rollback_proved_absent_migration_unlocked(owner)
            return False
        connection = self._connection
        if connection is None:
            raise ExactPublicationError("Bash history ordinary migration lost its journal")
        if owner is None:
            rows = tuple(
                (_extract_epoch(rendered), rendered, len(rendered.encode("utf-8")))
                for rendered in self._ordinary_buffer
            )
            if len(rows) != reserved_rows or sum(row[2] for row in rows) != reserved_bytes:
                raise ExactPublicationError(
                    "Bash history ordinary migration changed after preflight"
                )
            maximum = connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) FROM entries"
            ).fetchone()
            if maximum is None:
                raise ExactPublicationError("Bash history ordinary migration lost its sequence")
            owner = _OrdinaryMigration(
                start_sequence=int(maximum[0]),
                rows=rows,
                retained_bytes=reserved_bytes,
            )
            self._ordinary_migration = owner
            self._ordinary_migration_started = True
            try:
                connection.execute("BEGIN IMMEDIATE")
                for offset, (epoch, rendered, encoded_bytes) in enumerate(owner.rows, start=1):
                    sequence = self._insert_ordinary_migration_row_unlocked(
                        connection,
                        epoch=epoch,
                        rendered=rendered,
                        encoded_bytes=encoded_bytes,
                    )
                    if sequence != owner.start_sequence + offset:
                        raise ExactPublicationError(
                            "Bash history ordinary migration lost contiguous FIFO sequence"
                        )
                self._commit_ordinary_migration_unlocked(connection)
            except BaseException as primary:
                try:
                    connection.rollback()
                except BaseException as rollback_error:
                    primary.add_note(
                        f"Bash history ordinary migration rollback also failed: {rollback_error!r}"
                    )
                durable = self._load_ordinary_migration_unlocked(owner)
                if not durable:
                    self._ordinary_migration_rollback_proved = True
                    raise
                if durable != owner.rows:
                    raise ExactPublicationError(
                        "Bash history ordinary migration encountered conflicting durable state"
                    ) from primary
        else:
            durable = self._load_ordinary_migration_unlocked(owner)
            if not durable:
                self._ordinary_migration_rollback_proved = True
                self._rollback_proved_absent_migration_unlocked(owner)
                return False
            if durable != owner.rows:
                raise ExactPublicationError(
                    "Bash history ordinary migration lost its durable transaction"
                )

        rendered_rows = tuple(row[1] for row in owner.rows)
        if tuple(self._ordinary_buffer[:reserved_rows]) != rendered_rows:
            raise ExactPublicationError("Bash history ordinary migration lost its source buffer")
        self._budget.commit_ordinary_migration(reserved_rows, reserved_bytes)
        self._pending_rows += reserved_rows
        self._pending_bytes += reserved_bytes
        del self._ordinary_buffer[:reserved_rows]
        self._ordinary_migration_reservation = None
        self._ordinary_migration = None
        self._ordinary_migration_started = False
        self._ordinary_migration_rollback_proved = False
        return True

    def _rollback_proved_absent_migration_unlocked(self, owner: _OrdinaryMigration) -> None:
        """Retryably discard a migration whose complete transaction is durably absent."""

        reservation = self._ordinary_migration_reservation
        if reservation is None:
            raise ExactPublicationError("Bash history absent migration lost its capacity owner")
        reserved_rows, reserved_bytes = reservation
        rendered_rows = tuple(row[1] for row in owner.rows)
        if (
            len(owner.rows) != reserved_rows
            or owner.retained_bytes != reserved_bytes
            or tuple(self._ordinary_buffer[:reserved_rows]) != rendered_rows
        ):
            raise ExactPublicationError("Bash history absent migration lost its source buffer")
        if (
            self._journal_mode
            or self._pending_rows
            or self._pending_bytes
            or self._receipt_rows
            or self._admission_receipts
            or self._export_receipts
            or self._plan_rows
            or self._plan_bytes
            or self._exact_receipts
            or self._exact_release_receipts
            or self._unreconciled_export_plan is not None
            or self._export_completion is not None
        ):
            raise ExactPublicationError(
                "Bash history absent migration conflicts with retained publication state"
            )
        if not self._exact_route_active:
            raise ExactPublicationError("Bash history absent migration lost its exact route")
        self._discard_unadopted_journal_unlocked()
        self._budget.rollback_ordinary_migration_and_writer_route(
            reserved_rows,
            reserved_bytes,
        )
        self._exact_route_active = False
        self._ordinary_migration_reservation = None
        self._ordinary_migration = None
        self._ordinary_migration_started = False
        self._ordinary_migration_rollback_proved = False

    def _insert_ordinary_migration_row_unlocked(
        self,
        connection: sqlite3.Connection,
        *,
        epoch: int,
        rendered: str,
        encoded_bytes: int,
    ) -> int:
        """Insert one row inside the caller-owned all-or-nothing migration."""

        cursor = connection.execute(
            """INSERT INTO entries
            (publication_key, publication_digest, epoch, rendered, payload_bytes)
            VALUES (NULL, NULL, ?, ?, ?)""",
            (epoch, rendered, encoded_bytes),
        )
        if cursor.lastrowid is None:
            raise ExactPublicationError("Bash history ordinary migration lost a sequence")
        return int(cursor.lastrowid)

    def _commit_ordinary_migration_unlocked(self, connection: sqlite3.Connection) -> None:
        """Fault-injection seam for the atomic legacy-buffer transaction."""

        connection.commit()

    def _load_ordinary_migration_unlocked(
        self,
        owner: _OrdinaryMigration,
    ) -> tuple[tuple[int, str, int], ...]:
        """Load a prospective migration suffix for commit-lost-return adoption."""

        connection = self._connection
        if connection is None:
            raise ExactPublicationError("Bash history ordinary migration lost its journal")
        rows = connection.execute(
            """SELECT sequence, publication_key, publication_digest, epoch, rendered,
            payload_bytes FROM entries WHERE sequence > ? ORDER BY sequence""",
            (owner.start_sequence,),
        ).fetchall()
        durable_counts = connection.execute(
            """SELECT
            (SELECT COUNT(*) FROM entries),
            (SELECT COUNT(*) FROM publication_receipts),
            (SELECT COUNT(*) FROM export_plan)"""
        ).fetchone()
        if durable_counts is None or tuple(map(int, durable_counts)) != (len(rows), 0, 0):
            raise ExactPublicationError(
                "Bash history ordinary migration encountered conflicting durable state"
            )
        if owner.start_sequence != 0:
            raise ExactPublicationError(
                "Bash history ordinary migration encountered a conflicting prefix"
            )
        if not rows:
            return ()
        expected_sequences = tuple(
            range(owner.start_sequence + 1, owner.start_sequence + len(rows) + 1)
        )
        if tuple(int(row[0]) for row in rows) != expected_sequences or any(
            row[1] is not None or row[2] is not None for row in rows
        ):
            raise ExactPublicationError(
                "Bash history ordinary migration encountered a conflicting suffix"
            )
        return tuple((int(row[3]), str(row[4]), int(row[5])) for row in rows)

    def rollback_failed_exact_upgrade(self) -> bool:
        """Reclaim a proved-uncommitted migration and restore legacy writer state."""

        with self._lock:
            reservation = self._ordinary_migration_reservation
            if reservation is None:
                if self._journal_mode or self._ordinary_buffer:
                    return False
                return self.reclaim_if_idle()
            if self._ordinary_migration_rollback_proved:
                owner = self._ordinary_migration
                if owner is None:
                    raise ExactPublicationError(
                        "Bash history absent migration lost its cleanup owner"
                    )
                self._rollback_proved_absent_migration_unlocked(owner)
                return True
            if self._ordinary_migration is not None or not self._ordinary_migration_started:
                return False
            self._discard_unadopted_journal_unlocked()
            self._budget.rollback_ordinary_migration(*reservation)
            self._ordinary_migration_reservation = None
            self._ordinary_migration_started = False
            self._ordinary_migration_rollback_proved = False
            return True

    def _discard_unadopted_journal_unlocked(self) -> None:
        """Remove a private journal whose migration transaction proved absent."""

        if self._pending_rows or self._journal_mode:
            raise ExactPublicationError("Bash history cannot discard an adopted journal")
        connection = self._connection
        if connection is not None:
            connection.close()
            self._connection = None
        journal_directory = self._journal_directory
        journal_name = self._journal_name
        if journal_directory is None or journal_name is None:
            raise ExactPublicationError("Bash history unadopted journal lost its cleanup owner")
        directory_descriptor = journal_directory.directory_descriptor
        if not self._journal_unlinked:
            self._validate_journal_identity_unlocked()
            try:
                self._unlink_cleanup_journal(directory_descriptor, journal_name)
            except BaseException:
                if (
                    _safe_file_metadata(
                        directory_descriptor,
                        journal_name,
                        label="journal",
                    )
                    is None
                ):
                    self._journal_unlinked = True
                raise
            else:
                self._journal_unlinked = True
        self._fsync_cleanup_directory(directory_descriptor)
        journal_directory.close()
        self._journal_directory = None
        self._journal_path = None
        self._journal_name = None
        self._journal_identity = None
        self._journal_unlinked = False

    def _journal_ordinary_unlocked(self, rendered: str, *, record_event: bool) -> None:
        """Durably append one ordinary row after the route enters exact mode."""

        encoded_bytes = len(rendered.encode("utf-8"))
        self._budget.charge_ordinary(encoded_bytes)
        try:
            self._insert_unlocked(
                publication_key=None,
                publication_digest=None,
                rendered=rendered,
                encoded_bytes=encoded_bytes,
            )
        except BaseException:
            self._budget.rollback_ordinary(encoded_bytes)
            raise
        self._pending_rows += 1
        self._pending_bytes += encoded_bytes
        if record_event:
            self._retained_event_count += 1
            self._budget.record_ordinary_commit()

    def _flush_ordinary_unlocked(self) -> None:
        """Preserve the legacy path-only Bash-history flush behavior."""

        if not self._ordinary_buffer:
            return
        self._ordinary_buffer.sort(key=_extract_epoch)
        last_clear = -1
        for index, entry in enumerate(self._ordinary_buffer):
            if _is_clear_entry(entry):
                last_clear = index
        cleared = last_clear >= 0
        if cleared:
            self._ordinary_buffer = self._ordinary_buffer[last_clear + 1 :]
        if not self._ordinary_buffer:
            if cleared and self.output_path.exists():
                self.output_path.write_text("", encoding="utf-8")
            return
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        mode = "w" if cleared else "a"
        with self.output_path.open(mode, encoding="utf-8") as output:
            for entry in self._ordinary_buffer:
                output.write(entry)
                if not entry.endswith("\n"):
                    output.write("\n")
        self._ordinary_buffer.clear()

    def commit_exact(
        self,
        key: ExactPublicationKey,
        digest: str,
        rendered: str,
        retained_bytes: int,
    ) -> None:
        """Durably admit or reconcile one stable exact-publication row."""

        stable_key = _publication_key(key)
        with self._lock:
            self._require_open_unlocked()
            journal_directory = self._journal_directory
            if journal_directory is None or not self._journal_mode:
                raise ExactPublicationError("Exact Bash history route lost its private journal")
            journal_directory.require_exact_guarantees()
            retained = self._exact_receipts.get(key)
            if retained is not None:
                if retained != digest:
                    raise ExactPublicationError("Exact Bash history content changed on retry")
                return
            self._budget.commit_exact(retained_bytes)
            try:
                connection = self._open_journal_unlocked()
            except BaseException:
                self._budget.rollback_exact_commit(retained_bytes)
                raise
            try:
                receipt = connection.execute(
                    """SELECT publication_digest, admission_active, exported
                    FROM publication_receipts WHERE publication_key = ?""",
                    (stable_key,),
                ).fetchone()
            except BaseException:
                self._budget.rollback_exact_commit(retained_bytes)
                raise
            if receipt is not None:
                try:
                    if receipt[0] != digest or int(receipt[1]) != 1 or int(receipt[2]) != 0:
                        raise ExactPublicationError(
                            "Exact Bash history publication key changed content"
                        )
                    row = connection.execute(
                        """SELECT publication_digest, rendered, payload_bytes
                        FROM entries WHERE publication_key = ?""",
                        (stable_key,),
                    ).fetchone()
                    if row != (digest, rendered, retained_bytes):
                        raise ExactPublicationError(
                            "Exact Bash history pending operation changed content"
                        )
                except BaseException:
                    self._budget.rollback_exact_commit(retained_bytes)
                    raise
                self._record_exact_admission_unlocked(
                    key,
                    digest,
                    retained_bytes,
                )
                return
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """INSERT INTO entries
                    (publication_key, publication_digest, epoch, rendered, payload_bytes)
                    VALUES (?, ?, ?, ?, ?)""",
                    (stable_key, digest, _extract_epoch(rendered), rendered, retained_bytes),
                )
                connection.execute(
                    """INSERT INTO publication_receipts
                    (publication_key, publication_digest, admission_active, exported)
                    VALUES (?, ?, 1, 0)""",
                    (stable_key, digest),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                self._budget.rollback_exact_commit(retained_bytes)
                raise
            self._record_exact_admission_unlocked(
                key,
                digest,
                retained_bytes,
            )

    def _record_exact_admission_unlocked(
        self,
        key: ExactPublicationKey,
        digest: str,
        retained_bytes: int,
    ) -> None:
        """Record one durable exact receipt after fresh or reconciled admission."""

        self._exact_receipts[key] = digest
        self._pending_rows += 1
        self._pending_bytes += retained_bytes
        self._receipt_rows += 1
        self._admission_receipts += 1
        self._retained_event_count += 1

    def release_exact(self, key: ExactPublicationKey) -> None:
        """Release admission/export receipts while retaining an unexported operation."""

        with self._lock:
            retained = self._exact_receipts.get(key)
            release_receipt = self._exact_release_receipts.get(key)
            if retained is None:
                if release_receipt is not None:
                    raise ExactPublicationError(
                        "Exact Bash history release lost its local admission receipt"
                    )
                return
            connection = self._connection
            if connection is None:
                raise ExactPublicationError("Exact Bash history release lost its journal")
            self._validate_journal_identity_unlocked()
            if self._export_completion is not None:
                plan = self._load_export_plan_unlocked()
                self._reconcile_export_completion_unlocked(plan)
            stable_key = _publication_key(key)
            receipt = connection.execute(
                """SELECT admission_active, exported FROM publication_receipts
                WHERE publication_key = ?""",
                (stable_key,),
            ).fetchone()
            if release_receipt is None:
                if receipt is None:
                    raise ExactPublicationError(
                        "Exact Bash history release lost its durable admission receipt"
                    )
                admission_active, exported = map(int, receipt)
                if admission_active != 1 or exported not in {0, 1}:
                    raise ExactPublicationError(
                        "Exact Bash history release encountered an invalid durable receipt"
                    )
                release_receipt = (admission_active, exported)
                self._exact_release_receipts[key] = release_receipt
            admission_active, exported = release_receipt
            if self._release_is_durable_unlocked(receipt, release_receipt):
                self._finish_exact_release_unlocked(key, release_receipt)
                return
            if receipt != release_receipt:
                raise ExactPublicationError(
                    "Exact Bash history release encountered conflicting durable state"
                )
            try:
                connection.execute("BEGIN IMMEDIATE")
                if exported:
                    connection.execute(
                        "DELETE FROM publication_receipts WHERE publication_key = ?",
                        (stable_key,),
                    )
                elif admission_active:
                    connection.execute(
                        """UPDATE publication_receipts SET admission_active = 0
                        WHERE publication_key = ?""",
                        (stable_key,),
                    )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
            durable_receipt = connection.execute(
                """SELECT admission_active, exported FROM publication_receipts
                WHERE publication_key = ?""",
                (stable_key,),
            ).fetchone()
            if not self._release_is_durable_unlocked(durable_receipt, release_receipt):
                raise ExactPublicationError(
                    "Exact Bash history release did not reach its durable terminal state"
                )
            self._finish_exact_release_unlocked(key, release_receipt)

    @staticmethod
    def _release_is_durable_unlocked(
        durable_receipt: object,
        release_receipt: tuple[int, int],
    ) -> bool:
        """Return whether SQLite reflects the post-release state."""

        _admission_active, exported = release_receipt
        if exported:
            return durable_receipt is None
        return durable_receipt == (0, 0)

    def _finish_exact_release_unlocked(
        self,
        key: ExactPublicationKey,
        release_receipt: tuple[int, int],
    ) -> None:
        """Reconcile local/global counters exactly once after durable release."""

        admission_active, exported = release_receipt
        if exported:
            self._budget.release_exported_receipt()
            self._receipt_rows -= 1
            self._admission_receipts -= admission_active
            self._export_receipts -= 1
        else:
            self._budget.release_admission()
            self._admission_receipts -= admission_active
        self._exact_release_receipts.pop(key, None)
        self._exact_receipts.pop(key, None)

    def _require_open_unlocked(self) -> None:
        if self._close_requested or self._terminal:
            raise RuntimeError("Bash history writer is already closed")

    def _open_journal_unlocked(self) -> sqlite3.Connection:
        if self._connection is not None:
            self._validate_journal_identity_unlocked()
            return self._connection
        journal_directory = self._journal_directory
        if journal_directory is None:
            raise ExactPublicationError("Exact Bash history route has no private journal")
        _validate_future_output_path(self._base_dir, self.output_path)
        journal_directory_descriptor = journal_directory.directory_descriptor
        connection: sqlite3.Connection | None = None
        descriptor: int | None = None
        journal_name: str | None = None
        identity: tuple[int, int] | None = None
        try:
            route_stem = _private_route_stem(self._base_dir, self.output_path)
            descriptor, journal_name = _create_private_file(
                journal_directory_descriptor,
                f".{route_stem}.journal-",
                _JOURNAL_PRIVATE_SUFFIX,
            )
            metadata = os.fstat(descriptor)
            identity = (int(metadata.st_dev), int(metadata.st_ino))
            journal_root = journal_directory.path
            if journal_root is None:  # pragma: no cover - descriptor validation guards this
                raise ExactPublicationError("Bash history private journal lost its path")
            journal_path = journal_root / journal_name
            try:
                connection = _connect_existing_journal(journal_path)
            except sqlite3.Error as error:
                raise ExactPublicationError(
                    "Bash history journal could not be opened without creating another file"
                ) from error
            journal_directory.validate()
            current = os.stat(
                journal_name,
                dir_fd=journal_directory_descriptor,
                follow_symlinks=False,
            )
            retained = os.fstat(descriptor)
            if (
                not stat.S_ISREG(current.st_mode)
                or (int(current.st_dev), int(current.st_ino)) != identity
                or (int(retained.st_dev), int(retained.st_ino)) != identity
            ):
                raise ExactPublicationError("Bash history journal identity changed at creation")
            for suffix in _SQLITE_COMPANION_SUFFIXES:
                if (
                    _safe_file_metadata(
                        journal_directory_descriptor,
                        f"{journal_name}{suffix}",
                        label="journal companion",
                    )
                    is not None
                ):
                    raise ExactPublicationError(
                        "Bash history journal companion existed before SQLite initialization"
                    )
            # Exact journal volume is globally capped, and all ORDER BY inputs
            # share that cap. Keep SQLite sort temporaries in memory so no temp
            # pathname can escape this protected per-writer directory.
            connection.execute("PRAGMA temp_store=MEMORY")
            temp_store = connection.execute("PRAGMA temp_store").fetchone()
            if temp_store != (2,):
                raise ExactPublicationError("Bash history journal could not confine temp storage")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                """CREATE TABLE entries (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    publication_key TEXT UNIQUE,
                    publication_digest TEXT,
                    epoch INTEGER NOT NULL,
                    rendered TEXT NOT NULL,
                    payload_bytes INTEGER NOT NULL
                )"""
            )
            connection.execute("CREATE INDEX entries_epoch_sequence ON entries(epoch, sequence)")
            connection.execute(
                """CREATE TABLE publication_receipts (
                    publication_key TEXT PRIMARY KEY,
                    publication_digest TEXT NOT NULL,
                    admission_active INTEGER NOT NULL CHECK(admission_active IN (0, 1)),
                    exported INTEGER NOT NULL CHECK(exported IN (0, 1))
                )"""
            )
            connection.execute(
                """CREATE TABLE export_plan (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    max_sequence INTEGER NOT NULL,
                    baseline_exists INTEGER NOT NULL CHECK(baseline_exists IN (0, 1)),
                    baseline_digest TEXT NOT NULL,
                    baseline_size INTEGER NOT NULL,
                    expected_exists INTEGER NOT NULL CHECK(expected_exists IN (0, 1)),
                    expected_digest TEXT NOT NULL,
                    expected_size INTEGER NOT NULL,
                    temporary_name TEXT NOT NULL,
                    temporary_device INTEGER NOT NULL,
                    temporary_inode INTEGER NOT NULL,
                    working_bytes INTEGER NOT NULL
                )"""
            )
            connection.commit()
            journal_directory.fsync()
            os.close(descriptor)
            descriptor = None
            self._connection = connection
            self._journal_path = journal_path
            self._journal_name = journal_name
            self._journal_identity = identity
            self._journal_unlinked = False
            return connection
        except BaseException:
            if connection is not None:
                connection.close()
            if journal_name is not None:
                try:
                    metadata = _safe_file_metadata(
                        journal_directory_descriptor,
                        journal_name,
                        label="journal",
                    )
                    if (
                        metadata is not None
                        and identity is not None
                        and (
                            int(metadata.st_dev),
                            int(metadata.st_ino),
                        )
                        == identity
                    ):
                        for suffix in _SQLITE_COMPANION_SUFFIXES:
                            companion = f"{journal_name}{suffix}"
                            if (
                                _safe_file_metadata(
                                    journal_directory_descriptor,
                                    companion,
                                    label="journal companion",
                                )
                                is not None
                            ):
                                os.unlink(companion, dir_fd=journal_directory_descriptor)
                        os.unlink(journal_name, dir_fd=journal_directory_descriptor)
                        os.fsync(journal_directory_descriptor)
                except FileNotFoundError:
                    pass
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _validate_journal_identity_unlocked(self) -> None:
        journal_name = self._journal_name
        identity = self._journal_identity
        if journal_name is None or identity is None:
            if self._connection is not None:
                raise ExactPublicationError("Bash history journal lost its identity")
            return
        journal_directory = self._journal_directory
        if journal_directory is None:
            raise ExactPublicationError("Bash history journal lost its private directory")
        directory_descriptor = journal_directory.directory_descriptor
        metadata = _safe_file_metadata(
            directory_descriptor,
            journal_name,
            label="journal",
        )
        if self._journal_unlinked:
            if metadata is not None:
                raise ExactPublicationError(
                    "Bash history journal name was reused during terminal cleanup"
                )
            return
        if metadata is None or (int(metadata.st_dev), int(metadata.st_ino)) != identity:
            raise ExactPublicationError("Bash history journal identity changed")
        for suffix in _SQLITE_COMPANION_SUFFIXES:
            _safe_file_metadata(
                directory_descriptor,
                f"{journal_name}{suffix}",
                label="journal companion",
            )

    def _census_unlocked(self) -> _HistoryJournalCensus:
        global_census = self._budget.snapshot()
        return _HistoryJournalCensus(
            self._pending_rows,
            self._pending_bytes,
            self._retained_event_count,
            global_census.high_water_rows,
            global_census.high_water_bytes,
            0,
            0,
            self._receipt_rows,
            self._admission_receipts,
            self._export_receipts,
            self._plan_rows,
            self._plan_bytes,
        )

    def census(self) -> _HistoryJournalCensus:
        with self._lock:
            return self._census_unlocked()

    def _insert_unlocked(
        self,
        *,
        publication_key: str | None,
        publication_digest: str | None,
        rendered: str,
        encoded_bytes: int,
    ) -> None:
        connection = self._open_journal_unlocked()
        epoch = _extract_epoch(rendered)
        sequence: int | None = None
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """INSERT INTO entries
                (publication_key, publication_digest, epoch, rendered, payload_bytes)
                VALUES (?, ?, ?, ?, ?)""",
                (
                    publication_key,
                    publication_digest,
                    epoch,
                    rendered,
                    encoded_bytes,
                ),
            )
            if cursor.lastrowid is None:
                raise ExactPublicationError("Bash history insert lost its durable sequence")
            sequence = int(cursor.lastrowid)
            connection.commit()
        except BaseException as primary:
            try:
                connection.rollback()
            except BaseException as rollback_error:
                primary.add_note(f"Bash history insert rollback also failed: {rollback_error!r}")
            if sequence is None:
                raise
            try:
                durable_row = connection.execute(
                    """SELECT publication_key, publication_digest, epoch, rendered, payload_bytes
                    FROM entries WHERE sequence = ?""",
                    (sequence,),
                ).fetchone()
            except BaseException as reconciliation_error:
                primary.add_note(
                    f"Bash history insert reconciliation also failed: {reconciliation_error!r}"
                )
                raise
            expected_row = (
                publication_key,
                publication_digest,
                epoch,
                rendered,
                encoded_bytes,
            )
            if durable_row == expected_row:
                return
            if durable_row is not None:
                raise ExactPublicationError(
                    "Bash history insert encountered conflicting durable state"
                ) from primary
            raise

    @staticmethod
    def _survivor_clause(last_clear: tuple[int, int] | None) -> tuple[str, tuple[int, ...]]:
        if last_clear is None:
            return "sequence <= ?", ()
        epoch, sequence = last_clear
        return (
            "sequence <= ? AND (epoch, sequence) > (?, ?)",
            (epoch, sequence),
        )

    def _find_last_clear_unlocked(self, max_sequence: int) -> tuple[int, int] | None:
        connection = self._connection
        if connection is None:
            raise RuntimeError("Bash history journal is not open")
        last_clear: tuple[int, int] | None = None
        cursor = connection.execute(
            """SELECT epoch, sequence, rendered FROM entries
            INDEXED BY entries_epoch_sequence
            WHERE sequence <= ? ORDER BY epoch, sequence""",
            (max_sequence,),
        )
        for epoch, sequence, rendered in cursor:
            if _is_clear_entry(str(rendered)):
                last_clear = (int(epoch), int(sequence))
        return last_clear

    def _append_size_unlocked(
        self,
        max_sequence: int,
        last_clear: tuple[int, int] | None,
    ) -> tuple[int, int]:
        connection = self._connection
        if connection is None:
            raise RuntimeError("Bash history journal is not open")
        clause, tail = self._survivor_clause(last_clear)
        row = connection.execute(
            f"""SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(rendered AS BLOB)) + 1), 0)
            FROM entries WHERE {clause}""",  # noqa: S608 - clause is internal static SQL
            (max_sequence, *tail),
        ).fetchone()
        if row is None:
            raise ExactPublicationError("Bash history export lost its survivor census")
        return int(row[0]), int(row[1])

    def _stream_survivors_unlocked(
        self,
        descriptor: int,
        digest: Any,
        max_sequence: int,
        last_clear: tuple[int, int] | None,
    ) -> int:
        connection = self._connection
        if connection is None:
            raise RuntimeError("Bash history journal is not open")
        clause, tail = self._survivor_clause(last_clear)
        cursor = connection.execute(
            f"""SELECT rendered FROM entries INDEXED BY entries_epoch_sequence WHERE {clause}
            ORDER BY epoch, sequence""",  # noqa: S608 - clause is internal static SQL
            (max_sequence, *tail),
        )
        written_total = 0
        for (rendered,) in cursor:
            encoded = f"{str(rendered).rstrip(chr(10))}\n".encode()
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            digest.update(encoded)
            written_total += len(encoded)
        return written_total

    def _load_export_plan_unlocked(self) -> _ExportPlan | None:
        connection = self._connection
        if connection is None:
            return None
        self._validate_journal_identity_unlocked()
        row = connection.execute(
            """SELECT max_sequence, baseline_exists, baseline_digest, baseline_size,
            expected_exists, expected_digest, expected_size, temporary_name,
            temporary_device, temporary_inode, working_bytes
            FROM export_plan WHERE singleton = 1"""
        ).fetchone()
        if row is None:
            return None
        return _ExportPlan(
            max_sequence=int(row[0]),
            baseline_exists=bool(int(row[1])),
            baseline_digest=str(row[2]),
            baseline_size=int(row[3]),
            expected_exists=bool(int(row[4])),
            expected_digest=str(row[5]),
            expected_size=int(row[6]),
            temporary_name=str(row[7]),
            temporary_device=int(row[8]),
            temporary_inode=int(row[9]),
            working_bytes=int(row[10]),
        )

    def _build_export_plan_unlocked(self, max_sequence: int) -> None:
        connection = self._connection
        if connection is None:
            raise RuntimeError("Bash history journal is not open")
        self._validate_journal_identity_unlocked()
        last_clear = self._find_last_clear_unlocked(max_sequence)
        survivor_rows, append_bytes = self._append_size_unlocked(max_sequence, last_clear)
        directory_descriptor = _open_directory_nofollow(self.output_path.parent, create=True)
        temporary_name = ""
        temporary_identity = (0, 0)
        plan_charged = False
        plan_stored = False
        working_bytes = 0
        baseline_descriptor: int | None = None
        baseline_identity: tuple[int, int] | None = None
        try:
            _validate_parent_capacity(
                directory_descriptor,
                base_dir=self._base_dir,
                output_path=self.output_path,
            )
            baseline_metadata = _safe_file_metadata(
                directory_descriptor,
                self.output_path.name,
                label="output",
            )
            baseline_exists = baseline_metadata is not None
            baseline_size = 0 if baseline_metadata is None else int(baseline_metadata.st_size)
            expected_exists = baseline_exists or survivor_rows > 0
            expected_upper = (0 if last_clear is not None else baseline_size) + append_bytes
            working_bytes = baseline_size + expected_upper
            self._budget.reserve_export_plan(working_bytes)
            plan_charged = True
            baseline_digest = hashlib.sha256().hexdigest()
            if baseline_exists:
                baseline_descriptor = _open_regular_nofollow(
                    directory_descriptor,
                    self.output_path.name,
                    os.O_RDONLY,
                )
                opened = os.fstat(baseline_descriptor)
                baseline_identity = (int(opened.st_dev), int(opened.st_ino))
                if baseline_metadata is None or (
                    *baseline_identity,
                    int(opened.st_size),
                ) != (
                    int(baseline_metadata.st_dev),
                    int(baseline_metadata.st_ino),
                    baseline_size,
                ):
                    raise ExactPublicationError(
                        "Bash history output changed while sealing an export plan"
                    )
                baseline_digest, measured_size = _hash_descriptor(
                    baseline_descriptor,
                    expected_size=baseline_size,
                )
                if measured_size != baseline_size:
                    raise ExactPublicationError(
                        "Bash history output size changed while sealing an export plan"
                    )

            expected_digest_builder = hashlib.sha256()
            expected_size = 0
            if expected_exists:
                temporary_descriptor, temporary_name = _create_private_file(
                    directory_descriptor,
                    f".{_private_route_stem(self._base_dir, self.output_path)}.export-",
                    _EXPORT_PRIVATE_SUFFIX,
                )
                try:
                    created_metadata = os.fstat(temporary_descriptor)
                    temporary_identity = (
                        int(created_metadata.st_dev),
                        int(created_metadata.st_ino),
                    )
                    if last_clear is None and baseline_exists:
                        if baseline_descriptor is None or baseline_identity is None:
                            raise ExactPublicationError(
                                "Bash history export lost its sealed baseline descriptor"
                            )
                        expected_size += _copy_descriptor(
                            baseline_descriptor,
                            temporary_descriptor,
                            expected_digest_builder,
                            expected_size=baseline_size,
                            expected_digest=baseline_digest,
                        )
                        copied_metadata = os.fstat(baseline_descriptor)
                        current_baseline = _safe_file_metadata(
                            directory_descriptor,
                            self.output_path.name,
                            label="output",
                        )
                        if current_baseline is None or (
                            int(copied_metadata.st_dev),
                            int(copied_metadata.st_ino),
                            int(copied_metadata.st_size),
                            int(current_baseline.st_dev),
                            int(current_baseline.st_ino),
                            int(current_baseline.st_size),
                        ) != (
                            *baseline_identity,
                            baseline_size,
                            *baseline_identity,
                            baseline_size,
                        ):
                            raise ExactPublicationError(
                                "Bash history output changed while copying its sealed baseline"
                            )
                    expected_size += self._stream_survivors_unlocked(
                        temporary_descriptor,
                        expected_digest_builder,
                        max_sequence,
                        last_clear,
                    )
                    if expected_size > expected_upper:
                        raise ExactPublicationError(
                            "Bash history export exceeded its charged expected size"
                        )
                    os.fsync(temporary_descriptor)
                    metadata = os.fstat(temporary_descriptor)
                    if (int(metadata.st_dev), int(metadata.st_ino)) != temporary_identity:
                        raise ExactPublicationError(
                            "Bash history export temporary identity changed while sealing"
                        )
                finally:
                    os.close(temporary_descriptor)
            expected_digest = expected_digest_builder.hexdigest()
            os.fsync(directory_descriptor)

            sealed_plan = _ExportPlan(
                max_sequence=max_sequence,
                baseline_exists=baseline_exists,
                baseline_digest=baseline_digest,
                baseline_size=baseline_size,
                expected_exists=expected_exists,
                expected_digest=expected_digest,
                expected_size=expected_size,
                temporary_name=temporary_name,
                temporary_device=temporary_identity[0],
                temporary_inode=temporary_identity[1],
                working_bytes=working_bytes,
            )
            self._unreconciled_export_plan = sealed_plan
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """INSERT INTO export_plan
                    (singleton, max_sequence, baseline_exists, baseline_digest,
                    baseline_size, expected_exists, expected_digest, expected_size,
                    temporary_name, temporary_device, temporary_inode, working_bytes)
                    VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        max_sequence,
                        int(baseline_exists),
                        baseline_digest,
                        baseline_size,
                        int(expected_exists),
                        expected_digest,
                        expected_size,
                        temporary_name,
                        temporary_identity[0],
                        temporary_identity[1],
                        working_bytes,
                    ),
                )
                connection.commit()
                plan_stored = True
                self._adopt_export_plan_unlocked(sealed_plan)
            except BaseException as primary:
                try:
                    connection.rollback()
                except BaseException as rollback_error:
                    primary.add_note(
                        f"Bash history export-plan rollback also failed: {rollback_error!r}"
                    )
                raise
        finally:
            if baseline_descriptor is not None:
                os.close(baseline_descriptor)
            if not plan_stored and plan_charged and self._unreconciled_export_plan is None:
                if temporary_name:
                    try:
                        metadata = _safe_file_metadata(
                            directory_descriptor,
                            temporary_name,
                            label="export temporary",
                        )
                        if metadata is not None:
                            if (
                                int(metadata.st_dev),
                                int(metadata.st_ino),
                            ) != temporary_identity:
                                raise ExactPublicationError(
                                    "Bash history export temporary identity changed"
                                )
                            os.unlink(temporary_name, dir_fd=directory_descriptor)
                            os.fsync(directory_descriptor)
                    except FileNotFoundError:
                        pass
                self._budget.rollback_export_plan(working_bytes)
            os.close(directory_descriptor)

    def _adopt_export_plan_unlocked(self, plan: _ExportPlan) -> None:
        """Attach one durably stored plan to its already charged local census."""

        if self._unreconciled_export_plan != plan:
            raise ExactPublicationError("Bash history export plan lost its retry owner")
        if self._plan_rows != 0 or self._plan_bytes != 0:
            raise ExactPublicationError("Bash history export plan census is already occupied")
        self._plan_rows = 1
        self._plan_bytes = plan.working_bytes
        self._unreconciled_export_plan = None

    def _discard_export_plan_unlocked(self, plan: _ExportPlan) -> None:
        """Discard one proved-uncommitted plan without leaking its global charge."""

        if self._unreconciled_export_plan != plan:
            raise ExactPublicationError("Bash history export plan lost its discard owner")
        self._remove_export_temporary_unlocked(plan)
        self._budget.rollback_export_plan(plan.working_bytes)
        self._unreconciled_export_plan = None

    def _finish_export_completion_unlocked(self, completion: _ExportCompletion) -> None:
        """Reconcile local and global export census after durable SQLite cleanup."""

        if self._export_completion != completion:
            raise ExactPublicationError("Bash history export completion lost its retry owner")
        self._budget.complete_export(
            pending_rows=completion.removed_rows,
            pending_bytes=completion.removed_bytes,
            inactive_receipts=completion.inactive_exact,
            active_receipts=completion.active_exact,
            working_bytes=completion.plan.working_bytes,
        )
        self._pending_rows -= completion.removed_rows
        self._pending_bytes -= completion.removed_bytes
        self._receipt_rows -= completion.inactive_exact
        self._export_receipts += completion.active_exact
        self._plan_rows = 0
        self._plan_bytes = 0
        self._export_completion = None

    def _reconcile_export_completion_unlocked(self, plan: _ExportPlan | None) -> bool:
        """Resolve an ambiguous export cleanup from durable plan state."""

        completion = self._export_completion
        if completion is None:
            return False
        if self._unreconciled_export_plan is not None:
            raise ExactPublicationError(
                "Bash history export retained conflicting transaction owners"
            )
        if plan is None:
            self._finish_export_completion_unlocked(completion)
            return True
        if plan != completion.plan:
            raise ExactPublicationError(
                "Bash history export completion encountered a conflicting durable plan"
            )
        # The atomic cleanup did not commit. Its sealed plan still owns all
        # local/global census and can be retried from the pre-transaction state.
        self._export_completion = None
        return False

    def _resume_export_plan_unlocked(self) -> bool:
        """Reconcile one sealed export epoch and retain later admissions."""

        connection = self._connection
        if connection is None:
            return False
        plan = self._load_export_plan_unlocked()
        if self._reconcile_export_completion_unlocked(plan):
            return True
        unreconciled = self._unreconciled_export_plan
        if unreconciled is not None:
            if plan is None:
                self._discard_export_plan_unlocked(unreconciled)
                return False
            if plan != unreconciled:
                raise ExactPublicationError(
                    "Bash history export-plan retry encountered conflicting durable state"
                )
            self._adopt_export_plan_unlocked(unreconciled)
        if plan is None:
            return False
        current_exists, current_digest, current_size = self._output_state_unlocked()
        expected_matches = (
            current_exists == plan.expected_exists
            and current_digest == plan.expected_digest
            and current_size == plan.expected_size
        )
        baseline_matches = (
            current_exists == plan.baseline_exists
            and current_digest == plan.baseline_digest
            and current_size == plan.baseline_size
        )
        if not expected_matches and baseline_matches:
            if plan.expected_exists:
                self._replace_output(plan)
                current_exists, current_digest, current_size = self._output_state_unlocked()
            expected_matches = (
                current_exists == plan.expected_exists
                and current_digest == plan.expected_digest
                and current_size == plan.expected_size
            )
        if not expected_matches:
            raise ExactPublicationError(
                "Bash history export encountered conflicting final-file bytes"
            )
        if plan.expected_exists:
            self._reconcile_output(plan.expected_digest, plan.expected_size)
        else:
            self._reconcile_absent_output_unlocked()
        self._remove_export_temporary_unlocked(plan)

        bad_receipts = connection.execute(
            """SELECT COUNT(*) FROM entries AS entry
            LEFT JOIN publication_receipts AS receipt
            ON receipt.publication_key = entry.publication_key
            WHERE entry.sequence <= ? AND entry.publication_key IS NOT NULL
            AND (receipt.publication_key IS NULL
            OR receipt.publication_digest != entry.publication_digest
            OR receipt.exported != 0)""",
            (plan.max_sequence,),
        ).fetchone()
        if bad_receipts is None or int(bad_receipts[0]) != 0:
            raise ExactPublicationError("Bash history export lost an admission receipt")
        counts = connection.execute(
            """SELECT COUNT(*), COALESCE(SUM(entry.payload_bytes), 0),
            COALESCE(SUM(CASE WHEN entry.publication_key IS NOT NULL
                AND receipt.admission_active = 1 THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN entry.publication_key IS NOT NULL
                AND receipt.admission_active = 0 THEN 1 ELSE 0 END), 0)
            FROM entries AS entry
            LEFT JOIN publication_receipts AS receipt
            ON receipt.publication_key = entry.publication_key
            WHERE entry.sequence <= ?""",
            (plan.max_sequence,),
        ).fetchone()
        if counts is None:
            raise ExactPublicationError("Bash history export lost its pending census")
        removed_rows, removed_bytes, active_exact, inactive_exact = map(int, counts)
        completion = _ExportCompletion(
            plan=plan,
            removed_rows=removed_rows,
            removed_bytes=removed_bytes,
            active_exact=active_exact,
            inactive_exact=inactive_exact,
        )
        self._export_completion = completion

        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """UPDATE publication_receipts SET exported = 1
                WHERE admission_active = 1 AND publication_key IN
                (SELECT publication_key FROM entries
                WHERE sequence <= ? AND publication_key IS NOT NULL)""",
                (plan.max_sequence,),
            )
            connection.execute(
                """DELETE FROM publication_receipts
                WHERE admission_active = 0 AND publication_key IN
                (SELECT publication_key FROM entries
                WHERE sequence <= ? AND publication_key IS NOT NULL)""",
                (plan.max_sequence,),
            )
            connection.execute(
                "DELETE FROM entries WHERE sequence <= ?",
                (plan.max_sequence,),
            )
            connection.execute("DELETE FROM export_plan WHERE singleton = 1")
            connection.commit()
        except BaseException as primary:
            try:
                connection.rollback()
            except BaseException as rollback_error:
                primary.add_note(
                    f"Bash history export cleanup rollback also failed: {rollback_error!r}"
                )
            raise
        self._finish_export_completion_unlocked(completion)
        return True

    def _output_state_unlocked(self) -> tuple[bool, str, int]:
        directory_descriptor = _open_directory_nofollow(self.output_path.parent, create=False)
        try:
            metadata = _safe_file_metadata(
                directory_descriptor,
                self.output_path.name,
                label="output",
            )
            if metadata is None:
                return False, hashlib.sha256().hexdigest(), 0
            descriptor = _open_regular_nofollow(
                directory_descriptor,
                self.output_path.name,
                os.O_RDONLY,
            )
            try:
                opened = os.fstat(descriptor)
                if (int(opened.st_dev), int(opened.st_ino), int(opened.st_size)) != (
                    int(metadata.st_dev),
                    int(metadata.st_ino),
                    int(metadata.st_size),
                ):
                    raise ExactPublicationError(
                        "Bash history output identity changed during reconciliation"
                    )
                digest, size = _hash_descriptor(
                    descriptor,
                    expected_size=int(opened.st_size),
                )
                return True, digest, size
            finally:
                os.close(descriptor)
        finally:
            os.close(directory_descriptor)

    def _remove_export_temporary_unlocked(self, plan: _ExportPlan) -> None:
        if not plan.temporary_name:
            return
        directory_descriptor = _open_directory_nofollow(self.output_path.parent, create=False)
        try:
            metadata = _safe_file_metadata(
                directory_descriptor,
                plan.temporary_name,
                label="export temporary",
            )
            if metadata is None:
                return
            if (int(metadata.st_dev), int(metadata.st_ino)) != (
                plan.temporary_device,
                plan.temporary_inode,
            ):
                raise ExactPublicationError("Bash history export temporary identity changed")
            os.unlink(plan.temporary_name, dir_fd=directory_descriptor)
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)

    def _reconcile_output(self, expected_digest: str, expected_size: int) -> None:
        """Re-fsync exact final bytes and their directory after a lost return."""

        directory_descriptor = _open_directory_nofollow(self.output_path.parent, create=False)
        try:
            metadata = _safe_file_metadata(
                directory_descriptor,
                self.output_path.name,
                label="output",
            )
            if metadata is None or int(metadata.st_size) != expected_size:
                raise ExactPublicationError(
                    "Bash history output size changed during reconciliation"
                )
            descriptor = _open_regular_nofollow(
                directory_descriptor,
                self.output_path.name,
                os.O_RDONLY,
            )
            try:
                digest, size = _hash_descriptor(descriptor, expected_size=expected_size)
                if digest != expected_digest or size != expected_size:
                    raise ExactPublicationError("Bash history output changed during reconciliation")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)

    def _reconcile_absent_output_unlocked(self) -> None:
        directory_descriptor = _open_directory_nofollow(self.output_path.parent, create=False)
        try:
            if (
                _safe_file_metadata(
                    directory_descriptor,
                    self.output_path.name,
                    label="output",
                )
                is not None
            ):
                raise ExactPublicationError("Bash history output appeared during clear-only export")
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)

    def _export_unlocked(self) -> None:
        connection = self._connection
        if connection is None:
            return
        if self._exact_release_receipts:
            raise ExactPublicationError(
                "Bash history export requires pending exact releases to reconcile first"
            )
        while True:
            self._resume_export_plan_unlocked()
            if self._pending_rows == 0:
                return
            max_row = connection.execute("SELECT MAX(sequence) FROM entries").fetchone()
            if max_row is None or max_row[0] is None:
                raise ExactPublicationError("Bash history pending census lost its operations")
            max_sequence = int(max_row[0])
            self._build_export_plan_unlocked(max_sequence)

    def _replace_output(self, payload: object) -> None:
        """Fault-injection seam for final-file publication."""

        if type(payload) is not _ExportPlan:
            raise ExactPublicationError("Bash history replacement lost its sealed export plan")
        plan = payload
        if not plan.expected_exists or not plan.temporary_name:
            raise ExactPublicationError("Bash history replacement lost its expected file")
        directory_descriptor = _open_directory_nofollow(self.output_path.parent, create=False)
        try:
            _safe_file_metadata(directory_descriptor, self.output_path.name, label="output")
            temporary = _safe_file_metadata(
                directory_descriptor,
                plan.temporary_name,
                label="export temporary",
            )
            if temporary is None or (int(temporary.st_dev), int(temporary.st_ino)) != (
                plan.temporary_device,
                plan.temporary_inode,
            ):
                raise ExactPublicationError("Bash history export temporary identity changed")
            os.rename(
                plan.temporary_name,
                self.output_path.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)

    def flush(self) -> None:
        """Atomically publish every admitted row or retain a resumable plan."""

        with self._lock:
            self._reconcile_ordinary_migration_unlocked()
            if self._terminal:
                return
            if self._close_requested:
                self._cleanup_terminal_journal_unlocked()
                return
            if not self._journal_mode:
                self._flush_ordinary_unlocked()
                return
            self._export_unlocked()

    def close(self) -> None:
        """Export and remove the journal after every terminal receipt is released."""

        with self._lock:
            self._reconcile_ordinary_migration_unlocked()
            if self._terminal:
                return
            if self._journal_mode:
                self._export_unlocked()
            else:
                self._flush_ordinary_unlocked()
            self._close_requested = True
            self._cleanup_terminal_journal_unlocked()

    def reclaim_if_idle(self) -> bool:
        """Terminally remove an empty route journal so the emitter can drop the writer."""

        with self._lock:
            if self._terminal:
                return True
            if (
                self._ordinary_buffer
                or self._pending_rows
                or self._receipt_rows
                or self._admission_receipts
                or self._export_receipts
                or self._plan_rows
                or self._exact_receipts
                or self._ordinary_migration_reservation is not None
                or self._ordinary_migration is not None
            ):
                return False
            self._close_requested = True
            self._cleanup_terminal_journal_unlocked()
            return self._terminal

    def _cleanup_terminal_journal_unlocked(self) -> None:
        self._reconcile_ordinary_migration_unlocked()
        if (
            self._ordinary_buffer
            or self._pending_rows
            or self._receipt_rows
            or self._admission_receipts
            or self._export_receipts
            or self._plan_rows
            or self._exact_receipts
            or self._ordinary_migration_reservation is not None
            or self._ordinary_migration is not None
        ):
            return
        if self._connection is not None:
            self._validate_journal_identity_unlocked()
            self._connection.close()
            self._connection = None
        journal_name = self._journal_name
        journal_directory = self._journal_directory
        if journal_name is not None:
            if journal_directory is None:
                raise ExactPublicationError("Bash history journal lost its cleanup owner")
            directory_descriptor = journal_directory.directory_descriptor
            self._validate_journal_identity_unlocked()
            if not self._journal_unlinked:
                try:
                    self._unlink_cleanup_journal(directory_descriptor, journal_name)
                except BaseException:
                    metadata = _safe_file_metadata(
                        directory_descriptor,
                        journal_name,
                        label="journal",
                    )
                    if metadata is None:
                        self._journal_unlinked = True
                    raise
                else:
                    self._journal_unlinked = True
            self._fsync_cleanup_directory(directory_descriptor)
            self._journal_path = None
            self._journal_name = None
            self._journal_identity = None
        if journal_directory is not None:
            journal_directory.close()
        self._terminal = True
        self._closed = True

    def _fsync_cleanup_directory(self, directory_descriptor: int) -> None:
        """Fault-injection seam for retryable terminal directory durability."""

        os.fsync(directory_descriptor)

    def _unlink_cleanup_journal(self, directory_descriptor: int, journal_name: str) -> None:
        """Fault-injection seam for retryable terminal journal unlink."""

        os.unlink(journal_name, dir_fd=directory_descriptor)

    @property
    def event_count(self) -> int:
        with self._lock:
            return self._retained_event_count

    @property
    def terminal(self) -> bool:
        """Return whether durable terminal cleanup has fully completed."""

        with self._lock:
            return self._terminal


class BashHistoryEmitter(LogEmitter):
    """Multiplex durable history journals by sanitized user and host identity."""

    _supported_types: set[str] = {"bash_command"}

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10_000,
        threaded: bool = False,
        *,
        journal_route_capacity: int = _DEFAULT_JOURNAL_ROUTE_CAPACITY,
        journal_row_capacity: int = _DEFAULT_JOURNAL_ROW_CAPACITY,
        journal_byte_capacity: int = _DEFAULT_JOURNAL_BYTE_CAPACITY,
    ) -> None:
        if type(journal_route_capacity) is not int or journal_route_capacity <= 0:
            raise ValueError("Bash history journal route capacity must be a positive exact int")
        if type(journal_row_capacity) is not int or journal_row_capacity <= 0:
            raise ValueError("Bash history journal row capacity must be a positive exact int")
        if type(journal_byte_capacity) is not int or journal_byte_capacity <= 0:
            raise ValueError("Bash history journal byte capacity must be a positive exact int")
        self._base_dir = _lexical_absolute(Path(output_path))
        self._writers: dict[tuple[str, str], _SingleHistoryWriter] = {}
        self._writers_lock = Lock()
        self._admission_lock = RLock()
        self._receipt_lock = RLock()
        self._exact_history_receipts: dict[ExactPublicationKey, tuple[tuple[str, str], str]] = {}
        self._exact_capacity_reservations: dict[
            ExactPublicationKey, tuple[str, int, tuple[str, str]]
        ] = {}
        self._provisional_routes: set[tuple[str, str]] = set()
        self._buffer_size = buffer_size
        self._journal_route_capacity = journal_route_capacity
        self._journal_row_capacity = journal_row_capacity
        self._journal_byte_capacity = journal_byte_capacity
        # This protects exact publication from output-tree attackers on POSIX.
        # Isolation from an arbitrary same-UID process requires a separate UID,
        # sandbox, or a native dirfd-anchored SQLite VFS and is out of scope here.
        self._exact_journal_capabilities_validated = False
        self._budget = _GlobalHistoryBudget(
            route_capacity=journal_route_capacity,
            row_capacity=journal_row_capacity,
            byte_capacity=journal_byte_capacity,
        )
        super().__init__(format_def, output_path, buffer_size, threaded)

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        """Return whether this is a Linux bash-command occurrence."""

        return event.event_type in self._supported_types and (
            event.src_host is not None and event.src_host.os_category == "linux"
        )

    def emit(self, event: CanonicalOccurrence) -> None:
        """Extract immutable history fields from one canonical occurrence."""

        host = event.src_host
        self.emit_event(
            {
                "timestamp": event.timestamp,
                "username": event.auth.username if event.auth else "unknown",
                "hostname": host.hostname if host else "unknown",
                "host_fqdn": (host.fqdn or host.hostname) if host else "unknown",
                "command": event.shell.command if event.shell else "",
            }
        )

    @staticmethod
    def _writer_key(username: object, host_fqdn: object) -> tuple[str, str]:
        safe_user = sanitize_path_component(str(username)) or "unknown"
        safe_host = sanitize_path_component(str(host_fqdn)) or "unknown"
        return safe_user, safe_host

    def _writer_path(self, key: tuple[str, str]) -> Path:
        return self._base_dir / key[1] / "bash_history" / f"{key[0]}.bash_history"

    def _get_writer_by_key(
        self,
        key: tuple[str, str],
        *,
        consume_reserved_route: bool = False,
    ) -> _SingleHistoryWriter:
        with self._writers_lock:
            writer = self._writers.get(key)
            if writer is not None and not writer.terminal:
                if consume_reserved_route and not writer.exact_route_active:
                    if key not in self._provisional_routes:
                        raise ExactPublicationError(
                            "Exact Bash history route lost its global capacity reservation"
                        )
                    self._budget.commit_reserved_route()
                    self._provisional_routes.discard(key)
                    writer.activate_exact_route()
                return writer
            if writer is not None:
                self._writers.pop(key)
                if writer.exact_route_active:
                    self._budget.release_writer_route()
            path = self._writer_path(key)
            if consume_reserved_route:
                if key not in self._provisional_routes:
                    raise ExactPublicationError(
                        "Exact Bash history route lost its global capacity reservation"
                    )
            writer = _SingleHistoryWriter(
                path,
                self._template,
                self._buffer_size,
                base_dir=self._base_dir,
                budget=self._budget,
            )
            if consume_reserved_route:
                self._budget.commit_reserved_route()
                self._provisional_routes.discard(key)
                writer.activate_exact_route()
            self._writers[key] = writer
            logger.debug("Created bash_history writer: %s", path)
            return writer

    def _get_writer(self, username: str, host_fqdn: str) -> _SingleHistoryWriter:
        return self._get_writer_by_key(self._writer_key(username, host_fqdn))

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Admit ordinary or exact work without allowing a close-boundary overtake."""

        prepared = self._prepare_event(event_data)
        attempt = _EXACT_PUBLICATION_ATTEMPT.get()
        if attempt is not None:
            self._ensure_exact_journal_capabilities()
            writer_key = (prepared["user"], prepared["host"])
            _validate_future_output_path(self._base_dir, self._writer_path(writer_key))
            self._emit_exact_event(prepared, attempt)
            return
        self._emit_ordinary_event(prepared)

    def _prepare_event(self, event_data: dict[str, Any]) -> dict[str, Any]:
        """Detach and render caller-controlled values before taking admission locks."""

        detached = deepcopy(event_data)
        if type(detached) is not dict or not all(type(key) is str for key in detached):
            raise TypeError("Bash history event data must be one exact string-keyed dictionary")
        host_fqdn = detached.get("host_fqdn", detached.get("hostname", "unknown"))
        writer_key = self._writer_key(detached.get("username", "unknown"), host_fqdn)
        _require_contained(self._base_dir, self._writer_path(writer_key))
        rendered = self._template.render(
            timestamp=detached.get("timestamp"),
            command=detached.get("command"),
        ).strip()
        if type(rendered) is not str:
            raise TypeError("Bash history rendering must produce one exact string")
        frozen = json.dumps(
            {
                "host": writer_key[1],
                "rendered": rendered,
                "user": writer_key[0],
                "version": _EXACT_HISTORY_ENVELOPE_VERSION,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return {
            "_bash_prepared_version": _PREPARED_HISTORY_EVENT_VERSION,
            "envelope": frozen,
            "host": writer_key[1],
            "rendered": rendered,
            "user": writer_key[0],
        }

    def _emit_ordinary_event(self, prepared: dict[str, Any]) -> None:
        """Admit ordinary work only when no exact batch owns the FIFO."""

        while True:
            self._wait_for_exact_publication_turn(None)
            with self._admission_lock:
                with self._close_condition:
                    if self._active_exact_publication_keys:
                        continue
                    self._require_accepting_events_locked()
                self._reconcile_prepared_ordinary_owner(prepared)
                if self.threaded:
                    self._begin_queue_admission()
                    try:
                        self._put_ordinary_queue_item(prepared)
                    finally:
                        self._finish_queue_admission()
                    return
                self._begin_queue_admission()
                break
        try:
            self._dispatch(prepared)
        finally:
            self._finish_queue_admission()

    def _reconcile_prepared_ordinary_owner(self, prepared: dict[str, Any]) -> None:
        """Fence a later ordinary suffix before it can enter the worker FIFO."""

        writer_key = (prepared["user"], prepared["host"])
        with self._writers_lock:
            writer = self._writers.get(writer_key)
        if writer is not None and not writer.terminal:
            writer.reconcile_ordinary_migration()

    def _put_ordinary_queue_item(self, event_data: dict[str, Any]) -> None:
        """Preserve the base emitter's bounded ordinary queue semantics."""

        try:
            self._event_queue.put(event_data, timeout=1.0)
        except Full:
            logger.warning(
                "Event queue full for %s emitter, applying backpressure",
                self.format_def.name,
            )
            self._event_queue.put(event_data, block=True)

    def _emit_exact_event(
        self,
        prepared: dict[str, Any],
        attempt: _ExactPublicationAttempt,
    ) -> None:
        """Drain once, register once, and hand off exact work without a physical flush."""

        while not attempt.batch._has_participant(self):
            self._wait_for_exact_publication_turn(None)
            with self._admission_lock:
                with self._close_condition:
                    if self._active_exact_publication_keys:
                        continue
                    self._require_accepting_events_locked()
                    while self._queue_admissions:
                        self._close_condition.wait()
                if self.threaded:
                    self._drain_threaded_before_exact()
                registration_token = _EXACT_HISTORY_REGISTRATION_READY.set(
                    attempt.batch._participant_key
                )
                try:
                    attempt.register_participant(self)
                finally:
                    _EXACT_HISTORY_REGISTRATION_READY.reset(registration_token)
                queued = self._handoff_exact_event(prepared, attempt)
                break
        else:
            with self._admission_lock:
                participant_key = attempt.batch._participant_key
                with self._close_condition:
                    if participant_key not in self._active_exact_publication_keys:
                        raise ExactPublicationError(
                            "Exact Bash history continuation lost its participant fence"
                        )
                    if self._close_state == "closed":
                        raise RuntimeError("bash_history emitter is closing or closed")
                queued = self._handoff_exact_event(prepared, attempt)

        if queued is None:
            self._dispatch(prepared)
            return
        while not queued.completed.wait(timeout=0.1):
            self._raise_if_thread_failed()
        if queued.error is not None:
            raise queued.error
        self._raise_if_thread_failed()

    def _handoff_exact_event(
        self,
        prepared: dict[str, Any],
        attempt: _ExactPublicationAttempt,
    ) -> _ExactQueuedPublication | None:
        """Stage directly or enqueue one already-fenced exact event."""

        if not self.threaded:
            return None
        queued = _ExactQueuedPublication(payload=prepared, attempt=attempt)
        while True:
            self._raise_if_thread_failed()
            try:
                self._event_queue.put(queued, block=True, timeout=0.1)
                return queued
            except Full:
                continue

    def _render_event(self, event_data: dict[str, Any]) -> str:
        raise NotImplementedError("BashHistoryEmitter uses _dispatch, not _render_event")

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        if (
            type(event_data) is not dict
            or set(event_data) != {"_bash_prepared_version", "envelope", "host", "rendered", "user"}
            or type(event_data.get("_bash_prepared_version")) is not int
            or event_data["_bash_prepared_version"] != _PREPARED_HISTORY_EVENT_VERSION
            or not all(
                type(event_data.get(field)) is str
                for field in ("envelope", "host", "rendered", "user")
            )
        ):
            raise TypeError("Bash history dispatch requires one detached prepared event")
        writer_key = (event_data["user"], event_data["host"])
        if self._writer_key(*writer_key) != writer_key:
            raise ExactPublicationError("Prepared Bash history route is not canonical")
        rendered = event_data["rendered"]
        frozen = event_data["envelope"]
        route_token = _EXACT_HISTORY_RESERVATION_ROUTE.set(writer_key)
        try:
            staged = stage_exact_publication_row(
                self,
                frozen,
                publish=self._commit_exact_history,
                release=self._release_exact_history,
            )
        finally:
            _EXACT_HISTORY_RESERVATION_ROUTE.reset(route_token)
        if staged:
            return
        writer = self._get_writer_by_key(writer_key)
        try:
            writer.write_rendered(rendered)
        except BaseException as primary:
            try:
                self._try_reclaim_writer(writer_key, writer)
            except BaseException as cleanup_error:
                primary.add_note(
                    f"Bash history failed-admission cleanup also failed: {cleanup_error!r}"
                )
            raise
        self._try_reclaim_writer(writer_key, writer)

    def _reserve_exact_publication_row(
        self,
        key: ExactPublicationKey,
        digest: str,
        retained_bytes: int,
    ) -> None:
        """Bind precanonical capacity to the exact sanitized writer route."""

        route = _EXACT_HISTORY_RESERVATION_ROUTE.get()
        if route is None:
            raise ExactPublicationError("Exact Bash history reservation lost its writer route")
        with self._receipt_lock:
            retained = self._exact_capacity_reservations.get(key)
            if retained is not None:
                if retained != (digest, retained_bytes, route):
                    raise ExactPublicationError("Exact Bash history reservation changed")
                return
            _validate_future_output_path(self._base_dir, self._writer_path(route))
            with self._writers_lock:
                retained_writer = self._writers.get(route)
                if retained_writer is not None and retained_writer.terminal:
                    retained_writer = None
            if retained_writer is None:
                migration_rows, migration_bytes, migration_already_reserved = 0, 0, False
                route_exists = False
            else:
                (
                    migration_rows,
                    migration_bytes,
                    migration_already_reserved,
                ) = retained_writer.ordinary_migration_preflight()
                route_exists = retained_writer.exact_route_active
            add_route = not route_exists and route not in self._provisional_routes
            self._budget.preflight_exact_upgrade(
                retained_bytes=retained_bytes,
                add_route=add_route,
                migration_rows=0 if migration_already_reserved else migration_rows,
                migration_bytes=0 if migration_already_reserved else migration_bytes,
            )
            exact_reserved = False
            reserved_route = False
            writer: _SingleHistoryWriter | None = None
            try:
                self._budget.reserve_exact(retained_bytes)
                exact_reserved = True
                if add_route:
                    self._budget.reserve_route()
                    self._provisional_routes.add(route)
                    reserved_route = True
                self._exact_capacity_reservations[key] = (digest, retained_bytes, route)
                writer = self._get_writer_by_key(
                    route,
                    consume_reserved_route=route in self._provisional_routes,
                )
                if migration_rows and not migration_already_reserved:
                    writer.reserve_ordinary_migration(migration_rows, migration_bytes)
                writer.enable_exact_journal(migration_rows, migration_bytes)
            except BaseException as primary:
                self._exact_capacity_reservations.pop(key, None)
                upgrade_rolled_back = False
                if writer is not None:
                    try:
                        upgrade_rolled_back = writer.rollback_failed_exact_upgrade()
                    except BaseException as cleanup_error:
                        primary.add_note(
                            f"Bash history failed-migration rollback also failed: {cleanup_error!r}"
                        )
                    if upgrade_rolled_back and writer.exact_route_active:
                        writer.deactivate_exact_route()
                        self._budget.release_writer_route()
                if reserved_route and route in self._provisional_routes:
                    self._provisional_routes.discard(route)
                    self._budget.release_reserved_route()
                if exact_reserved:
                    self._budget.release_exact_reservation(retained_bytes)
                if writer is not None:
                    try:
                        self._try_reclaim_writer(route, writer)
                    except BaseException as cleanup_error:
                        primary.add_note(
                            f"Bash history failed-upgrade cleanup also failed: {cleanup_error!r}"
                        )
                raise

    def _commit_exact_history(
        self,
        key: ExactPublicationKey,
        digest: str,
        frozen: object,
    ) -> None:
        if type(frozen) is not str:
            raise ExactPublicationError("Exact Bash history row lost its frozen schema")
        try:
            envelope = json.loads(frozen)
        except (TypeError, ValueError) as error:
            raise ExactPublicationError("Exact Bash history row is not valid JSON") from error
        if (
            type(envelope) is not dict
            or set(envelope) != {"host", "rendered", "user", "version"}
            or type(envelope.get("version")) is not int
            or envelope["version"] != _EXACT_HISTORY_ENVELOPE_VERSION
            or type(envelope.get("user")) is not str
            or type(envelope.get("host")) is not str
            or type(envelope.get("rendered")) is not str
        ):
            raise ExactPublicationError("Exact Bash history row lost its frozen schema")
        safe_user = envelope["user"]
        safe_host = envelope["host"]
        rendered = envelope["rendered"]
        if self._writer_key(safe_user, safe_host) != (safe_user, safe_host):
            raise ExactPublicationError("Exact Bash history route is not canonical")
        writer_key = (safe_user, safe_host)
        retained_bytes = len(frozen.encode("utf-8"))
        with self._receipt_lock:
            retained = self._exact_history_receipts.get(key)
            if retained is not None:
                if retained != (writer_key, digest):
                    raise ExactPublicationError("Exact Bash history route changed on retry")
                return
            reservation = self._exact_capacity_reservations.get(key)
            if reservation != (
                digest,
                retained_bytes,
                writer_key,
            ):
                raise ExactPublicationError("Exact Bash history capacity reservation changed")
            writer = self._get_writer_by_key(
                writer_key,
                consume_reserved_route=writer_key in self._provisional_routes,
            )
            writer.commit_exact(key, digest, rendered, retained_bytes)
            self._exact_history_receipts[key] = (writer_key, digest)
            self._exact_capacity_reservations.pop(key, None)

    def _release_exact_history(self, key: ExactPublicationKey) -> None:
        writer: _SingleHistoryWriter | None = None
        writer_key: tuple[str, str] | None = None
        with self._receipt_lock:
            retained = self._exact_history_receipts.get(key)
            if retained is None:
                return
            writer_key, _digest = retained
            with self._writers_lock:
                writer = self._writers.get(writer_key)
            if writer is None:
                raise ExactPublicationError("Exact Bash history receipt lost its route writer")
            writer.release_exact(key)
        self._try_reclaim_writer(writer_key, writer)
        with self._receipt_lock:
            retained = self._exact_history_receipts.get(key)
            if retained is not None and retained[0] == writer_key:
                self._exact_history_receipts.pop(key, None)

    def _clear_exact_capacity_reservations(self, participant_key: tuple[str, int]) -> None:
        affected_routes: set[tuple[str, str]] = set()
        with self._receipt_lock:
            keys = [key for key in self._exact_capacity_reservations if key[:2] == participant_key]
            for key in keys:
                _digest, retained_bytes, writer_key = self._exact_capacity_reservations.pop(key)
                affected_routes.add(writer_key)
                self._budget.release_exact_reservation(retained_bytes)
            retained_routes = {
                writer_key
                for _digest, _retained_bytes, writer_key in self._exact_capacity_reservations.values()
            }
            for writer_key in affected_routes:
                if writer_key in self._provisional_routes and writer_key not in retained_routes:
                    self._provisional_routes.discard(writer_key)
                    self._budget.release_reserved_route()
        for writer_key in affected_routes:
            with self._writers_lock:
                writer = self._writers.get(writer_key)
            if writer is not None:
                self._try_reclaim_writer(writer_key, writer)

    def _complete_exact_publication_batch(self, key: tuple[str, int]) -> None:
        self._clear_exact_capacity_reservations(key)
        super()._complete_exact_publication_batch(key)

    def _abort_exact_publication_batch(self, key: tuple[str, int]) -> None:
        self._clear_exact_capacity_reservations(key)
        super()._abort_exact_publication_batch(key)

    def _register_exact_publication_batch(self, key: tuple[str, int]) -> None:
        """Drain prior FIFO work before either direct or render-time registration."""

        self._ensure_exact_journal_capabilities()
        if _EXACT_HISTORY_REGISTRATION_READY.get() == key:
            super()._activate_exact_publication_batch(key)
            return
        while True:
            self._wait_for_exact_publication_turn(None)
            with self._admission_lock:
                with self._close_condition:
                    if self._active_exact_publication_keys:
                        continue
                    self._require_accepting_events_locked()
                    while self._queue_admissions:
                        self._close_condition.wait()
                if self.threaded:
                    self._drain_threaded_before_exact()
                super()._activate_exact_publication_batch(key)
                return

    def _ensure_exact_journal_capabilities(self) -> None:
        """Probe the exact-only filesystem contract before any private allocation."""

        if self._exact_journal_capabilities_validated:
            return
        _require_exact_journal_capabilities()
        self._exact_journal_capabilities_validated = True

    def _run(self) -> None:
        """Dispatch ordinary and exact queue items without acknowledging before staging."""

        logger.debug("Emitter thread started for %s", self.format_def.name)
        while not self._stop_event.is_set():
            try:
                queue_item = self._event_queue.get(timeout=0.1)
                queued = None
                try:
                    if self._handle_exact_drain_request(queue_item):
                        continue
                    if self._handle_flush_request(queue_item):
                        continue
                    event_data, queued = exact_publication_queue_payload(queue_item)
                    if not isinstance(event_data, dict):
                        raise TypeError("Emitter queue item must contain an event dictionary")
                    self._wait_for_exact_publication_turn(queued)
                    try:
                        with exact_publication_worker_attempt(queued):
                            self._dispatch(event_data)
                    except BaseException as error:
                        complete_exact_publication_queue_item(queued, error)
                        if queued is None:
                            raise
                        continue
                    complete_exact_publication_queue_item(queued, None)
                except BaseException as error:
                    if isinstance(error, Exception):
                        self._thread_error = error
                    else:
                        wrapped = RuntimeError("Emitter worker terminated by BaseException")
                        wrapped.__cause__ = error
                        self._thread_error = wrapped
                    logger.exception(
                        "Unhandled exception in %s emitter thread; stopping thread",
                        self.format_def.name,
                    )
                    self._stop_event.set()
                finally:
                    self._event_queue.task_done()
            except Empty:
                continue
        logger.debug("Emitter thread stopping for %s", self.format_def.name)
        self._flush_all_writers()

    def _drain_threaded_before_exact(self) -> None:
        """Drain preceding FIFO work without creating a physical flush boundary."""

        request = _ExactDrainRequest()
        while True:
            self._raise_if_thread_failed()
            try:
                self._event_queue.put(request, timeout=0.1)
                break
            except Full:
                continue
        while not request.completed.wait(timeout=0.1):
            self._raise_if_thread_failed()
        if request.error is not None:
            raise request.error
        self._raise_if_thread_failed()

    def _handle_exact_drain_request(self, queue_item: object) -> bool:
        if type(queue_item) is not _ExactDrainRequest:
            return False
        try:
            self._process_exact_drain()
        except BaseException as error:
            queue_item.error = error
        finally:
            queue_item.completed.set()
        return True

    def _process_exact_drain(self) -> None:
        """FIFO position is the drain; deliberately perform no physical flush."""

    def _flush_all_writers(self) -> None:
        """Flush writers without taking the producer admission lock."""

        writers = self._reconcile_ordinary_migration_owners()
        for _writer_key, writer in writers:
            writer.flush()
        for writer_key, writer in writers:
            self._try_reclaim_writer(writer_key, writer)

    def _reconcile_ordinary_migration_owners(
        self,
    ) -> tuple[tuple[tuple[str, str], _SingleHistoryWriter], ...]:
        """Adopt every retained migration before a public operation can mutate output."""

        with self._writers_lock:
            writers = tuple(self._writers.items())
        for _writer_key, writer in writers:
            writer.reconcile_ordinary_migration()
        return writers

    def _try_reclaim_writer(
        self,
        writer_key: tuple[str, str],
        writer: _SingleHistoryWriter,
    ) -> None:
        """Drop one terminal empty route without scanning any other writer."""

        if not writer.reclaim_if_idle():
            return
        with self._writers_lock:
            if self._writers.get(writer_key) is not writer:
                return
            self._writers.pop(writer_key)
            if writer.exact_route_active:
                self._budget.release_writer_route()

    def _flush_at_barrier(self) -> None:
        self._flush_all_writers()

    def _enter_public_flush(self) -> None:
        """Wait outside the admission lock, then close the recheck race."""

        attempt = _EXACT_PUBLICATION_ATTEMPT.get()
        if attempt is not None and attempt.batch._has_participant(self):
            raise ExactPublicationError(
                "Bash history public flush cannot re-enter its active exact render"
            )
        while True:
            self._wait_for_exact_publication_turn(None)
            self._admission_lock.acquire()
            with self._close_condition:
                if self._active_exact_publication_keys:
                    self._admission_lock.release()
                    continue
                owner_is_closer = self._close_thread == get_ident()
                if self._close_state != "open" and not owner_is_closer:
                    self._admission_lock.release()
                    raise RuntimeError(f"{self.format_def.name} emitter is closing or closed")
                while self._queue_admissions:
                    self._close_condition.wait()
            return

    def barrier_flush(self) -> None:
        """Retain the legacy physical barrier without locking the worker."""

        self._enter_public_flush()
        try:
            self._reconcile_ordinary_migration_owners()
            super().barrier_flush()
        finally:
            self._admission_lock.release()

    def flush(self) -> None:
        """Fence unrelated flushes until every staged exact row is durably admitted."""

        self._enter_public_flush()
        try:
            self._flush_all_writers()
        finally:
            self._admission_lock.release()

    def _flush_unlocked(self) -> None:
        """Prevent the base emitter from writing a single multiplexed file."""

    def close(self) -> None:
        """Fence, drain the worker, and remove journals only after final export."""

        attempt = _EXACT_PUBLICATION_ATTEMPT.get()
        if attempt is not None and attempt.batch._has_participant(self):
            raise ExactPublicationError(
                "Bash history close cannot re-enter its active exact render"
            )
        if not self._claim_close():
            return
        writers: tuple[tuple[tuple[str, str], _SingleHistoryWriter], ...] = ()
        try:
            with self._close_condition:
                while self._active_exact_publication_keys or self._queue_admissions:
                    self._close_condition.wait()
            self._raise_if_thread_failed()
            if self.threaded:
                worker_alive = self._thread is not None and self._thread.is_alive()
                worker_stopping = self._stop_event is not None and self._stop_event.is_set()
                if worker_alive and not worker_stopping:
                    self._drain_threaded_before_exact()
                elif self._event_queue is not None and self._event_queue.unfinished_tasks:
                    raise RuntimeError("Bash history worker stopped with undrained FIFO work")
            writers = self._reconcile_ordinary_migration_owners()
            # Keep every journal open until all outputs have crossed their atomic
            # export boundary; one later writer failure must not half-drain the set.
            for _writer_key, writer in writers:
                writer.flush()
            for _writer_key, writer in writers:
                writer.close()
            for writer_key, writer in writers:
                self._try_reclaim_writer(writer_key, writer)
            if self.threaded:
                self.stop_thread()
        except BaseException as primary:
            for writer_key, writer in writers:
                try:
                    self._try_reclaim_writer(writer_key, writer)
                except BaseException as cleanup_error:
                    primary.add_note(
                        f"Bash history failed-close cleanup also failed: {cleanup_error!r}"
                    )
            self._fail_close()
            raise
        self._finish_close()

    def _claim_close(self) -> bool:
        """Claim closing under admission serialization, then let active work continue."""

        owner_thread = get_ident()
        while True:
            with self._admission_lock:
                with self._close_condition:
                    if self._close_state == "closing":
                        if self._close_thread == owner_thread:
                            raise RuntimeError("Emitter close cannot be re-entered")
                        wait_for_closer = True
                    elif self._close_state == "closed":
                        return False
                    else:
                        self._close_state = "closing"
                        self._close_thread = owner_thread
                        return True
            if wait_for_closer:
                with self._close_condition:
                    while self._close_state == "closing":
                        self._close_condition.wait()

    def journal_census(self) -> BashHistoryJournalCensus:
        """Return exact bounded counts without exposing journal payloads."""

        census = self._budget.snapshot()
        return BashHistoryJournalCensus(
            writers=census.writers,
            pending_operations=census.pending_operations,
            pending_bytes=census.pending_bytes,
            reserved_rows=census.reserved_rows,
            reserved_bytes=census.reserved_bytes,
            admission_receipts=census.admission_receipts,
            export_receipts=census.export_receipts,
            retained_rows=census.retained_rows,
            retained_bytes=census.retained_bytes,
            row_capacity_per_writer=self._journal_row_capacity,
            byte_capacity_per_writer=self._journal_byte_capacity,
            high_water_rows=census.high_water_rows,
            high_water_bytes=census.high_water_bytes,
            routes=census.routes,
            route_capacity=self._journal_route_capacity,
        )

    @property
    def event_count(self) -> int:
        return self._budget.snapshot().total_events

    @event_count.setter
    def event_count(self, value: int) -> None:
        # LogEmitter initializes this before any sub-writer exists.
        del value
