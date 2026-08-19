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

"""Snort/Suricata alert emitter with a durable final-writer journal."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import stat
import tempfile
from collections import deque
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from queue import Full
from threading import Event, RLock, get_ident
from typing import Any

from evidenceforge.config.snort_classifications import snort_classification_description
from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.events.contexts import (
    IdsAlertPolicyContext,
    IdsDetectionFilterContext,
    IdsEventFilterContext,
)
from evidenceforge.events.ids_evaluation import new_ids_digest, update_ids_digest
from evidenceforge.generation.emitters.base import (
    ExactPublicationError,
    ExactPublicationKey,
    exact_publication_attempt_active,
    register_exact_publication_participant,
    stage_exact_publication_row,
)
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter
from evidenceforge.generation.ids_filtering import IdsAlertCandidate, IdsAlertFilterEngine

_DEFAULT_JOURNAL_ROW_CAPACITY = 2_000_000
_DEFAULT_JOURNAL_BYTE_CAPACITY = 2 * 1024 * 1024 * 1024
_PENDING_TERMINAL_ROW_HEADROOM = 5
_PENDING_TERMINAL_BYTE_OVERHEAD = 4096
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_SQLITE_COMPANION_SUFFIXES = ("-journal", "-wal", "-shm")
_SPOOL_DIRECTORY_ENVIRONMENT = "EFORGE_SPOOL_DIR"
_SPOOL_DIRECTORY_PREFIX = ".evidenceforge-snort-journal-"
_CANONICAL_SNORT_TEMPLATE_SHA256 = (
    "7a7271f681cabec29acde277f7da15c234dc665802addea9f2a2662036730f7b"
)
_PRE_RENDERED_LINES_KEY = "_snort_pre_rendered_lines"
_CUSTOM_RENDER_CAPTURE: ContextVar[tuple[int, list[tuple[str, str | None]]] | None] = ContextVar(
    "snort_custom_render_capture", default=None
)


def _lexical_absolute(path: Path) -> Path:
    """Return a normalized absolute path without following symlinks."""

    return Path(os.path.abspath(os.fspath(path)))


def _real_absolute(path: Path) -> Path:
    """Return a canonical absolute path for trusted private-spool selection."""

    return _lexical_absolute(Path(os.path.realpath(os.fspath(path))))


def _effective_user_id() -> int | None:
    getter = getattr(os, "geteuid", None)
    return None if getter is None else int(getter())


def _open_directory_nofollow(path: Path, *, create: bool) -> int:
    """Open a directory by walking every component without following links."""

    absolute = _lexical_absolute(path)
    if os.open not in os.supports_dir_fd:  # pragma: no cover - non-POSIX fallback
        current = Path(absolute.anchor)
        for component in absolute.parts[1:]:
            current /= component
            try:
                metadata = os.lstat(current)
            except FileNotFoundError:
                if not create:
                    raise
                current.mkdir(mode=0o755)
                metadata = os.lstat(current)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ExactPublicationError(f"Unsafe Snort directory ancestry: {current}")
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
                    f"Unsafe Snort directory ancestry: {absolute}"
                ) from error
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _safe_file_metadata(
    directory_descriptor: int,
    name: str,
    *,
    label: str,
) -> os.stat_result | None:
    try:
        metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ExactPublicationError(f"Unsafe Snort {label}: {name}")
    return metadata


def _open_regular_nofollow(directory_descriptor: int, name: str, flags: int) -> int:
    descriptor = os.open(name, flags | _NOFOLLOW, dir_fd=directory_descriptor)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise ExactPublicationError(f"Unsafe Snort regular file: {name}")
    return descriptor


def _read_descriptor_exact(descriptor: int, expected_size: int) -> bytes:
    """Read one stat-sealed regular file and reject concurrent size changes."""

    chunks: list[bytes] = []
    retained = 0
    os.lseek(descriptor, 0, os.SEEK_SET)
    while retained < expected_size:
        chunk = os.read(descriptor, min(64 * 1024, expected_size - retained))
        if not chunk:
            raise ExactPublicationError("Snort output shrank while reading its baseline")
        chunks.append(chunk)
        retained += len(chunk)
    if os.read(descriptor, 1):
        raise ExactPublicationError("Snort output grew while reading its baseline")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return b"".join(chunks)


def _directory_path_limits(directory_descriptor: int) -> tuple[int, int]:
    """Return bounded component and pathname limits for one pinned directory."""

    fpathconf = getattr(os, "fpathconf", None)
    if fpathconf is None:  # pragma: no cover - exact POSIX gate rejects this platform
        raise ExactPublicationError("Snort cannot safely determine filesystem path limits")
    try:
        name_max = int(fpathconf(directory_descriptor, "PC_NAME_MAX"))
        path_max = int(fpathconf(directory_descriptor, "PC_PATH_MAX"))
    except (OSError, ValueError) as error:  # pragma: no cover - platform-specific failure
        raise ExactPublicationError(
            "Snort cannot safely determine filesystem path limits"
        ) from error
    if name_max <= 0 or path_max <= 0:  # pragma: no cover - indeterminate platform limit
        raise ExactPublicationError("Snort filesystem path limits are not bounded")
    return name_max, path_max


def _validate_component_capacity(component: str, name_max: int, *, label: str) -> None:
    """Reject unsafe or overlong derived directory entries before mutation."""

    if (
        not component
        or component in {".", ".."}
        or "\x00" in component
        or "/" in component
        or (os.altsep is not None and os.altsep in component)
    ):
        raise ExactPublicationError(f"Unsafe Snort {label} component")
    encoded_bytes = len(os.fsencode(component))
    if encoded_bytes > name_max:
        raise ExactPublicationError(
            f"Snort {label} component exceeds NAME_MAX ({encoded_bytes} > {name_max})"
        )


def _validate_path_capacity(path: Path, path_max: int, *, label: str) -> None:
    """Reject an absolute pathname that cannot include its terminating NUL."""

    encoded_bytes = len(os.fsencode(os.fspath(_lexical_absolute(path)))) + 1
    if encoded_bytes > path_max:
        raise ExactPublicationError(
            f"Snort {label} path exceeds PATH_MAX ({encoded_bytes} > {path_max})"
        )


def _create_private_file(
    directory_descriptor: int,
    *,
    prefix: str,
    suffix: str,
) -> tuple[int, str]:
    """Create one owner-only regular file under a pinned directory."""

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
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            raise ExactPublicationError("Snort private file is not regular")
        return descriptor, name
    raise ExactPublicationError("Unable to allocate a unique Snort private file")


def _connect_existing_journal(journal_path: Path) -> sqlite3.Connection:
    """Open only an existing private SQLite database."""

    return sqlite3.connect(
        f"{journal_path.as_uri()}?mode=rw",
        uri=True,
        check_same_thread=False,
    )


def _validate_private_spool_ancestry(path: Path) -> None:
    """Require root-or-process-owned, sticky-safe private-spool ancestry."""

    effective_user = _effective_user_id()
    current = path
    while True:
        descriptor = _open_directory_nofollow(current, create=False)
        try:
            metadata = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if effective_user is not None and int(metadata.st_uid) not in {0, effective_user}:
            raise ExactPublicationError(
                f"Snort private spool ancestry is not emitter-controlled: {current}"
            )
        permissions = stat.S_IMODE(metadata.st_mode)
        if permissions & 0o022 and not metadata.st_mode & stat.S_ISVTX:
            raise ExactPublicationError(
                f"Snort private spool ancestry is externally writable: {current}"
            )
        if current == current.parent:
            return
        current = current.parent


def _validate_existing_private_spool_ancestor(path: Path) -> None:
    current = path
    while True:
        try:
            descriptor = _open_directory_nofollow(current, create=False)
        except FileNotFoundError as error:
            parent = current.parent
            if parent == current:  # pragma: no cover - filesystem root must exist
                raise ExactPublicationError(
                    "Snort private spool has no existing filesystem ancestor"
                ) from error
            current = parent
            continue
        os.close(descriptor)
        _validate_private_spool_ancestry(current)
        return


def _open_private_spool_root(base_dir: Path) -> tuple[Path, int]:
    """Open a trusted spool root outside the public output ancestry."""

    configured = os.environ.get(_SPOOL_DIRECTORY_ENVIRONMENT)
    spool_root = _real_absolute(
        Path(configured).expanduser() if configured else Path(tempfile.gettempdir())
    )
    real_base_dir = _real_absolute(base_dir)
    try:
        spool_root.relative_to(real_base_dir)
    except ValueError:
        pass
    else:
        raise ExactPublicationError(
            "Snort private spool must be outside its public output root; "
            f"configure {_SPOOL_DIRECTORY_ENVIRONMENT} to a disjoint trusted directory"
        )
    if configured:
        _validate_existing_private_spool_ancestor(spool_root)
    descriptor = _open_directory_nofollow(spool_root, create=configured is not None)
    try:
        _validate_private_spool_ancestry(spool_root)
        return spool_root, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _require_exact_journal_capabilities(base_dir: Path) -> None:
    """Fail exact admission closed without the required POSIX filesystem contract."""

    supports_dir_fd = getattr(os, "supports_dir_fd", frozenset())
    supports_follow_symlinks = getattr(os, "supports_follow_symlinks", frozenset())
    required_dir_fd = (os.open, os.mkdir, os.stat, os.unlink, os.rmdir, os.rename)
    if (
        os.name != "posix"
        or _NOFOLLOW == 0
        or _DIRECTORY == 0
        or _effective_user_id() is None
        or not callable(getattr(os, "fsync", None))
        or not callable(getattr(os, "fpathconf", None))
        or not callable(getattr(os, "listdir", None))
        or any(operation not in supports_dir_fd for operation in required_dir_fd)
        or os.stat not in supports_follow_symlinks
    ):
        raise ExactPublicationError(
            "Exact Snort publication requires POSIX directory-descriptor, no-follow, "
            "and effective-owner support"
        )
    configured = os.environ.get(_SPOOL_DIRECTORY_ENVIRONMENT)
    probe = _real_absolute(
        Path(configured).expanduser() if configured else Path(tempfile.gettempdir())
    )
    while True:
        try:
            descriptor = _open_directory_nofollow(probe, create=False)
        except FileNotFoundError as error:
            parent = probe.parent
            if parent == probe:  # pragma: no cover - filesystem root must exist
                raise ExactPublicationError(
                    "Snort private spool has no capability probe root"
                ) from error
            probe = parent
            continue
        break
    try:
        os.listdir(descriptor)
        os.fsync(descriptor)
    except (OSError, TypeError, NotImplementedError) as error:
        raise ExactPublicationError(
            "Exact Snort publication requires descriptor listing and directory fsync"
        ) from error
    finally:
        os.close(descriptor)
    _spool_root, spool_descriptor = _open_private_spool_root(base_dir)
    try:
        os.listdir(spool_descriptor)
        os.fsync(spool_descriptor)
    finally:
        os.close(spool_descriptor)


class _PrivateJournalDirectory:
    """Retry-owned protected SQLite directory outside public output paths."""

    def __init__(self, *, base_dir: Path) -> None:
        self._base_dir = _lexical_absolute(base_dir)
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

    def create(self) -> None:
        """Allocate ownership incrementally so every failure remains retryable."""

        if self._closed:
            raise ExactPublicationError("Snort private spool is already terminal")
        if self.path is not None or self._parent_descriptor is not None:
            self.validate()
            return
        spool_root, parent_descriptor = _open_private_spool_root(self._base_dir)
        self._parent_descriptor = parent_descriptor
        try:
            created = Path(tempfile.mkdtemp(prefix=_SPOOL_DIRECTORY_PREFIX, dir=spool_root))
        except BaseException:
            os.close(parent_descriptor)
            self._parent_descriptor = None
            raise
        if created.parent != spool_root:  # pragma: no cover - tempfile contract
            raise ExactPublicationError("Snort private spool escaped its trusted root")
        self.path = created
        self._directory_name = created.name
        self._initialization_pending = True
        try:
            self._finish_initialization()
        except BaseException as error:
            self._initialization_error = error
        self.validate()

    def _retained_identity(self) -> tuple[os.stat_result, os.stat_result, os.stat_result]:
        """Open or revalidate every retained spelling of the private directory."""

        if self._closed or self._unlinked:
            raise ExactPublicationError("Snort private spool is already terminal")
        path = self.path
        parent = self._parent_descriptor
        name = self._directory_name
        if path is None or parent is None or name is None:
            raise ExactPublicationError("Snort private spool lost its identity")
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(current.st_mode):
            raise ExactPublicationError("Snort private spool identity changed")
        descriptor = self._directory_descriptor
        if descriptor is None:
            descriptor = os.open(
                name,
                os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                dir_fd=parent,
            )
            self._directory_descriptor = descriptor
        retained = os.fstat(descriptor)
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
            raise ExactPublicationError("Snort private spool identity changed")
        return current, retained, reopened

    def _finish_initialization(self) -> None:
        """Complete or retry validation of a newly allocated private directory."""

        _current, retained, _reopened = self._retained_identity()
        effective_user = _effective_user_id()
        if effective_user is not None and int(retained.st_uid) != effective_user:
            raise ExactPublicationError("Snort private spool has an unsafe owner")
        if stat.S_IMODE(retained.st_mode) != 0o700:
            raise ExactPublicationError("Snort private spool is not owner-only mode 0700")
        descriptor = self._directory_descriptor
        parent = self._parent_descriptor
        path = self.path
        if descriptor is None or parent is None or path is None:
            raise ExactPublicationError("Snort private spool lost its descriptors")
        if os.listdir(descriptor):
            raise ExactPublicationError("Snort private spool was not created empty")
        name_max, path_max = _directory_path_limits(descriptor)
        prototype = f"journal-{'0' * 32}.sqlite3"
        for suffix in ("", *_SQLITE_COMPANION_SUFFIXES):
            candidate = f"{prototype}{suffix}"
            _validate_component_capacity(candidate, name_max, label="private journal")
            _validate_path_capacity(path / candidate, path_max, label="private journal")
        self._fsync_parent(parent)
        self._initialization_pending = False

    @property
    def directory_descriptor(self) -> int:
        self.validate()
        if self._directory_descriptor is None:  # pragma: no cover - validate fails first
            raise ExactPublicationError("Snort private spool lost its descriptor")
        return self._directory_descriptor

    def validate(self) -> None:
        initialization_error = self._initialization_error
        if initialization_error is not None:
            self._initialization_error = None
            raise initialization_error
        if self._initialization_pending:
            self._finish_initialization()
        current, retained, reopened = self._retained_identity()
        if self._strict_exact:
            if self.path is None:  # pragma: no cover - guarded above
                raise ExactPublicationError("Snort exact private spool lost its path")
            _validate_private_spool_ancestry(self.path.parent)
            effective_user = _effective_user_id()
            if effective_user is None:
                raise ExactPublicationError("Snort exact private spool lost POSIX ownership")
            for metadata in (current, retained, reopened):
                if (
                    int(metadata.st_uid) != effective_user
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                ):
                    raise ExactPublicationError("Snort exact private spool lost owner or mode 0700")

    def require_exact_guarantees(self) -> None:
        self.validate()
        if self.path is None or self._parent_descriptor is None:
            raise ExactPublicationError("Snort exact private spool lost its ownership")
        _validate_private_spool_ancestry(self.path.parent)
        os.fsync(self.directory_descriptor)
        os.fsync(self._parent_descriptor)
        self._strict_exact = True
        self.validate()

    def fsync(self) -> None:
        os.fsync(self.directory_descriptor)

    def close(self) -> None:
        """Retryably remove the empty private directory and persist its parent."""

        if self._closed:
            return
        self._initialization_error = None
        parent = self._parent_descriptor
        name = self._directory_name
        path = self.path
        if parent is None:
            self._closed = True
            return
        if name is None or path is None:
            os.close(parent)
            self._parent_descriptor = None
            self._closed = True
            return
        if not self._unlinked:
            try:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                self._unlinked = True
            else:
                identity = self._identity
                effective_user = _effective_user_id()
                if (
                    not stat.S_ISDIR(current.st_mode)
                    or (
                        identity is not None
                        and (int(current.st_dev), int(current.st_ino)) != identity
                    )
                    or (effective_user is not None and int(current.st_uid) != effective_user)
                ):
                    raise ExactPublicationError("Snort private spool changed during cleanup")
                descriptor = self._directory_descriptor
                if descriptor is None:
                    descriptor = os.open(
                        name,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                        dir_fd=parent,
                    )
                    self._directory_descriptor = descriptor
                if os.listdir(descriptor):
                    raise ExactPublicationError("Snort private spool retained an unowned file")
                try:
                    self._remove_directory(parent, name, path)
                except BaseException:
                    try:
                        os.stat(name, dir_fd=parent, follow_symlinks=False)
                    except FileNotFoundError:
                        self._unlinked = True
                    raise
                else:
                    self._unlinked = True
        self._fsync_parent(parent)
        if self._directory_descriptor is not None:
            os.close(self._directory_descriptor)
            self._directory_descriptor = None
        os.close(parent)
        self._parent_descriptor = None
        self._initialization_pending = False
        self._closed = True

    def _remove_directory(self, parent: int, name: str, path: Path) -> None:
        if os.rmdir in os.supports_dir_fd:
            os.rmdir(name, dir_fd=parent)
        else:  # pragma: no cover - non-POSIX fallback
            os.rmdir(path)

    def _fsync_parent(self, parent: int) -> None:
        os.fsync(parent)


@dataclass(frozen=True, slots=True)
class _OutputRouteState:
    """One no-follow physical output owner and its charged baseline."""

    sensor: str
    path: Path
    parent_identity: tuple[int, int]
    file_identity: tuple[int, int] | None
    size: int

    @property
    def owner_tokens(self) -> tuple[tuple[object, ...], ...]:
        tokens: list[tuple[object, ...]] = [
            ("parent", *self.parent_identity, self.path.name),
        ]
        if self.file_identity is not None:
            tokens.append(("file", *self.file_identity))
        return tuple(tokens)


@dataclass(frozen=True, slots=True)
class SnortJournalCensus:
    """Constant-time counts for durable rows and exact retry receipts."""

    pending_rows: int
    pending_bytes: int
    exported_rows: int
    exported_bytes: int
    reserved_rows: int
    reserved_bytes: int
    active_receipts: int
    row_capacity: int
    byte_capacity: int
    high_water_rows: int
    high_water_bytes: int
    total_events: int
    admission_receipts: int
    export_receipts: int
    summary_rows: int
    filter_rows: int
    terminal_headroom_bytes: int
    retained_rows: int
    retained_bytes: int


@dataclass(frozen=True, slots=True)
class _SnortJournalState:
    """Durable scalar accounting for every retained journal object."""

    pending_rows: int = 0
    pending_bytes: int = 0
    exported_rows: int = 0
    exported_bytes: int = 0
    admission_receipts: int = 0
    admission_bytes: int = 0
    export_slots: int = 0
    export_slot_bytes: int = 0
    export_receipts: int = 0
    export_bytes: int = 0
    summary_rows: int = 0
    summary_bytes: int = 0
    filter_rows: int = 0
    filter_bytes: int = 0
    terminal_headroom_bytes: int = 0
    plan_rows: int = 0
    plan_bytes: int = 0
    total_events: int = 0
    high_water_rows: int = 0
    high_water_bytes: int = 0

    @property
    def retained_rows(self) -> int:
        return (
            self.pending_rows
            + self.exported_rows
            + self.admission_receipts
            + self.export_slots
            + self.export_receipts
            + self.summary_rows
            + self.filter_rows
            + self.plan_rows
        )

    @property
    def retained_bytes(self) -> int:
        return (
            self.pending_bytes
            + self.exported_bytes
            + self.admission_bytes
            + self.export_slot_bytes
            + self.export_bytes
            + self.summary_bytes
            + self.filter_bytes
            + self.plan_bytes
        )


class _SnortDrainRequest:
    """FIFO request that drains rendering without creating a flush boundary."""

    def __init__(self) -> None:
        self.completed = Event()
        self.error: BaseException | None = None


@dataclass(slots=True)
class _SnortCheckpointEventWindow:
    """Restored bounded event-filter state compatible with IdsAlertFilterEngine."""

    start: datetime
    matches: int
    emitted: bool


@dataclass(slots=True)
class _PendingSummarySnapshot:
    """One summary/filter commit that may have returned after becoming durable."""

    records: list[tuple[str, str, int]]
    alert_summary: dict[str, dict[int, dict[str, Any]]]
    evaluation_summary: dict[str, dict[str, dict[str, Any]]]
    scope: str
    decisions: list[tuple[int, int, str | None]]
    filter_records: list[tuple[str, str, str, int]]
    filter_watermark: str


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _publication_key(key: ExactPublicationKey) -> str:
    return f"{key[0]}:{key[1]}:{key[2]}"


def _line_bytes(line: str) -> bytes:
    return (line if line.endswith("\n") else f"{line}\n").encode("utf-8")


class SnortEmitter(SensorMultiplexEmitter):
    """Spool every alert before deterministic filter and final-file publication."""

    _log_filename = "snort_alert.log"
    _flat_filename = "snort_alert.log"
    _sort_before_flush: bool = True
    _external_sorting: bool = False
    _include_sensor_identity: bool = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        journal_row_capacity = kwargs.pop("journal_row_capacity", _DEFAULT_JOURNAL_ROW_CAPACITY)
        journal_byte_capacity = kwargs.pop("journal_byte_capacity", _DEFAULT_JOURNAL_BYTE_CAPACITY)
        if type(journal_row_capacity) is not int or journal_row_capacity <= 0:
            raise ValueError("Snort journal row capacity must be a positive exact int")
        if type(journal_byte_capacity) is not int or journal_byte_capacity <= 0:
            raise ValueError("Snort journal byte capacity must be a positive exact int")
        self._journal_row_capacity = journal_row_capacity
        self._journal_byte_capacity = journal_byte_capacity
        self._spool_lock = RLock()
        self._producer_lock = RLock()
        self._spool_connection: sqlite3.Connection | None = None
        self._spool_path: Path | None = None
        self._journal_path: Path | None = None
        self._journal_directory: Path | None = None
        self._journal_directory_descriptor: int | None = None
        self._journal_filename: str | None = None
        self._journal_identity: tuple[int, int] | None = None
        self._journal_directory_identity: tuple[int, int] | None = None
        self._journal_owner: _PrivateJournalDirectory | None = None
        self._journal_unlinked = False
        self._journal_cleanup_pending = False
        self._exact_journal_capabilities_validated = False
        self._exact_candidate_receipts: dict[ExactPublicationKey, str] = {}
        self._exact_capacity_reservations: dict[ExactPublicationKey, tuple[str, int, int]] = {}
        self._preparing_exact_terminal_headroom: int | None = None
        self._preparing_exact_sensor: str | None = None
        self._preparing_exact_policy_limits: dict[str, tuple[int, int]] | None = None
        self._exact_provisional_sensors: dict[tuple[str, int], set[str]] = {}
        self._exact_prepared_policy_limits: dict[tuple[str, int], dict[str, tuple[int, int]]] = {}
        self._exact_provisional_output_states: dict[
            tuple[str, int], dict[str, _OutputRouteState]
        ] = {}
        self._exact_provisional_output_owners: dict[
            tuple[str, int], dict[tuple[object, ...], str]
        ] = {}
        self._exact_provisional_output_bytes: dict[tuple[str, int], int] = {}
        self._exact_reserved_rows = 0
        self._exact_reserved_bytes = 0
        self._unpersisted_summary_rows = 0
        self._unpersisted_summary_bytes = 0
        self._retained_total_events = 0
        self._emitted_event_count = 0
        self._retained_high_water_rows = 0
        self._retained_high_water_bytes = 0
        self._ids_alert_summary: dict[str, dict[int, dict[str, Any]]] = {}
        self._ids_evaluation_summary: dict[str, dict[str, dict[str, Any]]] = {}
        self._pending_summary_snapshot: _PendingSummarySnapshot | None = None
        self._summary_decisions: list[tuple[int, int, str | None]] = []
        self._summary_filter_records: list[tuple[str, str, str, int]] = []
        self._summary_filter_watermark = ""
        self._summary_scope = "none"
        self._consumed_plan_buffers: set[tuple[str, int]] = set()
        self._export_recovery_pending = False
        self._worker_publication_error: BaseException | None = None
        self._terminal_cleanup_pending = False
        self._terminal_cleanup_thread: int | None = None
        self._next_epoch = 1
        super().__init__(*args, **kwargs)
        self._canonical_template = (
            _sha256(self.format_def.output.template.encode("utf-8"))
            == _CANONICAL_SNORT_TEMPLATE_SHA256
        )
        self._known_output_sensors = {str(sensor) for sensor in self._sensor_hostnames}
        if self._direct_file_path:
            self._known_output_sensors.add("__direct__")
        self._output_routes_initialized = False
        self._output_route_states: dict[str, _OutputRouteState] = {}
        self._output_owner_sensors: dict[tuple[object, ...], str] = {}
        self._output_baseline_bytes = 0

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Serialize FIFO admission without letting ordinary work split an exact epoch."""

        prepared = dict(event_data)
        if exact_publication_attempt_active() or (
            not self._canonical_template
            and (
                bool(prepared.get("_ids_candidate", False))
                or prepared.get("sid")
                or prepared.get("message")
            )
        ):
            # Custom templates have no static expansion bound. Freeze each
            # sensor-projected final string before producer/journal locks.
            prepared[_PRE_RENDERED_LINES_KEY] = self._capture_custom_candidate_lines(prepared)

        if exact_publication_attempt_active():
            with self._producer_lock:
                super().emit_event(prepared)
            return
        while True:
            with self._producer_lock:
                with self._exact_publication_condition:
                    exact_active = bool(self._active_exact_publication_keys)
                if not exact_active:
                    super().emit_event(prepared)
                    return
            self._wait_for_exact_publication_turn(None)

    def _capture_custom_candidate_lines(
        self,
        event_data: dict[str, Any],
    ) -> deque[tuple[str, str | None]]:
        """Render each custom-template sensor view once outside admission locks."""

        captured: list[tuple[str, str | None]] = []
        token = _CUSTOM_RENDER_CAPTURE.set((id(self), captured))
        try:
            SensorMultiplexEmitter._dispatch(self, dict(event_data))
        finally:
            _CUSTOM_RENDER_CAPTURE.reset(token)
        return deque(captured)

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Consume every pre-rendered custom sensor row in inherited route order."""

        rendered_lines = event_data.get(_PRE_RENDERED_LINES_KEY)
        super()._dispatch(event_data)
        if rendered_lines is not None and rendered_lines:
            raise ExactPublicationError("Snort custom rendering retained an unrouted sensor view")

    @staticmethod
    def _take_pre_rendered_line(event_data: dict[str, Any]) -> tuple[bool, str | None]:
        rendered_lines = event_data.get(_PRE_RENDERED_LINES_KEY)
        if rendered_lines is None:
            return False, None
        if not isinstance(rendered_lines, deque):
            raise TypeError("Snort rendering must retain an ordered sensor line queue")
        sensor = str(event_data.get("_sensor_identity", "__direct__"))
        if not rendered_lines:
            raise ExactPublicationError("Snort custom rendering lost its sensor view")
        expected_sensor, rendered = rendered_lines.popleft()
        if expected_sensor != sensor:
            raise ExactPublicationError("Snort custom sensor rendering order changed")
        if rendered is not None and type(rendered) is not str:
            raise TypeError("Snort rendering must retain one exact string")
        return True, rendered

    def _emit_threaded(self, event_data: dict[str, Any]) -> None:
        if not exact_publication_attempt_active():
            with self._spool_lock:
                durable_journal = self._spool_connection is not None
            if durable_journal:
                self._require_accepting_events()
                self._drain_threaded_before_exact()
                self._dispatch(dict(event_data))
                return
            super()._emit_threaded(event_data)
            return
        if not register_exact_publication_participant(self):
            raise ExactPublicationError("Snort exact drain lost its active publication")
        super()._emit_threaded(event_data)

    def _require_accepting_events_locked(self) -> None:
        if self._export_recovery_pending:
            raise RuntimeError("Snort emitter requires terminal export recovery")
        if exact_publication_attempt_active() and self._active_exact_publication_keys:
            return
        super()._require_accepting_events_locked()

    def _register_exact_publication_batch(self, key: tuple[str, int]) -> None:
        """Drain earlier FIFO work before the first row installs its exact fence."""

        if not self._exact_journal_capabilities_validated:
            _require_exact_journal_capabilities(self._base_dir)
            self._exact_journal_capabilities_validated = True
        with self._spool_lock:
            if self._journal_owner is not None:
                self._journal_owner.require_exact_guarantees()
        with self._producer_lock:
            with self._exact_publication_condition:
                already_registered = key in self._active_exact_publication_keys
            if not already_registered:
                self._require_accepting_events()
                if self.threaded:
                    self._drain_threaded_before_exact()
            super()._register_exact_publication_batch(key)

    def _drain_threaded_before_exact(self) -> None:
        """Wait for prior FIFO rendering without establishing a flush boundary."""

        request = _SnortDrainRequest()
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

    def _process_exact_drain(self) -> None:
        """FIFO position itself proves that all preceding rendering completed."""

    def _handle_flush_request(self, queue_item: Any) -> bool:
        if not isinstance(queue_item, _SnortDrainRequest):
            return super()._handle_flush_request(queue_item)
        try:
            self._process_exact_drain()
        except BaseException as error:
            queue_item.error = error
        finally:
            queue_item.completed.set()
        return True

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        """Handle physical canonical transports that carry an IdsAlertPlan."""

        return (
            event.network is not None
            and bool(event.ids_alerts)
            and not event.network.application_layer_only
        )

    def emit(self, event: CanonicalOccurrence) -> None:
        """Freeze one candidate per attached IDS plan and visible sensor."""

        net = event.network
        for ids in event.ids_alerts:
            response_packet = (
                ids.predicate is not None and ids.predicate.payload_direction == "resp"
            )
            self.emit_event(
                {
                    "timestamp": event.timestamp,
                    "gid": ids.gid,
                    "sid": ids.sid,
                    "rev": ids.rev,
                    "message": ids.message,
                    "classification": ids.classification,
                    "priority": ids.priority,
                    "protocol": (net.protocol or "TCP").upper() if net else "TCP",
                    "src_ip": net.dst_ip if net and response_packet else net.src_ip if net else "",
                    "src_port": (
                        net.dst_port if net and response_packet else net.src_port if net else 0
                    ),
                    "dst_ip": net.src_ip if net and response_packet else net.dst_ip if net else "",
                    "dst_port": (
                        net.src_port if net and response_packet else net.dst_port if net else 0
                    ),
                    "_ids_candidate": True,
                    "_ids_policy": asdict(ids.policy) if ids.policy is not None else None,
                    "_cluster_id": event.storyline_cluster_id or event.occurrence_id,
                    "_occurrence_id": event.occurrence_id,
                    "_source_observation_status": getattr(
                        event, "_source_observation_status", "visible"
                    ),
                    "_ids_origin": ids.origin,
                    **self._sensor_metadata(event, "snort_alert"),
                }
            )

    def _render_event(self, event_data: dict[str, Any]) -> str | None:
        """Freeze exact rows at the final native-string boundary."""

        capture = _CUSTOM_RENDER_CAPTURE.get()
        if capture is not None and capture[0] == id(self):
            token = _CUSTOM_RENDER_CAPTURE.set(None)
            try:
                rendered = self._render_alert(event_data)
            finally:
                _CUSTOM_RENDER_CAPTURE.reset(token)
            if rendered is not None and type(rendered) is not str:
                raise TypeError("Snort rendering must produce one exact string")
            sensor = str(event_data.get("_sensor_identity", "__direct__"))
            capture[1].append((sensor, rendered))
            return None

        row_kind = "candidate" if bool(event_data.get("_ids_candidate", False)) else "raw"
        has_pre_rendered, rendered = self._take_pre_rendered_line(event_data)
        if exact_publication_attempt_active():
            if not has_pre_rendered:
                rendered = self._render_alert(event_data)
            if rendered is None:
                return None
            policy_limits: dict[str, tuple[int, int]] = {}
            if row_kind == "candidate":
                with self._spool_lock:
                    policy_limits = self._validate_candidate_watermark_unlocked(event_data)
            envelope = self._exact_envelope(row_kind, event_data, rendered)
            parsed = self._parse_exact_envelope(envelope)
            values = (
                parsed["sensor"],
                parsed["timestamp"],
                parsed["gid"],
                parsed["sid"],
                parsed["payload"],
                parsed["policy"],
                parsed["cluster_id"],
                parsed["occurrence_id"],
                parsed["observation_status"],
                parsed["origin"],
            )
            self._preparing_exact_terminal_headroom = (
                8 * len(envelope.encode("utf-8"))
            ) + _PENDING_TERMINAL_BYTE_OVERHEAD
            self._preparing_exact_sensor = str(parsed["sensor"])
            self._preparing_exact_policy_limits = policy_limits
            try:
                if not stage_exact_publication_row(
                    self,
                    envelope,
                    publish=self._commit_exact_row,
                    release=self._release_exact_candidate,
                ):
                    raise ExactPublicationError("Snort exact row lost its active publication")
            finally:
                self._preparing_exact_terminal_headroom = None
                self._preparing_exact_sensor = None
                self._preparing_exact_policy_limits = None
            return None
        if row_kind == "candidate":
            if has_pre_rendered:
                if rendered is None:
                    return None
                self._spool_candidate(event_data, final_line=rendered)
            else:
                self._spool_candidate(event_data)
            return None
        if not has_pre_rendered:
            rendered = self._render_alert(event_data)
        if rendered is None:
            return None
        values = self._frozen_values(event_data, preserve_unknown=False)
        with self._spool_lock:
            pending_for_sensor = self._insert_values_unlocked(
                "raw",
                values,
                None,
                None,
                final_line=rendered,
                released=True,
            )
            if pending_for_sensor >= self._buffer_size:
                try:
                    self._publish_pending_unlocked(raw_only=True)
                except BaseException as error:
                    worker = self._thread.ident if self._thread is not None else None
                    if worker is None or get_ident() != worker:
                        raise
                    # The base worker treats a dispatch exception as terminal.
                    # Retain this adapter-owned failure behind the recovery fence
                    # so close/flush can finish the durable epoch retryably.
                    self._worker_publication_error = error
                    self._export_recovery_pending = True
        return None

    def emit_raw(self, event_data: dict[str, Any]) -> None:
        """Journal an unchanged raw alert with its authorized origin."""

        payload = dict(event_data)
        payload["_ids_origin"] = "raw"
        super().emit_raw(payload)

    def _render_alert(self, event_data: dict[str, Any]) -> str | None:
        """Render one admitted payload to Snort fast-alert text."""

        if not event_data.get("sid") and not event_data.get("message"):
            return None
        proto = event_data.get("protocol") or event_data.get("proto")
        context = {
            "timestamp": event_data.get("timestamp") or event_data.get("ts"),
            "gid": event_data.get("gid", 1),
            "sid": event_data.get("sid"),
            "rev": event_data.get("rev", 1),
            "classification": snort_classification_description(
                str(event_data.get("classification") or "")
            ),
            "priority": event_data.get("priority"),
            "protocol": proto.upper() if proto else None,
            "src_ip": event_data.get("src_ip") or event_data.get("id.orig_h"),
            "src_port": event_data.get("src_port") or event_data.get("id.orig_p"),
            "dst_ip": event_data.get("dst_ip") or event_data.get("id.resp_h"),
            "dst_port": event_data.get("dst_port") or event_data.get("id.resp_p"),
            "message": event_data.get("message"),
        }
        return self._template.render(**context).strip()

    def _exact_envelope(
        self,
        row_kind: str,
        event_data: dict[str, Any],
        final_line: str,
    ) -> str:
        """Return one canonical exact string containing all replay decisions."""

        values = self._frozen_values(event_data, preserve_unknown=True)
        return json.dumps(
            {
                "schema": 1,
                "row_kind": row_kind,
                "final_line": final_line,
                "sensor": values[0],
                "timestamp": values[1],
                "gid": values[2],
                "sid": values[3],
                "payload": values[4],
                "policy": values[5],
                "cluster_id": values[6],
                "occurrence_id": values[7],
                "observation_status": values[8],
                "origin": values[9],
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    @staticmethod
    def _parse_exact_envelope(frozen: object) -> dict[str, Any]:
        if type(frozen) is not str:
            raise ExactPublicationError("Exact IDS row must retain one exact str")
        try:
            envelope = json.loads(frozen)
        except json.JSONDecodeError as error:
            raise ExactPublicationError("Exact IDS row lost its frozen schema") from error
        required = {
            "schema",
            "row_kind",
            "final_line",
            "sensor",
            "timestamp",
            "gid",
            "sid",
            "payload",
            "policy",
            "cluster_id",
            "occurrence_id",
            "observation_status",
            "origin",
        }
        if (
            type(envelope) is not dict
            or set(envelope) != required
            or envelope.get("schema") != 1
            or envelope.get("row_kind") not in {"candidate", "raw"}
            or type(envelope.get("final_line")) is not str
            or type(envelope.get("sensor")) is not str
            or type(envelope.get("timestamp")) is not str
            or type(envelope.get("gid")) is not int
            or type(envelope.get("sid")) is not int
            or not all(
                type(envelope.get(name)) is str
                for name in (
                    "payload",
                    "policy",
                    "cluster_id",
                    "occurrence_id",
                    "observation_status",
                    "origin",
                )
            )
        ):
            raise ExactPublicationError("Exact IDS row lost its frozen schema")
        return envelope

    def _initialize_spool_schema(self, connection: sqlite3.Connection) -> None:
        """Initialize one verified private SQLite file before exposing it to callers."""

        connection.execute("PRAGMA temp_store=MEMORY")
        if connection.execute("PRAGMA temp_store").fetchone() != (2,):
            raise ExactPublicationError("Snort journal could not confine temporary storage")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            """CREATE TABLE candidates (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                publication_key TEXT UNIQUE,
                publication_digest TEXT,
                row_kind TEXT NOT NULL,
                sensor TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                gid INTEGER NOT NULL,
                sid INTEGER NOT NULL,
                payload TEXT NOT NULL,
                policy TEXT NOT NULL,
                cluster_id TEXT NOT NULL,
                occurrence_id TEXT NOT NULL,
                observation_status TEXT NOT NULL,
                origin TEXT NOT NULL,
                final_line TEXT,
                payload_bytes INTEGER NOT NULL,
                terminal_headroom_bytes INTEGER NOT NULL,
                detection_key TEXT,
                detection_count INTEGER,
                detection_seconds INTEGER,
                event_key TEXT,
                event_count INTEGER,
                event_seconds INTEGER,
                exported INTEGER NOT NULL DEFAULT 0,
                summarized INTEGER NOT NULL DEFAULT 0,
                admitted INTEGER,
                released INTEGER NOT NULL DEFAULT 0,
                epoch INTEGER
            )"""
        )
        connection.execute(
            """CREATE INDEX candidates_detection_key
            ON candidates (detection_key, exported)"""
        )
        connection.execute(
            """CREATE INDEX candidates_event_key
            ON candidates (event_key, exported)"""
        )
        connection.execute(
            """CREATE INDEX candidates_final_order
            ON candidates (timestamp, sensor, occurrence_id, gid, sid, sequence)"""
        )
        connection.execute(
            """CREATE TABLE raw_sensor_state (
                sensor TEXT PRIMARY KEY,
                pending_rows INTEGER NOT NULL CHECK (pending_rows >= 0)
            )"""
        )
        connection.execute(
            """CREATE TABLE spool_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                pending_rows INTEGER NOT NULL,
                pending_bytes INTEGER NOT NULL,
                exported_rows INTEGER NOT NULL,
                exported_bytes INTEGER NOT NULL,
                admission_receipts INTEGER NOT NULL,
                admission_bytes INTEGER NOT NULL,
                export_slots INTEGER NOT NULL,
                export_slot_bytes INTEGER NOT NULL,
                export_receipts INTEGER NOT NULL,
                export_bytes INTEGER NOT NULL,
                summary_rows INTEGER NOT NULL,
                summary_bytes INTEGER NOT NULL,
                filter_rows INTEGER NOT NULL,
                filter_bytes INTEGER NOT NULL,
                terminal_headroom_bytes INTEGER NOT NULL,
                plan_rows INTEGER NOT NULL,
                plan_bytes INTEGER NOT NULL,
                total_events INTEGER NOT NULL,
                high_water_rows INTEGER NOT NULL,
                high_water_bytes INTEGER NOT NULL,
                filter_watermark TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE export_plans (
                sensor TEXT PRIMARY KEY,
                epoch INTEGER NOT NULL,
                raw_only INTEGER NOT NULL,
                cutoff_sequence INTEGER NOT NULL,
                baseline_digest TEXT NOT NULL,
                baseline_size INTEGER NOT NULL,
                expected_digest TEXT NOT NULL,
                expected_size INTEGER NOT NULL,
                planned_lines TEXT NOT NULL,
                buffer_lines TEXT NOT NULL,
                buffer_consumed INTEGER NOT NULL,
                raw_rows INTEGER NOT NULL,
                retained_bytes INTEGER NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE admission_receipts (
                publication_key TEXT PRIMARY KEY,
                publication_digest TEXT NOT NULL,
                retained_bytes INTEGER NOT NULL,
                export_slot INTEGER NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE export_receipts (
                publication_key TEXT PRIMARY KEY,
                publication_digest TEXT NOT NULL,
                retained_bytes INTEGER NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE summaries (
                summary_key TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                retained_bytes INTEGER NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE filter_checkpoints (
                checkpoint_key TEXT PRIMARY KEY,
                checkpoint_kind TEXT NOT NULL,
                payload TEXT NOT NULL,
                retained_bytes INTEGER NOT NULL
            )"""
        )
        summary_records = self._summary_records(
            self._ids_alert_summary,
            self._ids_evaluation_summary,
        )
        summary_bytes = sum(record[2] for record in summary_records)
        connection.executemany(
            """INSERT INTO summaries (summary_key, payload, retained_bytes)
            VALUES (?, ?, ?)""",
            summary_records,
        )
        connection.execute(
            """INSERT INTO spool_state
            (singleton, pending_rows, pending_bytes, exported_rows, exported_bytes,
             admission_receipts, admission_bytes, export_slots, export_slot_bytes,
             export_receipts, export_bytes,
             summary_rows, summary_bytes, filter_rows, filter_bytes,
             terminal_headroom_bytes, plan_rows, plan_bytes, total_events,
             high_water_rows, high_water_bytes, filter_watermark)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                len(summary_records),
                summary_bytes,
                0,
                0,
                0,
                0,
                0,
                len(summary_records),
                summary_bytes,
                "",
            ),
        )
        connection.commit()

    def _discard_failed_spool_initialization_unlocked(self, primary: BaseException) -> None:
        """Attempt cleanup while retaining every unresolved retry owner."""

        self._journal_cleanup_pending = True
        try:
            self._cleanup_journal_unlocked()
        except BaseException as cleanup_error:
            primary.add_note(f"Snort journal initialization cleanup also failed: {cleanup_error!r}")

    def _create_journal_file_unlocked(
        self,
        owner: _PrivateJournalDirectory,
    ) -> tuple[int, str]:
        """Create and immediately install retry ownership for one SQLite main file."""

        directory_descriptor = owner.directory_descriptor
        name_max, _path_max = _directory_path_limits(directory_descriptor)
        for _attempt in range(128):
            journal_filename = f"journal-{secrets.token_hex(16)}.sqlite3"
            _validate_component_capacity(
                journal_filename,
                name_max,
                label="private journal",
            )
            try:
                descriptor = os.open(
                    journal_filename,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                    0o600,
                    dir_fd=directory_descriptor,
                )
            except FileExistsError:
                continue
            created = os.fstat(descriptor)
            journal_identity = (int(created.st_dev), int(created.st_ino))
            journal_directory = owner.path
            if journal_directory is None:  # pragma: no cover - owner validation guards this
                os.close(descriptor)
                raise ExactPublicationError("Snort private journal lost its path")
            journal_path = journal_directory / journal_filename
            self._spool_path = journal_path
            self._journal_path = journal_path
            self._journal_directory = journal_directory
            self._journal_directory_descriptor = directory_descriptor
            self._journal_filename = journal_filename
            self._journal_identity = journal_identity
            directory_identity = os.fstat(directory_descriptor)
            self._journal_directory_identity = (
                int(directory_identity.st_dev),
                int(directory_identity.st_ino),
            )
            self._journal_unlinked = False
            try:
                if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
                    raise ExactPublicationError("Snort private journal is not a regular file")
                os.fchmod(descriptor, 0o600)
            except BaseException:
                os.close(descriptor)
                raise
            return descriptor, journal_filename
        raise ExactPublicationError("Unable to allocate a unique Snort private journal")

    def _open_spool(self) -> sqlite3.Connection:
        """Create the bounded durable row journal lazily."""

        if self._journal_cleanup_pending:
            self._cleanup_journal_unlocked()
        if self._spool_connection is not None:
            return self._spool_connection
        owner = self._journal_owner
        if owner is None:
            owner = _PrivateJournalDirectory(base_dir=self._base_dir)
            self._journal_owner = owner
        descriptor: int | None = None
        connection: sqlite3.Connection | None = None
        try:
            owner.create()
            if self._exact_journal_capabilities_validated:
                owner.require_exact_guarantees()
            directory_descriptor = owner.directory_descriptor
            descriptor, journal_filename = self._create_journal_file_unlocked(owner)
            created = os.fstat(descriptor)
            journal_identity = (int(created.st_dev), int(created.st_ino))
            journal_directory = owner.path
            if journal_directory is None:  # pragma: no cover - owner validation guards this
                raise ExactPublicationError("Snort private journal lost its path")
            journal_path = journal_directory / journal_filename
            connection = _connect_existing_journal(journal_path)
            self._spool_connection = connection
            owner.validate()
            try:
                current = _safe_file_metadata(
                    directory_descriptor,
                    journal_filename,
                    label="journal",
                )
            except ExactPublicationError as error:
                raise ExactPublicationError(
                    "Snort journal path changed before SQLite opened"
                ) from error
            retained = os.fstat(descriptor)
            if (
                current is None
                or current.st_nlink != 1
                or retained.st_nlink != 1
                or stat.S_IMODE(current.st_mode) != 0o600
                or (int(current.st_dev), int(current.st_ino)) != journal_identity
                or (int(retained.st_dev), int(retained.st_ino)) != journal_identity
            ):
                raise ExactPublicationError("Snort journal path changed before SQLite opened")
            for suffix in _SQLITE_COMPANION_SUFFIXES:
                if (
                    _safe_file_metadata(
                        directory_descriptor,
                        f"{journal_filename}{suffix}",
                        label="journal companion",
                    )
                    is not None
                ):
                    raise ExactPublicationError(
                        "Snort journal companion existed before SQLite initialization"
                    )
            self._initialize_spool_schema(connection)
            owner.fsync()
        except BaseException as error:
            if self._journal_filename is not None:
                self._discard_failed_spool_initialization_unlocked(error)
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if connection is None:  # pragma: no cover - initialization either returns or raises
            raise ExactPublicationError("Snort journal did not open a verified SQLite file")
        self._journal_cleanup_pending = False
        self._unpersisted_summary_rows = 0
        self._unpersisted_summary_bytes = 0
        return connection

    @staticmethod
    def _frozen_values(
        event_data: dict[str, Any],
        *,
        preserve_unknown: bool,
    ) -> tuple[str, str, int, int, str, str, str, str, str, str]:
        timestamp = event_data.get("timestamp") or event_data.get("ts")
        if not isinstance(timestamp, datetime):
            timestamp = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        timestamp = (
            timestamp.replace(tzinfo=UTC) if timestamp.tzinfo is None else timestamp.astimezone(UTC)
        )
        replay_fields = {
            "timestamp",
            "ts",
            "gid",
            "sid",
            "rev",
            "message",
            "classification",
            "priority",
            "protocol",
            "proto",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "id.orig_h",
            "id.orig_p",
            "id.resp_h",
            "id.resp_p",
        }
        payload = {
            key: value.isoformat() if isinstance(value, datetime) else value
            for key, value in event_data.items()
            if not key.startswith("_") and (preserve_unknown or key in replay_fields)
        }
        payload["timestamp"] = timestamp.isoformat()
        return (
            str(event_data.get("_sensor_identity", "__direct__")),
            timestamp.isoformat(),
            int(event_data.get("gid", 1)),
            int(event_data["sid"]),
            json.dumps(payload, sort_keys=True),
            json.dumps(event_data.get("_ids_policy"), sort_keys=True),
            str(event_data.get("_cluster_id", "")),
            str(event_data.get("_occurrence_id", "")),
            str(event_data.get("_source_observation_status", "visible")),
            str(event_data.get("_ids_origin", "built_in")),
        )

    def _spool_candidate(
        self,
        event_data: dict[str, Any],
        *,
        final_line: str | None = None,
    ) -> None:
        values = self._frozen_values(event_data, preserve_unknown=False)
        self._wait_for_exact_publication_turn(None)
        with self._spool_lock:
            self._validate_candidate_watermark_unlocked(event_data)
            self._insert_values_unlocked(
                "candidate",
                values,
                None,
                None,
                final_line=final_line,
                released=True,
            )

    def _filter_watermark_unlocked(self) -> str:
        connection = self._spool_connection
        if connection is None:
            return ""
        row = connection.execute(
            "SELECT filter_watermark FROM spool_state WHERE singleton = ?",
            (1,),
        ).fetchone()
        if row is None:
            raise RuntimeError("Snort journal lost its filter watermark")
        return str(row[0])

    def _validate_candidate_watermark_unlocked(
        self,
        event_data: dict[str, Any],
    ) -> dict[str, tuple[int, int]]:
        """Reject stale timestamps or conflicting filter policy before admission."""

        values = self._frozen_values(event_data, preserve_unknown=False)
        limits = self._validate_filter_policy_limits_unlocked(values)
        watermark = self._filter_watermark_unlocked()
        if not watermark:
            return limits
        timestamp = event_data.get("timestamp") or event_data.get("ts")
        if not isinstance(timestamp, datetime):
            timestamp = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        timestamp = (
            timestamp.replace(tzinfo=UTC) if timestamp.tzinfo is None else timestamp.astimezone(UTC)
        )
        if timestamp < datetime.fromisoformat(watermark):
            raise ExactPublicationError("Snort candidate predates the finalized filter checkpoint")
        return limits

    def _buffer_plan_headroom(
        self,
        *,
        extra_baseline_bytes: int = 0,
        extra_sensor: str | None = None,
        extra_line: str | None = None,
    ) -> tuple[int, int]:
        """Return O(1) cached baseline plus bounded writer-plan headroom."""

        self._initialize_output_routes_unlocked()
        with self._writers_lock:
            writers = list(self._writers.items())
        retained_bytes = self._output_baseline_bytes + extra_baseline_bytes
        buffered: dict[str, list[str]] = {}
        for key, writer in writers:
            sensor = "__direct__" if key == "" else key
            with writer._exact_publication_condition:
                with writer._lock:
                    if writer.buffer:
                        buffered[sensor] = list(writer.buffer)
        if extra_sensor is not None and extra_line is not None:
            buffered.setdefault(extra_sensor, []).append(extra_line)
        for lines in buffered.values():
            encoded = json.dumps(
                lines,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            retained_bytes += (2 * len(encoded)) + 256
        return len(buffered), retained_bytes

    def _filter_policy_limits(
        self,
        values: tuple[str, str, int, int, str, str, str, str, str, str],
    ) -> dict[str, tuple[int, int]]:
        """Return canonical checkpoint keys and immutable count/window policy claims."""

        policy = self._policy_from_json(values[5])
        if policy is None:
            return {}
        payload = json.loads(values[4])
        if type(payload) is not dict:
            raise ExactPublicationError("Snort candidate payload lost its frozen schema")
        limits: dict[str, tuple[int, int]] = {}
        detection = policy.detection_filter
        if detection is not None:
            tracked = (
                payload.get("src_ip", "")
                if detection.track == "by_src"
                else payload.get("dst_ip", "")
            )
            key = [
                values[0],
                values[2],
                values[3],
                "detection",
                detection.track,
                str(tracked),
            ]
            checkpoint_key = json.dumps(
                ["detection", *key],
                ensure_ascii=False,
                separators=(",", ":"),
            )
            limits[checkpoint_key] = (detection.count, detection.seconds)
        event_filter = policy.event_filter
        if event_filter is not None:
            tracked = (
                payload.get("src_ip", "")
                if event_filter.track == "by_src"
                else payload.get("dst_ip", "")
            )
            key = [
                values[0],
                values[2],
                values[3],
                "event",
                event_filter.type,
                event_filter.track,
                str(tracked),
            ]
            checkpoint_key = json.dumps(
                ["event", *key],
                ensure_ascii=False,
                separators=(",", ":"),
            )
            limits[checkpoint_key] = (event_filter.count, event_filter.seconds)
        return limits

    def _ordinary_terminal_headroom(
        self,
        row_kind: str,
        payload_bytes: int,
        values: tuple[str, str, int, int, str, str, str, str, str, str],
        final_line: str | None,
    ) -> int:
        """Bound deferred line, summary, checkpoint, and plan materialization."""

        checkpoint_count = len(self._filter_policy_limits(values)) if row_kind == "candidate" else 0
        rendered_bound = (
            len(_line_bytes(final_line)) if final_line is not None else payload_bytes
        ) + _PENDING_TERMINAL_BYTE_OVERHEAD
        return (5 + (2 * checkpoint_count)) * max(
            payload_bytes + _PENDING_TERMINAL_BYTE_OVERHEAD,
            rendered_bound,
        )

    @staticmethod
    def _policy_claim_columns(
        limits: dict[str, tuple[int, int]],
    ) -> tuple[
        str | None,
        int | None,
        int | None,
        str | None,
        int | None,
        int | None,
    ]:
        detection: tuple[str, int, int] | None = None
        event: tuple[str, int, int] | None = None
        for checkpoint_key, (count, seconds) in limits.items():
            decoded = json.loads(checkpoint_key)
            if type(decoded) is not list or not decoded:
                raise ExactPublicationError("Snort filter policy key lost its schema")
            retained = (checkpoint_key, count, seconds)
            if decoded[0] == "detection":
                detection = retained
            elif decoded[0] == "event":
                event = retained
            else:
                raise ExactPublicationError("Snort filter policy kind is invalid")
        return (
            *(detection or (None, None, None)),
            *(event or (None, None, None)),
        )

    def _validate_filter_policy_limits_unlocked(
        self,
        values: tuple[str, str, int, int, str, str, str, str, str, str],
    ) -> dict[str, tuple[int, int]]:
        """Reject a policy change before its candidate receives durable admission."""

        limits = self._filter_policy_limits(values)
        connection = self._spool_connection
        if connection is None:
            return limits
        for checkpoint_key, expected in limits.items():
            decoded_key = json.loads(checkpoint_key)
            if type(decoded_key) is not list or decoded_key[0] not in {"detection", "event"}:
                raise ExactPublicationError("Snort filter policy key lost its schema")
            kind = str(decoded_key[0])
            durable = connection.execute(
                "SELECT payload FROM filter_checkpoints WHERE checkpoint_key = ?",
                (checkpoint_key,),
            ).fetchone()
            if durable is not None:
                payload = json.loads(str(durable[0]))
                if type(payload) is not dict:
                    raise ExactPublicationError("Snort filter checkpoint lost its policy")
                retained = (payload.get("count"), payload.get("seconds"))
                if retained != expected:
                    raise ExactPublicationError(
                        "Snort filter policy changed after its durable checkpoint"
                    )
            if kind == "detection":
                pending = connection.execute(
                    """SELECT detection_count, detection_seconds FROM candidates
                    WHERE detection_key = ? AND exported = ? LIMIT ?""",
                    (checkpoint_key, 0, 1),
                ).fetchone()
            else:
                pending = connection.execute(
                    """SELECT event_count, event_seconds FROM candidates
                    WHERE event_key = ? AND exported = ? LIMIT ?""",
                    (checkpoint_key, 0, 1),
                ).fetchone()
            if pending is not None and (int(pending[0]), int(pending[1])) != expected:
                raise ExactPublicationError("Snort filter policy changed within a pending epoch")
        return limits

    def _commit_exact_row(
        self,
        key: ExactPublicationKey,
        digest: str,
        frozen: object,
    ) -> None:
        envelope = self._parse_exact_envelope(frozen)
        values = (
            envelope["sensor"],
            envelope["timestamp"],
            envelope["gid"],
            envelope["sid"],
            envelope["payload"],
            envelope["policy"],
            envelope["cluster_id"],
            envelope["occurrence_id"],
            envelope["observation_status"],
            envelope["origin"],
        )
        stable_key = _publication_key(key)
        retained_bytes = len(str(frozen).encode("utf-8"))
        terminal_headroom = (8 * retained_bytes) + _PENDING_TERMINAL_BYTE_OVERHEAD
        policy_limits = (
            self._filter_policy_limits(values) if envelope["row_kind"] == "candidate" else {}
        )
        policy_columns = self._policy_claim_columns(policy_limits)
        with self._spool_lock:
            retained = self._exact_candidate_receipts.get(key)
            if retained is not None:
                if retained != digest:
                    raise ExactPublicationError("Exact IDS row changed on retry")
                return
            reservation = self._exact_capacity_reservations.get(key)
            connection = self._open_spool()
            row = connection.execute(
                """SELECT publication_digest, row_kind, sensor, timestamp, gid, sid, payload,
                policy, cluster_id, occurrence_id, observation_status, origin, final_line,
                payload_bytes, terminal_headroom_bytes,
                detection_key, detection_count, detection_seconds,
                event_key, event_count, event_seconds
                FROM candidates WHERE publication_key = ?""",
                (stable_key,),
            ).fetchone()
            expected = (
                digest,
                envelope["row_kind"],
                *values,
                envelope["final_line"],
                retained_bytes,
                terminal_headroom,
                *policy_columns,
            )
            if row is not None:
                if row != expected:
                    raise ExactPublicationError("Exact IDS publication key changed content")
                receipt = connection.execute(
                    """SELECT publication_digest, retained_bytes, export_slot
                    FROM admission_receipts WHERE publication_key = ?""",
                    (stable_key,),
                ).fetchone()
                if receipt != (digest, 256, 1):
                    raise ExactPublicationError("Exact IDS row lost its admission receipt")
                self._exact_candidate_receipts[key] = digest
                self._promote_output_route_unlocked(
                    str(envelope["sensor"]),
                    key[:2],
                )
                self._consume_exact_capacity_reservation_unlocked(
                    key,
                    digest,
                    retained_bytes,
                )
                self._refresh_retained_census_unlocked()
                return
            if reservation != (digest, retained_bytes, terminal_headroom):
                raise ExactPublicationError("Exact IDS row lost its prepared journal capacity")
            if envelope["row_kind"] == "candidate":
                durable_limits = self._validate_filter_policy_limits_unlocked(values)
                if durable_limits != policy_limits:
                    raise ExactPublicationError("Exact IDS filter policy claim changed")
            self._insert_values_unlocked(
                envelope["row_kind"],
                values,
                stable_key,
                digest,
                final_line=envelope["final_line"],
                retained_bytes=retained_bytes,
                terminal_headroom=terminal_headroom,
                exact_key=key,
            )
            self._exact_candidate_receipts[key] = digest

    def _reserve_exact_publication_row(
        self,
        key: ExactPublicationKey,
        digest: str,
        retained_bytes: int,
    ) -> None:
        """Reserve exact spool capacity while the outer batch is still precanonical."""

        with self._spool_lock:
            retained = self._exact_capacity_reservations.get(key)
            terminal_headroom = self._preparing_exact_terminal_headroom
            sensor = self._preparing_exact_sensor
            policy_limits = self._preparing_exact_policy_limits
            if terminal_headroom is None or sensor is None or policy_limits is None:
                raise ExactPublicationError("Exact IDS row lost its terminal capacity estimate")
            if retained is not None:
                if retained != (digest, retained_bytes, terminal_headroom):
                    raise ExactPublicationError("Exact IDS prepared row changed")
                return
            participant_key = key[:2]
            prepared_limits = self._exact_prepared_policy_limits.get(participant_key, {})
            for checkpoint_key, expected in policy_limits.items():
                claimed = prepared_limits.get(checkpoint_key)
                if claimed is not None and claimed != expected:
                    raise ExactPublicationError(
                        "Snort filter policy changed within one exact publication"
                    )
            census = self.journal_census()
            state = self._state_unlocked()
            pending_rows = state.pending_rows * _PENDING_TERMINAL_ROW_HEADROOM
            self._prepare_output_route_unlocked(sensor, participant_key)
            provisional_sensors = set(
                self._exact_provisional_output_states.get(participant_key, {})
            )
            buffer_rows, buffer_bytes = self._buffer_plan_headroom(
                extra_baseline_bytes=self._exact_provisional_output_bytes.get(
                    participant_key,
                    0,
                )
            )
            charged_rows = 3 + _PENDING_TERMINAL_ROW_HEADROOM
            projected_rows = (
                census.retained_rows
                + pending_rows
                + census.reserved_rows
                + buffer_rows
                + charged_rows
            )
            if projected_rows > self._journal_row_capacity:
                raise ExactPublicationError("Snort journal row capacity is exhausted")
            charged_bytes = retained_bytes + terminal_headroom + 512
            projected_bytes = (
                census.retained_bytes
                + state.terminal_headroom_bytes
                + census.reserved_bytes
                + buffer_bytes
                + charged_bytes
            )
            if projected_bytes > self._journal_byte_capacity:
                raise ExactPublicationError("Snort journal byte capacity is exhausted")
            self._exact_capacity_reservations[key] = (
                digest,
                retained_bytes,
                terminal_headroom,
            )
            self._exact_provisional_sensors[participant_key] = provisional_sensors
            if policy_limits:
                prepared_limits = dict(prepared_limits)
                prepared_limits.update(policy_limits)
                self._exact_prepared_policy_limits[participant_key] = prepared_limits
            self._exact_reserved_rows += charged_rows
            self._exact_reserved_bytes += charged_bytes
            self._retained_high_water_rows = max(
                self._retained_high_water_rows,
                projected_rows,
            )
            self._retained_high_water_bytes = max(
                self._retained_high_water_bytes,
                projected_bytes,
            )

    def _consume_exact_capacity_reservation_unlocked(
        self,
        key: ExactPublicationKey,
        digest: str,
        retained_bytes: int,
    ) -> None:
        reservation = self._exact_capacity_reservations.pop(key, None)
        if reservation is None:
            return
        if reservation[:2] != (digest, retained_bytes):
            raise ExactPublicationError("Exact IDS capacity reservation changed")
        terminal_headroom = reservation[2]
        self._exact_reserved_rows -= 3 + _PENDING_TERMINAL_ROW_HEADROOM
        self._exact_reserved_bytes -= retained_bytes + terminal_headroom + 512

    def _clear_exact_capacity_reservations_unlocked(
        self,
        participant_key: tuple[str, int],
    ) -> None:
        keys = [key for key in self._exact_capacity_reservations if key[:2] == participant_key]
        for key in keys:
            _digest, retained_bytes, terminal_headroom = self._exact_capacity_reservations.pop(key)
            self._exact_reserved_rows -= 3 + _PENDING_TERMINAL_ROW_HEADROOM
            self._exact_reserved_bytes -= retained_bytes + terminal_headroom + 512
        self._exact_provisional_sensors.pop(participant_key, None)
        self._exact_provisional_output_states.pop(participant_key, None)
        self._exact_provisional_output_owners.pop(participant_key, None)
        self._exact_provisional_output_bytes.pop(participant_key, None)
        self._exact_prepared_policy_limits.pop(participant_key, None)

    def _complete_exact_publication_batch(self, key: tuple[str, int]) -> None:
        with self._spool_lock:
            self._clear_exact_capacity_reservations_unlocked(key)
        super()._complete_exact_publication_batch(key)

    def _abort_exact_publication_batch(self, key: tuple[str, int]) -> None:
        with self._spool_lock:
            self._clear_exact_capacity_reservations_unlocked(key)
        super()._abort_exact_publication_batch(key)

    def _release_exact_candidate(self, key: ExactPublicationKey) -> None:
        """Drop durable receipts and collect an already-exported exact row."""

        with self._spool_lock:
            connection = self._spool_connection
            if connection is None:
                if self._terminal_cleanup_pending or self._journal_cleanup_pending:
                    self._cleanup_journal_unlocked()
                    self._terminal_cleanup_pending = False
                self._exact_candidate_receipts.pop(key, None)
                return
            stable_key = _publication_key(key)
            admission = connection.execute(
                """SELECT retained_bytes, export_slot FROM admission_receipts
                WHERE publication_key = ?""",
                (stable_key,),
            ).fetchone()
            exported = connection.execute(
                """SELECT retained_bytes FROM export_receipts
                WHERE publication_key = ?""",
                (stable_key,),
            ).fetchone()
            retained_row = connection.execute(
                """SELECT exported, summarized, payload_bytes, released,
                terminal_headroom_bytes FROM candidates
                WHERE publication_key = ?""",
                (stable_key,),
            ).fetchone()
            delete_exported_row = bool(
                retained_row is not None and int(retained_row[0]) and int(retained_row[1])
            )
            admission_bytes = int(admission[0]) if admission is not None else 0
            export_slot = int(admission[1]) if admission is not None else 0
            export_slot_bytes = admission_bytes if export_slot else 0
            export_bytes = int(exported[0]) if exported is not None else 0
            deleted_bytes = int(retained_row[2]) if delete_exported_row else 0
            deleted_headroom = int(retained_row[4]) if delete_exported_row else 0
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "DELETE FROM admission_receipts WHERE publication_key = ?",
                    (stable_key,),
                )
                connection.execute(
                    "DELETE FROM export_receipts WHERE publication_key = ?",
                    (stable_key,),
                )
                if delete_exported_row:
                    connection.execute(
                        "DELETE FROM candidates WHERE publication_key = ?",
                        (stable_key,),
                    )
                elif retained_row is not None:
                    connection.execute(
                        "UPDATE candidates SET released = ? WHERE publication_key = ?",
                        (1, stable_key),
                    )
                connection.execute(
                    """UPDATE spool_state SET
                    exported_rows = exported_rows - ?,
                    exported_bytes = exported_bytes - ?,
                    terminal_headroom_bytes = terminal_headroom_bytes - ?,
                    admission_receipts = admission_receipts - ?,
                    admission_bytes = admission_bytes - ?,
                    export_slots = export_slots - ?,
                    export_slot_bytes = export_slot_bytes - ?,
                    export_receipts = export_receipts - ?,
                    export_bytes = export_bytes - ?
                    WHERE singleton = ?""",
                    (
                        int(delete_exported_row),
                        deleted_bytes,
                        deleted_headroom,
                        int(admission is not None),
                        admission_bytes,
                        export_slot,
                        export_slot_bytes,
                        int(exported is not None),
                        export_bytes,
                        1,
                    ),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
            self._refresh_retained_census_unlocked()
            terminal_release = (
                self._terminal_cleanup_pending or self._close_state == "closed"
            ) and self._state_unlocked().retained_rows == 0
            if terminal_release:
                self._terminal_cleanup_pending = True
                self._cleanup_journal_unlocked()
                self._terminal_cleanup_pending = False
            self._exact_candidate_receipts.pop(key, None)

    def _output_path_for_sensor(self, sensor: str) -> Path:
        if sensor == "__direct__":
            if self._direct_file_path is None:
                raise ExactPublicationError("Snort direct route has no direct output file")
            writer_key = ""
        else:
            writer_key = self._safe_writer_key(sensor)
            if not writer_key or writer_key != sensor:
                raise ExactPublicationError("Snort sensor route is not one canonical component")
        base = _lexical_absolute(self._base_dir)
        output_path = _lexical_absolute(self._writer_path_for_key(writer_key))
        try:
            output_path.relative_to(base)
        except ValueError as error:
            raise ExactPublicationError("Snort output route escaped its public root") from error
        return output_path

    def _inspect_output_route_unlocked(
        self,
        sensor: str,
        *,
        include_payload: bool = False,
    ) -> tuple[_OutputRouteState, bytes | None, str]:
        """Return one descriptor-authenticated physical output snapshot."""

        output_path = self._output_path_for_sensor(sensor)
        directory_descriptor = _open_directory_nofollow(output_path.parent, create=True)
        try:
            name_max, _path_max = _directory_path_limits(directory_descriptor)
            _validate_component_capacity(
                output_path.name,
                name_max,
                label="public output",
            )
            _validate_component_capacity(
                f".{output_path.name}.{'0' * 32}.tmp",
                name_max,
                label="private export",
            )
            parent = os.fstat(directory_descriptor)
            parent_identity = (int(parent.st_dev), int(parent.st_ino))
            retained = self._output_route_states.get(sensor)
            if retained is not None and retained.parent_identity != parent_identity:
                raise ExactPublicationError("Snort output parent identity changed")
            metadata = _safe_file_metadata(
                directory_descriptor,
                output_path.name,
                label="output",
            )
            if metadata is None:
                state = _OutputRouteState(sensor, output_path, parent_identity, None, 0)
                return state, b"" if include_payload else None, _sha256(b"")
            descriptor = _open_regular_nofollow(
                directory_descriptor,
                output_path.name,
                os.O_RDONLY,
            )
            try:
                opened = os.fstat(descriptor)
                sealed = (
                    int(metadata.st_dev),
                    int(metadata.st_ino),
                    int(metadata.st_size),
                )
                if sealed != (
                    int(opened.st_dev),
                    int(opened.st_ino),
                    int(opened.st_size),
                ):
                    raise ExactPublicationError("Snort output identity changed while opening")
                if int(opened.st_size):
                    os.lseek(descriptor, -1, os.SEEK_END)
                    if os.read(descriptor, 1) != b"\n":
                        raise ExactPublicationError(
                            "Snort output baseline is not newline terminated"
                        )
                payload = (
                    _read_descriptor_exact(descriptor, int(opened.st_size))
                    if include_payload
                    else None
                )
                digest = _sha256(payload) if payload is not None else ""
                current = _safe_file_metadata(
                    directory_descriptor,
                    output_path.name,
                    label="output",
                )
                if (
                    current is None
                    or (
                        int(current.st_dev),
                        int(current.st_ino),
                        int(current.st_size),
                    )
                    != sealed
                ):
                    raise ExactPublicationError("Snort output changed during its snapshot")
                state = _OutputRouteState(
                    sensor,
                    output_path,
                    parent_identity,
                    (int(opened.st_dev), int(opened.st_ino)),
                    int(opened.st_size),
                )
                return state, payload, digest
            finally:
                os.close(descriptor)
        finally:
            os.close(directory_descriptor)

    @staticmethod
    def _claim_output_state(
        state: _OutputRouteState,
        owners: dict[tuple[object, ...], str],
    ) -> None:
        for token in state.owner_tokens:
            retained = owners.get(token)
            if retained is not None and retained != state.sensor:
                raise ExactPublicationError("Snort sensors resolved to one physical output")
            owners[token] = state.sensor

    def _replace_output_route_states_unlocked(
        self,
        states: dict[str, _OutputRouteState],
    ) -> None:
        owners: dict[tuple[object, ...], str] = {}
        for state in states.values():
            self._claim_output_state(state, owners)
        self._output_route_states = states
        self._output_owner_sensors = owners
        self._output_baseline_bytes = sum(state.size for state in states.values())
        self._output_routes_initialized = True

    def _initialize_output_routes_unlocked(self) -> None:
        if self._output_routes_initialized:
            return
        sensors = set(self._known_output_sensors)
        if self._direct_file_path:
            sensors.add("__direct__")
        states = {
            sensor: self._inspect_output_route_unlocked(sensor)[0] for sensor in sorted(sensors)
        }
        self._replace_output_route_states_unlocked(states)

    def _prepare_output_route_unlocked(
        self,
        sensor: str,
        participant_key: tuple[str, int] | None,
    ) -> _OutputRouteState:
        """Inspect one new route once and retain a participant-local claim."""

        self._initialize_output_routes_unlocked()
        retained = self._output_route_states.get(sensor)
        if retained is not None:
            return retained
        if participant_key is not None:
            provisional = self._exact_provisional_output_states.setdefault(participant_key, {})
            retained = provisional.get(sensor)
            if retained is not None:
                return retained
        state = self._inspect_output_route_unlocked(sensor)[0]
        owners = dict(self._output_owner_sensors)
        if participant_key is not None:
            participant_owners = self._exact_provisional_output_owners.setdefault(
                participant_key,
                {},
            )
            for token in state.owner_tokens:
                retained_sensor = participant_owners.get(token)
                if retained_sensor is not None and retained_sensor != sensor:
                    raise ExactPublicationError(
                        "Snort exact routes resolved to one physical output"
                    )
            self._claim_output_state(state, owners)
            for token in state.owner_tokens:
                participant_owners[token] = sensor
            self._exact_provisional_output_states[participant_key][sensor] = state
            self._exact_provisional_output_bytes[participant_key] = (
                self._exact_provisional_output_bytes.get(participant_key, 0) + state.size
            )
        else:
            self._claim_output_state(state, owners)
        return state

    def _promote_output_route_unlocked(
        self,
        sensor: str,
        participant_key: tuple[str, int] | None,
        fallback: _OutputRouteState | None = None,
    ) -> None:
        state = fallback
        if participant_key is not None:
            state = self._exact_provisional_output_states.get(participant_key, {}).get(
                sensor, state
            )
        if sensor in self._output_route_states:
            self._discard_provisional_output_sensor_unlocked(participant_key, sensor, state)
            return
        if state is None:
            state = self._inspect_output_route_unlocked(sensor)[0]
        owners = dict(self._output_owner_sensors)
        self._claim_output_state(state, owners)
        self._output_route_states[sensor] = state
        self._output_owner_sensors = owners
        self._output_baseline_bytes += state.size
        self._known_output_sensors.add(sensor)
        self._discard_provisional_output_sensor_unlocked(participant_key, sensor, state)

    def _discard_provisional_output_sensor_unlocked(
        self,
        participant_key: tuple[str, int] | None,
        sensor: str,
        state: _OutputRouteState | None,
    ) -> None:
        if participant_key is None:
            return
        states = self._exact_provisional_output_states.get(participant_key)
        removed = states.pop(sensor, None) if states is not None else None
        retained = removed or state
        if removed is not None:
            self._exact_provisional_output_bytes[participant_key] = max(
                0,
                self._exact_provisional_output_bytes.get(participant_key, 0) - removed.size,
            )
        owners = self._exact_provisional_output_owners.get(participant_key)
        if owners is not None and retained is not None:
            for token in retained.owner_tokens:
                if owners.get(token) == sensor:
                    owners.pop(token, None)

    def _refresh_output_route_unlocked(self, state: _OutputRouteState) -> None:
        old = self._output_route_states.get(state.sensor)
        states = dict(self._output_route_states)
        states[state.sensor] = state
        self._replace_output_route_states_unlocked(states)
        if old is None:
            self._known_output_sensors.add(state.sensor)

    def _state_unlocked(self) -> _SnortJournalState:
        connection = self._spool_connection
        if connection is None:
            return _SnortJournalState(
                summary_rows=self._unpersisted_summary_rows,
                summary_bytes=self._unpersisted_summary_bytes,
                total_events=self._retained_total_events,
                high_water_rows=self._retained_high_water_rows,
                high_water_bytes=self._retained_high_water_bytes,
            )
        row = connection.execute(
            """SELECT pending_rows, pending_bytes, exported_rows, exported_bytes,
            admission_receipts, admission_bytes, export_slots, export_slot_bytes,
            export_receipts, export_bytes,
            summary_rows, summary_bytes, filter_rows, filter_bytes,
            terminal_headroom_bytes, plan_rows, plan_bytes, total_events,
            high_water_rows, high_water_bytes
            FROM spool_state WHERE singleton = ?""",
            (1,),
        ).fetchone()
        if row is None:
            raise RuntimeError("Snort journal lost its bounded census")
        state = _SnortJournalState(*map(int, row))
        return _SnortJournalState(
            **{
                **asdict(state),
                "high_water_rows": max(
                    state.high_water_rows,
                    self._retained_high_water_rows,
                ),
                "high_water_bytes": max(
                    state.high_water_bytes,
                    self._retained_high_water_bytes,
                ),
            }
        )

    def _refresh_retained_census_unlocked(self) -> None:
        state = self._state_unlocked()
        self._retained_total_events = state.total_events
        self._retained_high_water_rows = max(
            self._retained_high_water_rows,
            state.high_water_rows,
        )
        self._retained_high_water_bytes = max(
            self._retained_high_water_bytes,
            state.high_water_bytes,
        )

    def _insert_values_unlocked(
        self,
        row_kind: str,
        values: tuple[str, str, int, int, str, str, str, str, str, str],
        publication_key: str | None,
        publication_digest: str | None,
        *,
        final_line: str | None = None,
        retained_bytes: int | None = None,
        terminal_headroom: int | None = None,
        exact_key: ExactPublicationKey | None = None,
        released: bool = False,
    ) -> int:
        connection = self._spool_connection
        state = self._state_unlocked()
        payload_bytes = (
            retained_bytes
            if retained_bytes is not None
            else len(repr((*values, final_line)).encode("utf-8"))
        )
        receipt_bytes = 256 if exact_key is not None else 0
        reservation: tuple[str, int, int] | None = None
        participant_key = exact_key[:2] if exact_key is not None else None
        output_state = self._prepare_output_route_unlocked(values[0], participant_key)
        policy_limits: dict[str, tuple[int, int]] = {}
        if exact_key is not None:
            connection = self._open_spool()
            state = self._state_unlocked()
            reservation = self._exact_capacity_reservations.get(exact_key)
            if reservation is None or reservation[0] != publication_digest:
                raise ExactPublicationError("Exact IDS row lost its prepared journal capacity")
            if reservation[1] != payload_bytes:
                raise ExactPublicationError("Exact IDS retained-byte reservation changed")
            if terminal_headroom is None or reservation[2] != terminal_headroom:
                raise ExactPublicationError("Exact IDS terminal reservation changed")
            if row_kind == "candidate":
                policy_limits = self._validate_filter_policy_limits_unlocked(values)
        else:
            if row_kind == "candidate":
                policy_limits = self._validate_filter_policy_limits_unlocked(values)
            terminal_headroom = self._ordinary_terminal_headroom(
                row_kind,
                payload_bytes,
                values,
                final_line,
            )
            census = self.journal_census()
            pending_rows = state.pending_rows * _PENDING_TERMINAL_ROW_HEADROOM
            extra_baseline_bytes = (
                0 if values[0] in self._output_route_states else output_state.size
            )
            buffer_rows, buffer_bytes = self._buffer_plan_headroom(
                extra_baseline_bytes=extra_baseline_bytes
            )
            charged_rows = 1 + _PENDING_TERMINAL_ROW_HEADROOM
            projected_rows = (
                census.retained_rows
                + pending_rows
                + census.reserved_rows
                + buffer_rows
                + charged_rows
            )
            if projected_rows > self._journal_row_capacity:
                raise ExactPublicationError("Snort journal row capacity is exhausted")
            if payload_bytes > self._journal_byte_capacity:
                raise ExactPublicationError("Snort journal byte capacity is exhausted")
            projected_bytes = (
                census.retained_bytes
                + state.terminal_headroom_bytes
                + census.reserved_bytes
                + buffer_bytes
                + payload_bytes
                + terminal_headroom
            )
            if projected_bytes > self._journal_byte_capacity:
                raise ExactPublicationError("Snort journal byte capacity is exhausted")
            connection = self._open_spool()
        if connection is None:  # pragma: no cover - open either returns or raises
            raise RuntimeError("Snort journal did not open for admission")
        if terminal_headroom is None:
            raise ExactPublicationError("Snort journal lost terminal capacity headroom")
        policy_columns = self._policy_claim_columns(policy_limits)
        next_rows = state.pending_rows + 1
        next_bytes = state.pending_bytes + payload_bytes
        next_terminal_headroom = state.terminal_headroom_bytes + terminal_headroom
        next_admissions = state.admission_receipts + int(exact_key is not None)
        next_admission_bytes = state.admission_bytes + receipt_bytes
        next_export_slots = state.export_slots + int(exact_key is not None)
        next_export_slot_bytes = state.export_slot_bytes + receipt_bytes
        retained_rows = state.retained_rows + 1 + (2 * int(exact_key is not None))
        retained_bytes_total = (
            state.retained_bytes + payload_bytes + (2 * receipt_bytes) + next_terminal_headroom
        )
        if exact_key is None:
            retained_rows = projected_rows
            retained_bytes_total = projected_bytes
        retained_rows = max(retained_rows, self._retained_high_water_rows)
        retained_bytes_total = max(retained_bytes_total, self._retained_high_water_bytes)
        pending_raw_rows = 0
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO candidates
                (publication_key, publication_digest, row_kind, sensor, timestamp, gid, sid,
                 payload, policy, cluster_id, occurrence_id, observation_status, origin,
                 final_line, payload_bytes, terminal_headroom_bytes,
                 detection_key, detection_count, detection_seconds,
                 event_key, event_count, event_seconds, admitted, released)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    publication_key,
                    publication_digest,
                    row_kind,
                    *values,
                    final_line,
                    payload_bytes,
                    terminal_headroom,
                    *policy_columns,
                    1 if row_kind == "raw" else None,
                    int(released),
                ),
            )
            if row_kind == "raw":
                pending_raw = connection.execute(
                    """INSERT INTO raw_sensor_state (sensor, pending_rows)
                    VALUES (?, ?)
                    ON CONFLICT(sensor) DO UPDATE SET pending_rows = pending_rows + ?
                    RETURNING pending_rows""",
                    (values[0], 1, 1),
                ).fetchone()
                if pending_raw is None:
                    raise RuntimeError("Snort journal lost its raw sensor census")
                pending_raw_rows = int(pending_raw[0])
            if exact_key is not None:
                connection.execute(
                    """INSERT INTO admission_receipts
                    (publication_key, publication_digest, retained_bytes, export_slot)
                    VALUES (?, ?, ?, ?)""",
                    (publication_key, publication_digest, receipt_bytes, 1),
                )
            connection.execute(
                """UPDATE spool_state SET
                pending_rows = ?, pending_bytes = ?,
                terminal_headroom_bytes = ?,
                admission_receipts = ?, admission_bytes = ?,
                export_slots = ?, export_slot_bytes = ?,
                total_events = total_events + 1,
                high_water_rows = MAX(high_water_rows, ?),
                high_water_bytes = MAX(high_water_bytes, ?)
                WHERE singleton = 1""",
                (
                    next_rows,
                    next_bytes,
                    next_terminal_headroom,
                    next_admissions,
                    next_admission_bytes,
                    next_export_slots,
                    next_export_slot_bytes,
                    retained_rows,
                    retained_bytes_total,
                ),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            durable_sensor = connection.execute(
                "SELECT 1 FROM candidates WHERE sensor = ? LIMIT ?",
                (values[0], 1),
            ).fetchone()
            if durable_sensor is not None:
                self._promote_output_route_unlocked(
                    values[0],
                    participant_key,
                    output_state,
                )
            raise
        self._promote_output_route_unlocked(values[0], participant_key, output_state)
        if exact_key is not None and reservation is not None:
            self._consume_exact_capacity_reservation_unlocked(
                exact_key,
                str(publication_digest),
                reservation[1],
            )
        self._refresh_retained_census_unlocked()
        return pending_raw_rows

    @staticmethod
    def _policy_from_json(value: str) -> IdsAlertPolicyContext | None:
        data = json.loads(value)
        if data is None:
            return None
        detection = data.get("detection_filter")
        event_filter = data.get("event_filter")
        return IdsAlertPolicyContext(
            detection_filter=(
                IdsDetectionFilterContext(**detection) if detection is not None else None
            ),
            event_filter=(
                IdsEventFilterContext(**event_filter) if event_filter is not None else None
            ),
        )

    @staticmethod
    def _summary_policy(policy: IdsAlertPolicyContext | None) -> str | dict[str, Any]:
        return "every" if policy is None else asdict(policy)

    @staticmethod
    def _evaluation_signature_in(
        summaries: dict[str, dict[str, dict[str, Any]]],
        sensor: str,
        gid: int,
        sid: int,
    ) -> dict[str, Any]:
        signatures = summaries.setdefault(sensor, {})
        return signatures.setdefault(
            f"{gid}:{sid}",
            {
                "gid": gid,
                "sid": sid,
                "candidate": 0,
                "emitted": 0,
                "policy_filtered": 0,
                "emitted_visible": 0,
                "emitted_delayed": 0,
                "origins": {},
                "_digest": new_ids_digest(),
            },
        )

    @staticmethod
    def _record_evaluation_in(
        summaries: dict[str, dict[str, dict[str, Any]]],
        sensor: str,
        payload: dict[str, Any],
        *,
        origin: str,
        observation_status: str,
    ) -> None:
        summary = SnortEmitter._evaluation_signature_in(
            summaries,
            sensor,
            int(payload.get("gid", 1)),
            int(payload["sid"]),
        )
        summary["emitted"] += 1
        status_key = "emitted_delayed" if observation_status == "delayed" else "emitted_visible"
        summary[status_key] += 1
        origins = summary["origins"]
        origins[origin] = origins.get(origin, 0) + 1
        update_ids_digest(summary["_digest"], sensor, payload)

    @staticmethod
    def _summary_records(
        alert_summary: dict[str, dict[int, dict[str, Any]]],
        evaluation_summary: dict[str, dict[str, dict[str, Any]]],
    ) -> list[tuple[str, str, int]]:
        records: list[tuple[str, str, int]] = []
        for cluster_id, signatures in sorted(alert_summary.items()):
            for sid, summary in sorted(signatures.items()):
                payload = json.dumps(summary, separators=(",", ":"), sort_keys=True)
                summary_key = f"alert:{cluster_id}:{sid}"
                retained_bytes = len(summary_key.encode()) + len(payload.encode()) + 128
                records.append((summary_key, payload, retained_bytes))
        for sensor, signatures in sorted(evaluation_summary.items()):
            for key, summary in sorted(signatures.items()):
                payload_data = {name: value for name, value in summary.items() if name != "_digest"}
                payload_data["emitted_sha256"] = summary["_digest"].hexdigest()
                payload = json.dumps(payload_data, separators=(",", ":"), sort_keys=True)
                summary_key = f"evaluation:{sensor}:{key}"
                retained_bytes = len(summary_key.encode()) + len(payload.encode()) + 128
                records.append((summary_key, payload, retained_bytes))
        return records

    def _install_summary_snapshot_unlocked(
        self,
        alert_summary: dict[str, dict[int, dict[str, Any]]],
        evaluation_summary: dict[str, dict[str, dict[str, Any]]],
    ) -> None:
        """Install one durable public summary snapshot exactly once."""

        self._ids_alert_summary = alert_summary
        self._ids_evaluation_summary = evaluation_summary
        self._emitted_event_count = sum(
            int(summary["emitted"])
            for signatures in evaluation_summary.values()
            for summary in signatures.values()
        )

    def _reconcile_pending_summary_unlocked(self) -> bool:
        """Recover a summary commit whose durable return may have been lost."""

        snapshot = self._pending_summary_snapshot
        connection = self._spool_connection
        if snapshot is None or connection is None:
            return False
        durable = [
            (str(key), str(payload), int(retained_bytes))
            for key, payload, retained_bytes in connection.execute(
                """SELECT summary_key, payload, retained_bytes
                FROM summaries ORDER BY summary_key"""
            ).fetchall()
        ]
        expected = sorted(snapshot.records)
        if durable != expected:
            return False
        durable_filters = [
            (str(key), str(kind), str(payload), int(retained_bytes))
            for key, kind, payload, retained_bytes in connection.execute(
                """SELECT checkpoint_key, checkpoint_kind, payload, retained_bytes
                FROM filter_checkpoints ORDER BY checkpoint_key"""
            ).fetchall()
        ]
        if durable_filters != sorted(snapshot.filter_records):
            return False
        watermark = connection.execute(
            "SELECT filter_watermark FROM spool_state WHERE singleton = ?",
            (1,),
        ).fetchone()
        if watermark is None or str(watermark[0]) != snapshot.filter_watermark:
            return False
        for sequence, admitted, final_line in snapshot.decisions:
            decision = connection.execute(
                """SELECT admitted, final_line, terminal_headroom_bytes
                FROM candidates WHERE sequence = ?""",
                (sequence,),
            ).fetchone()
            if decision is None or decision != (admitted, final_line, 0):
                return False
        if snapshot.scope == "raw":
            unsummarized = connection.execute(
                """SELECT 1 FROM candidates
                WHERE summarized = ? AND row_kind = ? LIMIT ?""",
                (0, "raw", 1),
            ).fetchone()
        elif snapshot.scope == "all":
            unsummarized = connection.execute(
                "SELECT 1 FROM candidates WHERE summarized = ? LIMIT ?",
                (0, 1),
            ).fetchone()
        else:
            unsummarized = None
        if unsummarized is not None:
            return False
        summarized_headroom = connection.execute(
            """SELECT 1 FROM candidates
            WHERE summarized = ? AND terminal_headroom_bytes != ? LIMIT ?""",
            (1, 0, 1),
        ).fetchone()
        if summarized_headroom is not None:
            return False
        self._install_summary_snapshot_unlocked(
            snapshot.alert_summary,
            snapshot.evaluation_summary,
        )
        self._pending_summary_snapshot = None
        return True

    def _persist_summaries_unlocked(
        self,
        alert_summary: dict[str, dict[int, dict[str, Any]]],
        evaluation_summary: dict[str, dict[str, dict[str, Any]]],
    ) -> None:
        connection = self._spool_connection
        if connection is None:
            return
        records = self._summary_records(alert_summary, evaluation_summary)
        summary_bytes = sum(record[2] for record in records)
        filter_records = list(self._summary_filter_records)
        filter_bytes = sum(record[3] for record in filter_records)
        if self._summary_scope == "raw":
            headroom_row = connection.execute(
                """SELECT COALESCE(SUM(terminal_headroom_bytes), 0)
                FROM candidates WHERE summarized = ? AND row_kind = ?""",
                (0, "raw"),
            ).fetchone()
        elif self._summary_scope == "all":
            headroom_row = connection.execute(
                """SELECT COALESCE(SUM(terminal_headroom_bytes), 0)
                FROM candidates WHERE summarized = ?""",
                (0,),
            ).fetchone()
        else:
            raise RuntimeError("Snort summary scope is not active")
        selected_headroom = int(headroom_row[0]) if headroom_row is not None else 0
        decision_updates: list[tuple[int, str | None, int, int]] = []
        materialized_line_bytes = 0
        for sequence, admitted, final_line in self._summary_decisions:
            existing = connection.execute(
                "SELECT final_line FROM candidates WHERE sequence = ?",
                (sequence,),
            ).fetchone()
            if existing is None:
                raise ExactPublicationError("Snort summary lost its candidate row")
            current_line = existing[0]
            if current_line is not None and final_line is not None and current_line != final_line:
                raise ExactPublicationError("Snort candidate final line changed during summary")
            added_bytes = (
                len(final_line.encode("utf-8"))
                if current_line is None and final_line is not None
                else 0
            )
            materialized_line_bytes += added_bytes
            decision_updates.append((admitted, final_line, added_bytes, sequence))
        state = self._state_unlocked()
        prospective_rows = (
            state.retained_rows
            - state.summary_rows
            - state.filter_rows
            + len(records)
            + len(filter_records)
        )
        prospective_bytes = (
            state.retained_bytes
            - state.summary_bytes
            - state.filter_bytes
            + summary_bytes
            + filter_bytes
            + materialized_line_bytes
        )
        remaining_headroom = state.terminal_headroom_bytes - selected_headroom
        if remaining_headroom < 0:
            raise ExactPublicationError("Snort journal terminal headroom became inconsistent")
        if prospective_rows > self._journal_row_capacity:
            raise ExactPublicationError("Snort journal row capacity is exhausted")
        if prospective_bytes + remaining_headroom > self._journal_byte_capacity:
            raise ExactPublicationError("Snort journal byte capacity is exhausted")
        snapshot = _PendingSummarySnapshot(
            records=records,
            alert_summary=deepcopy(alert_summary),
            evaluation_summary=self._copy_evaluation_summaries(evaluation_summary),
            scope=self._summary_scope,
            decisions=list(self._summary_decisions),
            filter_records=filter_records,
            filter_watermark=self._summary_filter_watermark,
        )
        self._pending_summary_snapshot = snapshot
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM summaries")
            connection.executemany(
                """INSERT INTO summaries (summary_key, payload, retained_bytes)
                VALUES (?, ?, ?)""",
                records,
            )
            connection.execute("DELETE FROM filter_checkpoints")
            connection.executemany(
                """INSERT INTO filter_checkpoints
                (checkpoint_key, checkpoint_kind, payload, retained_bytes)
                VALUES (?, ?, ?, ?)""",
                filter_records,
            )
            connection.executemany(
                """UPDATE candidates SET admitted = ?,
                final_line = COALESCE(?, final_line),
                payload_bytes = payload_bytes + ?
                WHERE sequence = ? AND summarized = ?""",
                [
                    (admitted, final_line, added_bytes, sequence, 0)
                    for admitted, final_line, added_bytes, sequence in decision_updates
                ],
            )
            if self._summary_scope == "raw":
                connection.execute(
                    """UPDATE candidates SET summarized = ?, terminal_headroom_bytes = ?
                    WHERE summarized = ? AND row_kind = ?""",
                    (1, 0, 0, "raw"),
                )
            elif self._summary_scope == "all":
                connection.execute(
                    """UPDATE candidates SET summarized = ?, terminal_headroom_bytes = ?
                    WHERE summarized = ?""",
                    (1, 0, 0),
                )
            connection.execute(
                """UPDATE spool_state SET
                pending_bytes = pending_bytes + ?,
                terminal_headroom_bytes = ?,
                summary_rows = ?, summary_bytes = ?,
                filter_rows = ?, filter_bytes = ?, filter_watermark = ?,
                high_water_rows = MAX(high_water_rows, ?),
                high_water_bytes = MAX(high_water_bytes, ?)
                WHERE singleton = ?""",
                (
                    materialized_line_bytes,
                    remaining_headroom,
                    len(records),
                    summary_bytes,
                    len(filter_records),
                    filter_bytes,
                    self._summary_filter_watermark,
                    prospective_rows,
                    prospective_bytes + remaining_headroom,
                    1,
                ),
            )
            connection.commit()
        except BaseException:
            try:
                connection.rollback()
            finally:
                self._reconcile_pending_summary_unlocked()
            raise
        if not self._reconcile_pending_summary_unlocked():
            raise ExactPublicationError("Snort summary commit was not durable")

    @staticmethod
    def _copy_evaluation_summaries(
        summaries: dict[str, dict[str, dict[str, Any]]],
    ) -> dict[str, dict[str, dict[str, Any]]]:
        copied: dict[str, dict[str, dict[str, Any]]] = {}
        for sensor, signatures in summaries.items():
            copied[sensor] = {}
            for key, summary in signatures.items():
                retained = dict(summary)
                retained["origins"] = dict(summary["origins"])
                retained["_digest"] = summary["_digest"].copy()
                copied[sensor][key] = retained
        return copied

    def _load_filter_checkpoint_unlocked(
        self,
    ) -> tuple[
        IdsAlertFilterEngine,
        dict[tuple[object, ...], tuple[int, int]],
        dict[tuple[object, ...], tuple[int, int]],
    ]:
        """Restore the bounded durable IDS filter state for the next epoch."""

        engine = IdsAlertFilterEngine()
        detection_limits: dict[tuple[object, ...], tuple[int, int]] = {}
        event_limits: dict[tuple[object, ...], tuple[int, int]] = {}
        connection = self._spool_connection
        if connection is None:
            return engine, detection_limits, event_limits
        for checkpoint_key, checkpoint_kind, payload_json in connection.execute(
            """SELECT checkpoint_key, checkpoint_kind, payload
            FROM filter_checkpoints ORDER BY checkpoint_key"""
        ):
            try:
                payload = json.loads(str(payload_json))
            except json.JSONDecodeError as error:
                raise ExactPublicationError("Snort filter checkpoint is not valid JSON") from error
            if type(payload) is not dict or type(payload.get("key")) is not list:
                raise ExactPublicationError("Snort filter checkpoint lost its schema")
            key = tuple(payload["key"])
            canonical_key = json.dumps(
                [str(checkpoint_kind), *key],
                ensure_ascii=False,
                separators=(",", ":"),
            )
            if canonical_key != str(checkpoint_key):
                raise ExactPublicationError("Snort filter checkpoint key changed")
            count = payload.get("count")
            seconds = payload.get("seconds")
            if type(count) is not int or count <= 0 or type(seconds) is not int or seconds <= 0:
                raise ExactPublicationError("Snort filter checkpoint count is invalid")
            if checkpoint_kind == "detection":
                timestamps = payload.get("timestamps")
                if type(timestamps) is not list or not all(
                    type(timestamp) is str for timestamp in timestamps
                ):
                    raise ExactPublicationError("Snort detection checkpoint lost timestamps")
                engine._detection_windows[key] = deque(
                    datetime.fromisoformat(timestamp) for timestamp in timestamps
                )
                detection_limits[key] = (count, seconds)
            elif checkpoint_kind == "event":
                start = payload.get("start")
                matches = payload.get("matches")
                emitted = payload.get("emitted")
                if (
                    type(start) is not str
                    or type(matches) is not int
                    or matches < 0
                    or type(emitted) is not bool
                ):
                    raise ExactPublicationError("Snort event checkpoint lost its state")
                engine._event_windows[key] = _SnortCheckpointEventWindow(
                    start=datetime.fromisoformat(start),
                    matches=matches,
                    emitted=emitted,
                )
                event_limits[key] = (count, seconds)
            else:
                raise ExactPublicationError("Snort filter checkpoint kind is invalid")
        return engine, detection_limits, event_limits

    @staticmethod
    def _filter_checkpoint_records(
        engine: IdsAlertFilterEngine,
        detection_limits: dict[tuple[object, ...], tuple[int, int]],
        event_limits: dict[tuple[object, ...], tuple[int, int]],
        watermark: datetime | None,
    ) -> list[tuple[str, str, str, int]]:
        """Serialize only bounded window state required for later filter decisions."""

        records: list[tuple[str, str, str, int]] = []
        for key, timestamps in sorted(engine._detection_windows.items(), key=lambda item: item[0]):
            limit = detection_limits.get(key)
            if limit is None:
                raise ExactPublicationError("Snort detection checkpoint lost its policy count")
            count, seconds = limit
            retained_timestamps = list(timestamps)
            if watermark is not None:
                retained_timestamps = [
                    timestamp
                    for timestamp in retained_timestamps
                    if (watermark - timestamp).total_seconds() < seconds
                ]
            retained_timestamps = retained_timestamps[-(count + 1) :]
            if not retained_timestamps:
                continue
            payload = json.dumps(
                {
                    "key": list(key),
                    "count": count,
                    "seconds": seconds,
                    "timestamps": [timestamp.isoformat() for timestamp in retained_timestamps],
                },
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            checkpoint_key = json.dumps(
                ["detection", *key],
                ensure_ascii=False,
                separators=(",", ":"),
            )
            retained_bytes = len(checkpoint_key.encode()) + len(payload.encode()) + 128
            records.append((checkpoint_key, "detection", payload, retained_bytes))
        for key, window in sorted(engine._event_windows.items(), key=lambda item: item[0]):
            limit = event_limits.get(key)
            if limit is None:
                raise ExactPublicationError("Snort event checkpoint lost its policy count")
            count, seconds = limit
            if watermark is not None and (watermark - window.start).total_seconds() >= seconds:
                continue
            payload = json.dumps(
                {
                    "key": list(key),
                    "count": count,
                    "seconds": seconds,
                    "start": window.start.isoformat(),
                    "matches": min(int(window.matches), count + 1),
                    "emitted": bool(window.emitted),
                },
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            checkpoint_key = json.dumps(
                ["event", *key],
                ensure_ascii=False,
                separators=(",", ":"),
            )
            retained_bytes = len(checkpoint_key.encode()) + len(payload.encode()) + 128
            records.append((checkpoint_key, "event", payload, retained_bytes))
        records.sort(key=lambda record: record[0])
        return records

    def _build_finalization(
        self,
        *,
        raw_only: bool,
    ) -> tuple[
        dict[str, list[str]],
        dict[str, int],
        dict[str, dict[int, dict[str, Any]]],
        dict[str, dict[str, dict[str, Any]]],
    ]:
        connection = self._spool_connection
        if connection is None:
            self._summary_decisions = []
            self._summary_filter_records = []
            self._summary_filter_watermark = ""
            return (
                {},
                {},
                deepcopy(self._ids_alert_summary),
                self._copy_evaluation_summaries(self._ids_evaluation_summary),
            )
        filter_engine, detection_limits, event_limits = self._load_filter_checkpoint_unlocked()
        alert_summary = deepcopy(self._ids_alert_summary)
        evaluation_summary = self._copy_evaluation_summaries(self._ids_evaluation_summary)
        output_lines: dict[str, list[str]] = {}
        cutoffs: dict[str, int] = {}
        decisions: list[tuple[int, int, str | None]] = []
        evaluation_records: list[tuple[str, str, int, dict[str, Any], str, str]] = []
        watermark = self._filter_watermark_unlocked()
        watermark_timestamp = datetime.fromisoformat(watermark) if watermark else None
        rows = connection.execute(
            """SELECT sequence, row_kind, sensor, timestamp, gid, sid, payload, policy,
            cluster_id, occurrence_id, observation_status, origin, final_line, exported,
            summarized, admitted
            FROM candidates
            ORDER BY timestamp, sensor, occurrence_id, gid, sid, sequence"""
        )
        for (
            sequence,
            row_kind,
            sensor,
            timestamp,
            gid,
            sid,
            payload_json,
            policy_json,
            cluster_id,
            _occurrence_id,
            observation_status,
            origin,
            final_line,
            exported,
            summarized,
            frozen_admitted,
        ) in rows:
            if raw_only and row_kind != "raw":
                continue
            payload = json.loads(payload_json)
            payload["timestamp"] = datetime.fromisoformat(timestamp)
            is_exported = bool(int(exported))
            is_summarized = bool(int(summarized))
            evaluation: dict[str, Any] | None = None
            if not is_summarized:
                evaluation = self._evaluation_signature_in(
                    evaluation_summary,
                    str(sensor),
                    int(gid),
                    int(sid),
                )
                evaluation["candidate"] += 1
            admitted = True
            sid_summary: dict[str, Any] | None = None
            if row_kind == "candidate":
                policy = self._policy_from_json(policy_json)
                if not is_summarized:
                    sid_summary = alert_summary.setdefault(str(cluster_id), {}).setdefault(
                        int(sid),
                        {
                            "sid": int(sid),
                            "effective_policy": self._summary_policy(policy),
                            "candidate": 0,
                            "emitted": 0,
                            "policy_filtered": 0,
                            "emitted_visible": 0,
                            "emitted_delayed": 0,
                        },
                    )
                    sid_summary["candidate"] += 1
                if is_summarized:
                    if frozen_admitted is None:
                        raise ExactPublicationError("Snort candidate lost its frozen decision")
                    admitted = bool(int(frozen_admitted))
                else:
                    if policy is not None and policy.detection_filter is not None:
                        detection = policy.detection_filter
                        tracked = (
                            payload.get("src_ip", "")
                            if detection.track == "by_src"
                            else payload.get("dst_ip", "")
                        )
                        detection_key = (
                            str(sensor),
                            int(gid),
                            int(sid),
                            "detection",
                            detection.track,
                            str(tracked),
                        )
                        detection_limit = (detection.count, detection.seconds)
                        if detection_key in detection_limits and (
                            detection_limits[detection_key] != detection_limit
                        ):
                            raise ExactPublicationError(
                                "Snort detection policy changed after filter checkpoint"
                            )
                        detection_limits[detection_key] = detection_limit
                    if policy is not None and policy.event_filter is not None:
                        event_filter = policy.event_filter
                        tracked = (
                            payload.get("src_ip", "")
                            if event_filter.track == "by_src"
                            else payload.get("dst_ip", "")
                        )
                        event_key = (
                            str(sensor),
                            int(gid),
                            int(sid),
                            "event",
                            event_filter.type,
                            event_filter.track,
                            str(tracked),
                        )
                        event_limit = (event_filter.count, event_filter.seconds)
                        if event_key in event_limits and event_limits[event_key] != event_limit:
                            raise ExactPublicationError(
                                "Snort event policy changed after filter checkpoint"
                            )
                        event_limits[event_key] = event_limit
                    admitted = filter_engine.admit(
                        IdsAlertCandidate(
                            sensor=str(sensor),
                            timestamp=payload["timestamp"],
                            gid=int(gid),
                            sid=int(sid),
                            src_ip=payload.get("src_ip", ""),
                            dst_ip=payload.get("dst_ip", ""),
                            policy=policy,
                        )
                    )
                    if watermark_timestamp is None or payload["timestamp"] > watermark_timestamp:
                        watermark_timestamp = payload["timestamp"]
                if not admitted:
                    if sid_summary is not None:
                        sid_summary["policy_filtered"] += 1
                    if evaluation is not None:
                        evaluation["policy_filtered"] += 1
            if not is_exported:
                cutoffs[str(sensor)] = max(cutoffs.get(str(sensor), 0), int(sequence))
            rendered = str(final_line) if final_line is not None else None
            if admitted and rendered is None:
                rendered = self._render_alert(payload)
            if row_kind == "candidate" and not is_summarized:
                decisions.append((int(sequence), int(admitted and rendered is not None), rendered))
            if not admitted or is_exported or rendered is None:
                continue
            output_lines.setdefault(str(sensor), []).append(rendered)
            if sid_summary is not None:
                sid_summary["emitted"] += 1
                status_key = (
                    "emitted_delayed" if observation_status == "delayed" else "emitted_visible"
                )
                sid_summary[status_key] += 1
            if evaluation is not None:
                evaluation_records.append(
                    (
                        str(sensor),
                        rendered,
                        int(sequence),
                        payload,
                        str(origin),
                        str(observation_status),
                    )
                )
        for sensor, _line, _sequence, payload, origin, observation_status in sorted(
            evaluation_records,
            key=lambda record: (record[0], record[1], record[2]),
        ):
            self._record_evaluation_in(
                evaluation_summary,
                sensor,
                payload,
                origin=origin,
                observation_status=observation_status,
            )
        self._summary_decisions = decisions
        self._summary_filter_records = self._filter_checkpoint_records(
            filter_engine,
            detection_limits,
            event_limits,
            watermark_timestamp,
        )
        self._summary_filter_watermark = (
            watermark_timestamp.isoformat() if watermark_timestamp is not None else ""
        )
        return output_lines, cutoffs, alert_summary, evaluation_summary

    def _writer_buffer(self, sensor: str) -> tuple[Any | None, list[str]]:
        writer_key = "" if sensor == "__direct__" else self._safe_writer_key(sensor)
        writer = self._writers.get(writer_key)
        if writer is None:
            return None, []
        with writer._exact_publication_condition:
            with writer._lock:
                return writer, list(writer.buffer)

    def _consume_plan_buffer_unlocked(
        self,
        sensor: str,
        epoch: int,
        writer: Any | None,
        lines: list[str],
    ) -> None:
        """Consume one authenticated prefix once, including across lost SQL returns."""

        connection = self._spool_connection
        if connection is None:
            raise RuntimeError("Snort export lost its candidate journal")
        durable = connection.execute(
            """SELECT buffer_consumed FROM export_plans
            WHERE sensor = ? AND epoch = ?""",
            (sensor, epoch),
        ).fetchone()
        if durable is None:
            raise RuntimeError("Snort export lost its writer-prefix receipt")
        plan_key = (sensor, epoch)
        if int(durable[0]):
            self._consumed_plan_buffers.discard(plan_key)
            return
        if plan_key not in self._consumed_plan_buffers:
            if writer is not None and lines:
                with writer._exact_publication_condition:
                    with writer._lock:
                        if writer.buffer[: len(lines)] != lines:
                            raise ExactPublicationError(
                                "Snort export lost its authenticated writer prefix"
                            )
                        del writer.buffer[: len(lines)]
            self._consumed_plan_buffers.add(plan_key)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """UPDATE export_plans SET buffer_consumed = ?
                WHERE sensor = ? AND epoch = ? AND buffer_consumed = ?""",
                (1, sensor, epoch, 0),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        self._consumed_plan_buffers.discard(plan_key)

    def _validate_global_publication_capacity_unlocked(
        self,
        sensors: list[str],
        output_lines: dict[str, list[str]],
    ) -> None:
        """Charge every distinct output and sealed plan before any plan becomes durable."""

        if not sensors:
            return
        state = self._state_unlocked()
        planned_sensors = set(sensors)
        census_sensors = set(self._known_output_sensors) | planned_sensors
        with self._writers_lock:
            census_sensors.update("__direct__" if key == "" else key for key in self._writers)
        if self._direct_file_path:
            census_sensors.add("__direct__")
        expected_output_bytes = 0
        plan_bytes = 0
        refreshed_states: dict[str, _OutputRouteState] = {}
        refreshed_owners: dict[tuple[object, ...], str] = {}
        for sensor in sorted(census_sensors):
            state_snapshot = self._inspect_output_route_unlocked(sensor)[0]
            self._claim_output_state(state_snapshot, refreshed_owners)
            refreshed_states[sensor] = state_snapshot
            current_size = state_snapshot.size
            if sensor not in planned_sensors:
                expected_output_bytes += current_size
                continue
            _writer, buffer_lines = self._writer_buffer(sensor)
            new_lines = [*buffer_lines, *output_lines.get(sensor, [])]
            new_lines.sort()
            expected_output_bytes += current_size + sum(
                len(_line_bytes(line)) for line in new_lines
            )
            planned_json = json.dumps(
                new_lines,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            buffer_json = json.dumps(
                buffer_lines,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            plan_bytes += len(planned_json.encode("utf-8")) + len(buffer_json.encode("utf-8")) + 256
        self._replace_output_route_states_unlocked(refreshed_states)
        if state.retained_rows + len(sensors) > self._journal_row_capacity:
            raise ExactPublicationError("Snort journal row capacity is exhausted")
        projected_bytes = (
            state.retained_bytes
            + state.terminal_headroom_bytes
            + expected_output_bytes
            + plan_bytes
        )
        if projected_bytes > self._journal_byte_capacity:
            raise ExactPublicationError("Snort journal byte capacity is exhausted")
        self._retained_high_water_rows = max(
            self._retained_high_water_rows,
            state.retained_rows + len(sensors),
        )
        self._retained_high_water_bytes = max(
            self._retained_high_water_bytes,
            projected_bytes,
        )

    def _create_export_plan_unlocked(
        self,
        sensor: str,
        lines: list[str],
        cutoff: int | None,
        *,
        raw_only: bool,
    ) -> None:
        connection = self._spool_connection
        if connection is None:
            if cutoff is not None:
                raise RuntimeError("Snort export lost its candidate journal")
            return
        if (
            connection.execute(
                "SELECT 1 FROM export_plans WHERE sensor = ?",
                (sensor,),
            ).fetchone()
            is not None
        ):
            raise RuntimeError("Snort export plan was not reconciled before resealing")
        writer, buffer_lines = self._writer_buffer(sensor)
        if cutoff is None and not buffer_lines:
            return
        output_state, current_payload, baseline_digest = self._inspect_output_route_unlocked(
            sensor,
            include_payload=True,
        )
        if output_state.size > self._journal_byte_capacity:
            raise ExactPublicationError("Snort output exceeds journal byte capacity")
        if current_payload is None:  # pragma: no cover - requested above
            raise RuntimeError("Snort output snapshot lost its payload")
        current = current_payload
        new_lines = [*buffer_lines, *lines]
        new_lines.sort()
        expected = current + b"".join(_line_bytes(line) for line in new_lines)
        planned_json = json.dumps(
            new_lines,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        buffer_json = json.dumps(
            buffer_lines,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        retained_bytes = len(planned_json.encode("utf-8")) + len(buffer_json.encode("utf-8")) + 256
        state = self._state_unlocked()
        if state.retained_rows + 1 > self._journal_row_capacity:
            raise ExactPublicationError("Snort journal row capacity is exhausted")
        prospective_bytes = (
            len(expected) + state.retained_bytes + state.terminal_headroom_bytes + retained_bytes
        )
        if prospective_bytes > self._journal_byte_capacity:
            raise ExactPublicationError("Snort journal byte capacity is exhausted")
        epoch = self._next_epoch
        self._next_epoch += 1
        sealed_cutoff = cutoff or 0
        raw_rows = 0
        if cutoff is not None:
            raw_count = connection.execute(
                """SELECT COUNT(*) FROM candidates
                WHERE sensor = ? AND sequence <= ? AND exported = ? AND row_kind = ?""",
                (sensor, cutoff, 0, "raw"),
            ).fetchone()
            raw_rows = int(raw_count[0]) if raw_count is not None else 0
        try:
            connection.execute("BEGIN IMMEDIATE")
            if cutoff is not None:
                if raw_only:
                    connection.execute(
                        """UPDATE candidates SET epoch = ?
                        WHERE sensor = ? AND sequence <= ? AND exported = 0
                        AND row_kind = 'raw'""",
                        (epoch, sensor, cutoff),
                    )
                else:
                    connection.execute(
                        """UPDATE candidates SET epoch = ?
                        WHERE sensor = ? AND sequence <= ? AND exported = 0""",
                        (epoch, sensor, cutoff),
                    )
            connection.execute(
                """INSERT INTO export_plans
                (sensor, epoch, raw_only, cutoff_sequence, baseline_digest, baseline_size,
                 expected_digest, expected_size, planned_lines, buffer_lines,
                 buffer_consumed, raw_rows, retained_bytes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sensor,
                    epoch,
                    int(raw_only),
                    sealed_cutoff,
                    baseline_digest,
                    len(current),
                    _sha256(expected),
                    len(expected),
                    planned_json,
                    buffer_json,
                    0,
                    raw_rows,
                    retained_bytes,
                ),
            )
            connection.execute(
                """UPDATE spool_state SET
                plan_rows = plan_rows + ?, plan_bytes = plan_bytes + ?,
                high_water_rows = MAX(high_water_rows, ?),
                high_water_bytes = MAX(high_water_bytes, ?)
                WHERE singleton = ?""",
                (
                    1,
                    retained_bytes,
                    max(state.retained_rows + 1, state.high_water_rows),
                    max(prospective_bytes, state.high_water_bytes),
                    1,
                ),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        self._consume_plan_buffer_unlocked(sensor, epoch, writer, buffer_lines)

    def _reconcile_output(self, sensor: str, digest: str, size: int) -> None:
        """Verify expected bytes and repeat both file and directory durability barriers."""

        state_snapshot, payload, actual_digest = self._inspect_output_route_unlocked(
            sensor,
            include_payload=True,
        )
        if state_snapshot.size != size or payload is None:
            raise ExactPublicationError("Snort export encountered conflicting final-file bytes")
        if actual_digest != digest:
            raise ExactPublicationError("Snort export encountered conflicting final-file bytes")
        output_path = state_snapshot.path
        directory_descriptor = _open_directory_nofollow(output_path.parent, create=False)
        try:
            parent = os.fstat(directory_descriptor)
            if (int(parent.st_dev), int(parent.st_ino)) != state_snapshot.parent_identity:
                raise ExactPublicationError("Snort output parent identity changed")
            descriptor = _open_regular_nofollow(
                directory_descriptor,
                output_path.name,
                os.O_RDONLY,
            )
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        self._refresh_output_route_unlocked(state_snapshot)

    def _replace_output(self, sensor: str, payload: bytes) -> None:
        """Atomically publish one complete sensor file and prove its durability."""

        output_path = self._output_path_for_sensor(sensor)
        retained = self._output_route_states.get(sensor)
        if retained is None:
            raise ExactPublicationError("Snort output route lost its physical owner")
        directory_descriptor = _open_directory_nofollow(output_path.parent, create=False)
        temporary_descriptor: int | None = None
        temporary_name: str | None = None
        temporary_identity: tuple[int, int] | None = None
        try:
            parent = os.fstat(directory_descriptor)
            if (int(parent.st_dev), int(parent.st_ino)) != retained.parent_identity:
                raise ExactPublicationError("Snort output parent identity changed")
            _safe_file_metadata(directory_descriptor, output_path.name, label="output")
            temporary_descriptor, temporary_name = _create_private_file(
                directory_descriptor,
                prefix=f".{output_path.name}.",
                suffix=".tmp",
            )
            temporary = os.fstat(temporary_descriptor)
            temporary_identity = (int(temporary.st_dev), int(temporary.st_ino))
            os.fchmod(temporary_descriptor, 0o600)
            view = memoryview(payload)
            while view:
                written = os.write(temporary_descriptor, view)
                view = view[written:]
            os.fsync(temporary_descriptor)
            os.close(temporary_descriptor)
            temporary_descriptor = None
            os.rename(
                temporary_name,
                output_path.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            temporary_name = None
            os.fsync(directory_descriptor)
        finally:
            if temporary_descriptor is not None:
                os.close(temporary_descriptor)
            if temporary_name is not None:
                metadata = _safe_file_metadata(
                    directory_descriptor,
                    temporary_name,
                    label="export temporary",
                )
                if metadata is not None and temporary_identity == (
                    int(metadata.st_dev),
                    int(metadata.st_ino),
                ):
                    os.unlink(temporary_name, dir_fd=directory_descriptor)
                    os.fsync(directory_descriptor)
            os.close(directory_descriptor)
        self._reconcile_output(sensor, _sha256(payload), len(payload))

    def _resume_export_plan_unlocked(self, sensor: str) -> bool:
        connection = self._spool_connection
        if connection is None:
            return False
        plan = connection.execute(
            """SELECT epoch, raw_only, baseline_digest, baseline_size, expected_digest,
            expected_size, planned_lines, buffer_lines, buffer_consumed, raw_rows,
            retained_bytes
            FROM export_plans WHERE sensor = ?""",
            (sensor,),
        ).fetchone()
        if plan is None:
            return False
        (
            epoch,
            raw_only,
            baseline_digest,
            baseline_size,
            expected_digest,
            expected_size,
            planned_json,
            buffer_json,
            _buffer_consumed,
            raw_rows,
            retained_bytes,
        ) = plan
        writer, _current_buffer = self._writer_buffer(sensor)
        planned_buffer = json.loads(str(buffer_json))
        if type(planned_buffer) is not list or not all(
            type(line) is str for line in planned_buffer
        ):
            raise ExactPublicationError("Snort export plan lost its writer prefix")
        planned_lines = json.loads(str(planned_json))
        if type(planned_lines) is not list or not all(type(line) is str for line in planned_lines):
            raise ExactPublicationError("Snort export plan lost its final lines")
        self._consume_plan_buffer_unlocked(
            sensor,
            int(epoch),
            writer,
            planned_buffer,
        )
        output_state, current_payload, current_digest = self._inspect_output_route_unlocked(
            sensor,
            include_payload=True,
        )
        actual_size = output_state.size
        if actual_size not in {int(baseline_size), int(expected_size)}:
            raise ExactPublicationError("Snort output changed outside its final-writer journal")
        if current_payload is None:  # pragma: no cover - requested above
            raise RuntimeError("Snort output snapshot lost its payload")
        current = current_payload
        if current_digest == str(baseline_digest):
            expected = current + b"".join(_line_bytes(line) for line in planned_lines)
            if len(expected) != int(expected_size) or _sha256(expected) != str(expected_digest):
                raise ExactPublicationError("Snort export plan changed before publication")
            self._replace_output(sensor, expected)
        elif current_digest != str(expected_digest):
            raise ExactPublicationError("Snort output changed outside its final-writer journal")
        self._reconcile_output(sensor, str(expected_digest), int(expected_size))
        parameters: tuple[object, ...] = (sensor, int(epoch))
        if int(raw_only):
            row = connection.execute(
                """SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0),
                COALESCE(SUM(terminal_headroom_bytes), 0)
                FROM candidates
                WHERE sensor = ? AND epoch = ? AND exported = 0
                AND row_kind = 'raw'""",
                parameters,
            ).fetchone()
        else:
            row = connection.execute(
                """SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0),
                COALESCE(SUM(terminal_headroom_bytes), 0)
                FROM candidates
                WHERE sensor = ? AND epoch = ? AND exported = 0""",
                parameters,
            ).fetchone()
        total_rows, total_bytes, total_headroom = (
            (int(row[0]), int(row[1]), int(row[2])) if row else (0, 0, 0)
        )
        if int(raw_only):
            retained_row = connection.execute(
                """SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0)
                FROM candidates
                WHERE sensor = ? AND epoch = ? AND exported = 0 AND released = 0
                AND row_kind = 'raw'""",
                parameters,
            ).fetchone()
        else:
            retained_row = connection.execute(
                """SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0)
                FROM candidates
                WHERE sensor = ? AND epoch = ? AND exported = 0 AND released = 0""",
                parameters,
            ).fetchone()
        retained_rows, retained_candidate_bytes = (
            (int(retained_row[0]), int(retained_row[1])) if retained_row else (0, 0)
        )
        if int(raw_only):
            receipt_row = connection.execute(
                """SELECT COUNT(*), COALESCE(SUM(a.retained_bytes), 0)
                FROM candidates AS c
                JOIN admission_receipts AS a
                ON a.publication_key = c.publication_key
                WHERE c.sensor = ? AND c.epoch = ? AND c.exported = 0
                AND c.row_kind = 'raw' AND a.export_slot = ?""",
                (*parameters, 1),
            ).fetchone()
        else:
            receipt_row = connection.execute(
                """SELECT COUNT(*), COALESCE(SUM(a.retained_bytes), 0)
                FROM candidates AS c
                JOIN admission_receipts AS a
                ON a.publication_key = c.publication_key
                WHERE c.sensor = ? AND c.epoch = ? AND c.exported = 0
                AND a.export_slot = ?""",
                (*parameters, 1),
            ).fetchone()
        receipt_rows, receipt_bytes = (
            (int(receipt_row[0]), int(receipt_row[1])) if receipt_row else (0, 0)
        )
        try:
            connection.execute("BEGIN IMMEDIATE")
            if int(raw_only):
                connection.execute(
                    """INSERT OR IGNORE INTO export_receipts
                    (publication_key, publication_digest, retained_bytes)
                    SELECT c.publication_key, c.publication_digest, a.retained_bytes
                    FROM candidates AS c
                    JOIN admission_receipts AS a
                    ON a.publication_key = c.publication_key
                    WHERE c.sensor = ? AND c.epoch = ? AND c.exported = 0
                    AND c.row_kind = 'raw' AND a.export_slot = ?""",
                    (*parameters, 1),
                )
                connection.execute(
                    """UPDATE admission_receipts SET export_slot = ?
                    WHERE export_slot = ? AND publication_key IN (
                        SELECT publication_key FROM candidates
                        WHERE sensor = ? AND epoch = ? AND exported = 0
                        AND row_kind = 'raw'
                    )""",
                    (0, 1, *parameters),
                )
                connection.execute(
                    """UPDATE candidates SET exported = 1
                    WHERE sensor = ? AND epoch = ? AND exported = 0
                    AND row_kind = 'raw' AND released = 0""",
                    parameters,
                )
                connection.execute(
                    """DELETE FROM candidates
                    WHERE sensor = ? AND epoch = ? AND exported = 0
                    AND row_kind = 'raw' AND released = 1 AND summarized = 1""",
                    parameters,
                )
            else:
                connection.execute(
                    """INSERT OR IGNORE INTO export_receipts
                    (publication_key, publication_digest, retained_bytes)
                    SELECT c.publication_key, c.publication_digest, a.retained_bytes
                    FROM candidates AS c
                    JOIN admission_receipts AS a
                    ON a.publication_key = c.publication_key
                    WHERE c.sensor = ? AND c.epoch = ? AND c.exported = 0
                    AND a.export_slot = ?""",
                    (*parameters, 1),
                )
                connection.execute(
                    """UPDATE admission_receipts SET export_slot = ?
                    WHERE export_slot = ? AND publication_key IN (
                        SELECT publication_key FROM candidates
                        WHERE sensor = ? AND epoch = ? AND exported = 0
                    )""",
                    (0, 1, *parameters),
                )
                connection.execute(
                    """UPDATE candidates SET exported = 1
                    WHERE sensor = ? AND epoch = ? AND exported = 0 AND released = 0""",
                    parameters,
                )
                connection.execute(
                    """DELETE FROM candidates
                    WHERE sensor = ? AND epoch = ? AND exported = 0
                    AND released = 1 AND summarized = 1""",
                    parameters,
                )
            connection.execute(
                """UPDATE spool_state SET
                pending_rows = pending_rows - ?,
                pending_bytes = pending_bytes - ?,
                terminal_headroom_bytes = terminal_headroom_bytes - ?,
                exported_rows = exported_rows + ?,
                exported_bytes = exported_bytes + ?,
                export_slots = export_slots - ?,
                export_slot_bytes = export_slot_bytes - ?,
                export_receipts = export_receipts + ?,
                export_bytes = export_bytes + ?,
                plan_rows = plan_rows - ?,
                plan_bytes = plan_bytes - ?
                WHERE singleton = 1""",
                (
                    total_rows,
                    total_bytes,
                    total_headroom,
                    retained_rows,
                    retained_candidate_bytes,
                    receipt_rows,
                    receipt_bytes,
                    receipt_rows,
                    receipt_bytes,
                    1,
                    int(retained_bytes),
                ),
            )
            if int(raw_rows):
                updated_raw = connection.execute(
                    """UPDATE raw_sensor_state SET pending_rows = pending_rows - ?
                    WHERE sensor = ? AND pending_rows >= ?
                    RETURNING pending_rows""",
                    (int(raw_rows), sensor, int(raw_rows)),
                ).fetchone()
                if updated_raw is None:
                    raise RuntimeError("Snort journal raw sensor census underflowed")
                if int(updated_raw[0]) == 0:
                    connection.execute(
                        "DELETE FROM raw_sensor_state WHERE sensor = ?",
                        (sensor,),
                    )
            connection.execute("DELETE FROM export_plans WHERE sensor = ?", (sensor,))
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        self._refresh_retained_census_unlocked()
        self._consumed_plan_buffers.discard((sensor, int(epoch)))
        return True

    def _publish_pending_once_unlocked(self, *, raw_only: bool) -> None:
        connection = self._spool_connection
        if connection is None:
            return
        self._reconcile_pending_summary_unlocked()
        for (sensor,) in connection.execute(
            "SELECT sensor FROM export_plans ORDER BY sensor"
        ).fetchall():
            self._resume_export_plan_unlocked(str(sensor))
        output_lines, cutoffs, alert_summary, evaluation_summary = self._build_finalization(
            raw_only=raw_only
        )
        writer_sensors = {
            "__direct__" if key == "" else key
            for key, writer in self._writers.items()
            if writer.buffer
        }
        sensors = sorted(set(cutoffs) | writer_sensors)
        self._summary_scope = "raw" if raw_only else "all"
        try:
            self._persist_summaries_unlocked(alert_summary, evaluation_summary)
        finally:
            self._summary_scope = "none"
        self._validate_global_publication_capacity_unlocked(sensors, output_lines)
        for sensor in sensors:
            self._create_export_plan_unlocked(
                sensor,
                output_lines.get(sensor, []),
                cutoffs.get(sensor),
                raw_only=raw_only,
            )
        for sensor in sensors:
            self._resume_export_plan_unlocked(sensor)

    def _publish_pending_unlocked(self, *, raw_only: bool) -> None:
        """Publish one sealed epoch or retain a recovery-only admission fence."""

        try:
            self._publish_pending_once_unlocked(raw_only=raw_only)
        except BaseException:
            connection = self._spool_connection
            if connection is not None:
                unresolved = connection.execute(
                    "SELECT 1 FROM export_plans LIMIT ?",
                    (1,),
                ).fetchone()
                sealed = connection.execute(
                    """SELECT 1 FROM candidates
                    WHERE summarized = ? AND exported = ? LIMIT ?""",
                    (1, 0, 1),
                ).fetchone()
                self._export_recovery_pending = (
                    self._export_recovery_pending or unresolved is not None or sealed is not None
                )
            raise
        self._export_recovery_pending = False
        self._worker_publication_error = None

    def _finalize_candidates(self) -> None:
        """Replay filtering and publish all rows in one closed retry epoch."""

        self._publish_pending_unlocked(raw_only=False)

    def _flush_impl(self) -> None:
        self._wait_for_exact_publication_turn(None)
        with self._spool_lock:
            if self._spool_connection is not None:
                self._publish_pending_unlocked(raw_only=True)
                return
        super().flush()

    def _begin_boundary_admission(self) -> None:
        """Admit a recovery boundary without admitting new event payloads."""

        with self._close_condition:
            super()._require_accepting_events_locked()
            self._queue_admissions += 1

    def flush(self) -> None:
        """Preserve ordinary raw visibility and publish committed exact raw rows."""

        owner_thread = get_ident()
        worker_thread = self._thread.ident if self._thread is not None else None
        internal_boundary = owner_thread in {
            worker_thread,
            self._close_thread,
            self._terminal_cleanup_thread,
        }
        if internal_boundary:
            self._flush_impl()
            return
        with self._producer_lock:
            self._begin_boundary_admission()
        try:
            while True:
                with self._producer_lock:
                    with self._exact_publication_condition:
                        exact_active = bool(self._active_exact_publication_keys)
                    if not exact_active:
                        self._flush_impl()
                        return
                self._wait_for_exact_publication_turn(None)
        finally:
            self._finish_queue_admission()

    def barrier_flush(self) -> None:
        """Keep the public FIFO barrier atomic with respect to producer admission."""

        owner_thread = get_ident()
        worker_thread = self._thread.ident if self._thread is not None else None
        internal_boundary = owner_thread in {
            worker_thread,
            self._close_thread,
            self._terminal_cleanup_thread,
        }
        if internal_boundary:
            super().barrier_flush()
            return
        with self._producer_lock:
            self._begin_boundary_admission()
        try:
            while True:
                with self._producer_lock:
                    with self._exact_publication_condition:
                        exact_active = bool(self._active_exact_publication_keys)
                    if not exact_active:
                        super().barrier_flush()
                        return
                self._wait_for_exact_publication_turn(None)
        finally:
            self._finish_queue_admission()

    def _begin_epoch_aware_close(self) -> bool:
        """Claim close atomically with producer admission, then wait without its lock."""

        owner_thread = get_ident()
        while True:
            wait_for_closer = False
            with self._producer_lock:
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
                        break
            if wait_for_closer:
                with self._close_condition:
                    while self._close_state == "closing":
                        self._close_condition.wait()
        with self._close_condition:
            while self._active_exact_publication_keys or self._queue_admissions:
                self._close_condition.wait()
        return True

    def _cleanup_journal_unlocked(self) -> None:
        """Retryably remove only the owned database, companions, and private leaf."""

        self._journal_cleanup_pending = True
        connection = self._spool_connection
        if connection is not None:
            try:
                self._close_spool_connection(connection)
            except BaseException:
                try:
                    connection.execute("SELECT 1")
                except sqlite3.ProgrammingError:
                    self._spool_connection = None
                raise
            else:
                self._spool_connection = None
        owner = self._journal_owner
        if owner is None:
            self._clear_journal_mirrors_unlocked()
            self._journal_cleanup_pending = False
            return
        journal_filename = self._journal_filename
        if journal_filename is not None:
            directory_descriptor = owner.directory_descriptor
            identity = _safe_file_metadata(
                directory_descriptor,
                journal_filename,
                label="journal",
            )
            if identity is None:
                self._journal_unlinked = True
            elif (
                self._journal_identity is None
                or identity.st_nlink != 1
                or (int(identity.st_dev), int(identity.st_ino)) != self._journal_identity
            ):
                raise ExactPublicationError("Snort journal identity changed before cleanup")
            if not self._journal_unlinked:
                try:
                    self._unlink_cleanup_journal(directory_descriptor, journal_filename)
                except BaseException:
                    try:
                        os.stat(
                            journal_filename,
                            dir_fd=directory_descriptor,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        self._journal_unlinked = True
                    raise
                else:
                    self._journal_unlinked = True
            for suffix in _SQLITE_COMPANION_SUFFIXES:
                companion = f"{journal_filename}{suffix}"
                metadata = _safe_file_metadata(
                    directory_descriptor,
                    companion,
                    label="journal companion",
                )
                if metadata is not None:
                    self._unlink_cleanup_companion(directory_descriptor, companion)
            self._fsync_cleanup_directory(directory_descriptor)
            self._spool_path = None
            self._journal_path = None
            self._journal_filename = None
            self._journal_identity = None
            self._journal_unlinked = False
        owner.close()
        self._journal_owner = None
        self._clear_journal_mirrors_unlocked()
        self._journal_cleanup_pending = False

    def _clear_journal_mirrors_unlocked(self) -> None:
        self._spool_path = None
        self._journal_path = None
        self._journal_directory = None
        self._journal_directory_descriptor = None
        self._journal_filename = None
        self._journal_identity = None
        self._journal_directory_identity = None
        self._journal_unlinked = False

    def _unlink_cleanup_journal(self, directory_descriptor: int, name: str) -> None:
        os.unlink(name, dir_fd=directory_descriptor)

    def _close_spool_connection(self, connection: sqlite3.Connection) -> None:
        connection.close()

    def _unlink_cleanup_companion(self, directory_descriptor: int, name: str) -> None:
        os.unlink(name, dir_fd=directory_descriptor)

    def _fsync_cleanup_directory(self, directory_descriptor: int) -> None:
        os.fsync(directory_descriptor)

    def _compact_terminal_journal_unlocked(self) -> bool:
        connection = self._spool_connection
        if connection is None:
            if self._journal_owner is not None or self._journal_cleanup_pending:
                self._cleanup_journal_unlocked()
            self._unpersisted_summary_rows = 0
            self._unpersisted_summary_bytes = 0
            return self._journal_owner is None
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM candidates")
            connection.execute("DELETE FROM export_receipts")
            connection.execute("DELETE FROM export_plans")
            connection.execute("DELETE FROM summaries")
            connection.execute("DELETE FROM filter_checkpoints")
            connection.execute("DELETE FROM raw_sensor_state")
            connection.execute(
                "UPDATE admission_receipts SET export_slot = ? WHERE export_slot = ?",
                (0, 1),
            )
            connection.execute(
                """UPDATE spool_state SET
                pending_rows = ?, pending_bytes = ?, exported_rows = ?, exported_bytes = ?,
                export_slots = ?, export_slot_bytes = ?,
                export_receipts = ?, export_bytes = ?,
                summary_rows = ?, summary_bytes = ?,
                filter_rows = ?, filter_bytes = ?, terminal_headroom_bytes = ?,
                filter_watermark = ?,
                plan_rows = ?, plan_bytes = ?
                WHERE singleton = ?""",
                (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "", 0, 0, 1),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        self._pending_summary_snapshot = None
        self._consumed_plan_buffers.clear()
        self._refresh_retained_census_unlocked()
        if self._state_unlocked().admission_receipts == 0:
            self._cleanup_journal_unlocked()
            return True
        return False

    def _finish_terminal_cleanup(self) -> None:
        """Retry terminal resource cleanup without ever reopening stopped resources."""

        owner_thread = get_ident()
        with self._close_condition:
            while (
                self._terminal_cleanup_thread is not None
                and self._terminal_cleanup_thread != owner_thread
            ):
                self._close_condition.wait()
            if not self._terminal_cleanup_pending:
                return
            self._terminal_cleanup_thread = owner_thread
        try:
            if self.threaded:
                self.stop_thread()
            with self._writers_lock:
                for writer in self._writers.values():
                    writer.close()
            with self._spool_lock:
                cleanup_complete = self._compact_terminal_journal_unlocked()
        except BaseException:
            raise
        else:
            self._terminal_cleanup_pending = not cleanup_complete
        finally:
            with self._close_condition:
                self._terminal_cleanup_thread = None
                self._close_condition.notify_all()

    def close(self) -> None:
        """Finalize retryably and remove the spool only after every file is proven."""

        if not self._begin_epoch_aware_close():
            self._finish_terminal_cleanup()
            return
        try:
            if self.threaded:
                self._drain_threaded_before_exact()
            with self._spool_lock:
                if self._spool_connection is not None:
                    self._finalize_candidates()
                    self._refresh_retained_census_unlocked()
        except BaseException:
            if self._export_recovery_pending:
                try:
                    with self._spool_lock:
                        self._finalize_candidates()
                except BaseException:
                    pass
            self._fail_close()
            raise
        self._terminal_cleanup_pending = True
        try:
            self._finish_terminal_cleanup()
        except BaseException:
            self._finish_close()
            raise
        self._finish_close()

    def journal_census(self) -> SnortJournalCensus:
        """Return bounded journal counts without materializing retained rows."""

        with self._spool_lock:
            state = self._state_unlocked()
            active_receipts = len(self._exact_candidate_receipts)
            reserved_rows = self._exact_reserved_rows
            reserved_bytes = self._exact_reserved_bytes
        return SnortJournalCensus(
            pending_rows=state.pending_rows,
            pending_bytes=state.pending_bytes,
            exported_rows=state.exported_rows,
            exported_bytes=state.exported_bytes,
            reserved_rows=reserved_rows,
            reserved_bytes=reserved_bytes,
            active_receipts=active_receipts,
            row_capacity=self._journal_row_capacity,
            byte_capacity=self._journal_byte_capacity,
            high_water_rows=state.high_water_rows,
            high_water_bytes=state.high_water_bytes,
            total_events=state.total_events,
            admission_receipts=state.admission_receipts,
            export_receipts=state.export_receipts,
            summary_rows=state.summary_rows,
            filter_rows=state.filter_rows,
            terminal_headroom_bytes=state.terminal_headroom_bytes,
            retained_rows=state.retained_rows,
            retained_bytes=state.retained_bytes,
        )

    @property
    def event_count(self) -> int:
        with self._spool_lock:
            return self._emitted_event_count

    @event_count.setter
    def event_count(self, value: int) -> None:
        del value

    @property
    def ids_alert_summary(self) -> dict[str, dict[int, dict[str, Any]]]:
        """Return per-storyline-event, per-SID candidate and filtering totals."""

        return self._ids_alert_summary

    @property
    def ids_evaluation_summary(self) -> dict[str, dict[str, dict[str, Any]]]:
        """Return bounded sensor/SID totals and expected rendered-alert digests."""

        return {
            sensor: {
                key: {
                    name: (value.hexdigest() if name == "_digest" else value)
                    for name, value in summary.items()
                    if name != "_digest"
                }
                | {"emitted_sha256": summary["_digest"].hexdigest()}
                for key, summary in signatures.items()
            }
            for sensor, signatures in self._ids_evaluation_summary.items()
        }
